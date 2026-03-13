// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/slayers"
	scionpath "github.com/scionproto/scion/pkg/slayers/path/scion"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	wgconn "github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// debugSCIONPreference is the TS_SCION_PREFERENCE envknob controlling the
// betterAddr points bonus for SCION paths. Default 15; set to 0 to disable.
var debugSCIONPreference = envknob.RegisterInt("TS_SCION_PREFERENCE")

// preferSCION reports whether TS_PREFER_SCION=1 is set, which makes SCION
// paths unconditionally preferred over all other path types (direct, relay).
// Other paths are only used if no SCION path is available.
var preferSCION = envknob.RegisterBool("TS_PREFER_SCION")

// scionPreferenceBonus returns the betterAddr points bonus for SCION paths.
// Returns the value of TS_SCION_PREFERENCE if set, otherwise defaults to 15.
func scionPreferenceBonus() int {
	if v := debugSCIONPreference(); v != 0 {
		return v
	}
	if v, ok := envknob.LookupInt("TS_SCION_PREFERENCE"); ok {
		return v // allow explicit 0
	}
	return 15
}

// scionPathKey is a compact index into the Conn-level scionPaths registry.
// This keeps epAddr small and comparable (snet.UDPAddr contains slices).
// A zero value means "not a SCION path."
type scionPathKey uint32

// IsSet reports whether k refers to a valid SCION path entry.
func (k scionPathKey) IsSet() bool { return k != 0 }

// scionAddrKey is a comparable key for the reverse index from (IA, host:port)
// to scionPathKey, enabling O(1) lookup in receiveSCION.
type scionAddrKey struct {
	ia   addr.IA
	addr netip.AddrPort
}

// scionPathInfo holds the full SCION path information for a peer, indexed by
// scionPathKey. The actual SCION address and path data live here rather than
// in epAddr to keep epAddr comparable and small.
type scionPathInfo struct {
	peerIA      addr.IA
	hostAddr    netip.AddrPort       // peer's SCION host IP:port
	fingerprint snet.PathFingerprint // SHA256 of interface sequence; for matching across refreshes
	path        snet.Path            // current best SCION path to this peer
	replyPath   *snet.UDPAddr        // bootstrapped from incoming packet (pre-reversed)
	cachedDst   *snet.UDPAddr        // pre-built destination addr; rebuilt when path changes
	fastPath    *scionFastPath       // pre-serialized header template for fast sends
	expiry           time.Time            // path expiration from path metadata
	mtu              uint16               // SCION payload MTU from path metadata
	refreshMissCount int                  // consecutive refresh cycles fingerprint absent from daemon
	mu               sync.Mutex
}

// buildCachedDst constructs the cached destination address from the current
// path info. Must be called with pi.mu held (or before the info is shared).
func (pi *scionPathInfo) buildCachedDst() {
	dst := &snet.UDPAddr{
		IA: pi.peerIA,
		Host: &net.UDPAddr{
			IP:   pi.hostAddr.Addr().AsSlice(),
			Port: int(pi.hostAddr.Port()),
		},
	}
	if pi.path != nil {
		dst.Path = pi.path.Dataplane()
		dst.NextHop = pi.path.UnderlayNextHop()
	}
	pi.cachedDst = dst
}

// scionHeaderOverhead is the fixed overhead added by SCION encapsulation,
// excluding the variable-length path header:
//   - Underlay IPv4+UDP: 20 + 8 = 28 bytes (or IPv6+UDP: 40 + 8 = 48 bytes)
//   - SCION common header: 12 bytes
//   - Address header (IPv4, 2x ISD-AS + 2x IPv4): 2*8 + 2*4 = 24 bytes
//   - SCION/UDP L4 header: 8 bytes
//
// Total fixed: 72 bytes. The path header is variable (depends on hop count).
// Rather than parsing the path to determine the exact overhead, we use the
// path MTU from metadata directly: the SCION daemon reports the maximum
// *payload* size that can traverse the path (i.e., MTU already accounts for
// all SCION headers). So the effective wire MTU for WireGuard is simply the
// SCION path MTU.
//
// However, when no path MTU is available, we use a conservative estimate:
// 1280 bytes (minimum IPv6-compatible MTU).
const scionFallbackPayloadMTU = 1280

// scionUnsetHopLatency is the assumed per-hop latency when the SCION daemon
// reports LatencyUnset for a hop. Conservative estimate for path selection.
const scionUnsetHopLatency = 10 * time.Millisecond

// scionReadDeadline is the read deadline set on the SCION socket.
// If no packet is received within this duration, we check whether the
// socket is still alive. This must be long enough to avoid spurious
// reconnections during idle periods, but short enough to detect a dead
// socket promptly.
const scionReadDeadline = 30 * time.Second

// scionReconnectThreshold is the maximum time without receiving any SCION
// packet before we consider the socket dead and attempt to reconnect.
// This is only checked when there are active SCION peers.
const scionReconnectThreshold = 30 * time.Second

// defaultSCIONProbePaths is the default number of SCION paths to probe per peer.
const defaultSCIONProbePaths = 5

// scionStalePathThreshold is the number of consecutive refresh cycles a
// fingerprint must be absent from daemon results before the path is removed.
// At the default 30s refresh interval, this is ~90s.
const scionStalePathThreshold = 3

// scionPongHistoryCount is the ring buffer size for per-path pong latency tracking.
const scionPongHistoryCount = 8

// scionMaxProbePaths returns the max number of SCION paths to probe per peer.
// Defaults to 5, overridable via TS_SCION_MAX_PROBE_PATHS.
func scionMaxProbePaths() int {
	if v, ok := envknob.LookupInt("TS_SCION_MAX_PROBE_PATHS"); ok && v > 0 {
		return v
	}
	return defaultSCIONProbePaths
}

// scionEndpointState tracks SCION-specific per-peer state on an endpoint.
type scionEndpointState struct {
	peerIA          addr.IA                                // peer's ISD-AS from Services advertisement
	hostAddr        netip.AddrPort                         // peer's SCION host IP:port
	paths           map[scionPathKey]*scionPathProbeState  // probed paths (up to scionMaxProbePaths)
	activePath      scionPathKey                           // currently selected best path for data
	lastDiscoveryAt time.Time                              // when path discovery last started (throttle)
	lastFullEvalAt  mono.Time                              // throttles re-evaluation of SCION path latencies
	probeRoundRobin int                                    // round-robin index for non-best path probing
}

// scionPathProbeState tracks disco probing state for one SCION path.
type scionPathProbeState struct {
	fingerprint     snet.PathFingerprint
	lastPing        mono.Time
	recentPongs     [scionPongHistoryCount]scionPongReply // ring buffer
	recentPong      uint16                                // index of most recent entry
	pongCount       uint16                                // total pongs received (capped at ring size)
	pingsSent       uint32                                // total pings sent on this path
	pongsReceived   uint32                                // total pongs received (uncapped)
	consecutiveLoss uint16                                // consecutive pings without pong (reset on pong)
	healthy         bool                                  // false = demoted from active selection
}

// scionPongReply records one pong measurement for a SCION path.
type scionPongReply struct {
	latency time.Duration
	pongAt  mono.Time
}

// addPongReply records a pong measurement in the ring buffer.
func (ps *scionPathProbeState) addPongReply(r scionPongReply) {
	ps.recentPong = (ps.recentPong + 1) % scionPongHistoryCount
	ps.recentPongs[ps.recentPong] = r
	if ps.pongCount < scionPongHistoryCount {
		ps.pongCount++
	}
}

// latency returns the most recent pong latency, or time.Hour if no pongs received.
func (ps *scionPathProbeState) latency() time.Duration {
	if ps.pongCount == 0 {
		return time.Hour
	}
	return ps.recentPongs[ps.recentPong].latency
}

// scionFastPath holds a pre-serialized SCION+UDP header template for a
// specific path. At send time, the template is copied, per-packet fields
// (PayloadLen, UDP Length, UDP Checksum) are patched, payload is appended,
// and the result is sent directly on the underlay UDP socket — bypassing
// snet.Conn and gopacket serialization entirely.
type scionFastPath struct {
	hdr        []byte       // [SCION header][UDP header], no payload
	udpOffset  int          // byte offset of UDP header within hdr
	nextHop    *net.UDPAddr // underlay next-hop for this path
	pseudoCsum uint32       // constant part of SCION pseudo-header checksum
}

// scionMaxBatchSize is the max number of packets in a single sendmmsg call.
const scionMaxBatchSize = 64

// scionSendBatch is a reusable set of buffers for sendSCIONBatchFast.
type scionSendBatch struct {
	bufs [][]byte
	msgs []ipv4.Message
}

var scionSendBatchPool = sync.Pool{
	New: func() any {
		b := &scionSendBatch{
			bufs: make([][]byte, scionMaxBatchSize),
			msgs: make([]ipv4.Message, scionMaxBatchSize),
		}
		for i := range b.bufs {
			b.bufs[i] = make([]byte, 1500)
		}
		for i := range b.msgs {
			b.msgs[i].Buffers = make([][]byte, 1)
		}
		return b
	},
}

// scionRecvBatch is a reusable set of buffers for receiveSCIONBatch.
type scionRecvBatch struct {
	msgs []ipv4.Message
	bufs [][]byte
	scn  slayers.SCION // reusable SCION header parser (with RecyclePaths)
}

var scionRecvBatchPool = sync.Pool{
	New: func() any {
		b := &scionRecvBatch{
			msgs: make([]ipv4.Message, scionMaxBatchSize),
			bufs: make([][]byte, scionMaxBatchSize),
		}
		b.scn.RecyclePaths()
		for i := range b.bufs {
			b.bufs[i] = make([]byte, 1500)
		}
		for i := range b.msgs {
			b.msgs[i].Buffers = [][]byte{b.bufs[i]}
		}
		return b
	},
}

// putScionRecvBatch resets batch state and returns it to the pool.
func putScionRecvBatch(batch *scionRecvBatch) {
	for i := range batch.msgs {
		batch.msgs[i].N = 0
		batch.msgs[i].Addr = nil
		batch.msgs[i].Buffers[0] = batch.bufs[i]
	}
	scionRecvBatchPool.Put(batch)
}

// scionPseudoHeaderPartial computes the constant part of the SCION
// pseudo-header checksum: srcIA + dstIA + srcAddr + dstAddr + protocol(17).
// The per-packet upper-layer length and data are added at send time.
func scionPseudoHeaderPartial(srcIA, dstIA addr.IA, srcIP, dstIP netip.Addr) uint32 {
	var csum uint32
	var buf [8]byte

	// Source IA (8 bytes)
	binary.BigEndian.PutUint64(buf[:], uint64(srcIA))
	for i := 0; i < 8; i += 2 {
		csum += uint32(buf[i]) << 8
		csum += uint32(buf[i+1])
	}

	// Destination IA (8 bytes)
	binary.BigEndian.PutUint64(buf[:], uint64(dstIA))
	for i := 0; i < 8; i += 2 {
		csum += uint32(buf[i]) << 8
		csum += uint32(buf[i+1])
	}

	// Source address
	if srcIP.Is4() {
		b4 := srcIP.As4()
		csum += uint32(b4[0])<<8 + uint32(b4[1])
		csum += uint32(b4[2])<<8 + uint32(b4[3])
	} else {
		b16 := srcIP.As16()
		for i := 0; i < 16; i += 2 {
			csum += uint32(b16[i])<<8 + uint32(b16[i+1])
		}
	}

	// Destination address
	if dstIP.Is4() {
		b4 := dstIP.As4()
		csum += uint32(b4[0])<<8 + uint32(b4[1])
		csum += uint32(b4[2])<<8 + uint32(b4[3])
	} else {
		b16 := dstIP.As16()
		for i := 0; i < 16; i += 2 {
			csum += uint32(b16[i])<<8 + uint32(b16[i+1])
		}
	}

	// Protocol: L4UDP = 17
	csum += 17

	return csum
}

// scionFinishChecksum completes the SCION/UDP checksum by adding the
// upper-layer length and bytes to the pre-computed partial checksum,
// then folding and complementing.
func scionFinishChecksum(partialCsum uint32, upperLayer []byte) uint16 {
	csum := partialCsum

	// Add upper-layer length
	l := uint32(len(upperLayer))
	csum += (l >> 16) + (l & 0xffff)

	// Sum upper-layer bytes in 16-bit words
	n := len(upperLayer)
	for i := 0; i+1 < n; i += 2 {
		csum += uint32(upperLayer[i]) << 8
		csum += uint32(upperLayer[i+1])
	}
	if n%2 == 1 {
		csum += uint32(upperLayer[n-1]) << 8
	}

	// Fold to 16 bits
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

// buildSCIONFastPath creates a pre-serialized header template for fast-path
// sends. Must be called with pi.mu held (or before pi is shared).
// Returns nil if the fast path cannot be built (e.g. no discovered path).
func buildSCIONFastPath(sc *scionConn, pi *scionPathInfo) *scionFastPath {
	if sc.underlayConn == nil {
		return nil
	}
	dst := pi.cachedDst
	if dst == nil || dst.Path == nil || dst.NextHop == nil {
		return nil
	}

	dstIP, ok := netip.AddrFromSlice(dst.Host.IP)
	if !ok {
		return nil
	}
	srcIP := sc.localHostIP

	// Use snet.Packet.Serialize() with empty payload to get a correctly
	// encoded SCION+UDP header template.
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: pi.peerIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: sc.localIA, Host: addr.HostIP(srcIP)},
			Path:        dst.Path,
			Payload: snet.UDPPayload{
				SrcPort: sc.localPort,
				DstPort: uint16(dst.Host.Port),
				Payload: nil, // empty payload → headers only
			},
		},
	}
	if err := pkt.Serialize(); err != nil {
		return nil
	}

	// pkt.Bytes is now [SCION header][8-byte UDP header]
	hdr := make([]byte, len(pkt.Bytes))
	copy(hdr, pkt.Bytes)
	udpOffset := len(hdr) - 8

	pseudoCsum := scionPseudoHeaderPartial(sc.localIA, pi.peerIA, srcIP, dstIP)

	return &scionFastPath{
		hdr:        hdr,
		udpOffset:  udpOffset,
		nextHop:    dst.NextHop,
		pseudoCsum: pseudoCsum,
	}
}

// parseSCIONPacket parses a raw SCION packet from the underlay, extracting
// the source address info and UDP payload. scn is a reusable slayers.SCION
// (with RecyclePaths enabled). Returns srcIA, srcAddr, payload, rawPath, ok.
func parseSCIONPacket(data []byte, scn *slayers.SCION) (
	srcIA addr.IA, srcAddr netip.AddrPort, payload []byte, rawPathBytes []byte, ok bool,
) {
	if err := scn.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return 0, netip.AddrPort{}, nil, nil, false
	}
	if scn.NextHdr != slayers.L4UDP {
		return 0, netip.AddrPort{}, nil, nil, false
	}

	srcHost, err := scn.SrcAddr()
	if err != nil {
		return 0, netip.AddrPort{}, nil, nil, false
	}
	srcIP := srcHost.IP()
	srcIA = scn.SrcIA

	// L4 payload starts at HdrLen * 4 bytes (SCION header is HdrLen
	// 4-byte words). The first 8 bytes are the UDP header.
	hdrBytes := int(scn.HdrLen) * 4
	if len(data) < hdrBytes+8 {
		return 0, netip.AddrPort{}, nil, nil, false
	}
	// Extract UDP source port from the first 2 bytes of the L4 header.
	srcPort := binary.BigEndian.Uint16(data[hdrBytes:])
	srcAddr = netip.AddrPortFrom(srcIP, srcPort)
	payload = data[hdrBytes+8:]

	// Extract raw path bytes for potential reversal (disco first-contact).
	if scn.Path != nil {
		pathLen := scn.Path.Len()
		// The path sits between the address header and the L4 header
		// in the SCION common+address+path header region.
		addrHdrLen := scn.AddrHdrLen()
		// Common header is 12 bytes, then address header, then path.
		pathStart := 12 + addrHdrLen
		pathEnd := pathStart + pathLen
		if pathEnd <= hdrBytes && pathLen > 0 {
			rawPathBytes = data[pathStart:pathEnd]
		}
	}

	return srcIA, srcAddr, payload, rawPathBytes, true
}

// buildSCIONReplyAddr builds an *snet.UDPAddr with reversed path for disco
// reply routing from raw path bytes extracted during receive.
func buildSCIONReplyAddr(srcIA addr.IA, srcHostAddr netip.AddrPort, rawPathBytes []byte) *snet.UDPAddr {
	if len(rawPathBytes) == 0 {
		return nil
	}
	// Copy path bytes since DecodeFromBytes references the slice.
	pathCopy := make([]byte, len(rawPathBytes))
	copy(pathCopy, rawPathBytes)

	var raw scionpath.Raw
	if err := raw.DecodeFromBytes(pathCopy); err != nil {
		return nil
	}
	reversed, err := raw.Reverse()
	if err != nil {
		return nil
	}
	// Serialize the reversed path to raw bytes and wrap in snetpath.SCION
	// which implements snet.DataplanePath.
	revBytes := make([]byte, reversed.Len())
	if err := reversed.SerializeTo(revBytes); err != nil {
		return nil
	}

	return &snet.UDPAddr{
		IA: srcIA,
		Host: &net.UDPAddr{
			IP:   srcHostAddr.Addr().AsSlice(),
			Port: int(srcHostAddr.Port()),
		},
		Path: snetpath.SCION{Raw: revBytes},
	}
}

// scionBatchRW abstracts ipv4.PacketConn and ipv6.PacketConn for
// batch I/O. Both have identical ReadBatch/WriteBatch signatures
// since ipv4.Message and ipv6.Message are the same type (socket.Message).
// On non-Linux platforms, ReadBatch/WriteBatch fall back to per-message
// sendto/recvfrom (golang.org/x/net handles this internally).
type scionBatchRW interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

// scionConn wraps a SCION connection for use by magicsock.
type scionConn struct {
	conn         *snet.Conn         // from SCIONNetwork.Listen()
	underlayConn *net.UDPConn       // raw underlay for fast-path sends (owned by conn)
	underlayXPC  scionBatchRW       // for WriteBatch / sendmmsg (ipv4 or ipv6)
	localIA      addr.IA            // our ISD-AS
	localHostIP  netip.Addr         // local host IP (e.g. 127.0.0.1)
	localPort    uint16             // local SCION/UDP port
	daemon       daemon.Connector   // for path queries
	topo         snet.Topology      // local topology
}

// close shuts down the SCION connection and daemon connector.
func (sc *scionConn) close() error {
	if sc.conn != nil {
		sc.conn.Close()
	}
	if sc.daemon != nil {
		sc.daemon.Close()
	}
	return nil
}

// writeTo sends b to a peer identified by the given scionPathInfo.
func (sc *scionConn) writeTo(b []byte, pi *scionPathInfo) (int, error) {
	pi.mu.Lock()
	replyPath := pi.replyPath
	cachedDst := pi.cachedDst
	pi.mu.Unlock()

	dst := cachedDst
	if dst == nil && replyPath != nil {
		dst = replyPath
	}
	if dst == nil {
		return 0, fmt.Errorf("no SCION destination")
	}
	return sc.conn.WriteTo(b, dst)
}

// readFrom reads a packet from the SCION connection, returning the data, the
// source SCION address, and any error.
func (sc *scionConn) readFrom(b []byte) (int, *snet.UDPAddr, error) {
	n, srcAddr, err := sc.conn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	src, ok := srcAddr.(*snet.UDPAddr)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected source address type: %T", srcAddr)
	}
	return n, src, nil
}

// scionDaemonAddr returns the SCION daemon address to use, checking the
// environment variable first, then falling back to the default socket.
func scionDaemonAddr() string {
	if a := os.Getenv("SCION_DAEMON_ADDRESS"); a != "" {
		return a
	}
	return daemon.DefaultAPIAddress
}

// scionListenPort returns the SCION port to use, checking the TS_SCION_PORT
// environment variable first, then falling back to 0 (auto-select from the
// topology's dispatched port range).
func scionListenPort() uint16 {
	if p := os.Getenv("TS_SCION_PORT"); p != "" {
		var v int
		if _, err := fmt.Sscanf(p, "%d", &v); err == nil && v > 0 && v <= 65535 {
			return uint16(v)
		}
	}
	return 0 // let snet auto-select from topology port range
}

// scionResolveLocalIP determines the local IP for the SCION underlay socket
// by checking what source IP the OS would use to reach the border routers'
// internal addresses from the topology. This mirrors how `scion address` works
// (via addrutil.ResolveLocal).
//
// With multiple BRs, if all resolve to the same local IP, that IP is used.
// If they disagree, the first resolved IP is used and a warning is logged —
// the user should set TS_SCION_LISTEN_ADDR explicitly.
//
// Falls back to 127.0.0.1 if no interfaces or resolution fails.
func scionResolveLocalIP(ctx context.Context, connector daemon.Connector) netip.Addr {
	ifMap, err := connector.Interfaces(ctx)
	if err != nil || len(ifMap) == 0 {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}

	var first netip.Addr
	allSame := true
	for _, ap := range ifMap {
		resolved, err := addrutil.ResolveLocal(ap.Addr().AsSlice())
		if err != nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(resolved)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !first.IsValid() {
			first = ip
		} else if first != ip {
			allSame = false
		}
	}

	if !first.IsValid() {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if !allSame {
		fmt.Fprintf(os.Stderr, "magicsock: SCION: multiple BRs resolve to different local IPs; using %s, set TS_SCION_LISTEN_ADDR to override\n", first)
	}
	return first
}

// scionListenAddr returns the listen address for the SCION underlay socket.
// TS_SCION_LISTEN_ADDR can override the IP (e.g. "::1" for IPv6 localhost).
// Otherwise resolves the local IP from the topology's BR internal addresses.
func scionListenAddr(ctx context.Context, connector daemon.Connector) *net.UDPAddr {
	port := scionListenPort()
	if a := os.Getenv("TS_SCION_LISTEN_ADDR"); a != "" {
		ip := net.ParseIP(a)
		if ip != nil {
			return &net.UDPAddr{IP: ip, Port: int(port)}
		}
	}
	ip := scionResolveLocalIP(ctx, connector)
	return &net.UDPAddr{IP: ip.AsSlice(), Port: int(port)}
}

// forceEmbeddedSCION is the TS_SCION_EMBEDDED envknob. When set to "1",
// the external daemon attempt is skipped and only the embedded connector is tried.
var forceEmbeddedSCION = envknob.RegisterBool("TS_SCION_EMBEDDED")

// trySCIONConnect attempts to set up a SCION connection using a cascading
// fallback strategy:
//  1. External daemon (existing behavior, quick check) — skipped if TS_SCION_EMBEDDED=1
//  2. Embedded with existing local topology file (TS_SCION_TOPOLOGY or /etc/scion/topology.json)
//  3. Bootstrap from configured URL (TS_SCION_BOOTSTRAP_URL / TS_SCION_BOOTSTRAP_URLS)
//  4. DNS-based discovery (SRV for _sciondiscovery._tcp)
//  5. Hardcoded bootstrap URLs (if any)
//
// Returns nil if SCION is not available via any method.
func trySCIONConnect(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor) (*scionConn, error) {
	var externalErr error

	// Step 1: Try external daemon (unless forced embedded).
	if !forceEmbeddedSCION() {
		sc, err := tryExternalDaemon(ctx, logf, netMon)
		if err == nil {
			return sc, nil
		}
		externalErr = err
	}

	// Step 2: Try embedded with existing local topology file.
	topoPath := scionTopologyPath()
	if _, err := os.Stat(topoPath); err == nil {
		sc, err := tryEmbeddedDaemon(ctx, topoPath, logf, netMon)
		if err == nil {
			return sc, nil
		}
		// Fall through to bootstrap attempts.
	}

	// Steps 3-5: Try bootstrap from URLs (explicit, DNS-discovered, hardcoded).
	stateDir := scionStateDir()
	if stateDir == "" {
		if externalErr != nil {
			return nil, fmt.Errorf("external daemon: %w; embedded: no state directory available", externalErr)
		}
		return nil, fmt.Errorf("SCION not available: no external daemon, no topology file, no state directory for bootstrap")
	}
	for _, url := range bootstrapURLs(ctx) {
		if err := bootstrapSCION(ctx, url, stateDir); err != nil {
			continue
		}
		bootstrappedTopo := filepath.Join(stateDir, "topology.json")
		if _, err := os.Stat(bootstrappedTopo); err != nil {
			continue
		}
		sc, err := tryEmbeddedDaemon(ctx, bootstrappedTopo, logf, netMon)
		if err == nil {
			return sc, nil
		}
	}

	if externalErr != nil {
		return nil, fmt.Errorf("external daemon: %w; embedded: no topology available", externalErr)
	}
	return nil, fmt.Errorf("SCION not available: no external daemon, no topology file, no bootstrap server")
}

// tryExternalDaemon attempts to connect to an external SCION daemon and set up
// a SCION listener. This is the original trySCIONConnect behavior.
func tryExternalDaemon(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor) (*scionConn, error) {
	daemonAddr := scionDaemonAddr()
	svc := daemon.Service{Address: daemonAddr}
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}

	topo, err := snetTopologyFromConnector(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("building topology from daemon: %w", err)
	}

	// Probe Paths() to detect wire-format incompatibility with older
	// daemons (e.g. v0.12 daemon vs v0.14 client). Simple RPCs like
	// LocalIA/Interfaces/ASInfo use compatible proto types, but Paths
	// responses with real hop data trigger unmarshal failures.
	// We need a reachable remote IA to get a non-empty response;
	// parse the topology file for a neighbor AS.
	if neighborIA, ok := neighborIAFromTopology(scionTopologyPath()); ok {
		localIA, _ := conn.LocalIA(ctx)
		if _, err := conn.Paths(ctx, neighborIA, localIA, daemon.PathReqFlags{}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("daemon path probe failed (version mismatch?): %w", err)
		}
	}

	sc, err := finishSCIONConnect(ctx, conn, topo, logf, netMon)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sc, nil
}

// snetTopologyFromConnector builds an snet.Topology struct by querying
// a daemon.Connector for local topology information.
func snetTopologyFromConnector(ctx context.Context, conn daemon.Connector) (snet.Topology, error) {
	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		return snet.Topology{}, fmt.Errorf("querying local IA: %w", err)
	}
	portStart, portEnd, err := conn.PortRange(ctx)
	if err != nil {
		return snet.Topology{}, fmt.Errorf("querying port range: %w", err)
	}
	ifMap, err := conn.Interfaces(ctx)
	if err != nil {
		return snet.Topology{}, fmt.Errorf("querying interfaces: %w", err)
	}
	return snet.Topology{
		LocalIA:   localIA,
		PortRange: snet.TopologyPortRange{Start: portStart, End: portEnd},
		Interface: func(id uint16) (netip.AddrPort, bool) {
			ap, ok := ifMap[id]
			return ap, ok
		},
	}, nil
}

// neighborIAFromTopology parses the SCION topology JSON file and returns
// the IA of the first neighbor AS found in the border router interfaces.
// This is used to probe the daemon with a Paths() call that returns real
// path data, detecting proto wire-format incompatibilities.
func neighborIAFromTopology(topoPath string) (addr.IA, bool) {
	data, err := os.ReadFile(topoPath)
	if err != nil {
		return 0, false
	}
	var topo struct {
		BorderRouters map[string]struct {
			Interfaces map[string]struct {
				ISDAS string `json:"isd_as"`
			} `json:"interfaces"`
		} `json:"border_routers"`
	}
	if err := json.Unmarshal(data, &topo); err != nil {
		return 0, false
	}
	for _, br := range topo.BorderRouters {
		for _, iface := range br.Interfaces {
			ia, err := addr.ParseIA(iface.ISDAS)
			if err == nil {
				return ia, true
			}
		}
	}
	return 0, false
}

// finishSCIONConnect completes the SCION connection setup given a
// daemon.Connector (for path queries) and snet.Topology (for local info).
// This is shared between the external daemon and embedded connector paths.
func finishSCIONConnect(ctx context.Context, connector daemon.Connector, topo snet.Topology, logf logger.Logf, netMon *netmon.Monitor) (*scionConn, error) {
	localIA, err := connector.LocalIA(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying local IA: %w", err)
	}

	network := &snet.SCIONNetwork{
		Topology: topo,
	}

	listenAddr := scionListenAddr(ctx, connector)
	if listenAddr.Port != 0 {
		// Validate the configured port against the dispatched range.
		portMin, portMax, err := connector.PortRange(ctx)
		if err != nil {
			return nil, fmt.Errorf("querying SCION port range: %w", err)
		}
		listenPort := uint16(listenAddr.Port)
		if listenPort < portMin || listenPort > portMax {
			return nil, fmt.Errorf("TS_SCION_PORT=%d outside dispatched range [%d, %d]", listenPort, portMin, portMax)
		}
	}

	// Use OpenRaw + NewCookedConn instead of Listen so we can set socket
	// buffer sizes on the underlying UDP connection before wrapping it.
	pconn, err := network.OpenRaw(ctx, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listening on SCION %s: %w", listenAddr, err)
	}

	// Extract the underlay *net.UDPConn for fast-path sends that bypass
	// snet.Conn serialization. Also increase socket buffer sizes.
	var underlayConn *net.UDPConn
	if pc, ok := pconn.(*snet.SCIONPacketConn); ok {
		underlayConn = pc.Conn
		if err := pc.SetReadBuffer(socketBufferSize); err != nil {
			logf("magicsock: SCION: failed to set read buffer to %d: %v", socketBufferSize, err)
		}
		if err := pc.SetWriteBuffer(socketBufferSize); err != nil {
			logf("magicsock: SCION: failed to set write buffer to %d: %v", socketBufferSize, err)
		}
	}

	// Apply platform-specific socket options (SO_MARK on Linux,
	// VpnService.protect on Android, IP_BOUND_IF on macOS) to
	// prevent the SCION underlay socket from routing through the
	// VPN tunnel, which would cause loops.
	if underlayConn != nil {
		rawConn, err := underlayConn.SyscallConn()
		if err == nil {
			lc := netns.Listener(logf, netMon)
			if lc.Control != nil {
				if err := lc.Control("udp", underlayConn.LocalAddr().String(), rawConn); err != nil {
					logf("magicsock: SCION: netns control: %v", err)
				}
			}
		} else {
			logf("magicsock: SCION: SyscallConn: %v", err)
		}
	}

	sconn, err := snet.NewCookedConn(pconn, topo)
	if err != nil {
		pconn.Close()
		return nil, fmt.Errorf("creating SCION conn: %w", err)
	}

	// Extract local address info for fast-path header templates.
	var localHostIP netip.Addr
	var localPort uint16
	if sa, saOk := sconn.LocalAddr().(*snet.UDPAddr); saOk && sa.Host != nil {
		if ip, ipOk := netip.AddrFromSlice(sa.Host.IP); ipOk {
			localHostIP = ip
		}
		localPort = uint16(sa.Host.Port)
	}

	// Wrap underlay conn for sendmmsg batching, selecting the correct
	// address family based on the local address.
	var underlayXPC scionBatchRW
	if underlayConn != nil {
		local := underlayConn.LocalAddr().(*net.UDPAddr)
		if local.IP.To4() != nil {
			underlayXPC = ipv4.NewPacketConn(underlayConn)
		} else {
			underlayXPC = ipv6.NewPacketConn(underlayConn)
		}
	}

	return &scionConn{
		conn:         sconn,
		underlayConn: underlayConn,
		underlayXPC:  underlayXPC,
		localIA:      localIA,
		localHostIP:  localHostIP,
		localPort:    localPort,
		daemon:       connector,
		topo:         topo,
	}, nil
}

// parseSCIONServiceAddr parses a SCION service description string of the form
// "ISD-AS,host-IP" and returns the IA and host address. The port comes from the
// Service.Port field.
func parseSCIONServiceAddr(description string, port uint16) (ia addr.IA, hostAddr netip.AddrPort, err error) {
	parts := strings.SplitN(description, ",", 2)
	if len(parts) != 2 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid SCION service description %q: want ISD-AS,host-IP", description)
	}

	ia, err = addr.ParseIA(parts[0])
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("parsing SCION IA %q: %w", parts[0], err)
	}

	hostIP, err := netip.ParseAddr(parts[1])
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("parsing SCION host IP %q: %w", parts[1], err)
	}

	return ia, netip.AddrPortFrom(hostIP, port), nil
}

// sendSCIONBatch sends a batch of WireGuard packets over the SCION connection.
// It looks up the full path info from the Conn's scionPaths registry using the
// scionPathKey from the epAddr.
//
// When a fast-path template is available (pre-serialized headers + underlay
// socket), packets are serialized by patching a header template and sent via
// sendmmsg in a single syscall. Otherwise, falls back to snet.Conn.WriteTo
// per packet.
func (c *Conn) sendSCIONBatch(addr epAddr, buffs [][]byte, offset int) (sent bool, err error) {
	sc := c.pconnSCION
	if sc == nil {
		return false, errNoSCION
	}

	pi := c.lookupSCIONPathLocking(addr.scionKey)
	if pi == nil {
		return false, fmt.Errorf("no SCION path info for key %d", addr.scionKey)
	}

	// Read path info once for the entire batch to avoid repeated locking.
	pi.mu.Lock()
	replyPath := pi.replyPath
	cachedDst := pi.cachedDst
	fastPath := pi.fastPath
	expired := !pi.expiry.IsZero() && time.Now().After(pi.expiry)
	pi.mu.Unlock()
	if expired {
		return false, fmt.Errorf("SCION path expired for key %d", addr.scionKey)
	}

	// Fast path: pre-serialized headers + sendmmsg.
	if fastPath != nil && sc.underlayXPC != nil {
		err = c.sendSCIONBatchFast(sc, fastPath, buffs, offset)
		return err == nil, err
	}

	// Slow path: snet.Conn.WriteTo per packet.
	dst := cachedDst
	if dst == nil && replyPath != nil {
		dst = replyPath
	}
	if dst == nil {
		return false, fmt.Errorf("no SCION destination for key %d", addr.scionKey)
	}

	for _, buf := range buffs {
		_, err = sc.conn.WriteTo(buf[offset:], dst)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// sendSCIONBatchFast sends a batch of packets using pre-serialized SCION
// headers and sendmmsg on the underlay UDP socket. Each packet is built by
// copying the header template, patching per-packet fields (PayloadLen, UDP
// Length, UDP Checksum), and appending the WireGuard payload.
func (c *Conn) sendSCIONBatchFast(sc *scionConn, fp *scionFastPath, buffs [][]byte, offset int) error {
	batch := scionSendBatchPool.Get().(*scionSendBatch)
	defer scionSendBatchPool.Put(batch)

	hdrLen := len(fp.hdr)
	n := len(buffs)
	if n > scionMaxBatchSize {
		n = scionMaxBatchSize
	}

	for i := 0; i < n; i++ {
		payload := buffs[i][offset:]
		pktLen := hdrLen + len(payload)

		// Grow buffer if needed.
		buf := batch.bufs[i]
		if cap(buf) < pktLen {
			buf = make([]byte, pktLen)
			batch.bufs[i] = buf
		} else {
			buf = buf[:pktLen]
		}

		// Copy header template and append payload.
		copy(buf, fp.hdr)
		copy(buf[hdrLen:], payload)

		// Patch SCION PayloadLen (bytes 6:8) = UDP header (8) + payload.
		udpTotalLen := uint16(8 + len(payload))
		binary.BigEndian.PutUint16(buf[6:], udpTotalLen)

		// Patch UDP Length (udpOffset+4:+6).
		binary.BigEndian.PutUint16(buf[fp.udpOffset+4:], udpTotalLen)

		// Zero checksum, compute over full upper layer, set result.
		buf[fp.udpOffset+6] = 0
		buf[fp.udpOffset+7] = 0
		upperLayer := buf[fp.udpOffset:pktLen]
		csum := scionFinishChecksum(fp.pseudoCsum, upperLayer)
		binary.BigEndian.PutUint16(buf[fp.udpOffset+6:], csum)

		batch.msgs[i].Buffers[0] = buf[:pktLen]
		batch.msgs[i].Addr = fp.nextHop
	}

	// WriteBatch uses sendmmsg on Linux for batched sends.
	msgs := batch.msgs[:n]
	var head int
	for {
		written, err := sc.underlayXPC.WriteBatch(msgs[head:], 0)
		if err != nil {
			return err
		}
		head += written
		if head >= n {
			return nil
		}
	}
}

// sendSCION sends a single packet over SCION, used for disco messages.
func (c *Conn) sendSCION(sk scionPathKey, b []byte) (bool, error) {
	sc := c.pconnSCION
	if sc == nil {
		return false, errNoSCION
	}
	pi := c.lookupSCIONPathLocking(sk)
	if pi == nil {
		return false, fmt.Errorf("no SCION path info for key %d", sk)
	}
	pi.mu.Lock()
	expired := !pi.expiry.IsZero() && time.Now().After(pi.expiry)
	pi.mu.Unlock()
	if expired {
		return false, fmt.Errorf("SCION path expired for key %d", sk)
	}
	_, err := sc.writeTo(b, pi)
	if err != nil {
		return false, err
	}
	return true, nil
}

// lookupSCIONPath returns the scionPathInfo for the given key, or nil if not found.
// c.mu must be held.
func (c *Conn) lookupSCIONPath(k scionPathKey) *scionPathInfo {
	return c.scionPaths[k]
}

// lookupSCIONPathLocking returns the scionPathInfo for the given key, acquiring c.mu.
func (c *Conn) lookupSCIONPathLocking(k scionPathKey) *scionPathInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scionPaths[k]
}

// registerSCIONPath stores a scionPathInfo and returns a key for it.
// c.mu must be held.
func (c *Conn) registerSCIONPath(pi *scionPathInfo) scionPathKey {
	k := scionPathKey(c.scionPathSeq.Add(1))
	if c.scionPaths == nil {
		c.scionPaths = make(map[scionPathKey]*scionPathInfo)
	}
	c.scionPaths[k] = pi
	// Don't unconditionally overwrite scionPathsByAddr here — with multi-path,
	// multiple keys share the same (IA, hostAddr). The caller is responsible
	// for setting the active path via setActiveSCIONPath.
	return k
}

// registerSCIONPathLocking stores a scionPathInfo, acquiring c.mu, and returns
// a key for it.
func (c *Conn) registerSCIONPathLocking(pi *scionPathInfo) scionPathKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registerSCIONPath(pi)
}

// unregisterSCIONPath removes a SCION path entry and its peerMap entry.
// c.mu must be held.
func (c *Conn) unregisterSCIONPath(k scionPathKey) {
	if pi, ok := c.scionPaths[k]; ok {
		// Only remove reverse index if it points to this key.
		ak := scionAddrKey{ia: pi.peerIA, addr: pi.hostAddr}
		if c.scionPathsByAddr[ak] == k {
			delete(c.scionPathsByAddr, ak)
		}
		// Remove stale peerMap entry for this scionKey.
		scionEp := epAddr{ap: pi.hostAddr, scionKey: k}
		if peerInf := c.peerMap.byEpAddr[scionEp]; peerInf != nil {
			delete(peerInf.epAddrs, scionEp)
			delete(c.peerMap.byEpAddr, scionEp)
		}
	}
	delete(c.scionPaths, k)
}

// setActiveSCIONPath updates the reverse index to point to the given key.
// c.mu must be held.
func (c *Conn) setActiveSCIONPath(peerIA addr.IA, hostAddr netip.AddrPort, k scionPathKey) {
	if c.scionPathsByAddr == nil {
		c.scionPathsByAddr = make(map[scionAddrKey]scionPathKey)
	}
	c.scionPathsByAddr[scionAddrKey{ia: peerIA, addr: hostAddr}] = k
}

// updateActiveSCIONPathLocking updates the reverse index, acquiring c.mu.
func (c *Conn) updateActiveSCIONPathLocking(peerIA addr.IA, hostAddr netip.AddrPort, k scionPathKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setActiveSCIONPath(peerIA, hostAddr, k)
}

// receiveSCION is the conn.ReceiveFunc for SCION packets. It reads from the
// SCION connection and dispatches disco or WireGuard packets.
//
// Unlike receiveIP, this function handles read timeouts internally and never
// propagates them to WireGuard. This is critical because WireGuard's
// RoutineReceiveIncoming exits the goroutine permanently after 10 consecutive
// temporary errors, and we need to survive SCION socket death + reconnection.
//
// The function uses SetReadDeadline to periodically wake up and check whether
// the socket is still alive. If no packets are received for
// scionReconnectThreshold while active SCION peers exist, we close the old
// socket and reconnect.
//
// When the underlay socket is available, packets are read in batches via
// recvmmsg and parsed with lightweight slayers.SCION decoding. Otherwise,
// falls back to single-packet snet.Conn.ReadFrom.
func (c *Conn) receiveSCION(buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	sc := c.pconnSCION
	if sc == nil {
		<-c.donec
		return 0, net.ErrClosed
	}

	// Initialize lastSCIONRecv so we don't trigger reconnection on startup.
	if c.lastSCIONRecv.LoadAtomic() == 0 {
		c.lastSCIONRecv.StoreAtomic(mono.Now())
	}

	for {
		// Check for graceful shutdown.
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		default:
		}

		// Re-read pconnSCION — it may have been swapped by reconnectSCION.
		sc = c.pconnSCION
		if sc == nil {
			// Socket was closed and reconnection failed. Retry.
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			case <-time.After(5 * time.Second):
			}
			c.retrySCIONConnect()
			continue
		}

		// Fast path: batch read from underlay via recvmmsg.
		if sc.underlayXPC != nil {
			sc.underlayConn.SetReadDeadline(time.Now().Add(scionReadDeadline))

			n, err := c.receiveSCIONBatch(sc, buffs, sizes, eps)
			if n > 0 {
				return n, nil
			}
			if err != nil {
				select {
				case <-c.donec:
					return 0, net.ErrClosed
				default:
				}
				if isTimeoutError(err) {
					if c.shouldReconnectSCION() {
						c.reconnectSCION()
					}
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					continue
				}
				c.logf("magicsock: SCION read error: %v", err)
				continue
			}
			// n == 0 and no error means all packets were disco/filtered.
			continue
		}

		// Slow path: single-packet snet.Conn.ReadFrom.
		sc.conn.SetReadDeadline(time.Now().Add(scionReadDeadline))

		n, srcAddr, err := sc.readFrom(buffs[0])
		if err != nil {
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			default:
			}
			if isTimeoutError(err) {
				if c.shouldReconnectSCION() {
					c.reconnectSCION()
				}
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			c.logf("magicsock: SCION read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		c.lastSCIONRecv.StoreAtomic(mono.Now())

		b := buffs[0][:n]
		srcHostAddr := srcAddr.Host.AddrPort()

		pt, _ := packetLooksLike(b)
		if pt == packetLooksLikeDisco {
			// Slow path disco: snet.Conn.ReadFrom returns a pre-reversed
			// path suitable for replies, so use srcAddr directly.
			srcEpAddr := epAddr{ap: srcHostAddr}
			c.mu.Lock()
			sk := c.scionPathsByAddr[scionAddrKey{ia: srcAddr.IA, addr: srcHostAddr}]
			if !sk.IsSet() {
				sk = c.registerSCIONPath(&scionPathInfo{
					peerIA:    srcAddr.IA,
					hostAddr:  srcHostAddr,
					replyPath: srcAddr,
				})
				c.setActiveSCIONPath(srcAddr.IA, srcHostAddr, sk)
			}
			c.mu.Unlock()
			srcEpAddr.scionKey = sk
			c.handleDiscoMessage(b, srcEpAddr, false, key.NodePublic{}, discoRXPathSCION)
			continue
		}

		if !c.havePrivateKey.Load() {
			continue
		}

		srcEpAddr := epAddr{ap: srcHostAddr}
		c.mu.Lock()
		ep, ok := c.peerMap.endpointForEpAddr(srcEpAddr)
		c.mu.Unlock()
		if !ok {
			sizes[0] = n
			eps[0] = &lazyEndpoint{c: c, src: srcEpAddr}
			return 1, nil
		}

		now := mono.Now()
		ep.lastRecvUDPAny.StoreAtomic(now)
		ep.noteRecvActivity(srcEpAddr, now)
		if c.metrics != nil {
			c.metrics.inboundPacketsSCIONTotal.Add(1)
			c.metrics.inboundBytesSCIONTotal.Add(int64(n))
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
}

// receiveSCIONBatch reads a batch of raw SCION packets from the underlay
// socket via recvmmsg, parses SCION+UDP headers with slayers, and copies
// payloads into WireGuard's buffs. Disco packets are handled inline and
// not reported to the caller.
func (c *Conn) receiveSCIONBatch(sc *scionConn, buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	batch := scionRecvBatchPool.Get().(*scionRecvBatch)
	defer putScionRecvBatch(batch)

	n := len(buffs)
	if n > scionMaxBatchSize {
		n = scionMaxBatchSize
	}

	numMsgs, err := sc.underlayXPC.ReadBatch(batch.msgs[:n], 0)
	if err != nil {
		return 0, err
	}

	reportToCaller := false
	count := 0
	for i := 0; i < numMsgs; i++ {
		msg := &batch.msgs[i]
		if msg.N == 0 {
			sizes[count] = 0
			continue
		}

		srcIA, srcHostAddr, payload, rawPath, ok := parseSCIONPacket(
			msg.Buffers[0][:msg.N], &batch.scn)
		if !ok || len(payload) == 0 {
			continue
		}

		// Copy payload into WireGuard's buffer.
		pn := copy(buffs[count], payload)

		c.lastSCIONRecv.StoreAtomic(mono.Now())

		pt, _ := packetLooksLike(buffs[count][:pn])
		if pt == packetLooksLikeDisco {
			c.handleSCIONDisco(buffs[count][:pn], srcIA, srcHostAddr, rawPath)
			continue
		}

		if !c.havePrivateKey.Load() {
			continue
		}

		srcEpAddr := epAddr{ap: srcHostAddr}
		c.mu.Lock()
		ep, ok := c.peerMap.endpointForEpAddr(srcEpAddr)
		c.mu.Unlock()
		if !ok {
			sizes[count] = pn
			eps[count] = &lazyEndpoint{c: c, src: srcEpAddr}
			count++
			reportToCaller = true
			continue
		}

		now := mono.Now()
		ep.lastRecvUDPAny.StoreAtomic(now)
		ep.noteRecvActivity(srcEpAddr, now)
		if c.metrics != nil {
			c.metrics.inboundPacketsSCIONTotal.Add(1)
			c.metrics.inboundBytesSCIONTotal.Add(int64(pn))
		}
		sizes[count] = pn
		eps[count] = ep
		count++
		reportToCaller = true
	}

	if reportToCaller {
		return count, nil
	}
	return 0, nil
}

// handleSCIONDisco handles a disco packet received on the batch path.
// It looks up or registers a SCION path entry and dispatches to handleDiscoMessage.
// For first-contact, the raw path bytes are reversed to build a reply path.
func (c *Conn) handleSCIONDisco(b []byte, srcIA addr.IA, srcHostAddr netip.AddrPort, rawPath []byte) {
	srcEpAddr := epAddr{ap: srcHostAddr}
	c.mu.Lock()
	sk := c.scionPathsByAddr[scionAddrKey{ia: srcIA, addr: srcHostAddr}]
	if !sk.IsSet() {
		// First disco packet from this SCION peer — build a reply path
		// by reversing the raw SCION path from the incoming packet.
		replyAddr := buildSCIONReplyAddr(srcIA, srcHostAddr, rawPath)
		sk = c.registerSCIONPath(&scionPathInfo{
			peerIA:    srcIA,
			hostAddr:  srcHostAddr,
			replyPath: replyAddr,
		})
		c.setActiveSCIONPath(srcIA, srcHostAddr, sk)
	}
	c.mu.Unlock()
	srcEpAddr.scionKey = sk
	c.handleDiscoMessage(b, srcEpAddr, false, key.NodePublic{}, discoRXPathSCION)
}

// isTimeoutError reports whether err is a network timeout (from SetReadDeadline).
func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// shouldReconnectSCION reports whether the SCION socket appears dead and
// should be reconnected. The socket is considered dead when:
//  1. No SCION packet has been received for scionReconnectThreshold, AND
//  2. There are active SCION peers (otherwise silence is expected).
func (c *Conn) shouldReconnectSCION() bool {
	lastRecv := c.lastSCIONRecv.LoadAtomic()
	if mono.Since(lastRecv) < scionReconnectThreshold {
		return false
	}

	// Check if any endpoint has SCION state (active SCION peers).
	c.mu.Lock()
	hasSCIONPeers := len(c.scionPaths) > 0
	c.mu.Unlock()
	return hasSCIONPeers
}

// reconnectSCION closes the current SCION socket and creates a new one.
// The receiveSCION loop will pick up the new socket on the next iteration.
func (c *Conn) reconnectSCION() {
	c.logf("magicsock: SCION socket appears dead (no recv for %v), reconnecting...", scionReconnectThreshold)

	oldSC := c.pconnSCION

	// Close old connection first — we must release the port before binding
	// the new socket. When TS_SCION_PORT is set, both sockets would try
	// to bind the same port. This means there's a brief window where
	// pconnSCION is nil and sends will fail, but that's acceptable —
	// the endpoint was already dead anyway.
	if oldSC != nil {
		oldSC.close()
	}
	c.pconnSCION = nil

	newSC, err := trySCIONConnect(c.connCtx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION reconnect failed: %v", err)
		// Reset the receive timestamp so we retry after scionReconnectThreshold.
		c.lastSCIONRecv.StoreAtomic(mono.Now())
		return
	}

	// Swap in the new connection.
	c.pconnSCION = newSC

	// Reset the receive timestamp so we don't immediately re-trigger.
	c.lastSCIONRecv.StoreAtomic(mono.Now())

	c.logf("magicsock: SCION reconnected successfully, local IA: %s", newSC.localIA)

	// Re-discover paths for all SCION peers. We need fresh paths that
	// use the new socket's local address.
	c.rediscoverAllSCIONPaths()
}

// retrySCIONConnect attempts to re-establish a SCION connection when
// pconnSCION is nil (previous reconnect attempt failed).
func (c *Conn) retrySCIONConnect() {
	if c.pconnSCION != nil {
		return // another goroutine beat us to it
	}
	newSC, err := trySCIONConnect(c.connCtx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION reconnect retry failed: %v", err)
		return
	}
	c.pconnSCION = newSC
	c.lastSCIONRecv.StoreAtomic(mono.Now())
	c.logf("magicsock: SCION reconnect retry succeeded, local IA: %s", newSC.localIA)
	c.rediscoverAllSCIONPaths()
}

// rediscoverAllSCIONPaths triggers path re-discovery for all endpoints that
// have SCION state. This is called after reconnecting the SCION socket to
// ensure paths reference the new connection.
func (c *Conn) rediscoverAllSCIONPaths() {
	c.mu.Lock()
	var peers []struct {
		ep       *endpoint
		peerIA   addr.IA
		hostAddr netip.AddrPort
	}
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.mu.Lock()
		if ep.scionState != nil {
			peers = append(peers, struct {
				ep       *endpoint
				peerIA   addr.IA
				hostAddr netip.AddrPort
			}{ep, ep.scionState.peerIA, ep.scionState.hostAddr})
		}
		ep.mu.Unlock()
	})
	c.mu.Unlock()

	for _, p := range peers {
		go p.ep.discoverSCIONPathAsync(p.peerIA, p.hostAddr)
	}
}

// discoverSCIONPaths queries the SCION daemon for paths to the given peer IA,
// deduplicates by fingerprint, selects the top N by latency, and stores them
// in the path registry. Returns the scionPathKeys for the registered paths
// (first element is the lowest-latency path).
func (c *Conn) discoverSCIONPaths(ctx context.Context, peerIA addr.IA, hostAddr netip.AddrPort) ([]scionPathKey, error) {
	sc := c.pconnSCION
	if sc == nil {
		return nil, errNoSCION
	}

	paths, err := sc.daemon.Paths(ctx, peerIA, sc.localIA, daemon.PathReqFlags{Refresh: false})
	if err != nil {
		return nil, fmt.Errorf("querying SCION paths to %s: %w", peerIA, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no SCION paths to %s", peerIA)
	}

	// Deduplicate by fingerprint (topologically identical paths).
	seen := make(map[snet.PathFingerprint]bool)
	var unique []pathWithMeta
	for _, p := range paths {
		fp := p.Metadata().Fingerprint()
		if fp != "" && seen[fp] {
			continue
		}
		if fp != "" {
			seen[fp] = true
		}
		unique = append(unique, pathWithMeta{
			path:        p,
			fingerprint: fp,
			latency:     totalPathLatency(p),
		})
	}

	// Select paths balancing latency and topological diversity.
	maxPaths := scionMaxProbePaths()
	unique = selectDiversePaths(unique, maxPaths)

	// Register each path.
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]scionPathKey, 0, len(unique))
	for _, u := range unique {
		var expiry time.Time
		var mtu uint16
		if md := u.path.Metadata(); md != nil {
			expiry = md.Expiry
			mtu = md.MTU
		}
		pi := &scionPathInfo{
			peerIA:      peerIA,
			hostAddr:    hostAddr,
			fingerprint: u.fingerprint,
			path:        u.path,
			expiry:      expiry,
			mtu:         mtu,
		}
		pi.buildCachedDst()
		if sc := c.pconnSCION; sc != nil {
			pi.fastPath = buildSCIONFastPath(sc, pi)
		}
		keys = append(keys, c.registerSCIONPath(pi))
	}
	// Set the first (lowest-latency) path as active for the reverse index.
	if len(keys) > 0 {
		c.setActiveSCIONPath(peerIA, hostAddr, keys[0])
	}
	return keys, nil
}

// totalPathLatency returns the sum of all hop latencies for a SCION path.
// Returns a large value if latency information is unavailable.
func totalPathLatency(p snet.Path) time.Duration {
	md := p.Metadata()
	if md == nil || len(md.Latency) == 0 {
		return time.Hour // large sentinel for unknown latency
	}
	var total time.Duration
	for _, l := range md.Latency {
		if l < 0 {
			// LatencyUnset — treat as unknown
			total += scionUnsetHopLatency
		} else {
			total += l
		}
	}
	return total
}

// pathWithMeta pairs a SCION path with its fingerprint and estimated latency
// for use in path selection and diversity algorithms.
type pathWithMeta struct {
	path        snet.Path
	fingerprint snet.PathFingerprint
	latency     time.Duration
}

// debugSCIONDiversityThreshold is the TS_SCION_DIVERSITY_THRESHOLD envknob
// controlling the latency penalty threshold (in ms) for diversity selection.
// Default 50ms.
var debugSCIONDiversityThreshold = envknob.RegisterInt("TS_SCION_DIVERSITY_THRESHOLD")

// scionDiversityThreshold returns the latency threshold for diversity scoring.
func scionDiversityThreshold() time.Duration {
	if v := debugSCIONDiversityThreshold(); v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return 50 * time.Millisecond
}

// interfaceOverlap computes the fraction of interfaces in path a that also
// appear in path b: |a ∩ b| / |a|. Returns 0.0 if either path has no
// interface metadata (unknown paths are assumed diverse).
func interfaceOverlap(a, b snet.Path) float64 {
	mdA := a.Metadata()
	mdB := b.Metadata()
	if mdA == nil || mdB == nil || len(mdA.Interfaces) == 0 || len(mdB.Interfaces) == 0 {
		return 0.0
	}

	bSet := make(map[snet.PathInterface]bool, len(mdB.Interfaces))
	for _, iface := range mdB.Interfaces {
		bSet[iface] = true
	}

	var overlap int
	for _, iface := range mdA.Interfaces {
		if bSet[iface] {
			overlap++
		}
	}
	return float64(overlap) / float64(len(mdA.Interfaces))
}

// selectDiversePaths selects up to maxPaths from candidates, balancing low
// latency with topological diversity. It uses a greedy algorithm:
//  1. Sort candidates by latency ascending, pick the best.
//  2. For each subsequent slot, score remaining candidates by diversity
//     (1 − max overlap with selected) minus latency penalty.
//  3. Fill remaining slots by pure latency if no diversity benefit.
func selectDiversePaths(candidates []pathWithMeta, maxPaths int) []pathWithMeta {
	if len(candidates) <= maxPaths {
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].latency < candidates[j].latency
		})
		return candidates
	}

	// Sort by latency ascending.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].latency < candidates[j].latency
	})

	threshold := scionDiversityThreshold()
	selected := make([]pathWithMeta, 0, maxPaths)
	used := make([]bool, len(candidates))

	// Always pick the lowest-latency path first.
	selected = append(selected, candidates[0])
	used[0] = true
	bestLatency := candidates[0].latency

	for len(selected) < maxPaths {
		bestScore := -1.0
		bestIdx := -1

		for i, c := range candidates {
			if used[i] {
				continue
			}

			// Compute diversity score: 1 − max overlap with any selected path.
			var maxOverlap float64
			for _, s := range selected {
				if ov := interfaceOverlap(c.path, s.path); ov > maxOverlap {
					maxOverlap = ov
				}
			}
			diversityScore := 1.0 - maxOverlap

			// Latency penalty: how much slower than the best path, normalized.
			var latencyPenalty float64
			if threshold > 0 {
				latencyPenalty = float64(c.latency-bestLatency) / float64(threshold)
			}

			score := diversityScore - latencyPenalty
			if score > bestScore {
				bestScore = score
				bestIdx = i
			}
		}

		if bestIdx < 0 || bestScore <= 0 {
			// No diversity benefit; fill remaining by pure latency.
			for i, c := range candidates {
				if used[i] {
					continue
				}
				selected = append(selected, c)
				if len(selected) >= maxPaths {
					break
				}
			}
			break
		}

		selected = append(selected, candidates[bestIdx])
		used[bestIdx] = true
	}

	return selected
}

// refreshSCIONPaths runs in a background goroutine, periodically refreshing
// SCION paths before they expire. It uses exponential backoff when the SCION
// daemon is unreachable.
func (c *Conn) refreshSCIONPaths() {
	const (
		baseInterval = 30 * time.Second
		maxBackoff   = 10 * time.Minute
	)
	ticker := time.NewTicker(baseInterval)
	defer ticker.Stop()

	var consecutiveFailures int
	for {
		select {
		case <-c.donec:
			return
		case <-ticker.C:
			if consecutiveFailures > 0 {
				backoff := baseInterval * time.Duration(1<<min(consecutiveFailures, 5))
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				ticker.Reset(backoff)
			}
			if err := c.refreshSCIONPathsOnce(); err != nil {
				consecutiveFailures++
				if consecutiveFailures == 1 || consecutiveFailures&(consecutiveFailures-1) == 0 {
					c.logf("magicsock: SCION path refresh failed (%d consecutive): %v",
						consecutiveFailures, err)
				}
			} else {
				if consecutiveFailures > 0 {
					ticker.Reset(baseInterval)
				}
				consecutiveFailures = 0
			}
		}
	}
}

func (c *Conn) refreshSCIONPathsOnce() error {
	sc := c.pconnSCION
	if sc == nil {
		return nil
	}

	c.mu.Lock()
	// Snapshot the current paths under lock.
	pathsCopy := make(map[scionPathKey]*scionPathInfo, len(c.scionPaths))
	for k, v := range c.scionPaths {
		pathsCopy[k] = v
	}
	c.mu.Unlock()

	// Group paths by peerIA so we query the daemon once per peer.
	type peerGroup struct {
		peerIA      addr.IA
		hostAddr    netip.AddrPort
		needRefresh bool
		keys        []scionPathKey
		infos       []*scionPathInfo
	}
	groups := make(map[addr.IA]*peerGroup)
	now := time.Now()
	for k, pi := range pathsCopy {
		pi.mu.Lock()
		peerIA := pi.peerIA
		hostAddr := pi.hostAddr
		needsRefresh := !pi.expiry.IsZero() && now.After(pi.expiry.Add(-1*time.Minute))
		pi.mu.Unlock()

		g := groups[peerIA]
		if g == nil {
			g = &peerGroup{peerIA: peerIA, hostAddr: hostAddr}
			groups[peerIA] = g
		}
		g.keys = append(g.keys, k)
		g.infos = append(g.infos, pi)
		if needsRefresh {
			g.needRefresh = true
		}
	}

	ctx, cancel := context.WithTimeout(c.connCtx, 10*time.Second)
	defer cancel()

	var lastErr error
	for _, g := range groups {
		if !g.needRefresh {
			continue
		}

		daemonPaths, err := sc.daemon.Paths(ctx, g.peerIA, sc.localIA, daemon.PathReqFlags{Refresh: true})
		if err != nil || len(daemonPaths) == 0 {
			c.logf("magicsock: SCION path refresh for %s failed: %v", g.peerIA, err)
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("no paths to %s", g.peerIA)
			}
			continue
		}

		// Index daemon paths by fingerprint for matching.
		type daemonPathEntry struct {
			path snet.Path
			fp   snet.PathFingerprint
		}
		var daemonByFP []daemonPathEntry
		for _, dp := range daemonPaths {
			daemonByFP = append(daemonByFP, daemonPathEntry{
				path: dp,
				fp:   dp.Metadata().Fingerprint(),
			})
		}

		// Find the best daemon path for fallback use.
		bestDaemon := daemonPaths[0]
		bestDaemonLat := totalPathLatency(bestDaemon)
		for _, p := range daemonPaths[1:] {
			lat := totalPathLatency(p)
			if lat < bestDaemonLat {
				bestDaemon = p
				bestDaemonLat = lat
			}
		}

		// Match existing registered paths to daemon paths by fingerprint.
		// Unmatched paths with known fingerprints (disappeared from daemon)
		// have their refreshMissCount incremented. When the count exceeds
		// scionStalePathThreshold, the path is removed. Paths with empty
		// fingerprints (no metadata) get the best daemon path as fallback.
		var stalePaths []scionPathKey
		for i, pi := range g.infos {
			pi.mu.Lock()
			fp := pi.fingerprint
			pi.mu.Unlock()

			var matched snet.Path
			if fp != "" {
				for _, d := range daemonByFP {
					if d.fp == fp {
						matched = d.path
						break
					}
				}
				if matched == nil {
					// Known fingerprint disappeared from daemon results.
					pi.mu.Lock()
					pi.refreshMissCount++
					if pi.refreshMissCount >= scionStalePathThreshold {
						stalePaths = append(stalePaths, g.keys[i])
					}
					pi.mu.Unlock()
					continue
				}
			} else {
				// No fingerprint (missing metadata). Use best daemon path.
				matched = bestDaemon
			}

			pi.mu.Lock()
			pi.refreshMissCount = 0
			pi.path = matched
			newFP := matched.Metadata().Fingerprint()
			pi.fingerprint = newFP
			if md := matched.Metadata(); md != nil {
				pi.expiry = md.Expiry
				pi.mtu = md.MTU
			}
			pi.buildCachedDst()
			pi.fastPath = buildSCIONFastPath(sc, pi)
			pi.mu.Unlock()
		}

		// Remove stale paths that have been absent for too many refresh cycles.
		if len(stalePaths) > 0 {
			c.mu.Lock()
			for _, k := range stalePaths {
				c.logf("magicsock: SCION path %d stale for %s, removing", k, g.peerIA)
				c.unregisterSCIONPath(k)
			}
			c.mu.Unlock()
			c.cleanStaleSCIONPathFromEndpoints(stalePaths, g.peerIA)
		}
	}

	// Soft refresh pass: for groups that did NOT need hard refresh, check
	// if new paths have appeared in the daemon's cache. This discovers new
	// better paths that become available mid-session without waiting for
	// expiry-driven hard refresh.
	const softRefreshInterval = 5 * time.Minute
	for _, g := range groups {
		if g.needRefresh {
			continue // already refreshed above
		}
		c.mu.Lock()
		lastSoft := c.scionSoftRefreshAt[g.peerIA]
		c.mu.Unlock()
		if !lastSoft.IsZero() && now.Sub(lastSoft) < softRefreshInterval {
			continue
		}

		daemonPaths, err := sc.daemon.Paths(ctx, g.peerIA, sc.localIA, daemon.PathReqFlags{Refresh: false})
		if err != nil || len(daemonPaths) == 0 {
			continue
		}

		// Collect existing fingerprints for this group.
		knownFPs := make(map[snet.PathFingerprint]bool, len(g.infos))
		for _, pi := range g.infos {
			pi.mu.Lock()
			if pi.fingerprint != "" {
				knownFPs[pi.fingerprint] = true
			}
			pi.mu.Unlock()
		}

		// Filter to paths with new fingerprints.
		maxSlots := scionMaxProbePaths()
		available := maxSlots - len(g.keys)
		if available <= 0 {
			c.mu.Lock()
			mak.Set(&c.scionSoftRefreshAt, g.peerIA, now)
			c.mu.Unlock()
			continue
		}

		var newPaths []snet.Path
		for _, dp := range daemonPaths {
			fp := dp.Metadata().Fingerprint()
			if fp == "" || knownFPs[fp] {
				continue
			}
			newPaths = append(newPaths, dp)
			if len(newPaths) >= available {
				break
			}
		}

		if len(newPaths) > 0 {
			c.addNewSCIONPathsForPeer(g.peerIA, g.hostAddr, newPaths)
			c.logf("magicsock: SCION soft refresh: %d new paths for %s", len(newPaths), g.peerIA)
		}

		c.mu.Lock()
		mak.Set(&c.scionSoftRefreshAt, g.peerIA, now)
		c.mu.Unlock()
	}

	return lastErr
}

// addNewSCIONPathsForPeer registers new SCION paths and adds probe states
// to the corresponding endpoint. Called during soft refresh when new paths
// appear in the daemon's cache.
func (c *Conn) addNewSCIONPathsForPeer(peerIA addr.IA, hostAddr netip.AddrPort, paths []snet.Path) {
	sc := c.pconnSCION
	if sc == nil {
		return
	}

	c.mu.Lock()
	var newKeys []scionPathKey
	for _, p := range paths {
		md := p.Metadata()
		var expiry time.Time
		var mtu uint16
		if md != nil {
			expiry = md.Expiry
			mtu = md.MTU
		}
		pi := &scionPathInfo{
			peerIA:      peerIA,
			hostAddr:    hostAddr,
			fingerprint: md.Fingerprint(),
			path:        p,
			expiry:      expiry,
			mtu:         mtu,
		}
		pi.buildCachedDst()
		pi.fastPath = buildSCIONFastPath(sc, pi)
		k := c.registerSCIONPath(pi)
		newKeys = append(newKeys, k)
	}

	// Find the endpoint for this peerIA and add probe states.
	for _, peerInf := range c.peerMap.byNodeKey {
		ep := peerInf.ep
		ep.mu.Lock()
		if ep.scionState != nil && ep.scionState.peerIA == peerIA {
			for _, k := range newKeys {
				if _, exists := ep.scionState.paths[k]; !exists {
					fp := c.scionPaths[k].fingerprint
					ep.scionState.paths[k] = &scionPathProbeState{
						fingerprint: fp,
						healthy:     true,
					}
				}
			}
		}
		ep.mu.Unlock()
	}
	c.mu.Unlock()
}

// cleanStaleSCIONPathFromEndpoints removes stale SCION path keys from all
// endpoints that reference the given peerIA. If the removed key was the
// activePath, reassigns to the first remaining path.
func (c *Conn) cleanStaleSCIONPathFromEndpoints(staleKeys []scionPathKey, peerIA addr.IA) {
	staleSet := make(map[scionPathKey]bool, len(staleKeys))
	for _, k := range staleKeys {
		staleSet[k] = true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pi := range c.peerMap.byNodeKey {
		ep := pi.ep
		ep.mu.Lock()
		if ep.scionState == nil || ep.scionState.peerIA != peerIA {
			ep.mu.Unlock()
			continue
		}
		for k := range ep.scionState.paths {
			if staleSet[k] {
				delete(ep.scionState.paths, k)
			}
		}
		if staleSet[ep.scionState.activePath] {
			ep.scionState.activePath = 0
			for k := range ep.scionState.paths {
				ep.scionState.activePath = k
				break
			}
		}
		ep.mu.Unlock()
	}
}

// scionServiceFromPeer extracts SCION service info from a peer node's Services.
// It checks for a dedicated SCION service entry first, then falls back to
// checking the peerapi4 Description field (which is used to piggyback SCION
// info through coord servers that only relay peerapi services).
func scionServiceFromPeer(n tailcfg.NodeView) (ia addr.IA, hostAddr netip.AddrPort, ok bool) {
	hi := n.Hostinfo()
	if !hi.Valid() {
		return 0, netip.AddrPort{}, false
	}
	services := hi.Services()
	for i := range services.Len() {
		svc := services.At(i)
		// Direct SCION service entry.
		if svc.Proto == tailcfg.SCION {
			parsedIA, parsedAddr, err := parseSCIONServiceAddr(svc.Description, svc.Port)
			if err != nil {
				continue
			}
			return parsedIA, parsedAddr, true
		}
		// Piggyback: SCION info in peerapi4's Description field.
		// Format: "scion=ISD-AS,host-IP:port"
		if svc.Proto == tailcfg.PeerAPI4 && strings.HasPrefix(svc.Description, "scion=") {
			scionDesc := svc.Description[len("scion="):]
			// Parse "ISD-AS,host-IP:port"
			lastColon := strings.LastIndex(scionDesc, ":")
			if lastColon < 0 {
				continue
			}
			addrPart := scionDesc[:lastColon]
			var port uint16
			if _, err := fmt.Sscanf(scionDesc[lastColon+1:], "%d", &port); err != nil {
				continue
			}
			parsedIA, parsedAddr, err := parseSCIONServiceAddr(addrPart, port)
			if err != nil {
				continue
			}
			return parsedIA, parsedAddr, true
		}
	}
	return 0, netip.AddrPort{}, false
}

// SCIONService returns the SCION service entry to advertise in Hostinfo,
// or ok=false if SCION is not available.
func (c *Conn) SCIONService() (svc tailcfg.Service, ok bool) {
	sc := c.pconnSCION
	if sc == nil {
		return tailcfg.Service{}, false
	}
	// snet.Conn.LocalAddr() returns an *snet.UDPAddr; extract host IP and port.
	localAddr := sc.conn.LocalAddr()
	hostIP := "127.0.0.1"
	var scionPort uint16
	if sa, saOk := localAddr.(*snet.UDPAddr); saOk && sa.Host != nil {
		if sa.Host.IP != nil {
			hostIP = sa.Host.IP.String()
		}
		scionPort = uint16(sa.Host.Port)
	}
	return tailcfg.Service{
		Proto:       tailcfg.SCION,
		Port:        scionPort,
		Description: fmt.Sprintf("%s,%s", sc.localIA, hostIP),
	}, true
}

// discoverSCIONPathAsync runs SCION path discovery in a goroutine,
// avoiding blocking updateFromNode which holds the endpoint lock.
// It self-throttles to at most once every 5 seconds to prevent concurrent
// launches (from updateFromNode and send error paths) from creating
// orphaned path entries.
func (de *endpoint) discoverSCIONPathAsync(peerIA addr.IA, hostAddr netip.AddrPort) {
	// Throttle: skip if discovery ran recently. This prevents concurrent
	// launches from orphaning path entries in the registry.
	de.mu.Lock()
	if de.scionState != nil && time.Since(de.scionState.lastDiscoveryAt) < 5*time.Second {
		de.mu.Unlock()
		return
	}
	if de.scionState != nil {
		de.scionState.lastDiscoveryAt = time.Now()
	}
	de.mu.Unlock()

	ctx, cancel := context.WithTimeout(de.c.connCtx, 10*time.Second)
	defer cancel()

	// Capture old keys before discovering new paths.
	de.mu.Lock()
	var oldKeys []scionPathKey
	if de.scionState != nil {
		for k := range de.scionState.paths {
			oldKeys = append(oldKeys, k)
		}
	}
	de.mu.Unlock()

	newKeys, err := de.c.discoverSCIONPaths(ctx, peerIA, hostAddr)
	if err != nil {
		de.c.logf("magicsock: SCION path discovery for %s failed: %v", peerIA, err)
		return
	}

	// Build set of new keys for fast lookup.
	newKeySet := make(map[scionPathKey]bool, len(newKeys))
	for _, k := range newKeys {
		newKeySet[k] = true
	}

	// Extract fingerprints under c.mu (must be acquired before de.mu per lock ordering).
	de.c.mu.Lock()
	fpByKey := make(map[scionPathKey]snet.PathFingerprint, len(newKeys))
	for _, k := range newKeys {
		if pi := de.c.lookupSCIONPath(k); pi != nil {
			fpByKey[k] = pi.fingerprint
		}
	}
	// Clean up old keys that aren't in the new set.
	for _, k := range oldKeys {
		if !newKeySet[k] {
			de.c.unregisterSCIONPath(k)
		}
	}
	de.c.mu.Unlock()

	// Build probe state map, preserving history for surviving paths by fingerprint.
	de.mu.Lock()
	var oldProbeByFP map[snet.PathFingerprint]*scionPathProbeState
	if de.scionState != nil {
		oldProbeByFP = make(map[snet.PathFingerprint]*scionPathProbeState, len(de.scionState.paths))
		for _, ps := range de.scionState.paths {
			if ps.fingerprint != "" {
				oldProbeByFP[ps.fingerprint] = ps
			}
		}
	}

	newPaths := make(map[scionPathKey]*scionPathProbeState, len(newKeys))
	for _, k := range newKeys {
		fp := fpByKey[k]
		// Preserve existing probe history if the fingerprint matches.
		if fp != "" && oldProbeByFP != nil {
			if old, ok := oldProbeByFP[fp]; ok {
				old.fingerprint = fp // ensure set
				newPaths[k] = old
				continue
			}
		}
		newPaths[k] = &scionPathProbeState{fingerprint: fp, healthy: true}
	}

	activePath := scionPathKey(0)
	if len(newKeys) > 0 {
		activePath = newKeys[0]
	}

	de.scionState = &scionEndpointState{
		peerIA:          peerIA,
		hostAddr:        hostAddr,
		paths:           newPaths,
		activePath:      activePath,
		lastDiscoveryAt: time.Now(),
	}
	de.mu.Unlock()

	de.c.logf("magicsock: discovered %d SCION paths to %s (active key=%d)", len(newKeys), peerIA, activePath)
}

// scionKeyForAddr returns the scionPathKey for the given peer IA and host
// address, or a zero key if not found. O(1) via reverse index.
func (c *Conn) scionKeyForAddr(peerIA addr.IA, hostAddr netip.AddrPort) scionPathKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scionPathsByAddr[scionAddrKey{ia: peerIA, addr: hostAddr}]
}

var errNoSCION = fmt.Errorf("SCION not available")

const discoRXPathSCION discoRXPath = "SCION"
