// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
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
	peerIA    addr.IA
	hostAddr  netip.AddrPort  // peer's SCION host IP:port
	path      snet.Path       // current best SCION path to this peer
	replyPath *snet.UDPAddr   // bootstrapped from incoming packet (pre-reversed)
	expiry    time.Time       // path expiration from path metadata
	mtu       uint16          // SCION payload MTU from path metadata
	mu        sync.Mutex
}

// scionHeaderOverhead is the fixed overhead added by SCION encapsulation,
// excluding the variable-length path header:
//   - Underlay IPv4+UDP: 20 + 8 = 28 bytes
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

// scionEndpointState tracks SCION-specific per-peer state on an endpoint.
type scionEndpointState struct {
	peerIA          addr.IA        // peer's ISD-AS from Services advertisement
	hostAddr        netip.AddrPort // peer's SCION host IP:port
	pathKey         scionPathKey   // key into Conn.scionPaths
	lastDiscoveryAt time.Time      // when path discovery last started (throttle)
}

// scionConn wraps a SCION connection for use by magicsock.
type scionConn struct {
	conn    *snet.Conn       // from SCIONNetwork.Listen()
	localIA addr.IA          // our ISD-AS
	daemon  daemon.Connector // for path queries
	topo    snet.Topology    // local topology
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
	path := pi.path
	replyPath := pi.replyPath
	hostAddr := pi.hostAddr
	peerIA := pi.peerIA
	pi.mu.Unlock()

	// If we have a replyPath (bootstrapped from an incoming packet),
	// use it directly — it's already reversed by snet's ReplyPather.
	if path == nil && replyPath != nil {
		return sc.conn.WriteTo(b, replyPath)
	}

	dst := &snet.UDPAddr{
		IA: peerIA,
		Host: &net.UDPAddr{
			IP:   hostAddr.Addr().AsSlice(),
			Port: int(hostAddr.Port()),
		},
	}
	if path != nil {
		dst.Path = path.Dataplane()
		dst.NextHop = path.UnderlayNextHop()
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

// trySCIONConnect attempts to connect to the local SCION daemon and set up a
// SCION listener. The listener binds to 127.0.0.1 (required by snet, which
// rejects unspecified addresses) on a port within the dispatched range.
// Returns nil if SCION is not available.
func trySCIONConnect(ctx context.Context) (*scionConn, error) {
	daemonAddr := scionDaemonAddr()
	svc := daemon.Service{Address: daemonAddr}
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}

	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("querying local IA: %w", err)
	}

	// In scion v0.12.0, daemon.Connector satisfies snet.Topology.
	network := &snet.SCIONNetwork{
		Topology: conn,
	}

	listenPort := scionListenPort()
	if listenPort != 0 {
		// Validate the configured port against the daemon's dispatched range.
		portMin, portMax, err := conn.PortRange(ctx)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("querying SCION port range: %w", err)
		}
		if listenPort < portMin || listenPort > portMax {
			conn.Close()
			return nil, fmt.Errorf("TS_SCION_PORT=%d outside dispatched range [%d, %d]", listenPort, portMin, portMax)
		}
	}

	listenAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(listenPort),
	}

	// Use OpenRaw + NewCookedConn instead of Listen so we can set socket
	// buffer sizes on the underlying UDP connection before wrapping it.
	pconn, err := network.OpenRaw(ctx, listenAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("listening on SCION %s: %w", listenAddr, err)
	}

	// Increase underlay UDP socket buffers to match the regular magicsock
	// UDP sockets (7 MB). The default kernel buffer (~212 KB) overflows
	// easily at high throughput, causing packet drops and TCP retransmissions.
	if pc, ok := pconn.(*snet.SCIONPacketConn); ok {
		if err := pc.SetReadBuffer(socketBufferSize); err != nil {
			fmt.Fprintf(os.Stderr, "magicsock: SCION: failed to set read buffer to %d: %v\n", socketBufferSize, err)
		}
		if err := pc.SetWriteBuffer(socketBufferSize); err != nil {
			fmt.Fprintf(os.Stderr, "magicsock: SCION: failed to set write buffer to %d: %v\n", socketBufferSize, err)
		}
	}

	sconn, err := snet.NewCookedConn(pconn, conn)
	if err != nil {
		pconn.Close()
		conn.Close()
		return nil, fmt.Errorf("creating SCION conn: %w", err)
	}

	return &scionConn{
		conn:    sconn,
		localIA: localIA,
		daemon:  conn,
		topo:    conn,
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
	path, replyPath, hostAddr, peerIA := pi.path, pi.replyPath, pi.hostAddr, pi.peerIA
	expired := !pi.expiry.IsZero() && time.Now().After(pi.expiry)
	pi.mu.Unlock()
	if expired {
		return false, fmt.Errorf("SCION path expired for key %d", addr.scionKey)
	}

	// If no discovered path, fall back to replyPath (bootstrapped from an
	// incoming packet before path discovery completes).
	if path == nil && replyPath != nil {
		for _, buf := range buffs {
			_, err = sc.conn.WriteTo(buf[offset:], replyPath)
			if err != nil {
				return false, err
			}
		}
		return true, nil
	}

	dst := &snet.UDPAddr{
		IA: peerIA,
		Host: &net.UDPAddr{
			IP:   hostAddr.Addr().AsSlice(),
			Port: int(hostAddr.Port()),
		},
	}
	if path != nil {
		dst.Path = path.Dataplane()
		dst.NextHop = path.UnderlayNextHop()
	}

	for _, buf := range buffs {
		_, err = sc.conn.WriteTo(buf[offset:], dst)
		if err != nil {
			return false, err
		}
	}
	return true, nil
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
	if c.scionPathsByAddr == nil {
		c.scionPathsByAddr = make(map[scionAddrKey]scionPathKey)
	}
	c.scionPaths[k] = pi
	c.scionPathsByAddr[scionAddrKey{ia: pi.peerIA, addr: pi.hostAddr}] = k
	return k
}

// registerSCIONPathLocking stores a scionPathInfo, acquiring c.mu, and returns
// a key for it.
func (c *Conn) registerSCIONPathLocking(pi *scionPathInfo) scionPathKey {
	k := scionPathKey(c.scionPathSeq.Add(1))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scionPaths == nil {
		c.scionPaths = make(map[scionPathKey]*scionPathInfo)
	}
	if c.scionPathsByAddr == nil {
		c.scionPathsByAddr = make(map[scionAddrKey]scionPathKey)
	}
	c.scionPaths[k] = pi
	c.scionPathsByAddr[scionAddrKey{ia: pi.peerIA, addr: pi.hostAddr}] = k
	return k
}

// unregisterSCIONPath removes a SCION path entry.
// c.mu must be held.
func (c *Conn) unregisterSCIONPath(k scionPathKey) {
	if pi, ok := c.scionPaths[k]; ok {
		delete(c.scionPathsByAddr, scionAddrKey{ia: pi.peerIA, addr: pi.hostAddr})
	}
	delete(c.scionPaths, k)
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
func (c *Conn) receiveSCION(buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	sc := c.pconnSCION
	if sc == nil {
		<-c.donec
		return 0, net.ErrClosed
	}

	// Initialize lastSCIONRecv so we don't trigger reconnection on startup.
	c.lastSCIONRecv.CompareAndSwap(0, time.Now().UnixNano())

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

		// Set a read deadline so we wake up periodically even if the socket
		// is silently dead (SCION router lost our port registration).
		sc.conn.SetReadDeadline(time.Now().Add(scionReadDeadline))

		n, srcAddr, err := sc.readFrom(buffs[0])
		if err != nil {
			// Graceful shutdown: Conn is closing.
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			default:
			}

			// Timeout: check if we need to reconnect.
			if isTimeoutError(err) {
				if c.shouldReconnectSCION() {
					c.reconnectSCION()
				}
				continue
			}

			// Socket closed (by reconnectSCION or externally): re-read
			// pconnSCION on next iteration.
			if errors.Is(err, net.ErrClosed) {
				continue
			}

			// Other errors: log and continue. Never propagate to WireGuard.
			c.logf("magicsock: SCION read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		// Got a packet — record receive time.
		c.lastSCIONRecv.Store(time.Now().UnixNano())

		b := buffs[0][:n]

		srcHostAddr := srcAddr.Host.AddrPort()

		// Check for disco packets (same as receiveIP does).
		pt, _ := packetLooksLike(b)
		if pt == packetLooksLikeDisco {
			// For disco messages, include the scionKey so pong replies
			// are routed back over SCION. Use a single critical section
			// for the lookup+register to avoid a TOCTOU race where a
			// concurrent discoverSCIONPaths could register between our
			// check and our register, creating orphaned entries.
			srcEpAddr := epAddr{ap: srcHostAddr}
			c.mu.Lock()
			sk := c.scionPathsByAddr[scionAddrKey{ia: srcAddr.IA, addr: srcHostAddr}]
			if !sk.IsSet() {
				// First disco packet from this SCION peer — bootstrap a
				// reverse path entry so the pong can go back over SCION.
				// ReadFrom returns a pre-reversed path suitable for replies.
				sk = c.registerSCIONPath(&scionPathInfo{
					peerIA:    srcAddr.IA,
					hostAddr:  srcHostAddr,
					replyPath: srcAddr,
				})
			}
			c.mu.Unlock()
			srcEpAddr.scionKey = sk
			c.handleDiscoMessage(b, srcEpAddr, false, key.NodePublic{}, discoRXPathSCION)
			continue
		}

		if !c.havePrivateKey.Load() {
			continue
		}

		// WireGuard packet — look up the endpoint by host addr only
		// (peerMap is keyed by netip.AddrPort, not scionKey).
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
	lastRecv := time.Unix(0, c.lastSCIONRecv.Load())
	if time.Since(lastRecv) < scionReconnectThreshold {
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

	newSC, err := trySCIONConnect(c.connCtx)
	if err != nil {
		c.logf("magicsock: SCION reconnect failed: %v", err)
		// Reset the receive timestamp so we retry after scionReconnectThreshold.
		c.lastSCIONRecv.Store(time.Now().UnixNano())
		return
	}

	// Swap in the new connection.
	c.pconnSCION = newSC

	// Reset the receive timestamp so we don't immediately re-trigger.
	c.lastSCIONRecv.Store(time.Now().UnixNano())

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
	newSC, err := trySCIONConnect(c.connCtx)
	if err != nil {
		c.logf("magicsock: SCION reconnect retry failed: %v", err)
		return
	}
	c.pconnSCION = newSC
	c.lastSCIONRecv.Store(time.Now().UnixNano())
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
// selects the best one, and stores it in the path registry. Returns the
// scionPathKey for the path.
func (c *Conn) discoverSCIONPaths(ctx context.Context, peerIA addr.IA, hostAddr netip.AddrPort) (scionPathKey, error) {
	sc := c.pconnSCION
	if sc == nil {
		return 0, errNoSCION
	}

	paths, err := sc.daemon.Paths(ctx, peerIA, sc.localIA, daemon.PathReqFlags{Refresh: false})
	if err != nil {
		return 0, fmt.Errorf("querying SCION paths to %s: %w", peerIA, err)
	}
	if len(paths) == 0 {
		return 0, fmt.Errorf("no SCION paths to %s", peerIA)
	}

	// Pick the path with lowest total latency.
	best := paths[0]
	bestLatency := totalPathLatency(best)
	for _, p := range paths[1:] {
		lat := totalPathLatency(p)
		if lat < bestLatency {
			best = p
			bestLatency = lat
		}
	}

	var expiry time.Time
	var mtu uint16
	if md := best.Metadata(); md != nil {
		expiry = md.Expiry
		mtu = md.MTU
	}

	pi := &scionPathInfo{
		peerIA:   peerIA,
		hostAddr: hostAddr,
		path:     best,
		expiry:   expiry,
		mtu:      mtu,
	}
	return c.registerSCIONPathLocking(pi), nil
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

	ctx, cancel := context.WithTimeout(c.connCtx, 10*time.Second)
	defer cancel()

	now := time.Now()
	var lastErr error
	for _, pi := range pathsCopy {
		pi.mu.Lock()
		needsRefresh := !pi.expiry.IsZero() && now.After(pi.expiry.Add(-1*time.Minute))
		peerIA := pi.peerIA
		pi.mu.Unlock()

		if !needsRefresh {
			continue
		}

		paths, err := sc.daemon.Paths(ctx, peerIA, sc.localIA, daemon.PathReqFlags{Refresh: true})
		if err != nil || len(paths) == 0 {
			c.logf("magicsock: SCION path refresh for %s failed: %v", peerIA, err)
			if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("no paths to %s", peerIA)
			}
			continue
		}

		best := paths[0]
		bestLatency := totalPathLatency(best)
		for _, p := range paths[1:] {
			lat := totalPathLatency(p)
			if lat < bestLatency {
				best = p
				bestLatency = lat
			}
		}

		pi.mu.Lock()
		pi.path = best
		if md := best.Metadata(); md != nil {
			pi.expiry = md.Expiry
			pi.mtu = md.MTU
		}
		pi.mu.Unlock()
	}
	return lastErr
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

	// Capture old key before discovering new path.
	de.mu.Lock()
	var oldKey scionPathKey
	if de.scionState != nil {
		oldKey = de.scionState.pathKey
	}
	de.mu.Unlock()

	pathKey, err := de.c.discoverSCIONPaths(ctx, peerIA, hostAddr)
	if err != nil {
		de.c.logf("magicsock: SCION path discovery for %s failed: %v", peerIA, err)
		return
	}

	// Clean up old path entry if the key changed.
	if oldKey.IsSet() && oldKey != pathKey {
		de.c.mu.Lock()
		de.c.unregisterSCIONPath(oldKey)
		de.c.mu.Unlock()
	}

	de.mu.Lock()
	de.scionState = &scionEndpointState{
		peerIA:          peerIA,
		hostAddr:        hostAddr,
		pathKey:         pathKey,
		lastDiscoveryAt: time.Now(),
	}
	de.mu.Unlock()

	pi := de.c.lookupSCIONPathLocking(pathKey)
	var mtu uint16
	if pi != nil {
		pi.mu.Lock()
		mtu = pi.mtu
		pi.mu.Unlock()
	}
	de.c.logf("magicsock: discovered SCION path to %s (key=%d, mtu=%d)", peerIA, pathKey, mtu)
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
