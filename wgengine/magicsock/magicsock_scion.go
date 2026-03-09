// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
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
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// scionPathKey is a compact index into the Conn-level scionPaths registry.
// This keeps epAddr small and comparable (snet.UDPAddr contains slices).
// A zero value means "not a SCION path."
type scionPathKey uint32

// IsSet reports whether k refers to a valid SCION path entry.
func (k scionPathKey) IsSet() bool { return k != 0 }

// scionPathInfo holds the full SCION path information for a peer, indexed by
// scionPathKey. The actual SCION address and path data live here rather than
// in epAddr to keep epAddr comparable and small.
type scionPathInfo struct {
	peerIA   addr.IA
	hostAddr netip.AddrPort // peer's SCION host IP:port
	path     snet.Path      // current best SCION path to this peer
	expiry   time.Time      // path expiration from path metadata
	mu       sync.Mutex
}

// scionEndpointState tracks SCION-specific per-peer state on an endpoint.
type scionEndpointState struct {
	peerIA   addr.IA        // peer's ISD-AS from Services advertisement
	hostAddr netip.AddrPort // peer's SCION host IP:port
	pathKey  scionPathKey   // key into Conn.scionPaths
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
	hostAddr := pi.hostAddr
	peerIA := pi.peerIA
	pi.mu.Unlock()

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

// trySCIONConnect attempts to connect to the local SCION daemon and set up a
// SCION listener. Returns nil if SCION is not available.
func trySCIONConnect(ctx context.Context, localPort uint16) (*scionConn, error) {
	daemonAddr := scionDaemonAddr()
	svc := daemon.Service{Address: daemonAddr}
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}

	topo, err := daemon.LoadTopology(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("loading SCION topology: %w", err)
	}

	network := &snet.SCIONNetwork{
		Topology: topo,
	}

	listenAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(localPort),
	}
	sconn, err := network.Listen(ctx, "udp", listenAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("listening on SCION: %w", err)
	}

	return &scionConn{
		conn:    sconn,
		localIA: topo.LocalIA,
		daemon:  conn,
		topo:    topo,
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

	pi := c.lookupSCIONPath(addr.scionKey)
	if pi == nil {
		return false, fmt.Errorf("no SCION path info for key %d", addr.scionKey)
	}

	for _, buf := range buffs {
		_, err = sc.writeTo(buf[offset:], pi)
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
	pi := c.lookupSCIONPath(sk)
	if pi == nil {
		return false, fmt.Errorf("no SCION path info for key %d", sk)
	}
	_, err := sc.writeTo(b, pi)
	if err != nil {
		return false, err
	}
	return true, nil
}

// lookupSCIONPath returns the scionPathInfo for the given key, or nil if not found.
func (c *Conn) lookupSCIONPath(k scionPathKey) *scionPathInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scionPaths[k]
}

// registerSCIONPath stores a scionPathInfo and returns a key for it.
func (c *Conn) registerSCIONPath(pi *scionPathInfo) scionPathKey {
	k := scionPathKey(c.scionPathSeq.Add(1))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scionPaths == nil {
		c.scionPaths = make(map[scionPathKey]*scionPathInfo)
	}
	c.scionPaths[k] = pi
	return k
}

// unregisterSCIONPath removes a SCION path entry.
func (c *Conn) unregisterSCIONPath(k scionPathKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.scionPaths, k)
}

// receiveSCION is the conn.ReceiveFunc for SCION packets. It reads from the
// SCION connection and dispatches disco or WireGuard packets.
func (c *Conn) receiveSCION(buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	sc := c.pconnSCION
	if sc == nil {
		// Block until the Conn is closed if SCION is not available.
		<-c.donec
		return 0, net.ErrClosed
	}

	for {
		n, srcAddr, err := sc.readFrom(buffs[0])
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}

		b := buffs[0][:n]

		// Build an epAddr for this SCION source. We use the host IP:port
		// from the SCION address. The scionKey on the epAddr is not set
		// here since we're on the receive path — the peerMap lookup uses
		// the host addr portion.
		srcHostAddr := srcAddr.Host.AddrPort()
		srcEpAddr := epAddr{ap: srcHostAddr}

		// Check for disco packets (same as receiveIP does).
		pt, _ := packetLooksLike(b)
		if pt == packetLooksLikeDisco {
			c.handleDiscoMessage(b, srcEpAddr, false, key.NodePublic{}, discoRXPathSCION)
			continue
		}

		// WireGuard packet — look up the endpoint by source address.
		c.mu.Lock()
		ep, ok := c.peerMap.endpointForEpAddr(srcEpAddr)
		c.mu.Unlock()
		if !ok {
			// Try looking up without SCION key since the receive side
			// may not have the scionKey set in peerMap.
			continue
		}

		ep.noteRecvActivity(srcEpAddr, mono.Now())
		sizes[0] = n
		eps[0] = ep
		return 1, nil
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
	if md := best.Metadata(); md != nil {
		expiry = md.Expiry
	}

	pi := &scionPathInfo{
		peerIA:   peerIA,
		hostAddr: hostAddr,
		path:     best,
		expiry:   expiry,
	}
	return c.registerSCIONPath(pi), nil
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
			total += 10 * time.Millisecond
		} else {
			total += l
		}
	}
	return total
}

// refreshSCIONPaths runs in a background goroutine, periodically refreshing
// SCION paths before they expire.
func (c *Conn) refreshSCIONPaths() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.donec:
			return
		case <-ticker.C:
			c.refreshSCIONPathsOnce()
		}
	}
}

func (c *Conn) refreshSCIONPathsOnce() {
	sc := c.pconnSCION
	if sc == nil {
		return
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
		}
		pi.mu.Unlock()
	}
}

// scionServiceFromPeer extracts SCION service info from a peer node's Services.
func scionServiceFromPeer(n tailcfg.NodeView) (ia addr.IA, hostAddr netip.AddrPort, ok bool) {
	hi := n.Hostinfo()
	if !hi.Valid() {
		return 0, netip.AddrPort{}, false
	}
	services := hi.Services()
	for i := range services.Len() {
		svc := services.At(i)
		if svc.Proto != tailcfg.SCION {
			continue
		}
		parsedIA, parsedAddr, err := parseSCIONServiceAddr(svc.Description, svc.Port)
		if err != nil {
			continue
		}
		return parsedIA, parsedAddr, true
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
	// The local host IP comes from the SCION connection's local address.
	localAddr := sc.conn.LocalAddr()
	hostIP := "0.0.0.0"
	if ua, uaOk := localAddr.(*net.UDPAddr); uaOk && ua.IP != nil {
		hostIP = ua.IP.String()
	}
	return tailcfg.Service{
		Proto:       tailcfg.SCION,
		Port:        c.LocalPort(),
		Description: fmt.Sprintf("%s,%s", sc.localIA, hostIP),
	}, true
}

var errNoSCION = fmt.Errorf("SCION not available")

const discoRXPathSCION discoRXPath = "SCION"
