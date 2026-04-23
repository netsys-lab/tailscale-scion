// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/slayers"
	scionpath "github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/addrutil"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	wgconn "github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tstun"
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

// scionDispatcherPort is the legacy SCION dispatcher port. Older deployments
// redirect all SCION traffic to this port instead of delivering to application
// ports directly.
const scionDispatcherPort = 30041

var (
	scionPort          = envknob.RegisterString("TS_SCION_PORT")
	scionListenAddrEnv = envknob.RegisterString("TS_SCION_LISTEN_ADDR")
	noDispatcherShim   = envknob.RegisterBool("TS_SCION_NO_DISPATCHER_SHIM")
	scionNoFastPath    = envknob.RegisterBool("TS_SCION_NO_FAST_PATH")
)

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

// scionIAKey is a type alias for addr.IA, used in Conn fields shared with
// the ts_omit_scion omit file (which defines scionIAKey = uint64).
type scionIAKey = addr.IA

// scionLazyEndpointRate and scionLazyEndpointBurst bound the rate at which
// receiveSCION/receiveSCIONShim may create new lazyEndpoint objects for
// unknown source addresses. A spoofed flood from many source addresses would
// otherwise allocate one lazyEndpoint per packet until WireGuard fails
// authentication and drops them — significant GC pressure under attack.
//
// The chosen values (500/sec sustained, 200 burst) are generous enough that
// legitimate first-contact bursts (netmap updates, re-discovery) never hit
// the limit; they are meant as a ceiling, not a shaping mechanism. Drops
// are observable via metricSCIONLazyEndpointDropped.
const (
	scionLazyEndpointRate  = 500
	scionLazyEndpointBurst = 200
)

// initSCIONLazyEndpointLimiter initialises c.scionLazyEndpointLimiter and
// c.scionHotLogf. Called from newConn before any SCION receive path runs.
func (c *Conn) initSCIONLazyEndpointLimiter() {
	c.scionLazyEndpointLimiter = rate.NewLimiter(rate.Limit(scionLazyEndpointRate), scionLazyEndpointBurst)
	// 1 message burst per 5s window, cache up to 32 distinct formats. Used
	// by SCION hot paths where a single incident (e.g. socket close) would
	// otherwise emit thousands of identical log lines.
	c.scionHotLogf = logger.RateLimitedFn(c.logf, 5*time.Second, 1, 32)
}

// allowSCIONLazyEndpoint reports whether receive code may create a new
// lazyEndpoint right now. Returns false when the limiter bucket is empty;
// callers should drop the offending packet (or skip emitting the endpoint
// to WireGuard) and bump metricSCIONLazyEndpointDropped.
func (c *Conn) allowSCIONLazyEndpoint() bool {
	if c.scionLazyEndpointLimiter == nil {
		return true // not initialised — behave as if unlimited
	}
	if c.scionLazyEndpointLimiter.Allow() {
		return true
	}
	metricSCIONLazyEndpointDropped.Add(1)
	return false
}

// scionPathKey is a compact index into the Conn-level scionPaths registry.
// This keeps epAddr small and comparable (snet.UDPAddr contains slices).
// A zero value means "not a SCION path."
// scionPathKey is a monotonically increasing index into the Conn.scionPaths
// registry. Kept wide (uint64) so that a long-running daemon with frequent
// path churn cannot wrap the counter and alias stale registry entries onto
// new peers. Zero is reserved as "unset" — see IsSet.
type scionPathKey uint64

// IsSet reports whether k refers to a valid SCION path entry.
func (k scionPathKey) IsSet() bool { return k != 0 }

// scionAddrKey is a comparable key for the reverse index from (IA, host:port)
// to scionPathKey, enabling O(1) lookup in receiveSCION.
type scionAddrKey struct {
	ia   addr.IA
	addr netip.AddrPort
}

// scionPathFPKey is a comparable key for the reverse index from
// (peer IA, peer host addr, path fingerprint) to scionPathKey. The
// fingerprint is SCION's stable topological identity — same interface
// sequence ⇒ same fingerprint — so this index lets the reconciler find
// the existing scionPathInfo when the daemon returns a re-signed
// (same-topology, later-expiry) path without accidentally minting a fresh
// scionPathKey and churning endpoint state.
//
// hostAddr MUST be part of the key. SCION path segments are per-IA (the
// daemon returns paths to an IA, not to a specific underlay host), so two
// Tailscale peers in the same AS share a fingerprint despite having
// different underlay addresses. Keying on (ia, fp) alone would collapse
// them into one scionPathInfo, and the second peer's outbound traffic
// would go to the first peer's hostAddr — a silent misroute.
type scionPathFPKey struct {
	ia       addr.IA
	hostAddr netip.AddrPort
	fp       snet.PathFingerprint
}

// scionPathInfo holds the full SCION path information for a peer, indexed by
// scionPathKey. The actual SCION address and path data live here rather than
// in epAddr to keep epAddr comparable and small.
type scionPathInfo struct {
	peerIA           addr.IA
	hostAddr         netip.AddrPort       // peer's SCION host IP:port
	fingerprint      snet.PathFingerprint // SHA256 of interface sequence; for matching across refreshes
	path             snet.Path            // current best SCION path to this peer
	replyPath        *snet.UDPAddr        // bootstrapped from incoming packet (pre-reversed)
	cachedDst        *snet.UDPAddr        // pre-built destination addr; rebuilt when path changes
	fastPath         *scionFastPath       // pre-serialized header template for fast sends
	expiry           time.Time            // path expiration from path metadata
	mtu              uint16               // SCION payload MTU from path metadata
	refreshMissCount int                  // consecutive refresh cycles fingerprint absent from daemon
	displayStr       string               // pre-computed human-readable path string
	// generation increments each time path/nextHop/fastPath is mutated.
	// scionFastPath.gen is snapshot at build time; senders that observe a
	// fastPath whose gen is behind the current pi.generation treat the
	// template as stale and fall through to the slow path.
	generation uint64
	mu         sync.Mutex
}

// String returns the pre-computed human-readable display string for this path.
// Format: scion:[srcIA ifid>ifid transitIA ... dstIA]:[host]:port
func (pi *scionPathInfo) String() string {
	return pi.displayStr
}

// buildDisplayStr pre-computes the human-readable display string from the
// current path metadata and host address. Must be called with pi.mu held
// (or before the info is shared), and whenever the path is updated.
func (pi *scionPathInfo) buildDisplayStr() {
	hops := "?"
	if pi.path != nil {
		if md := pi.path.Metadata(); md != nil && len(md.Interfaces) > 0 {
			hops = formatSCIONHops(md.Interfaces)
		}
	} else if pi.fingerprint == scionSameASFingerprint {
		hops = "local"
	}
	pi.displayStr = fmt.Sprintf("scion:[%s]:[%s]:%d",
		hops, pi.hostAddr.Addr(), pi.hostAddr.Port())
}

// formatSCIONHops formats SCION path interfaces into standard hop notation.
// Produces: "19-ffaa:1:eba 2>2 19-ffaa:1:bf5" for a 2-hop path.
// Mirrors the format used by snet/path.fmtInterfaces and `scion showpaths`.
func formatSCIONHops(ifaces []snet.PathInterface) string {
	if len(ifaces) == 0 {
		return "?"
	}
	if len(ifaces) == 1 {
		// Single interface shouldn't occur in valid SCION paths
		// (interfaces always come in pairs), but handle gracefully.
		return fmt.Sprintf("%s %d", ifaces[0].IA, ifaces[0].ID)
	}
	var sb strings.Builder
	// First interface: srcIA ifid
	fmt.Fprintf(&sb, "%s %d", ifaces[0].IA, ifaces[0].ID)
	// Middle interfaces come in pairs: entry-ifid transitIA exit-ifid
	for i := 1; i < len(ifaces)-1; i += 2 {
		fmt.Fprintf(&sb, ">%d %s %d", ifaces[i].ID, ifaces[i].IA, ifaces[i+1].ID)
	}
	// Last interface: ifid dstIA
	last := ifaces[len(ifaces)-1]
	fmt.Fprintf(&sb, ">%d %s", last.ID, last.IA)
	return sb.String()
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
	// Bump generation so any previously-built fastPath snapshot is flagged
	// as stale by the send path's staleness check.
	pi.generation++
}

// The SCION path metadata MTU is the maximum SCION packet size that can
// traverse the path (including all SCION headers but excluding underlay
// IP+UDP). The actual payload budget depends on the variable-length path
// header, which grows with hop count:
//   - SCION common header: 12 bytes
//   - Address header (IPv4, 2x ISD-AS + 2x IPv4): 24 bytes
//   - Path header: ~36 bytes (2 hops) to ~96 bytes (6+ hops)
//   - SCION/UDP L4 header: 8 bytes
//
// Rather than computing exact overhead per path, we use a conservative
// wire MTU of 1280 bytes (the minimum IPv6 link MTU). This guarantees
// WireGuard packets fit within any SCION path's payload budget regardless
// of hop count.
const scionWireMTU = tstun.WireMTU(1280)

// scionUnsetHopLatency is the assumed per-hop latency when the SCION daemon
// reports LatencyUnset for a hop. Conservative estimate for path selection.
const scionUnsetHopLatency = 10 * time.Millisecond

// scionDaemonProbeTimeout is the timeout for probing the SCION daemon
// connector to check if it's still alive (used for tiered reconnection).
const scionDaemonProbeTimeout = 5 * time.Second

// defaultSCIONProbePaths is the default number of SCION paths to probe per peer.
const defaultSCIONProbePaths = 5

// scionStalePathThreshold is the number of consecutive refresh cycles a
// fingerprint must be absent from daemon results before the path is removed.
// At the default 30s refresh interval, this is ~90s.
const scionStalePathThreshold = 3

// scionSameASFingerprint is a sentinel fingerprint for same-AS (intra-AS)
// paths. These paths use an empty SCION path (PathType=0, 0 wire bytes)
// and communicate directly via UDP without border routers. The sentinel
// prevents the refresh logic from garbage-collecting same-AS path entries.
const scionSameASFingerprint snet.PathFingerprint = "same-as"

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

// scionRefreshBaseInterval is the cadence at which refreshSCIONPaths ticks
// and (in the success case) the interval between per-peer refresh attempts.
const scionRefreshBaseInterval = 30 * time.Second

// scionRefreshMaxBackoff caps the per-peer exponential backoff on consecutive
// refresh failures. At 2 min a failing peer is retried 4 times per segment
// expiry cycle in the worst case, while leaving enough room that transient
// daemon errors do not produce tight retry storms. A global backoff of 10 min
// was the previous design and meant one failing peer (missing TRC, AS
// unreachable) could starve refresh for every other peer for minutes.
const scionRefreshMaxBackoff = 2 * time.Minute

// scionDiscoveryLogInterval is the minimum wall-clock gap between logging
// SCION discovery failures for the same peer. Previously, the same
// "SCION path discovery for 71-2:0:4a failed: TRC not found" line could
// fire on every netmap update and every all-paths-unhealthy demote for a
// permanently-broken peer (e.g. TRC missing for its ISD), flooding
// journalctl. The error is still surfaced for status queries via
// PeerStatus.SCION.LastDiscoveryError (Phase 4a) with no rate limit.
const scionDiscoveryLogInterval = 5 * time.Minute

// --- Phase 2d: cold-retry after initial discovery failure ---
//
// When a peer's first path-discovery attempt fails because the local SCION
// daemon is warming up (no segments received yet, CS returned a truncated
// TRC, gRPC Unavailable), we want to retry quickly — on the order of tens
// of seconds — rather than wait for the 5-minute soft-refresh recovery
// path. Cold-retry state lives on Conn (not on endpoint.scionState, which
// is nil when discovery has never succeeded) and is keyed by
// (peerIA, hostAddr). A dedicated goroutine ticks every 5s and re-kicks
// discovery for due peers. Entries are cleared on success or given up
// after scionColdRetryMaxAttempts (at which point the standard soft-
// refresh loop handles long-term recovery).

const (
	scionColdRetryTickInterval = 5 * time.Second
	scionColdRetryMaxAttempts  = 6 // ~310 s total budget before giving up
)

// scionColdRetryKey identifies a peer's cold-retry state. hostAddr is part
// of the key so two Tailscale peers in the same SCION AS get independent
// retry schedules (mirrors the Phase 2c fix).
type scionColdRetryKey struct {
	ia       addr.IA
	hostAddr netip.AddrPort
}

// scionColdRetryEntry tracks how many times we've retried discovery for
// a given peer and when to try next. Pure state — no goroutines, no
// timers; the ticker goroutine reads and acts on this.
type scionColdRetryEntry struct {
	attempts       int                     // 1-indexed; incremented on each schedule
	nextAttemptAt  time.Time               // wall-clock when the ticker should re-kick
	firstFailureAt time.Time               // original failure — for future "give up and log" reporting
	lastErrorKind  scionDiscoveryErrorKind // classified error (Phase 5)
}

// scionColdRetrySleep returns the delay before the Nth retry attempt
// (1-indexed): 10s, 20s, 40s, 80s, 160s, capped at 160s thereafter. Kept
// separate for unit testability.
func scionColdRetrySleep(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	return 10 * time.Second * (1 << shift)
}

// scheduleColdRetry records (or bumps) a cold-retry entry for (peerIA,
// hostAddr). After scionColdRetryMaxAttempts bumps without success the
// entry is deleted and long-term recovery is left to soft-refresh.
func (c *Conn) scheduleColdRetry(peerIA addr.IA, hostAddr netip.AddrPort, kind scionDiscoveryErrorKind) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scionColdRetry == nil {
		c.scionColdRetry = make(map[scionColdRetryKey]*scionColdRetryEntry)
	}
	key := scionColdRetryKey{ia: peerIA, hostAddr: hostAddr}
	now := time.Now()
	ent := c.scionColdRetry[key]
	if ent == nil {
		ent = &scionColdRetryEntry{firstFailureAt: now}
		c.scionColdRetry[key] = ent
	}
	ent.attempts++
	if ent.attempts > scionColdRetryMaxAttempts {
		delete(c.scionColdRetry, key)
		return
	}
	ent.nextAttemptAt = now.Add(scionColdRetrySleep(ent.attempts))
	ent.lastErrorKind = kind
}

// clearColdRetry removes any cold-retry entry for (peerIA, hostAddr).
// Called when discovery succeeds for that peer.
func (c *Conn) clearColdRetry(peerIA addr.IA, hostAddr netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.scionColdRetry, scionColdRetryKey{ia: peerIA, hostAddr: hostAddr})
}

// scionColdRetryLoop is the dedicated goroutine. Ticks at
// scionColdRetryTickInterval; for each due entry, re-kicks
// discoverSCIONPathAsync on the corresponding endpoint. CAS + throttle
// inside discoverSCIONPathAsync coalesce with any other trigger that
// might race us.
func (c *Conn) scionColdRetryLoop() {
	ticker := time.NewTicker(scionColdRetryTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.donec:
			return
		case <-ticker.C:
			c.scionColdRetryTick()
		}
	}
}

// scionColdRetryTick iterates due cold-retry entries and kicks discovery
// for the matching endpoints. Looks up endpoints via the netmap peer list
// (same pattern as discoverNewSCIONPeers) because a peer whose first
// discovery failed has no scionState and therefore no fast path from key
// to endpoint.
func (c *Conn) scionColdRetryTick() {
	now := time.Now()

	c.mu.Lock()
	if len(c.scionColdRetry) == 0 {
		c.mu.Unlock()
		return
	}
	peers := c.peers
	due := make(map[scionColdRetryKey]bool, len(c.scionColdRetry))
	for key, ent := range c.scionColdRetry {
		if !ent.nextAttemptAt.After(now) {
			due[key] = true
		}
	}
	c.mu.Unlock()

	if len(due) == 0 {
		return
	}

	for i := range peers.Len() {
		peer := peers.At(i)
		peerIA, hostAddr, ok := scionServiceFromPeer(peer)
		if !ok {
			continue
		}
		key := scionColdRetryKey{ia: peerIA, hostAddr: hostAddr}
		if !due[key] {
			continue
		}
		c.mu.Lock()
		ep, epOk := c.peerMap.endpointForNodeID(peer.ID())
		c.mu.Unlock()
		if !epOk || ep == nil {
			continue
		}
		// The CAS + 5 s throttle inside discoverSCIONPathAsync coalesces
		// with any other trigger (Hostinfo update, demote, send-time,
		// post-connect) that might race this tick.
		go ep.discoverSCIONPathAsync(peerIA, hostAddr)
	}
}

// scionDiscoveryErrorKind classifies SCION path-discovery failures so
// operators (and the per-peer backoff) can distinguish config problems
// (TRC missing — won't self-heal) from transient infrastructure errors
// (daemon timeout, no segments this moment). Phase 5.
type scionDiscoveryErrorKind int

const (
	scionErrOther             scionDiscoveryErrorKind = iota
	scionErrTRCMissing                                // trust root absent for the peer's ISD
	scionErrNoSegments                                // daemon returned zero paths to the peer (AS may be briefly unreachable)
	scionErrDaemonUnreachable                         // daemon gRPC Unavailable / context deadline
)

// String returns a short stable token suitable for JSON export. Empty
// string for scionErrOther keeps API payloads compact (omitempty-friendly).
func (k scionDiscoveryErrorKind) String() string {
	switch k {
	case scionErrTRCMissing:
		return "trc-missing"
	case scionErrNoSegments:
		return "no-segments"
	case scionErrDaemonUnreachable:
		return "daemon-unreachable"
	default:
		return ""
	}
}

// classifySCIONDiscoveryErr pattern-matches a discovery error into a kind.
// The pattern list is intentionally small: these are the error shapes we've
// seen in practice from the scionproto daemon + embedded connector. Unknown
// errors return scionErrOther — still useful (operator sees the raw
// LastError string), just not typed.
//
// Classification is heuristic. Clients exposing this via an API should
// always surface the raw error string as well and treat the kind only as a
// typed bucket (for conditional UX, metrics, or backoff policy), not as
// authoritative cause.
func classifySCIONDiscoveryErr(err error) scionDiscoveryErrorKind {
	if err == nil {
		return scionErrOther
	}
	msg := err.Error()
	// The embedded connector's trust engine wraps missing TRCs as
	// "TRC not found". Production SCION CS uses gRPC
	// "Unknown desc = reserved number" when the ISD number is not in its
	// cross-signing set — but the same phrase appears in unrelated
	// capnp/cert decoders, so require co-occurrence with ISD/TRC to avoid
	// over-claiming.
	if strings.Contains(msg, "TRC not found") {
		return scionErrTRCMissing
	}
	// Production SCION CS returns a gRPC error
	// `rpc error: code = Unknown desc = reserved number` on ISD-AS lookups
	// where the ISD is outside its cross-signing set. Require the
	// "rpc error:" wrapper to avoid false positives from any non-gRPC
	// caller that happens to render a reserved-number diagnostic.
	if strings.Contains(msg, "reserved number") && strings.Contains(msg, "rpc error:") {
		return scionErrTRCMissing
	}
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Unavailable") {
		return scionErrDaemonUnreachable
	}
	if strings.Contains(msg, "no paths") || strings.Contains(msg, "no SCION paths") {
		return scionErrNoSegments
	}
	return scionErrOther
}

// scionRefreshBackoff tracks per-peer refresh attempt throttling. Exponential
// backoff on consecutive failures, capped at scionRefreshMaxBackoff. Reset on
// success. Pure state — no timers, no goroutines; the refresh loop consults
// shouldAttempt before calling daemon.Paths for each peer.
type scionRefreshBackoff struct {
	consecutiveFailures int
	nextAttemptAt       time.Time
	lastError           string
	lastErrorAt         time.Time
	lastErrorKind       scionDiscoveryErrorKind
}

// shouldAttempt reports whether enough time has elapsed since the last
// scheduled attempt that we should try again. A zero nextAttemptAt (fresh
// struct) always returns true.
func (b *scionRefreshBackoff) shouldAttempt(now time.Time) bool {
	return b.nextAttemptAt.IsZero() || !now.Before(b.nextAttemptAt)
}

// recordSuccess resets the failure counter and clears any prior backoff
// schedule, so the next refresh tick can proceed immediately. The outer
// refresh goroutine's ticker (scionRefreshBaseInterval) is the authority
// on cadence in the success path; shouldAttempt only gates failures.
//
// The base argument is accepted for symmetry with recordFailure but is
// currently unused; retained for a potential future "healthy peers refresh
// slower" policy without a caller API change.
func (b *scionRefreshBackoff) recordSuccess(now time.Time, base time.Duration) {
	_ = base
	b.consecutiveFailures = 0
	b.lastError = ""
	b.lastErrorAt = time.Time{}
	b.lastErrorKind = scionErrOther
	b.nextAttemptAt = time.Time{}
}

// recordFailure increments the failure counter, stores the error, and
// schedules the next attempt with exponential backoff (base · 2^min(N,5))
// capped at maxBackoff. Also classifies the error into a lastErrorKind so
// operators can see at a glance whether a peer is unreachable due to a
// config issue (trc-missing) vs a transient infrastructure blip.
func (b *scionRefreshBackoff) recordFailure(now time.Time, err error, base, maxBackoff time.Duration) {
	b.consecutiveFailures++
	if err != nil {
		b.lastError = err.Error()
	}
	b.lastErrorKind = classifySCIONDiscoveryErr(err)
	b.lastErrorAt = now
	shift := b.consecutiveFailures
	if shift > 5 {
		shift = 5
	}
	backoff := base * time.Duration(1<<shift)
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	b.nextAttemptAt = now.Add(backoff)
}

// scionEndpointState tracks SCION-specific per-peer state on an endpoint.
type scionEndpointState struct {
	peerIA          addr.IA                               // peer's ISD-AS from Services advertisement
	hostAddr        netip.AddrPort                        // peer's SCION host IP:port
	paths           map[scionPathKey]*scionPathProbeState // probed paths (up to scionMaxProbePaths)
	activePath      scionPathKey                          // currently selected best path for data
	lastDiscoveryAt time.Time                             // when path discovery last started (throttle)
	lastFullEvalAt  mono.Time                             // throttles re-evaluation of SCION path latencies
	probeRoundRobin int                                   // round-robin index for non-best path probing

	// lastDiscoveryError is the most recent discovery error string for this
	// peer (e.g. "TRC not found"). Cleared on a successful discovery.
	// Surfaced via PeerStatus.SCION.LastDiscoveryError so operators can see
	// why a SCION-advertising peer has no probed paths without reading logs.
	lastDiscoveryError     string
	lastDiscoveryErrorAt   time.Time
	lastDiscoveryErrorKind scionDiscoveryErrorKind
}

// scionPathProbeState tracks disco probing state for one SCION path.
type scionPathProbeState struct {
	fingerprint snet.PathFingerprint
	// ifCount is the number of SCION interfaces (path hops × 2) captured
	// when this probe state was created. Used together with fingerprint as
	// a collision-hardening check: fingerprint alone is a truncated hash
	// and two topologically distinct paths could in theory share the same
	// value. Preserving probe history across a refresh requires BOTH to
	// match, so latency/health data from an unrelated path cannot leak in.
	ifCount         int
	displayStr      string        // cached from scionPathInfo.displayStr for lock-safe logging
	wireMTU         tstun.WireMTU // path-specific wireMTU (pathMTU - SCION headers), or scionWireMTU if unknown
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

// latency returns the median pong latency from available measurements,
// or time.Hour if no pongs received. The median is robust to single-sample
// outliers and provides stable path comparison for anti-flap logic.
func (ps *scionPathProbeState) latency() time.Duration {
	if ps.pongCount == 0 {
		return time.Hour
	}
	n := int(ps.pongCount)
	if n == 1 {
		return ps.recentPongs[ps.recentPong].latency
	}
	samples := make([]time.Duration, n)
	for i := range n {
		idx := (int(ps.recentPong) - i + scionPongHistoryCount) % scionPongHistoryCount
		samples[i] = ps.recentPongs[idx].latency
	}
	slices.Sort(samples)
	return samples[n/2]
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
	gen        uint64       // scionPathInfo.generation at build time (for staleness check)
}

// scionMaxBatchSize is the max number of packets in a single sendmmsg/recvmmsg
// call. Matches conn.IdealBatchSize (128) to avoid silently truncating batches
// from WireGuard on Linux.
const scionMaxBatchSize = 128

// scionExpiryGuard is the safety margin applied when checking path expiry
// at send time: a path is considered expired if it would expire within this
// window. Absorbs the small gap between the check and the underlying
// send syscall, preventing packets being handed to a path that expires
// mid-flight. 500ms is comfortably larger than worst-case batch-build +
// sendmmsg latency and negligible relative to typical SCION path lifetimes
// (minutes to hours).
const scionExpiryGuard = 500 * time.Millisecond

// scionSendBatch is a reusable set of buffers for sendSCIONBatchFast.
type scionSendBatch struct {
	bufs [][]byte
	msgs []ipv4.Message
}

// scionSendBatchInitBufSize is the initial capacity of each per-packet send
// buffer. Sized so typical SCION+UDP+WireGuard packets (up to ~60 bytes
// SCION header + 8 UDP + ~1472 SCION payload MTU on common testbeds) fit
// without the hot-path grow branch in sendSCIONBatchFast firing on a fresh
// batch. Larger-MTU paths still grow lazily; the grown buffer sticks with
// the batch via sync.Pool reuse, so subsequent batches skip the realloc.
const scionSendBatchInitBufSize = 2048

var scionSendBatchPool = sync.Pool{
	New: func() any {
		b := &scionSendBatch{
			bufs: make([][]byte, scionMaxBatchSize),
			msgs: make([]ipv4.Message, scionMaxBatchSize),
		}
		for i := range b.bufs {
			b.bufs[i] = make([]byte, scionSendBatchInitBufSize)
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
			b.bufs[i] = make([]byte, scionSendBatchInitBufSize)
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
		gen:        pi.generation,
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
// reply routing from raw path bytes extracted during receive. nextHop is the
// underlay border router address from the incoming packet (msg.Addr from
// recvmmsg); it is required for the reply to be routable.
func buildSCIONReplyAddr(srcIA addr.IA, srcHostAddr netip.AddrPort, rawPathBytes []byte, nextHop *net.UDPAddr) *snet.UDPAddr {
	if len(rawPathBytes) == 0 {
		// Same-AS: empty path, reply directly to source.
		return &snet.UDPAddr{
			IA: srcIA,
			Host: &net.UDPAddr{
				IP:   srcHostAddr.Addr().AsSlice(),
				Port: int(srcHostAddr.Port()),
			},
			Path:    snetpath.Empty{},
			NextHop: nextHop,
		}
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
		Path:    snetpath.SCION{Raw: revBytes},
		NextHop: nextHop,
	}
}

// scionBatchRW abstracts ipv4.PacketConn and ipv6.PacketConn for
// batch I/O (recvmmsg/sendmmsg). Both have identical ReadBatch/WriteBatch
// signatures since ipv4.Message and ipv6.Message are the same type
// (socket.Message). Only used on Linux; on other platforms underlayXPC
// and shimXPC are nil, and the receive/send loops fall back to
// single-packet snet.Conn.ReadFrom/WriteTo.
type scionBatchRW interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

// scionConn wraps a SCION connection for use by magicsock.
type scionConn struct {
	conn         *snet.Conn       // from SCIONNetwork.Listen()
	underlayConn *net.UDPConn     // raw underlay for fast-path sends (owned by conn)
	underlayXPC  scionBatchRW     // for WriteBatch / sendmmsg (ipv4 or ipv6)
	localIA      addr.IA          // our ISD-AS
	localHostIP  netip.Addr       // local host IP (e.g. 127.0.0.1)
	localPort    uint16           // local SCION/UDP port
	daemon       daemon.Connector // for path queries
	topo         snet.Topology    // local topology
	shimConn     *net.UDPConn     // receive-only socket on port 30041; nil if unavailable
	shimXPC      scionBatchRW     // batch reader for shim socket
	closeOnce    sync.Once        // ensures close/closeSocket are safe against concurrent calls
}

// close shuts down the SCION connection and daemon connector.
// Safe to call concurrently from multiple goroutines.
func (sc *scionConn) close() error {
	sc.closeOnce.Do(func() {
		if sc.shimConn != nil {
			sc.shimConn.Close()
		}
		if sc.conn != nil {
			sc.conn.Close()
		}
		if sc.daemon != nil {
			sc.daemon.Close()
		}
	})
	return nil
}

// closeSocket closes only the SCION socket (conn, underlayConn, underlayXPC)
// and the dispatcher shim, preserving the daemon connector and topology for
// socket-only reconnection. Uses closeOnce to prevent concurrent close races.
func (sc *scionConn) closeSocket() {
	sc.closeOnce.Do(func() {
		if sc.shimConn != nil {
			sc.shimConn.Close()
		}
		sc.shimConn = nil
		sc.shimXPC = nil
		if sc.conn != nil {
			sc.conn.Close()
		}
		sc.conn = nil
		sc.underlayConn = nil
		sc.underlayXPC = nil
	})
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

// scionListenPort returns the SCION port to use, checking the TS_SCION_PORT
// environment variable first, then falling back to 0 (auto-select from the
// topology's dispatched port range).
func scionListenPort() uint16 {
	if p := scionPort(); p != "" {
		var v int
		if _, err := fmt.Sscanf(p, "%d", &v); err == nil && v > 0 && v <= 65535 {
			return uint16(v)
		}
	}
	return 0 // let snet auto-select from topology port range
}

// extractSCIONUnderlayUDPConn returns the *net.UDPConn underlying an
// snet.SCIONPacketConn, or nil if it could not be accessed. scionproto v0.15
// made the field unexported; we read it reflectively because the fast-path
// sendmmsg/recvmmsg helpers and the netns control hook both need the raw
// *net.UDPConn. If scionproto later reshapes the struct this returns nil, the
// fast path is skipped, and magicsock falls back to pc.WriteTo / pc.ReadFrom.
func extractSCIONUnderlayUDPConn(pc *snet.SCIONPacketConn) *net.UDPConn {
	v := reflect.ValueOf(pc).Elem().FieldByName("conn")
	if !v.IsValid() {
		return nil
	}
	iface := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface()
	udp, _ := iface.(*net.UDPConn)
	return udp
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
func scionResolveLocalIP(ctx context.Context, connector daemon.Connector, logf logger.Logf) netip.Addr {
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
		logf("magicsock: SCION: multiple BRs resolve to different local IPs; using %s, set TS_SCION_LISTEN_ADDR to override", first)
	}
	return first
}

// scionListenAddr returns the listen address for the SCION underlay socket.
// TS_SCION_LISTEN_ADDR can override the IP (e.g. "::1" for IPv6 localhost).
// Otherwise resolves the local IP from the topology's BR internal addresses.
func scionListenAddr(ctx context.Context, connector daemon.Connector, logf logger.Logf) *net.UDPAddr {
	port := scionListenPort()
	if a := scionListenAddrEnv(); a != "" {
		ip := net.ParseIP(a)
		if ip != nil {
			return &net.UDPAddr{IP: ip, Port: int(port)}
		}
	}
	ip := scionResolveLocalIP(ctx, connector, logf)
	return &net.UDPAddr{IP: ip.AsSlice(), Port: int(port)}
}

// trySCIONConnect attempts to set up a SCION connection via the embedded
// connector. It first tries a local topology file (TS_SCION_TOPOLOGY or
// /etc/scion/topology.json); if that fails or is absent, it walks the
// configured bootstrap URLs (explicit env → DNS SRV → hardcoded defaults),
// fetches a topology and TRCs, and retries against the bootstrapped topology.
//
// Returns an error that names the remedies (TS_SCION_TOPOLOGY,
// TS_SCION_BOOTSTRAP_URL) when no path to a usable topology succeeds.
func trySCIONConnect(ctx context.Context, logf logger.Logf, netMon *netmon.Monitor) (*scionConn, error) {
	// Step 1: Try embedded with existing local topology file.
	topoPath := scionTopologyPath()
	if _, statErr := os.Stat(topoPath); statErr == nil {
		sc, err := tryEmbeddedDaemon(ctx, topoPath, logf, netMon)
		if err == nil {
			return sc, nil
		}
		logf("scion: embedded from %s failed: %v", topoPath, err)
	}

	// Step 2: Bootstrap from URLs (explicit env, DNS-discovered, hardcoded defaults).
	stateDir := scionStateDir()
	if stateDir == "" {
		return nil, fmt.Errorf("SCION not available: no topology file at %s and no state directory (set TS_SCION_STATE_DIR) for bootstrap", topoPath)
	}
	urls := bootstrapURLs(ctx, logf)
	if len(urls) == 0 {
		return nil, fmt.Errorf("SCION not available: no topology file at %s and no bootstrap URL (set TS_SCION_TOPOLOGY or TS_SCION_BOOTSTRAP_URL)", topoPath)
	}
	for _, url := range urls {
		if err := bootstrapSCION(ctx, logf, url, stateDir); err != nil {
			logf("scion: bootstrap from %s failed: %v", url, err)
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
		logf("scion: embedded from bootstrapped %s failed: %v", bootstrappedTopo, err)
	}

	return nil, fmt.Errorf("SCION not available: no topology file at %s and no bootstrap server succeeded (set TS_SCION_TOPOLOGY or TS_SCION_BOOTSTRAP_URL)", topoPath)
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

	listenAddr := scionListenAddr(ctx, connector, logf)
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
		underlayConn = extractSCIONUnderlayUDPConn(pc)
		if underlayConn != nil {
			logf("magicsock: SCION: extracted underlay conn, local=%v", underlayConn.LocalAddr())
		} else {
			logf("magicsock: SCION: WARNING: could not extract underlay *net.UDPConn from SCIONPacketConn; fast-path disabled")
		}
		if err := pc.SetReadBuffer(socketBufferSize); err != nil {
			logf("magicsock: SCION: failed to set read buffer to %d: %v", socketBufferSize, err)
		}
		if err := pc.SetWriteBuffer(socketBufferSize); err != nil {
			logf("magicsock: SCION: failed to set write buffer to %d: %v", socketBufferSize, err)
		}
	} else {
		logf("magicsock: SCION: WARNING: pconn is %T, not *snet.SCIONPacketConn; cannot extract underlay", pconn)
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
				logf("magicsock: SCION: calling netns control (VpnService.protect) on underlay fd")
				if err := lc.Control("udp", underlayConn.LocalAddr().String(), rawConn); err != nil {
					logf("magicsock: SCION: netns control FAILED: %v", err)
				} else {
					logf("magicsock: SCION: netns control succeeded on underlay socket")
				}
			} else {
				logf("magicsock: SCION: WARNING: netns Listener.Control is nil, socket NOT protected")
			}
		} else {
			logf("magicsock: SCION: SyscallConn: %v", err)
		}
	} else {
		logf("magicsock: SCION: WARNING: no underlay conn, socket NOT protected from VPN")
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

	// Wrap underlay conn for recvmmsg/sendmmsg batching (Linux only).
	// On non-Linux platforms, batch I/O is not available and the receive/send
	// loops fall back to single-packet snet.Conn.ReadFrom/WriteTo.
	var underlayXPC scionBatchRW
	if underlayConn != nil && runtime.GOOS == "linux" {
		local, ok := underlayConn.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("unexpected underlay local address type %T", underlayConn.LocalAddr())
		}
		if local.IP.To4() != nil {
			underlayXPC = ipv4.NewPacketConn(underlayConn)
		} else {
			underlayXPC = ipv6.NewPacketConn(underlayConn)
		}
	}

	sc := &scionConn{
		conn:         sconn,
		underlayConn: underlayConn,
		underlayXPC:  underlayXPC,
		localIA:      localIA,
		localHostIP:  localHostIP,
		localPort:    localPort,
		daemon:       connector,
		topo:         topo,
	}
	openDispatcherShim(sc, logf, netMon)
	return sc, nil
}

// openDispatcherShim tries to bind a receive-only UDP socket on the legacy
// dispatcher port (30041). In older SCION deployments, border routers send all
// packets to this port instead of directly to the application's endhost port.
// If binding succeeds (no dispatcher running), the shim socket receives packets
// identically to the main socket. If binding fails (EADDRINUSE), we log and
// continue — the real dispatcher handles forwarding.
func openDispatcherShim(sc *scionConn, logf logger.Logf, netMon *netmon.Monitor) {
	if noDispatcherShim() {
		logf("magicsock: SCION dispatcher shim disabled via TS_SCION_NO_DISPATCHER_SHIM")
		return
	}
	if sc.localPort == scionDispatcherPort {
		logf("magicsock: SCION main socket already on dispatcher port %d, skipping shim", scionDispatcherPort)
		return
	}

	// The shim binds to the same local IP as the SCION main socket (see
	// sc.localHostIP), not a wildcard. This is deliberate: if the operator
	// has chosen a specific local IP via TS_SCION_LISTEN_ADDR, the shim
	// must listen only on that address. If localHostIP is a wildcard
	// (0.0.0.0 or ::), the shim inherits the same exposure as the main
	// socket — operators who want the dispatcher to be localhost-only
	// should either (a) set TS_SCION_LISTEN_ADDR=127.0.0.1, or
	// (b) disable the shim entirely with TS_SCION_NO_DISPATCHER_SHIM=1.
	shimAddr := &net.UDPAddr{
		IP:   sc.localHostIP.AsSlice(),
		Port: scionDispatcherPort,
	}
	shimConn, err := net.ListenUDP("udp", shimAddr)
	if err != nil {
		logf("magicsock: SCION dispatcher shim on :%d: %v (continuing without shim)", scionDispatcherPort, err)
		return
	}

	if err := shimConn.SetReadBuffer(socketBufferSize); err != nil {
		logf("magicsock: SCION shim: failed to set read buffer to %d: %v", socketBufferSize, err)
	}

	// Apply platform-specific socket options (SO_MARK, VPN isolation)
	// to prevent the shim socket from routing through the VPN tunnel.
	if netMon != nil {
		rawConn, err := shimConn.SyscallConn()
		if err == nil {
			lc := netns.Listener(logf, netMon)
			if lc.Control != nil {
				if err := lc.Control("udp", shimConn.LocalAddr().String(), rawConn); err != nil {
					logf("magicsock: SCION shim: netns control: %v", err)
				}
			}
		} else {
			logf("magicsock: SCION shim: SyscallConn: %v", err)
		}
	}

	// Wrap for batch I/O (Linux only). On non-Linux, shimXPC stays nil
	// and receiveSCIONShim polls infrequently without reading.
	var xpc scionBatchRW
	if runtime.GOOS == "linux" {
		local, ok := shimConn.LocalAddr().(*net.UDPAddr)
		if !ok {
			shimConn.Close()
			logf("magicsock: SCION shim: unexpected local address type %T", shimConn.LocalAddr())
			return
		}
		if local.IP.To4() != nil {
			xpc = ipv4.NewPacketConn(shimConn)
		} else {
			xpc = ipv6.NewPacketConn(shimConn)
		}
	}

	sc.shimConn = shimConn
	sc.shimXPC = xpc
	logf("magicsock: SCION dispatcher shim listening on %s", shimConn.LocalAddr())
}

// parseSCIONServiceAddr parses a SCION service description string of the form
// "ISD-AS,[host-IP]" and returns the IA and host address. The port comes from
// the Service.Port field. Accepts both bracketed ("[192.0.2.1]", "[2001:db8::1]")
// and unbracketed ("192.0.2.1", "2001:db8::1") IP formats for backward compatibility.
func parseSCIONServiceAddr(description string, port uint16) (ia addr.IA, hostAddr netip.AddrPort, err error) {
	parts := strings.SplitN(description, ",", 2)
	if len(parts) != 2 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid SCION service description %q: want ISD-AS,[host-IP]", description)
	}

	ia, err = addr.ParseIA(parts[0])
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("parsing SCION IA %q: %w", parts[0], err)
	}

	// Strip brackets if present (e.g., "[192.0.2.1]" or "[2001:db8::1]").
	ipStr := strings.TrimPrefix(strings.TrimSuffix(parts[1], "]"), "[")
	hostIP, err := netip.ParseAddr(ipStr)
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
	sc := c.pconnSCION.Load()
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
	piGen := pi.generation
	// Apply a small safety margin so we don't hand off a packet on a path
	// that expires mid-flight. The window between this check and the
	// underlying send syscall is small but nonzero (template patching,
	// sendmmsg); on a path expiring inside that window, a border router
	// upstream would reject the packet with no error signal back to us.
	now := time.Now()
	expired := !pi.expiry.IsZero() && now.Add(scionExpiryGuard).After(pi.expiry)
	pi.mu.Unlock()
	if expired {
		// Kick an async rediscovery for this peer so fresh paths arrive
		// before the next scheduled refresh tick (which may be minutes
		// away under backoff). CAS + 5s-throttle inside
		// discoverSCIONPathAsync coalesces bursts from many expired-send
		// callers into at most one discovery round per peer.
		c.kickSCIONPathRediscoveryForKey(addr.scionKey)
		return false, fmt.Errorf("SCION path expired for key %d", addr.scionKey)
	}
	// If the captured fastPath predates the current pi.generation (a path
	// refresh interleaved with our capture), treat it as stale and fall
	// through to the slow path. The next send will see the fresh template.
	if fastPath != nil && fastPath.gen != piGen {
		metricSCIONFastPathStale.Add(1)
		fastPath = nil
	}

	// Fast path: pre-serialized headers + sendmmsg.
	if fastPath != nil && sc.underlayXPC != nil && !scionNoFastPath() {
		err = c.sendSCIONBatchFast(sc, fastPath, buffs, offset)
		if err != nil {
			c.handleSCIONSendError(err)
		}
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
			c.handleSCIONSendError(err)
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
	// Validate fastPath geometry up front. A stale or corrupted template
	// (e.g. captured before a path refresh that changed the hop count)
	// could otherwise cause buf[fp.udpOffset+…] to panic or corrupt
	// adjacent memory at send time. Fail the whole batch so the caller
	// can discard the template and rebuild it.
	const scionUDPHdrLen = 8
	if hdrLen < scionUDPHdrLen || fp.udpOffset < 0 || fp.udpOffset+scionUDPHdrLen > hdrLen {
		metricSCIONFastPathGeometryErr.Add(1)
		return fmt.Errorf("invalid SCION fastPath geometry: udpOffset=%d hdrLen=%d", fp.udpOffset, hdrLen)
	}

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
	for retries := 0; ; retries++ {
		written, err := sc.underlayXPC.WriteBatch(msgs[head:], 0)
		if err != nil {
			return err
		}
		head += written
		if head >= n {
			return nil
		}
		if written == 0 {
			if retries >= 3 {
				return fmt.Errorf("sendmmsg made no progress after %d retries (%d/%d sent)", retries, head, n)
			}
			// Brief backoff instead of tight-spin on transient socket
			// buffer pressure / EAGAIN. Scales from 10µs to 40µs across
			// the three allowed retries.
			time.Sleep(time.Duration(10<<retries) * time.Microsecond)
		}
	}
}

// sendSCION sends a single packet over SCION, used for disco messages.
func (c *Conn) sendSCION(sk scionPathKey, b []byte) (bool, error) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return false, errNoSCION
	}
	pi := c.lookupSCIONPathLocking(sk)
	if pi == nil {
		return false, fmt.Errorf("no SCION path info for key %d", sk)
	}
	pi.mu.Lock()
	expired := !pi.expiry.IsZero() && time.Now().Add(scionExpiryGuard).After(pi.expiry)
	pi.mu.Unlock()
	if expired {
		c.kickSCIONPathRediscoveryForKey(sk)
		return false, fmt.Errorf("SCION path expired for key %d", sk)
	}
	_, err := sc.writeTo(b, pi)
	if err != nil {
		c.handleSCIONSendError(err)
		return false, err
	}
	return true, nil
}

// handleSCIONSendError triggers SCION reconnection when a send fails with
// a socket error. This is the primary reconnection mechanism — rather than
// polling for liveness on the receive side, we reconnect when sends actually
// fail. The receive loop picks up the new socket automatically because the
// old socket's close unblocks its read with net.ErrClosed.
func (c *Conn) handleSCIONSendError(err error) {
	if err == nil {
		return
	}
	// Don't reconnect for logical errors (nil path, expired path, no SCION).
	if errors.Is(err, errNoSCION) {
		return
	}
	// CAS guard: only one goroutine reconnects at a time. Others skip
	// silently — when the reconnect completes they'll use the new socket.
	if !c.scionReconnecting.CompareAndSwap(false, true) {
		return
	}
	c.logf("magicsock: SCION send failed: %v, triggering reconnect", err)
	go func() {
		defer c.scionReconnecting.Store(false)
		c.reconnectSCION()
	}()
}

// initSCIONConnReady initializes c.scionConnReady. Must be called before any
// use of signalSCIONConnReady or scionConnReadyCh.
func (c *Conn) initSCIONConnReady() {
	ch := make(chan struct{})
	c.scionConnReady.Store(&ch)
}

// scionConnReadyCh returns the current scionConnReady channel. Callers use it
// as `case <-c.scionConnReadyCh():` inside a select — the select evaluates
// the expression once at entry, so each wait cycle sees a stable channel.
// On the next call (after a wake-up) a fresh channel is observed.
func (c *Conn) scionConnReadyCh() <-chan struct{} {
	return *c.scionConnReady.Load()
}

// signalSCIONConnReady closes the current scionConnReady channel to wake up
// receiveSCION and receiveSCIONShim goroutines waiting for a SCION connection,
// and installs a new channel for the next wait cycle.
//
// Concurrent callers are safe: the CAS loop ensures each channel value is
// closed exactly once (the goroutine that successfully swaps in the new
// channel is the one that closes the old one). This prevents the
// close-of-closed-channel panic that a naïve read-store-close would hit
// under concurrent reconnection paths.
func (c *Conn) signalSCIONConnReady() {
	for {
		oldPtr := c.scionConnReady.Load()
		newCh := make(chan struct{})
		if c.scionConnReady.CompareAndSwap(oldPtr, &newCh) {
			close(*oldPtr)
			return
		}
	}
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
//
// If pi.fingerprint is set, the (peerIA, fingerprint) reverse index is
// populated. Callers that upsert paths should check scionPathsByFP first
// and update the existing entry in place rather than calling this function,
// to preserve key stability across refresh. See reconcileSCIONPathsLocked.
func (c *Conn) registerSCIONPath(pi *scionPathInfo) scionPathKey {
	k := scionPathKey(c.scionPathSeq.Add(1))
	if c.scionPaths == nil {
		c.scionPaths = make(map[scionPathKey]*scionPathInfo)
	}
	c.scionPaths[k] = pi
	if pi.fingerprint != "" {
		if c.scionPathsByFP == nil {
			c.scionPathsByFP = make(map[scionPathFPKey]scionPathKey)
		}
		c.scionPathsByFP[scionPathFPKey{ia: pi.peerIA, hostAddr: pi.hostAddr, fp: pi.fingerprint}] = k
	}
	metricSCIONPathsRegistered.Add(1)
	metricSCIONPathsLive.Set(int64(len(c.scionPaths)))
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

// kickSCIONPathRediscoveryForKey schedules an asynchronous SCION path
// rediscovery for the peer owning the given scionPathKey. Called from
// send-time expiry detection so a peer with all-paths-about-to-expire
// doesn't have to wait for the next periodic refresh tick (up to 30 s,
// or longer under backoff) to get fresh paths.
//
// Safe for concurrent use. Takes c.mu briefly to resolve (peerIA, hostAddr,
// endpoint) from the scionPathKey. The actual rediscovery goroutine is
// CAS-guarded and 5s-throttled inside discoverSCIONPathAsync, so bursts
// of expired-send callers for the same peer coalesce into at most one
// discovery round.
func (c *Conn) kickSCIONPathRediscoveryForKey(k scionPathKey) {
	c.mu.Lock()
	pi := c.scionPaths[k]
	if pi == nil {
		c.mu.Unlock()
		return
	}
	peerIA := pi.peerIA
	hostAddr := pi.hostAddr
	scionEp := epAddr{ap: hostAddr, scionKey: k}
	peerInf := c.peerMap.byEpAddr[scionEp]
	c.mu.Unlock()
	if peerInf == nil || peerInf.ep == nil {
		return
	}
	go peerInf.ep.discoverSCIONPathAsync(peerIA, hostAddr)
}

// upsertSCIONPathLocked either updates an existing scionPathInfo for
// (peerIA, fp) in place or registers a new one. Returns the scionPathKey,
// whether the entry was freshly registered (vs updated in place), and whether
// a fingerprint collision was detected (two topologically distinct paths
// colliding on the same truncated fingerprint hash).
//
// If fp is set and already in the reverse index for peerIA, the existing
// entry is updated in place: same scionPathKey, pi.generation bumped,
// fastPath template rebuilt. This is the key-stability guarantee for the
// common "re-signed segment, same topology" refresh case.
//
// If the existing entry's hop count differs from the new path's hop count,
// it's a collision: metricSCIONFingerprintCollision is incremented, the
// existing entry is left untouched, and the caller should skip this path
// (the returned key is the existing one but registered=false,collision=true).
//
// c.mu must be held. sc must be non-nil.
func (c *Conn) upsertSCIONPathLocked(
	sc *scionConn,
	peerIA addr.IA,
	hostAddr netip.AddrPort,
	path snet.Path,
	fp snet.PathFingerprint,
) (k scionPathKey, registered, collision bool) {
	if fp != "" {
		fpk := scionPathFPKey{ia: peerIA, hostAddr: hostAddr, fp: fp}
		if existing, ok := c.scionPathsByFP[fpk]; ok {
			pi := c.scionPaths[existing]
			if pi == nil {
				// Stale reverse-index entry (should not happen; indicates a
				// bug where scionPaths was mutated without updating the
				// index). Clean up and fall through to fresh registration.
				delete(c.scionPathsByFP, fpk)
			} else {
				newHops := 0
				if md := path.Metadata(); md != nil {
					newHops = len(md.Interfaces)
				}
				pi.mu.Lock()
				oldHops := 0
				if pi.path != nil {
					if md := pi.path.Metadata(); md != nil {
						oldHops = len(md.Interfaces)
					}
				}
				if oldHops != newHops {
					// Hop-count differs despite fingerprint match → treat as
					// a hash collision. Leave the existing entry untouched;
					// the caller should skip this path rather than stomping
					// over probed latency history.
					pi.mu.Unlock()
					metricSCIONFingerprintCollision.Add(1)
					return existing, false, true
				}
				var expiry time.Time
				var mtu uint16
				if md := path.Metadata(); md != nil {
					expiry = md.Expiry
					mtu = md.MTU
				}
				pi.refreshMissCount = 0
				pi.path = path
				pi.expiry = expiry
				pi.mtu = mtu
				pi.buildCachedDst() // bumps pi.generation
				pi.buildDisplayStr()
				pi.fastPath = buildSCIONFastPath(sc, pi)
				pi.mu.Unlock()
				return existing, false, false
			}
		}
	}
	// Not in registry (or empty fingerprint): register fresh.
	var expiry time.Time
	var mtu uint16
	if md := path.Metadata(); md != nil {
		expiry = md.Expiry
		mtu = md.MTU
	}
	pi := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    hostAddr,
		fingerprint: fp,
		path:        path,
		expiry:      expiry,
		mtu:         mtu,
	}
	pi.buildCachedDst()
	pi.buildDisplayStr()
	pi.fastPath = buildSCIONFastPath(sc, pi)
	k = c.registerSCIONPath(pi)
	return k, true, false
}

// unregisterSCIONPath removes a SCION path entry and its peerMap entry.
// c.mu must be held.
//
// Race model: all three maps (scionPaths, scionPathsByAddr,
// peerMap.byEpAddr) are protected by c.mu. A concurrent sender or receiver
// holding c.mu sees either the pre- or post-delete state atomically, not
// a torn view. If a receive loop observes the post-delete state for an
// epAddr that just got unregistered, it falls through to the
// rate-limited lazyEndpoint path (allowSCIONLazyEndpoint), so a burst of
// in-flight packets cannot spawn unbounded lazy endpoints. This is the
// current "mark-stale" equivalent: delete is atomic under c.mu, and the
// downstream behaviour is bounded by the P0-3 rate limiter rather than a
// separate stale-GC epoch.
func (c *Conn) unregisterSCIONPath(k scionPathKey) {
	pi, ok := c.scionPaths[k]
	if !ok {
		return
	}
	// Only remove reverse index if it points to this key.
	ak := scionAddrKey{ia: pi.peerIA, addr: pi.hostAddr}
	if c.scionPathsByAddr[ak] == k {
		delete(c.scionPathsByAddr, ak)
	}
	if pi.fingerprint != "" {
		fpk := scionPathFPKey{ia: pi.peerIA, hostAddr: pi.hostAddr, fp: pi.fingerprint}
		if c.scionPathsByFP[fpk] == k {
			delete(c.scionPathsByFP, fpk)
		}
	}
	// Remove stale peerMap entry for this scionKey.
	scionEp := epAddr{ap: pi.hostAddr, scionKey: k}
	if peerInf := c.peerMap.byEpAddr[scionEp]; peerInf != nil {
		delete(peerInf.epAddrs, scionEp)
		delete(c.peerMap.byEpAddr, scionEp)
	}
	delete(c.scionPaths, k)
	metricSCIONPathsUnregistered.Add(1)
	metricSCIONPathsLive.Set(int64(len(c.scionPaths)))
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

// scionPathString returns the human-readable display string for a SCION path
// key. Returns "scion:<key>" as fallback if the key is not found in the
// registry. Acquires c.mu.
func (c *Conn) scionPathString(key scionPathKey) string {
	if !key.IsSet() {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if pi, ok := c.scionPaths[key]; ok {
		return pi.String()
	}
	return fmt.Sprintf("scion:%d", key)
}

// receiveSCION is the conn.ReceiveFunc for SCION packets. It reads from the
// SCION connection and dispatches disco or WireGuard packets.
//
// Unlike receiveIP, this function handles read errors internally and never
// propagates them to WireGuard. This is critical because WireGuard's
// RoutineReceiveIncoming exits the goroutine permanently after 10 consecutive
// temporary errors, and we need to survive SCION socket death + reconnection.
//
// The read blocks indefinitely (like IPv4/IPv6 sockets). On shutdown,
// closeSCIONBindLocked sets an immediate deadline to unblock the read.
// On socket swap (reconnection from the send path), the old socket is
// closed which unblocks the read with net.ErrClosed; the loop then
// re-reads c.pconnSCION to pick up the new socket.
//
// When the underlay socket is available, packets are read in batches via
// recvmmsg and parsed with lightweight slayers.SCION decoding. Otherwise,
// falls back to single-packet snet.Conn.ReadFrom.
func (c *Conn) receiveSCION(buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		// SCION not connected yet. Wait for scionConnReady signal
		// or timeout, so mid-session connects get instant wake-up.
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		case <-c.scionConnReadyCh():
		case <-time.After(5 * time.Second):
		}
		sc = c.pconnSCION.Load()
		if sc == nil {
			return 0, nil // return zero to let WireGuard call us again
		}
	}

	// Single-entry endpoint cache shared across loop iterations: repeated
	// packets from the same source in this slow path avoid c.mu.
	var slowCachedAddr epAddr
	var slowCachedEP *endpoint
	var slowCachedGen int64

	for {
		// Check for graceful shutdown.
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		default:
		}

		// Re-read pconnSCION — it may have been swapped by reconnectSCION.
		sc = c.pconnSCION.Load()
		if sc == nil {
			// Socket was closed and reconnection failed. Wait for
			// signal or retry after timeout.
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			case <-c.scionConnReadyCh():
			case <-time.After(5 * time.Second):
			}
			c.retrySCIONConnect()
			continue
		}

		// Fast path: batch read from underlay via recvmmsg.
		// No read deadline — blocks indefinitely like IPv4/IPv6 sockets.
		// On shutdown, closeSCIONBindLocked sets an immediate deadline.
		// On reconnection, the old socket is closed → net.ErrClosed.
		if sc.underlayXPC != nil {
			n, err := c.receiveSCIONBatch(sc.underlayXPC, buffs, sizes, eps)
			if n > 0 {
				return n, nil
			}
			if err != nil {
				select {
				case <-c.donec:
					return 0, net.ErrClosed
				default:
				}
				if errors.Is(err, net.ErrClosed) || isTimeoutError(err) {
					// Socket closed (reconnection or shutdown) or
					// deadline set by closeSCIONBindLocked — re-check.
					continue
				}
				c.scionHotLogf("magicsock: SCION read error: %v", err)
				continue
			}
			// n == 0 and no error means all packets were disco/filtered.
			continue
		}

		// Slow path: single-packet snet.Conn.ReadFrom.
		// No read deadline — blocks indefinitely.
		n, srcAddr, err := sc.readFrom(buffs[0])
		if err != nil {
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			default:
			}
			if errors.Is(err, net.ErrClosed) || isTimeoutError(err) {
				continue
			}
			c.scionHotLogf("magicsock: SCION read error: %v", err)
			continue
		}
		if n == 0 {
			continue
		}

		// Fold into per-call timestamp — slow path returns a single
		// packet per call, so this is already "per-batch". Keep it
		// here so we only store on a successful parse.
		nowRecv := mono.Now()

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
				pi := &scionPathInfo{
					peerIA:    srcAddr.IA,
					hostAddr:  srcHostAddr,
					replyPath: srcAddr,
				}
				pi.buildDisplayStr()
				sk = c.registerSCIONPath(pi)
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
		// Small single-entry cache so repeated packets from the same
		// source in this slow loop skip the c.mu round-trip. Mirrors
		// the cache pattern in receiveSCIONBatch.
		var ep *endpoint
		if slowCachedAddr == srcEpAddr && slowCachedEP != nil && slowCachedGen == slowCachedEP.numStopAndReset() {
			ep = slowCachedEP
		} else {
			c.mu.Lock()
			de, ok := c.peerMap.endpointForEpAddr(srcEpAddr)
			c.mu.Unlock()
			if !ok {
				// Unknown source. Admit to WireGuard for authentication via a
				// lazyEndpoint, but bound the rate so a spoofed flood cannot
				// allocate one lazyEndpoint per packet.
				if !c.allowSCIONLazyEndpoint() {
					return 0, nil
				}
				sizes[0] = n
				eps[0] = &lazyEndpoint{c: c, src: srcEpAddr}
				return 1, nil
			}
			slowCachedAddr = srcEpAddr
			slowCachedEP = de
			slowCachedGen = de.numStopAndReset()
			ep = de
		}

		c.lastSCIONRecv.StoreAtomic(nowRecv)
		ep.lastRecvUDPAny.StoreAtomic(nowRecv)
		ep.noteRecvActivity(srcEpAddr, nowRecv)
		if c.metrics != nil {
			c.metrics.inboundPacketsSCIONTotal.Add(1)
			c.metrics.inboundBytesSCIONTotal.Add(int64(n))
		}
		sizes[0] = n
		eps[0] = ep
		return 1, nil
	}
}

// receiveSCIONShim is the conn.ReceiveFunc for the legacy dispatcher shim
// socket (port 30041). It reads SCION packets identically to the main socket's
// batch path, reusing receiveSCIONBatch for all parsing and disco handling.
//
// Unlike receiveSCION, this function does not trigger reconnections (that is
// the main socket's responsibility) and has no slow-path fallback (the shim
// is always a raw *net.UDPConn).
func (c *Conn) receiveSCIONShim(buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		// SCION not connected yet. Wait for signal or timeout.
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		case <-c.scionConnReadyCh():
		case <-time.After(5 * time.Second):
		}
		sc = c.pconnSCION.Load()
		if sc == nil || sc.shimXPC == nil {
			return 0, nil
		}
	} else if sc.shimXPC == nil {
		// Connected but no dispatcher shim. shimXPC is immutable per
		// scionConn, so wait for a reconnect signal (which creates a
		// new scionConn that might have a shim) or poll infrequently.
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		case <-c.scionConnReadyCh():
		case <-time.After(5 * time.Second):
		}
		sc = c.pconnSCION.Load()
		if sc == nil || sc.shimXPC == nil {
			return 0, nil
		}
	}

	for {
		select {
		case <-c.donec:
			return 0, net.ErrClosed
		default:
		}

		// Re-read pconnSCION — it may have been swapped by reconnectSCION.
		sc = c.pconnSCION.Load()
		if sc == nil {
			// Main socket reconnection in progress. Wait for signal.
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			case <-c.scionConnReadyCh():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if sc.shimXPC == nil {
			// Shim was not created for this connection (immutable per scionConn).
			// Wait for reconnect signal or poll infrequently.
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			case <-c.scionConnReadyCh():
			case <-time.After(5 * time.Second):
			}
			continue
		}

		n, err := c.receiveSCIONBatch(sc.shimXPC, buffs, sizes, eps)
		if n > 0 {
			return n, nil
		}
		if err != nil {
			select {
			case <-c.donec:
				return 0, net.ErrClosed
			default:
			}
			if errors.Is(err, net.ErrClosed) || isTimeoutError(err) {
				continue
			}
			c.scionHotLogf("magicsock: SCION shim read error: %v", err)
			continue
		}
		// n == 0 and no error means all packets were disco/filtered.
		continue
	}
}

// receiveSCIONBatch reads a batch of raw SCION packets from the underlay
// socket via recvmmsg, parses SCION+UDP headers with slayers, and copies
// payloads into WireGuard's buffs. Disco packets are handled inline and
// not reported to the caller.
func (c *Conn) receiveSCIONBatch(xpc scionBatchRW, buffs [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	batch := scionRecvBatchPool.Get().(*scionRecvBatch)
	defer putScionRecvBatch(batch)

	n := len(buffs)
	if n > scionMaxBatchSize {
		n = scionMaxBatchSize
	}

	numMsgs, err := xpc.ReadBatch(batch.msgs[:n], 0)
	if err != nil {
		return 0, err
	}

	reportToCaller := false
	count := 0
	// Per-batch counters — we fold all per-packet atomic stores into a
	// single update at the end of the loop to cut cache-line ping-pong
	// at high packet rates.
	var metricsPkts, metricsBytes int64
	var anyData bool
	var lastAcceptedAt mono.Time

	// Batch-scoped endpoint cache: avoids c.mu acquisition for consecutive
	// packets from the same source (common in high-throughput flows).
	var cachedAddr epAddr
	var cachedEP *endpoint
	var cachedGen int64

	for i := 0; i < numMsgs; i++ {
		msg := &batch.msgs[i]
		if msg.N == 0 {
			sizes[count] = 0
			continue
		}

		// Reset the decoder before each Decode so transient path slices
		// from the previous packet don't linger between calls.
		batch.scn.RecyclePaths()
		srcIA, srcHostAddr, payload, rawPath, ok := parseSCIONPacket(
			msg.Buffers[0][:msg.N], &batch.scn)
		if !ok {
			metricSCIONParseError.Add(1)
			continue
		}
		if len(payload) == 0 {
			continue
		}

		// Copy payload into WireGuard's buffer.
		pn := copy(buffs[count], payload)

		pt, _ := packetLooksLike(buffs[count][:pn])
		if pt == packetLooksLikeDisco {
			// Extract underlay source address (border router) for reply NextHop.
			var nextHop *net.UDPAddr
			if ua, ok := msg.Addr.(*net.UDPAddr); ok {
				nextHop = ua
			}
			c.handleSCIONDisco(buffs[count][:pn], srcIA, srcHostAddr, rawPath, nextHop)
			continue
		}

		if !c.havePrivateKey.Load() {
			continue
		}

		srcEpAddr := epAddr{ap: srcHostAddr}

		// Check batch-scoped cache before acquiring c.mu.
		var ep *endpoint
		if cachedAddr == srcEpAddr && cachedEP != nil && cachedGen == cachedEP.numStopAndReset() {
			ep = cachedEP
		} else {
			c.mu.Lock()
			de, found := c.peerMap.endpointForEpAddr(srcEpAddr)
			c.mu.Unlock()
			if !found {
				// Unknown source. Admit via lazyEndpoint (so WireGuard can
				// authenticate it) but rate-limit to cap spoof-flood impact.
				if !c.allowSCIONLazyEndpoint() {
					continue
				}
				sizes[count] = pn
				eps[count] = &lazyEndpoint{c: c, src: srcEpAddr}
				count++
				reportToCaller = true
				continue
			}
			cachedAddr = srcEpAddr
			cachedEP = de
			cachedGen = de.numStopAndReset()
			ep = de
		}

		lastAcceptedAt = mono.Now()
		ep.lastRecvUDPAny.StoreAtomic(lastAcceptedAt)
		ep.noteRecvActivity(srcEpAddr, lastAcceptedAt)
		metricsPkts++
		metricsBytes += int64(pn)
		anyData = true
		sizes[count] = pn
		eps[count] = ep
		count++
		reportToCaller = true
	}

	if anyData {
		c.lastSCIONRecv.StoreAtomic(lastAcceptedAt)
		if c.metrics != nil {
			c.metrics.inboundPacketsSCIONTotal.Add(metricsPkts)
			c.metrics.inboundBytesSCIONTotal.Add(metricsBytes)
		}
	}

	if reportToCaller {
		return count, nil
	}
	return 0, nil
}

// handleSCIONDisco handles a disco packet received on the batch path.
// It looks up or registers a SCION path entry and dispatches to handleDiscoMessage.
// For first-contact, the raw path bytes are reversed to build a reply path.
// nextHop is the underlay border router address from the incoming packet.
func (c *Conn) handleSCIONDisco(b []byte, srcIA addr.IA, srcHostAddr netip.AddrPort, rawPath []byte, nextHop *net.UDPAddr) {
	srcEpAddr := epAddr{ap: srcHostAddr}
	c.mu.Lock()
	sk := c.scionPathsByAddr[scionAddrKey{ia: srcIA, addr: srcHostAddr}]
	if !sk.IsSet() {
		// First disco packet from this SCION peer — build a reply path
		// by reversing the raw SCION path from the incoming packet.
		replyAddr := buildSCIONReplyAddr(srcIA, srcHostAddr, rawPath, nextHop)
		if replyAddr == nil {
			c.logf("magicsock: SCION: failed to build reply path for %s %s (raw path len=%d), disco reply will fail", srcIA, srcHostAddr, len(rawPath))
		}
		pi := &scionPathInfo{
			peerIA:    srcIA,
			hostAddr:  srcHostAddr,
			replyPath: replyAddr,
		}
		pi.buildDisplayStr()
		sk = c.registerSCIONPath(pi)
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

// scionDaemonAlive probes the SCION daemon connector to check if it's
// still responsive. For the embedded connector this is trivial (field read);
// for external daemons it's a gRPC call confirming the process is alive.
func (c *Conn) scionDaemonAlive() bool {
	sc := c.pconnSCION.Load()
	if sc == nil || sc.daemon == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(c.connCtx, scionDaemonProbeTimeout)
	defer cancel()
	_, err := sc.daemon.LocalIA(ctx)
	return err == nil
}

// reconnectSCIONSocket attempts a socket-only reconnection: close the
// socket but keep the daemon connector and topology, then call
// finishSCIONConnect to create a new socket with the existing connector.
// Returns true on success.
func (c *Conn) reconnectSCIONSocket() bool {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return false
	}

	savedDaemon := sc.daemon
	savedTopo := sc.topo

	// Close socket, release the port for rebinding.
	sc.closeSocket()
	c.pconnSCION.Store(nil)

	newSC, err := finishSCIONConnect(c.connCtx, savedDaemon, savedTopo, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION socket-only reconnect failed: %v", err)
		return false
	}

	c.pconnSCION.Store(newSC)
	c.signalSCIONConnReady()
	c.logf("magicsock: SCION socket-only reconnect succeeded, local IA: %s", newSC.localIA)
	return true
}

// reconnectSCION performs tiered SCION reconnection:
//   - Tier 1: If the daemon connector is alive, do a socket-only reconnect
//     (avoids expensive bootstrap: DNS SRV, topology fetch, TRCs, etc.)
//   - Tier 2: Full bootstrap — close everything, trySCIONConnect from scratch
//
// The receiveSCION loop picks up the new socket on the next iteration
// because the old socket's close unblocks the read with net.ErrClosed.
func (c *Conn) reconnectSCION() {
	// Tier 1: socket-only reconnect if daemon is alive.
	if c.scionDaemonAlive() {
		c.logf("magicsock: SCION daemon alive, trying socket-only reconnect")
		if c.reconnectSCIONSocket() {
			c.rediscoverAllSCIONPaths()
			return
		}
		c.logf("magicsock: SCION socket-only reconnect failed, falling through to full bootstrap")
	}

	// Tier 2: full bootstrap.
	c.logf("magicsock: SCION doing full bootstrap reconnect")
	oldSC := c.pconnSCION.Load()

	// Close old connection first — we must release the port before binding
	// the new socket. When TS_SCION_PORT is set, both sockets would try
	// to bind the same port. This means there's a brief window where
	// pconnSCION is nil and sends will fail, but that's acceptable —
	// the endpoint was already dead anyway.
	if oldSC != nil {
		oldSC.close()
	}
	c.pconnSCION.Store(nil)

	newSC, err := trySCIONConnect(c.connCtx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION reconnect failed: %v", err)
		c.recordSCIONConnectError(err)
		return
	}

	c.pconnSCION.Store(newSC)
	c.recordSCIONConnectError(nil)
	c.signalSCIONConnReady()
	metricSCIONReconnect.Add(1)
	c.logf("magicsock: SCION reconnected successfully, local IA: %s", newSC.localIA)
	c.rediscoverAllSCIONPaths()
}

// retrySCIONConnect attempts to re-establish a SCION connection when
// pconnSCION is nil (previous reconnect attempt failed). Uses the
// scionReconnecting CAS guard to prevent concurrent retry attempts.
func (c *Conn) retrySCIONConnect() {
	if c.pconnSCION.Load() != nil {
		return // another goroutine beat us to it
	}
	if !c.scionReconnecting.CompareAndSwap(false, true) {
		return // reconnection already in progress
	}
	defer c.scionReconnecting.Store(false)

	newSC, err := trySCIONConnect(c.connCtx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION reconnect retry failed: %v", err)
		c.recordSCIONConnectError(err)
		return
	}
	c.pconnSCION.Store(newSC)
	c.recordSCIONConnectError(nil)
	c.signalSCIONConnReady()
	c.lastSCIONRecv.StoreAtomic(mono.Now())
	c.logf("magicsock: SCION reconnect retry succeeded, local IA: %s", newSC.localIA)
	c.rediscoverAllSCIONPaths()
	c.discoverNewSCIONPeers()
	c.ReSTUN("scion-connected")
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

// discoverNewSCIONPeers scans all known peers for SCION service advertisements
// and triggers path discovery for any peers that don't yet have scionState.
// Called after a successful SCION connect to handle the case where the netmap
// was processed before SCION was available.
func (c *Conn) discoverNewSCIONPeers() {
	c.mu.Lock()
	peers := c.peers
	c.mu.Unlock()

	for i := range peers.Len() {
		peer := peers.At(i)
		peerIA, hostAddr, ok := scionServiceFromPeer(peer)
		if !ok {
			continue
		}
		c.mu.Lock()
		ep, ok := c.peerMap.endpointForNodeID(peer.ID())
		c.mu.Unlock()
		if !ok || ep == nil {
			continue
		}
		ep.mu.Lock()
		hasScionState := ep.scionState != nil
		ep.mu.Unlock()
		if hasScionState {
			continue // already tracked by rediscoverAllSCIONPaths
		}
		c.logf("magicsock: SCION peer %s at %s, discovering paths (post-connect)...", peerIA, hostAddr)
		go ep.discoverSCIONPathAsync(peerIA, hostAddr)
	}
}

// discoverSCIONPaths queries the SCION daemon for paths to the given peer IA,
// deduplicates by fingerprint, selects the top N by latency, and stores them
// in the path registry. Returns the scionPathKeys for the registered paths
// (first element is the lowest-latency path).
func (c *Conn) discoverSCIONPaths(ctx context.Context, peerIA addr.IA, hostAddr netip.AddrPort) ([]scionPathKey, error) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return nil, errNoSCION
	}

	// Same-AS: no inter-AS path needed, use empty SCION path (direct UDP).
	if peerIA == sc.localIA {
		return c.registerSameASSCIONPath(sc, peerIA, hostAddr)
	}

	paths, err := sc.daemon.Paths(ctx, peerIA, sc.localIA, daemontypes.PathReqFlags{Refresh: false})
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
		var fp snet.PathFingerprint
		if md := p.Metadata(); md != nil {
			fp = md.Fingerprint()
		}
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

	// Upsert under c.mu. upsertSCIONPathLocked reuses existing scionPathKey
	// when (peerIA, fingerprint) is already registered, preserving key
	// identity across rediscovery for paths whose topology hasn't changed.
	// This is the key-stability guarantee that lets endpoint-level
	// scionState.paths[] entries survive a rediscovery when their
	// fingerprint is still present in the daemon response.
	//
	// buildSCIONFastPath (gopacket serialization) runs under c.mu here.
	// discoverSCIONPaths is called on demand (peer joins netmap,
	// all-paths-unhealthy demote, send-time expiry) at human timescales,
	// not on a hot path, so the lock hold time is acceptable.
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]scionPathKey, 0, len(unique))
	for _, u := range unique {
		k, _, collision := c.upsertSCIONPathLocked(sc, peerIA, hostAddr, u.path, u.fingerprint)
		if collision {
			// Existing path with same fingerprint but different hop count
			// was kept; skip this daemon path. Logged/counted inside
			// upsertSCIONPathLocked via metricSCIONFingerprintCollision.
			continue
		}
		keys = append(keys, k)
	}
	// Set the first (lowest-latency) path as active for the reverse index.
	if len(keys) > 0 {
		c.setActiveSCIONPath(peerIA, hostAddr, keys[0])
	}
	return keys, nil
}

// registerSameASSCIONPath creates a synthetic SCION path entry for a peer in
// the same AS. Same-AS communication uses an empty SCION path (PathType=0,
// 0 wire bytes) with direct UDP to the peer — no border routers are involved.
func (c *Conn) registerSameASSCIONPath(sc *scionConn, peerIA addr.IA, hostAddr netip.AddrPort) ([]scionPathKey, error) {
	pi := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    hostAddr,
		fingerprint: scionSameASFingerprint,
		// path is nil: no snet.Path needed for same-AS.
		// expiry is zero: same-AS paths never expire.
	}
	// Build cachedDst with empty SCION path and direct NextHop.
	pi.cachedDst = &snet.UDPAddr{
		IA:   peerIA,
		Host: &net.UDPAddr{IP: hostAddr.Addr().AsSlice(), Port: int(hostAddr.Port())},
		Path: snetpath.Empty{},
		NextHop: &net.UDPAddr{
			IP:   hostAddr.Addr().AsSlice(),
			Port: int(hostAddr.Port()),
		},
	}
	pi.buildDisplayStr()
	pi.fastPath = buildSCIONFastPath(sc, pi)

	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.registerSCIONPath(pi)
	c.setActiveSCIONPath(peerIA, hostAddr, k)
	return []scionPathKey{k}, nil
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
	ticker := time.NewTicker(scionRefreshBaseInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.donec:
			return
		case <-ticker.C:
			// Backoff is now per-peer (scionRefreshByIA, consulted inside
			// refreshSCIONPathsOnce). The outer goroutine ticks at a fixed
			// base interval; a failing peer delays only its own next attempt,
			// not refreshes for other peers. See scionRefreshBackoff.
			if err := c.refreshSCIONPathsOnce(); err != nil {
				// err reports the last per-peer failure observed this tick.
				// Log sparsely: once per tick is fine since per-peer state
				// throttles further attempts.
				c.logf("magicsock: SCION path refresh: %v", err)
			}
		}
	}
}

func (c *Conn) refreshSCIONPathsOnce() error {
	sc := c.pconnSCION.Load()
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
	anySuccess := false
	for _, g := range groups {
		if !g.needRefresh {
			continue
		}
		// Same-AS paths use an empty SCION path and never need daemon refresh.
		if g.peerIA == sc.localIA {
			continue
		}

		// Per-peer backoff gate: skip this peer if the last failure's
		// backoff window has not yet elapsed. Isolates a failing peer's
		// retry cadence from healthy peers on the same refresh tick.
		c.mu.Lock()
		b := c.scionRefreshByIA[g.peerIA]
		skip := b != nil && !b.shouldAttempt(now)
		c.mu.Unlock()
		if skip {
			continue
		}

		daemonPaths, err := sc.daemon.Paths(ctx, g.peerIA, sc.localIA, daemontypes.PathReqFlags{Refresh: true})
		if err != nil || len(daemonPaths) == 0 {
			metricSCIONPathRefreshError.Add(1)
			if err == nil {
				err = fmt.Errorf("no paths to %s", g.peerIA)
			}
			c.logf("magicsock: SCION path refresh for %s failed: %v", g.peerIA, err)
			lastErr = err
			// Record failure in per-peer backoff. Future ticks consult
			// scionRefreshByIA[g.peerIA].shouldAttempt before re-querying,
			// so a bad peer's failures do not delay refresh for good peers.
			c.mu.Lock()
			if c.scionRefreshByIA == nil {
				c.scionRefreshByIA = make(map[addr.IA]*scionRefreshBackoff)
			}
			if c.scionRefreshByIA[g.peerIA] == nil {
				c.scionRefreshByIA[g.peerIA] = &scionRefreshBackoff{}
			}
			c.scionRefreshByIA[g.peerIA].recordFailure(time.Now(), err, scionRefreshBaseInterval, scionRefreshMaxBackoff)
			c.mu.Unlock()
			continue
		}
		// Success: clear any prior backoff state for this peer.
		c.mu.Lock()
		if c.scionRefreshByIA == nil {
			c.scionRefreshByIA = make(map[addr.IA]*scionRefreshBackoff)
		}
		if c.scionRefreshByIA[g.peerIA] == nil {
			c.scionRefreshByIA[g.peerIA] = &scionRefreshBackoff{}
		}
		c.scionRefreshByIA[g.peerIA].recordSuccess(time.Now(), scionRefreshBaseInterval)
		c.mu.Unlock()
		anySuccess = true

		// Index daemon paths by fingerprint for matching.
		type daemonPathEntry struct {
			path snet.Path
			fp   snet.PathFingerprint
		}
		var daemonByFP []daemonPathEntry
		for _, dp := range daemonPaths {
			var fp snet.PathFingerprint
			if md := dp.Metadata(); md != nil {
				fp = md.Fingerprint()
			}
			daemonByFP = append(daemonByFP, daemonPathEntry{
				path: dp,
				fp:   fp,
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

			// Hop-count collision guard: if the fingerprint matches but the
			// hop count differs, treat as a truncated-hash collision rather
			// than a legitimate re-signing. Leave the existing entry
			// untouched so probed latency/health history isn't
			// contaminated by an unrelated topology. Discovery already
			// guards on the probe-state side (endpoint_scion.go); this
			// mirrors it on the Conn-registry side so the two paths are
			// symmetric, per the Phase 1a reconciler design.
			matchedHops := 0
			if md := matched.Metadata(); md != nil {
				matchedHops = len(md.Interfaces)
			}
			pi.mu.Lock()
			existingHops := 0
			if pi.path != nil {
				if md := pi.path.Metadata(); md != nil {
					existingHops = len(md.Interfaces)
				}
			}
			if fp != "" && existingHops != matchedHops {
				pi.mu.Unlock()
				metricSCIONFingerprintCollision.Add(1)
				continue
			}
			pi.refreshMissCount = 0
			pi.path = matched
			if md := matched.Metadata(); md != nil {
				pi.fingerprint = md.Fingerprint()
				pi.expiry = md.Expiry
				pi.mtu = md.MTU
			}
			pi.buildCachedDst()
			pi.buildDisplayStr()
			pi.fastPath = buildSCIONFastPath(sc, pi)
			pi.mu.Unlock()
		}

		// Remove stale paths that have been absent for too many refresh cycles.
		if len(stalePaths) > 0 {
			c.mu.Lock()
			for _, k := range stalePaths {
				pathStr := fmt.Sprintf("scion:%d", k)
				if pi, ok := c.scionPaths[k]; ok {
					pathStr = pi.String()
				}
				c.logf("magicsock: SCION path stale for %s, removing %s", g.peerIA, pathStr)
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
		// Same-AS paths don't change; skip daemon query.
		if g.peerIA == sc.localIA {
			continue
		}
		c.mu.Lock()
		lastSoft := c.scionSoftRefreshAt[g.peerIA]
		// Honor per-peer refresh backoff: if hard-refresh is backing off for
		// this peer (e.g. daemon reports TRC missing), don't hit the daemon
		// every 5 min for the same peer via soft-refresh either.
		b := c.scionRefreshByIA[g.peerIA]
		inBackoff := b != nil && !b.shouldAttempt(now)
		c.mu.Unlock()
		if inBackoff {
			continue
		}
		if !lastSoft.IsZero() && now.Sub(lastSoft) < softRefreshInterval {
			continue
		}

		daemonPaths, err := sc.daemon.Paths(ctx, g.peerIA, sc.localIA, daemontypes.PathReqFlags{Refresh: false})
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
			var fp snet.PathFingerprint
			if md := dp.Metadata(); md != nil {
				fp = md.Fingerprint()
			}
			if fp == "" || knownFPs[fp] {
				continue
			}
			newPaths = append(newPaths, dp)
			if len(newPaths) >= available {
				break
			}
		}

		if len(newPaths) > 0 {
			newKeys := c.addNewSCIONPathsForPeer(g.peerIA, g.hostAddr, newPaths)
			metricSCIONPathSoftRefreshAdded.Add(int64(len(newKeys)))
			for i, k := range newKeys {
				c.logf("magicsock: SCION soft refresh for %s: [%d] %s", g.peerIA, i, c.scionPathString(k))
			}
		}

		c.mu.Lock()
		mak.Set(&c.scionSoftRefreshAt, g.peerIA, now)
		c.mu.Unlock()
	}

	// Opportunistic GC: prune scionSoftRefreshAt and scionRefreshByIA
	// entries whose peerIA no longer has any registered paths. groups was
	// built from the current scionPaths snapshot; anything not present has
	// been fully unregistered (all its paths evicted) and the accompanying
	// metadata entries are dead weight.
	c.mu.Lock()
	for ia := range c.scionSoftRefreshAt {
		if _, live := groups[ia]; !live {
			delete(c.scionSoftRefreshAt, ia)
		}
	}
	for ia := range c.scionRefreshByIA {
		if _, live := groups[ia]; !live {
			delete(c.scionRefreshByIA, ia)
		}
	}
	if anySuccess {
		c.scionRefreshLastSuccess = time.Now()
	}
	c.mu.Unlock()

	if lastErr == nil {
		metricSCIONPathRefresh.Add(1)
	}
	return lastErr
}

// addNewSCIONPathsForPeer registers new SCION paths and adds probe states
// to the corresponding endpoint. Called during soft refresh when new paths
// appear in the daemon's cache. Returns the registered path keys.
func (c *Conn) addNewSCIONPathsForPeer(peerIA addr.IA, hostAddr netip.AddrPort, paths []snet.Path) []scionPathKey {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return nil
	}

	c.mu.Lock()
	var newKeys []scionPathKey
	for _, p := range paths {
		var fp snet.PathFingerprint
		if md := p.Metadata(); md != nil {
			fp = md.Fingerprint()
		}
		// Route through upsertSCIONPathLocked so that if the same
		// fingerprint is already registered for this peer (e.g. a
		// concurrent discovery registered it), we update the existing
		// entry in place instead of orphaning it. upsert preserves the
		// scionPathsByFP reverse-index invariant; a direct
		// registerSCIONPath here would leave the old entry indexed but
		// no longer reachable as (peerIA, fp) since the index would now
		// point at the new key.
		k, _, collision := c.upsertSCIONPathLocked(sc, peerIA, hostAddr, p, fp)
		if collision {
			continue
		}
		newKeys = append(newKeys, k)
	}

	// Find the endpoint for this peerIA and add probe states.
	for _, peerInf := range c.peerMap.byNodeKey {
		ep := peerInf.ep
		ep.mu.Lock()
		if ep.scionState != nil && ep.scionState.peerIA == peerIA {
			for _, k := range newKeys {
				if _, exists := ep.scionState.paths[k]; !exists {
					pi := c.scionPaths[k]
					ep.scionState.paths[k] = &scionPathProbeState{
						fingerprint: pi.fingerprint,
						displayStr:  pi.displayStr,
						healthy:     true,
					}
				}
			}
		}
		ep.mu.Unlock()
	}

	// Recovery: if no endpoint had scionState for this peerIA, the initial
	// discoverSCIONPathAsync may have failed. Find the endpoint via peerMap
	// (the plain hostAddr was registered by handlePingLocked from incoming
	// SCION disco) and initialize scionState so disco probing can begin.
	if len(newKeys) > 0 {
		if ep, ok := c.peerMap.endpointForEpAddr(epAddr{ap: hostAddr}); ok {
			ep.mu.Lock()
			if ep.scionState == nil {
				paths := make(map[scionPathKey]*scionPathProbeState, len(newKeys))
				var activePath scionPathKey
				for i, k := range newKeys {
					pi := c.scionPaths[k]
					paths[k] = &scionPathProbeState{
						fingerprint: pi.fingerprint,
						displayStr:  pi.displayStr,
						healthy:     true,
					}
					if i == 0 {
						activePath = k
					}
				}
				ep.scionState = &scionEndpointState{
					peerIA:          peerIA,
					hostAddr:        hostAddr,
					paths:           paths,
					activePath:      activePath,
					lastDiscoveryAt: time.Now(),
				}
				c.setActiveSCIONPath(peerIA, hostAddr, activePath)
				c.logf("magicsock: SCION recovery: initialized scionState for %s with %d paths", peerIA, len(newKeys))
			}
			ep.mu.Unlock()
		}
	}

	c.mu.Unlock()
	return newKeys
}

// cleanStaleSCIONPathFromEndpoints removes stale SCION path keys from all
// endpoints that reference the given peerIA. If the removed key was the
// activePath, reassigns to the first remaining path.
func (c *Conn) cleanStaleSCIONPathFromEndpoints(staleKeys []scionPathKey, peerIA addr.IA) {
	staleSet := make(map[scionPathKey]bool, len(staleKeys))
	for _, k := range staleKeys {
		staleSet[k] = true
	}

	// Phase 2b: endpoints whose probe set becomes empty after pruning need
	// a rediscovery kick. Without this, a peer whose paths silently age out
	// (refresh misses during a network blip, same-fingerprint never re-
	// admitted) stays permanently on UDP because no other code path fires:
	// Hostinfo didn't change, demote has no active path to time out, and
	// the refresh loop only touches existing registry entries. Collect the
	// (ep, peerIA, hostAddr) triples here; spawn goroutines after both
	// locks are released so discoverSCIONPathAsync can freely re-acquire
	// de.mu (which it does in its CAS-guarded prelude).
	type rediscoverKick struct {
		ep       *endpoint
		peerIA   addr.IA
		hostAddr netip.AddrPort
	}
	var kicks []rediscoverKick

	c.mu.Lock()
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
		// If pruning just cleared the peer's last SCION path, schedule a
		// rediscovery. Capture peerIA + hostAddr by value; the goroutine
		// runs after we release the locks.
		if len(ep.scionState.paths) == 0 {
			kicks = append(kicks, rediscoverKick{
				ep:       ep,
				peerIA:   ep.scionState.peerIA,
				hostAddr: ep.scionState.hostAddr,
			})
		}
		ep.mu.Unlock()
	}
	c.mu.Unlock()

	for _, k := range kicks {
		go k.ep.discoverSCIONPathAsync(k.peerIA, k.hostAddr)
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
		// Format: "scion=ISD-AS,[host-IP]:port"
		if svc.Proto == tailcfg.PeerAPI4 && strings.HasPrefix(svc.Description, "scion=") {
			scionDesc := svc.Description[len("scion="):]
			var addrPart, portStr string
			// Try bracket notation first: "ISD-AS,[hostIP]:port"
			if portSep := strings.LastIndex(scionDesc, "]:"); portSep >= 0 {
				addrPart = scionDesc[:portSep+1]
				portStr = scionDesc[portSep+2:]
			} else {
				// Backward compat: unbracketed "ISD-AS,hostIP:port"
				lastColon := strings.LastIndex(scionDesc, ":")
				if lastColon < 0 {
					continue
				}
				addrPart = scionDesc[:lastColon]
				portStr = scionDesc[lastColon+1:]
			}
			var port uint16
			if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
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
	sc := c.pconnSCION.Load()
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
		Description: fmt.Sprintf("%s,[%s]", sc.localIA, hostIP),
	}, true
}

// discoverSCIONPathAsync runs SCION path discovery in a goroutine,
// avoiding blocking updateFromNode which holds the endpoint lock.
// Uses an atomic CAS guard to prevent concurrent launches (from
// updateFromNode and send error paths) from creating orphaned path
// entries, plus a 5-second timestamp throttle to avoid excessive
// daemon queries.
func (de *endpoint) discoverSCIONPathAsync(peerIA addr.IA, hostAddr netip.AddrPort) {
	// CAS guard: only one discovery runs at a time per endpoint.
	if !de.scionDiscovering.CompareAndSwap(false, true) {
		return
	}
	defer de.scionDiscovering.Store(false)

	// Throttle: skip if discovery ran recently.
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
		metricSCIONPathDiscoveryError.Add(1)
		// Rate-limit the log to one line per peer per
		// scionDiscoveryLogInterval. The error itself is always recorded
		// on scionState (and surfaced via /scion-status and
		// PeerStatus.SCION.LastDiscoveryError) — it's just the log line
		// that's throttled, so journalctl doesn't fill with repeats of
		// the same "TRC not found" message for a permanently-broken peer.
		de.c.mu.Lock()
		last := de.c.scionDiscoveryLogAt[peerIA]
		shouldLog := last.IsZero() || time.Since(last) >= scionDiscoveryLogInterval
		if shouldLog {
			if de.c.scionDiscoveryLogAt == nil {
				de.c.scionDiscoveryLogAt = make(map[scionIAKey]time.Time)
			}
			de.c.scionDiscoveryLogAt[peerIA] = time.Now()
		}
		de.c.mu.Unlock()
		if shouldLog {
			de.c.logf("magicsock: SCION path discovery for %s failed: %v", peerIA, err)
		}
		// Record the error on per-endpoint state so it surfaces via
		// PeerStatus.SCION.LastDiscoveryError (tailscale status --json).
		// Operators can then see "peer advertises SCION but discovery is
		// failing with TRC not found" without reading logs. Also stash
		// the classified kind for typed consumers (Phase 5).
		errKind := classifySCIONDiscoveryErr(err)
		de.mu.Lock()
		if de.scionState != nil {
			de.scionState.lastDiscoveryError = err.Error()
			de.scionState.lastDiscoveryErrorAt = time.Now()
			de.scionState.lastDiscoveryErrorKind = errKind
		}
		de.mu.Unlock()
		// Phase 2d: schedule a short-interval retry. The initial-discovery
		// failure class is dominated by daemon warm-up (no segments yet,
		// truncated TRC from CS, gRPC Unavailable). Soft-refresh's recovery
		// path takes up to 5 min to kick in; cold-retry gets us back within
		// tens of seconds. After scionColdRetryMaxAttempts without success
		// the entry is removed and long-term recovery falls to soft-refresh.
		de.c.scheduleColdRetry(peerIA, hostAddr, errKind)
		return
	}
	// Successful discovery: clear any stale error so status reflects the
	// current state, not a prior transient failure. Phase 2d: also clear
	// the cold-retry schedule so a subsequent re-entry to the failure path
	// starts from the 10 s base again.
	de.c.clearColdRetry(peerIA, hostAddr)
	de.mu.Lock()
	if de.scionState != nil {
		de.scionState.lastDiscoveryError = ""
		de.scionState.lastDiscoveryErrorAt = time.Time{}
		de.scionState.lastDiscoveryErrorKind = scionErrOther
	}
	de.mu.Unlock()
	// Also clear the per-peer log-throttle timestamp so the next failure
	// (if any) logs promptly rather than being silently throttled from a
	// prior bad window.
	de.c.mu.Lock()
	delete(de.c.scionDiscoveryLogAt, peerIA)
	de.c.mu.Unlock()

	// Build set of new keys for fast lookup.
	newKeySet := make(map[scionPathKey]bool, len(newKeys))
	for _, k := range newKeys {
		newKeySet[k] = true
	}

	// Extract fingerprints, display strings, and wireMTU under c.mu (must be acquired before de.mu per lock ordering).
	type pathSnapshot struct {
		fingerprint snet.PathFingerprint
		ifCount     int
		displayStr  string
		wireMTU     tstun.WireMTU
	}
	de.c.mu.Lock()
	snapByKey := make(map[scionPathKey]pathSnapshot, len(newKeys))
	for _, k := range newKeys {
		if pi := de.c.lookupSCIONPath(k); pi != nil {
			pi.mu.Lock()
			mtu := pi.mtu
			hdrLen := 0
			if pi.fastPath != nil {
				hdrLen = len(pi.fastPath.hdr)
			}
			ifCount := 0
			if pi.path != nil {
				if md := pi.path.Metadata(); md != nil {
					ifCount = len(md.Interfaces)
				}
			}
			pi.mu.Unlock()
			wmtu := scionWireMTU
			if mtu > 0 && hdrLen > 0 {
				maxWG := int(mtu) - hdrLen
				if maxWG > 0 {
					wmtu = tstun.WireMTU(maxWG)
				}
			}
			snapByKey[k] = pathSnapshot{
				fingerprint: pi.fingerprint,
				ifCount:     ifCount,
				displayStr:  pi.displayStr,
				wireMTU:     wmtu,
			}
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
		snap := snapByKey[k]
		// Preserve existing probe history only when fingerprint AND
		// interface-count match. The extra ifCount check guards against
		// the (theoretical but possible) case of two topologically
		// distinct paths colliding on the truncated fingerprint hash —
		// we don't want latency/health numbers from a stale path to
		// colour the new one. metricSCIONFingerprintCollision fires when
		// we see a fingerprint match but a different hop count, which
		// is strong evidence of such a collision.
		if snap.fingerprint != "" && oldProbeByFP != nil {
			if old, ok := oldProbeByFP[snap.fingerprint]; ok {
				if old.ifCount == snap.ifCount {
					old.fingerprint = snap.fingerprint // ensure set
					old.displayStr = snap.displayStr
					old.wireMTU = snap.wireMTU
					newPaths[k] = old
					continue
				}
				metricSCIONFingerprintCollision.Add(1)
			}
		}
		newPaths[k] = &scionPathProbeState{
			fingerprint: snap.fingerprint,
			ifCount:     snap.ifCount,
			displayStr:  snap.displayStr,
			wireMTU:     snap.wireMTU,
			healthy:     true,
		}
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

	for i, k := range newKeys {
		active := ""
		if k == activePath {
			active = " (active)"
		}
		var mtuInfo string
		de.c.mu.Lock()
		if pi, ok := de.c.scionPaths[k]; ok {
			pi.mu.Lock()
			hdrLen := 0
			if pi.fastPath != nil {
				hdrLen = len(pi.fastPath.hdr)
			}
			mtu := pi.mtu
			pi.mu.Unlock()
			maxWG := int(mtu) - hdrLen
			mtuInfo = fmt.Sprintf(" pathMTU=%d hdr=%d maxWG=%d", mtu, hdrLen, maxWG)
			// WG overhead: 4 type + 4 receiver + 8 counter + 16 tag = 32 bytes.
			// Max TUN packet that fits: maxWG - 32.
			const wgOverhead = 32
			if mtu > 0 && hdrLen > 0 && maxWG < 1280+wgOverhead {
				de.c.logf("magicsock: WARNING: SCION path MTU %d too small for TUN 1280 (need %d, have %d for WG payload)",
					mtu, 1280+wgOverhead+hdrLen, maxWG)
			}
		}
		de.c.mu.Unlock()
		de.c.logf("magicsock: SCION path to %s: [%d] %s%s%s", peerIA, i, de.c.scionPathString(k), mtuInfo, active)
	}
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

// RefreshSCION re-triggers SCION path discovery for every peer without
// tearing down the SCION socket. Called when the IPN engine transitions
// from a non-Running state back to Running: the peer map and per-endpoint
// scionState survive the disconnect, but their paths may have gone stale
// (path expiry, idle peerings), and nothing else in the SetNetworkMap
// path re-runs discovery when the netmap hasn't structurally changed.
//
// If the SCION socket is up, this is a cheap "rediscover + catch up any
// peers that were skipped" pass. If the socket is down, it ensures a
// startup retry is in flight; retrySCIONStartup itself calls
// discoverNewSCIONPeers on success. No-op when SCION is disabled.
func (c *Conn) RefreshSCION() {
	if c.pconnSCION.Load() == nil {
		if c.scionStartupRetryActive.CompareAndSwap(false, true) {
			go c.retrySCIONStartup(c.connCtx)
		}
		return
	}
	c.rediscoverAllSCIONPaths()
	c.discoverNewSCIONPeers()
}

// ReconfigureSCION updates SCION configuration at runtime.
// If disabled, closes the current SCION connection.
// If enabled, updates envknobs, closes any existing connection, and
// triggers a fresh reconnection attempt.
func (c *Conn) ReconfigureSCION(cfg SCIONConfig) {
	if !cfg.Enabled {
		c.mu.Lock()
		c.closeSCIONLocked()
		c.mu.Unlock()
		return
	}
	if cfg.BootstrapURL != "" {
		envknob.Setenv("TS_SCION_BOOTSTRAP_URL", cfg.BootstrapURL)
	}
	if cfg.Prefer {
		envknob.Setenv("TS_PREFER_SCION", "true")
	} else {
		envknob.Setenv("TS_PREFER_SCION", "")
	}

	// Close existing connection (if any) so retrySCIONConnect starts fresh.
	c.mu.Lock()
	c.closeSCIONLocked()
	c.mu.Unlock()

	go c.retrySCIONConnect()
}

// SCIONStatus returns whether SCION is currently connected and the local IA.
func (c *Conn) SCIONStatus() (connected bool, localIA string) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return false, ""
	}
	return true, sc.localIA.String()
}

// SCIONLastConnectError returns the most recent trySCIONConnect failure
// message and when it occurred, or ("", time.Time{}) if none has been
// recorded. Operators use this from /scion-status to diagnose why SCION is
// down without reading the raw log stream.
func (c *Conn) SCIONLastConnectError() (msg string, when time.Time) {
	info := c.scionLastConnectErr.Load()
	if info == nil {
		return "", time.Time{}
	}
	return info.Err, info.When
}

// SCIONRefreshBackoffSnapshot is the per-peer refresh backoff view exposed
// to the localapi /scion-status endpoint (Phase 4b). All timestamps are
// wall-clock UTC, RFC3339-encoded at the handler layer.
type SCIONRefreshBackoffSnapshot struct {
	IA                  string
	ConsecutiveFailures int
	NextAttemptAt       time.Time
	LastError           string
	LastErrorAt         time.Time
	// LastErrorKind is the typed classification of LastError (Phase 5).
	// Empty string for unclassified ("other") errors. See
	// scionDiscoveryErrorKind.String for the vocabulary.
	LastErrorKind string
}

// SCIONRefreshStatus returns a snapshot of the refresh-health state: the
// most recent successful-refresh timestamp, and per-peer backoff entries
// for any peer whose refresh has failed recently. Empty map and zero
// timestamp if refresh has never run (e.g. SCION not connected yet).
// Returns copies of internal state so callers can iterate without
// holding c.mu.
func (c *Conn) SCIONRefreshStatus() (lastSuccessAt time.Time, perPeer []SCIONRefreshBackoffSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lastSuccessAt = c.scionRefreshLastSuccess
	if len(c.scionRefreshByIA) == 0 {
		return lastSuccessAt, nil
	}
	perPeer = make([]SCIONRefreshBackoffSnapshot, 0, len(c.scionRefreshByIA))
	for ia, b := range c.scionRefreshByIA {
		if b == nil {
			continue
		}
		// Only surface entries that have actually failed; clean peers
		// (ConsecutiveFailures=0, everything zero) are noise.
		if b.consecutiveFailures == 0 && b.nextAttemptAt.IsZero() && b.lastError == "" {
			continue
		}
		perPeer = append(perPeer, SCIONRefreshBackoffSnapshot{
			IA:                  ia.String(),
			ConsecutiveFailures: b.consecutiveFailures,
			NextAttemptAt:       b.nextAttemptAt,
			LastError:           b.lastError,
			LastErrorAt:         b.lastErrorAt,
			LastErrorKind:       b.lastErrorKind.String(),
		})
	}
	return lastSuccessAt, perPeer
}

// recordSCIONConnectError stores err as the latest trySCIONConnect failure
// and bumps metricSCIONConnectFailure. Passing nil clears the recorded
// error — use after a successful connect so /scion-status stops reporting
// stale errors.
func (c *Conn) recordSCIONConnectError(err error) {
	if err == nil {
		c.scionLastConnectErr.Store(nil)
		return
	}
	metricSCIONConnectFailure.Add(1)
	c.scionLastConnectErr.Store(&scionLastErrInfo{Err: err.Error(), When: time.Now()})
}

// SCIONDetailedStatus returns extended SCION connection info for diagnostics.
func (c *Conn) SCIONDetailedStatus() (info SCIONStatusInfo) {
	sc := c.pconnSCION.Load()
	if sc == nil {
		return info
	}
	info.Connected = true
	info.LocalIA = sc.localIA.String()
	info.LocalPort = sc.localPort
	info.HasFastPath = sc.underlayXPC != nil
	info.HasShim = sc.shimXPC != nil

	c.mu.Lock()
	info.PathCount = len(c.scionPaths)
	peerIAs := make(map[addr.IA]bool)
	for _, pi := range c.scionPaths {
		peerIAs[pi.peerIA] = true
	}
	info.PeerCount = len(peerIAs)
	c.mu.Unlock()
	return info
}

// SCIONStatusInfo holds extended SCION connection information.
type SCIONStatusInfo struct {
	Connected   bool
	LocalIA     string
	LocalPort   uint16
	PeerCount   int  // number of unique peer IAs with registered paths
	PathCount   int  // total number of registered SCION paths
	HasFastPath bool // whether batch I/O (sendmmsg/recvmmsg) is available
	HasShim     bool // whether the dispatcher shim socket is active
}

// populateSCIONPathsLocked fills ps.SCIONPaths and ps.SCION from de.scionState.
// de.mu must be held. c.mu must be held (caller is Conn.UpdateStatus).
//
// Populates ps.SCION whenever scionState is present (i.e. the peer has ever
// advertised SCION), even if SCIONPaths is empty — so a peer that advertised
// SCION but whose discovery keeps failing still shows up in
// `tailscale status --json` with the failure reason. Phase 4a.
func (de *endpoint) populateSCIONPathsLocked(ps *ipnstate.PeerStatus) {
	// Don't report paths if SCION is disconnected - they're stale.
	if de.c.pconnSCION.Load() == nil {
		return
	}
	ss := de.scionState
	if ss == nil {
		return
	}

	// Peer-level SCION state: always emitted when scionState exists, even
	// if ss.paths is empty (discovery never ran, or always failed).
	peerState := &ipnstate.SCIONPeerState{
		PeerIA:   ss.peerIA.String(),
		HostAddr: ss.hostAddr.String(),
	}
	if !ss.lastDiscoveryAt.IsZero() {
		peerState.LastDiscoveryAt = ss.lastDiscoveryAt.UTC().Format(time.RFC3339)
	}
	if ss.lastDiscoveryError != "" {
		peerState.LastDiscoveryError = ss.lastDiscoveryError
		if !ss.lastDiscoveryErrorAt.IsZero() {
			peerState.LastDiscoveryErrorAt = ss.lastDiscoveryErrorAt.UTC().Format(time.RFC3339)
		}
		peerState.LastDiscoveryErrorKind = ss.lastDiscoveryErrorKind.String()
	}
	ps.SCION = peerState

	if len(ss.paths) == 0 {
		return
	}
	ps.SCIONPaths = make([]ipnstate.SCIONPathInfo, 0, len(ss.paths))
	now := mono.Now()
	for pk, probe := range ss.paths {
		info := ipnstate.SCIONPathInfo{
			Path:               probe.displayStr,
			Active:             pk == ss.activePath,
			Healthy:            probe.healthy,
			Hops:               probe.ifCount,
			LossPercent:        -1,
			LastPongSecondsAgo: -1,
		}
		lat := probe.latency()
		if lat < time.Hour {
			info.LatencyMs = float64(lat.Microseconds()) / 1000.0
		}
		if probe.pingsSent > 0 {
			lost := probe.pingsSent - probe.pongsReceived
			info.LossPercent = 100.0 * float64(lost) / float64(probe.pingsSent)
			if info.LossPercent < 0 {
				info.LossPercent = 0
			}
			if info.LossPercent > 100 {
				info.LossPercent = 100
			}
		}
		if probe.pongCount > 0 {
			idx := probe.recentPong
			last := probe.recentPongs[idx].pongAt
			info.LastPongSecondsAgo = now.Sub(last).Seconds()
		}
		// Look up full path info from Conn-level registry for expiry/MTU.
		if pi, ok := de.c.scionPaths[pk]; ok {
			pi.mu.Lock()
			expiry := pi.expiry
			mtu := pi.mtu
			pi.mu.Unlock()
			if !expiry.IsZero() {
				info.ExpiresAt = expiry.UTC().Format(time.RFC3339)
			}
			if mtu > 0 {
				info.MTU = int(mtu)
			}
		}
		ps.SCIONPaths = append(ps.SCIONPaths, info)
	}
}
