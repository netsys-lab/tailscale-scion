// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

// The embedded SCION connector deliberately uses a no-op segment verifier
// (acceptAllVerifier) in this fork. This is a known Phase 1 limitation: path
// segments returned by the SCION control plane are accepted without
// cryptographic validation against TRCs. A hostile control server or on-path
// attacker (given the current plaintext bootstrap) can inject fabricated
// segments, effectively controlling path routing for SCION traffic.
//
// Operators must acknowledge this explicitly: the embedded connector refuses
// to start unless TS_SCION_ACKNOWLEDGE_INSECURE_SEGMENTS=1 is set. When the
// knob is set, the connector logs a one-time warning at startup so the risk
// is visible in the process's log stream. Removing the knob (leaving it
// unset) is the path forward for operators who cannot accept this posture.
//
// Phase 2 will replace acceptAllVerifier with a real trust-engine-backed
// verifier that validates segments against the bootstrapped TRCs.

package magicsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/scionproto/scion/daemon/config"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/drkey"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/paths"
	"tailscale.com/types/logger"
)

var (
	scionTopology    = envknob.RegisterString("TS_SCION_TOPOLOGY")
	scionStateDirEnv = envknob.RegisterString("TS_SCION_STATE_DIR")

	// scionAcceptInsecureSegments gates the Phase 1 accept-all verifier.
	// When unset, the embedded connector refuses to start so that a
	// security-conscious operator isn't surprised by the insecure posture.
	// When set, a one-time startup warning is emitted.
	scionAcceptInsecureSegments = envknob.RegisterBool("TS_SCION_ACKNOWLEDGE_INSECURE_SEGMENTS")
)

// scionInsecureWarnOnce ensures the Phase 1 verifier warning is logged at most
// once per process, even if the embedded connector is constructed multiple times
// (e.g., across SCION reconnects).
var scionInsecureWarnOnce sync.Once

func warnSCIONInsecureSegments(logf logger.Logf) {
	scionInsecureWarnOnce.Do(func() {
		logf("magicsock: SCION PHASE 1 WARNING: path segments are accepted without " +
			"cryptographic verification (acceptAllVerifier). A compromised SCION control " +
			"plane or on-path attacker can inject arbitrary path segments. This knob " +
			"(TS_SCION_ACKNOWLEDGE_INSECURE_SEGMENTS=1) must be explicitly set to opt in.")
	})
}

// embeddedConnector implements daemon.Connector using an embedded topology
// loader and path fetcher, eliminating the need for an external SCION daemon
// process.
type embeddedConnector struct {
	topo     *topology.Loader
	fetcher  fetcher.Fetcher
	pathDB   storage.PathDB
	revCache revcache.RevCache
	cancel   context.CancelFunc // cancels the topology loader goroutine
}

// Compile-time interface check.
var _ daemon.Connector = (*embeddedConnector)(nil)

// LocalIA returns the local ISD-AS from the topology.
func (ec *embeddedConnector) LocalIA(_ context.Context) (addr.IA, error) {
	return ec.topo.IA(), nil
}

// PortRange returns the endhost port range from the topology.
func (ec *embeddedConnector) PortRange(_ context.Context) (uint16, uint16, error) {
	min, max := ec.topo.PortRange()
	return min, max, nil
}

// Interfaces returns the interface-to-underlay address map from the topology.
func (ec *embeddedConnector) Interfaces(_ context.Context) (map[uint16]netip.AddrPort, error) {
	ifInfoMap := ec.topo.InterfaceInfoMap()
	result := make(map[uint16]netip.AddrPort, len(ifInfoMap))
	for id, info := range ifInfoMap {
		result[uint16(id)] = info.InternalAddr
	}
	return result, nil
}

// snetTopology returns an snet.Topology struct built from the embedded
// topology loader. The Interface callback delegates to the loader for
// live topology access.
func (ec *embeddedConnector) snetTopology() snet.Topology {
	ia := ec.topo.IA()
	portMin, portMax := ec.topo.PortRange()
	return snet.Topology{
		LocalIA:   ia,
		PortRange: snet.TopologyPortRange{Start: portMin, End: portMax},
		Interface: func(id uint16) (netip.AddrPort, bool) {
			ifInfoMap := ec.topo.InterfaceInfoMap()
			info, ok := ifInfoMap[iface.ID(id)]
			if !ok {
				return netip.AddrPort{}, false
			}
			return info.InternalAddr, true
		},
	}
}

// Paths resolves end-to-end paths using the embedded fetcher (segment fetch + combination).
func (ec *embeddedConnector) Paths(ctx context.Context, dst, src addr.IA, f daemon.PathReqFlags) ([]snet.Path, error) {
	return ec.fetcher.GetPaths(ctx, src, dst, f.Refresh)
}

// ASInfo is not supported by the embedded connector.
func (ec *embeddedConnector) ASInfo(_ context.Context, _ addr.IA) (daemon.ASInfo, error) {
	return daemon.ASInfo{}, serrors.New("not supported by embedded connector")
}

// SVCInfo is not supported by the embedded connector.
func (ec *embeddedConnector) SVCInfo(_ context.Context, _ []addr.SVC) (map[addr.SVC][]string, error) {
	return nil, serrors.New("not supported by embedded connector")
}

// RevNotification is not supported by the embedded connector.
func (ec *embeddedConnector) RevNotification(_ context.Context, _ *path_mgmt.RevInfo) error {
	return serrors.New("not supported by embedded connector")
}

// DRKeyGetASHostKey is not supported by the embedded connector.
func (ec *embeddedConnector) DRKeyGetASHostKey(_ context.Context, _ drkey.ASHostMeta) (drkey.ASHostKey, error) {
	return drkey.ASHostKey{}, serrors.New("not supported by embedded connector")
}

// DRKeyGetHostASKey is not supported by the embedded connector.
func (ec *embeddedConnector) DRKeyGetHostASKey(_ context.Context, _ drkey.HostASMeta) (drkey.HostASKey, error) {
	return drkey.HostASKey{}, serrors.New("not supported by embedded connector")
}

// DRKeyGetHostHostKey is not supported by the embedded connector.
func (ec *embeddedConnector) DRKeyGetHostHostKey(_ context.Context, _ drkey.HostHostMeta) (drkey.HostHostKey, error) {
	return drkey.HostHostKey{}, serrors.New("not supported by embedded connector")
}

// Close shuts down the embedded connector, stopping the topology loader
// and closing storage backends.
func (ec *embeddedConnector) Close() error {
	if ec.cancel != nil {
		ec.cancel()
	}
	if ec.pathDB != nil {
		ec.pathDB.Close()
	}
	if ec.revCache != nil {
		ec.revCache.Close()
	}
	return nil
}

// newEmbeddedConnector creates a new embeddedConnector from a topology file.
// It wires up the path fetcher pipeline following the daemon's own assembly
// (daemon/cmd/daemon/main.go), but without trust verification (Phase 1).
func newEmbeddedConnector(ctx context.Context, topoPath, stateDir string, logf logger.Logf, netMon *netmon.Monitor) (*embeddedConnector, error) {
	// Enforce explicit operator acknowledgement of the Phase 1 accept-all
	// verifier. See the top-of-file comment for the threat model.
	if !scionAcceptInsecureSegments() {
		return nil, fmt.Errorf("embedded SCION connector requires " +
			"TS_SCION_ACKNOWLEDGE_INSECURE_SEGMENTS=1 (Phase 1 limitation — " +
			"segments are not cryptographically verified)")
	}
	warnSCIONInsecureSegments(logf)

	// 1. Load topology.
	topo, err := topology.NewLoader(topology.LoaderCfg{
		File:      topoPath,
		Validator: &topology.DefaultValidator{},
	})
	if err != nil {
		return nil, fmt.Errorf("loading topology from %s: %w", topoPath, err)
	}

	// Start the topology loader in a background goroutine for reload support.
	topoCtx, topoCancel := context.WithCancel(ctx)
	go func() {
		_ = topo.Run(topoCtx)
	}()
	// Cancel topoCtx (and thus tear down the goroutine above) unless we
	// return a fully-constructed connector. Any future error path added
	// below is automatically covered; prior to this, specific error sites
	// had to remember to call topoCancel manually.
	success := false
	defer func() {
		if !success {
			topoCancel()
		}
	}()

	// 2. Create storage backends.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory %s: %w", stateDir, err)
	}

	dbPath := filepath.Join(stateDir, "scion-pathdb.sqlite")
	pathDB, err := storage.NewPathStorage(storage.DBConfig{Connection: dbPath})
	if err != nil {
		return nil, fmt.Errorf("creating path storage at %s: %w", dbPath, err)
	}

	revCache := storage.NewRevocationStorage()

	// 3. Create gRPC dialer that resolves CS addresses from the topology,
	// using netns-aware TCP connections for cross-platform compatibility
	// (SO_MARK on Linux, VpnService.protect on Android, IP_BOUND_IF on macOS).
	dialer := &netnsTCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
		NetDialer: netns.NewDialer(logf, netMon).DialContext,
	}

	// 4. Create the segment fetcher requester (gRPC to local CS).
	requester := &segfetchergrpc.Requester{
		Dialer: dialer,
	}

	// 5. Create the path fetcher with accept-all verification (Phase 1).
	sdCfg := config.SDConfig{}
	sdCfg.InitDefaults()

	f := fetcher.NewFetcher(fetcher.FetcherConfig{
		IA:         topo.IA(),
		MTU:        topo.MTU(),
		Core:       topo.Core(),
		NextHopper: topo,
		RPC:        requester,
		PathDB:     pathDB,
		Inspector:  endHostInspector{},
		Verifier:   acceptAllVerifier{},
		RevCache:   revCache,
		Cfg:        sdCfg,
	})

	ec := &embeddedConnector{
		topo:     topo,
		fetcher:  f,
		pathDB:   pathDB,
		revCache: revCache,
		cancel:   topoCancel,
	}
	success = true
	return ec, nil
}

// acceptAllVerifier skips segment verification. This matches the daemon's own
// behavior when DisableSegVerification is set (daemon/cmd/daemon/main.go:359-377).
type acceptAllVerifier struct{}

func (acceptAllVerifier) Verify(_ context.Context, _ *cryptopb.SignedMessage,
	_ ...[]byte) (*signed.Message, error) {
	return nil, nil
}

func (v acceptAllVerifier) WithServer(_ net.Addr) infra.Verifier {
	return v
}

func (v acceptAllVerifier) WithIA(_ addr.IA) infra.Verifier {
	return v
}

func (v acceptAllVerifier) WithValidity(_ cppki.Validity) infra.Verifier {
	return v
}

// endHostInspector is a minimal trust.Inspector for non-core endhosts.
// It always reports no attributes, which is correct for endhost path resolution.
type endHostInspector struct{}

func (endHostInspector) ByAttributes(_ context.Context, _ addr.ISD, _ trust.Attribute) ([]addr.IA, error) {
	return nil, nil
}

func (endHostInspector) HasAttributes(_ context.Context, _ addr.IA, _ trust.Attribute) (bool, error) {
	return false, nil
}

// netnsTCPDialer implements libgrpc.Dialer with netns-aware TCP connections
// for cross-platform socket control (SO_MARK, VpnService.protect, IP_BOUND_IF).
type netnsTCPDialer struct {
	SvcResolver func(addr.SVC) []resolver.Address
	NetDialer   func(ctx context.Context, network, address string) (net.Conn, error)
}

// Compile-time interface check.
var _ libgrpc.Dialer = (*netnsTCPDialer)(nil)

func (d *netnsTCPDialer) Dial(ctx context.Context, dst net.Addr) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return d.NetDialer(ctx, "tcp", addr)
		}),
		libgrpc.UnaryClientInterceptor(),
		libgrpc.StreamClientInterceptor(),
	}

	if v, ok := dst.(*snet.SVCAddr); ok {
		targets := d.SvcResolver(v.SVC)
		if len(targets) == 0 {
			return nil, serrors.New("could not resolve", "svc", v.SVC)
		}
		r := manual.NewBuilderWithScheme("svc")
		r.InitialState(resolver.State{Addresses: targets})
		opts = append(opts,
			grpc.WithDefaultServiceConfig(`{"loadBalancingConfig": [{"round_robin":{}}]}`),
			grpc.WithResolvers(r),
		)
		//nolint:staticcheck // grpc.DialContext is used by scionproto v0.14.0
		return grpc.DialContext(ctx, r.Scheme()+":///"+v.SVC.BaseString(), opts...)
	}

	//nolint:staticcheck // grpc.DialContext is used by scionproto v0.14.0
	return grpc.DialContext(ctx, dst.String(), opts...)
}

// scionTopologyPath returns the path to the SCION topology file, checking
// TS_SCION_TOPOLOGY first, then the platform's SCION config directory
// (/etc/scion/ on Linux), then a "scion" subdirectory under the tailscaled
// state directory (for bootstrapped topologies).
func scionTopologyPath() string {
	if p := scionTopology(); p != "" {
		return p
	}
	if runtime.GOOS == "linux" {
		const defaultSCIONTopology = "/etc/scion/topology.json"
		if _, err := os.Stat(defaultSCIONTopology); err == nil {
			return defaultSCIONTopology
		}
	}
	// Bootstrapped topology under the tailscaled state directory.
	return filepath.Join(paths.DefaultTailscaledStateDir(), "scion", "topology.json")
}

// scionStateDir returns the directory for SCION state (PathDB, etc.),
// checking TS_SCION_STATE_DIR first, then falling back to a "scion"
// subdirectory under the platform's default tailscaled state directory.
func scionStateDir() string {
	if d := scionStateDirEnv(); d != "" {
		return d
	}
	base := paths.DefaultTailscaledStateDir()
	if base == "" || base == "." {
		if appDir := paths.AppSharedDir.Load(); appDir != "" {
			base = appDir
		}
	}
	if base == "" || base == "." {
		return ""
	}
	return filepath.Join(base, "scion")
}

// tryEmbeddedDaemon attempts to set up a SCION connection using the embedded
// connector with the given topology file. This mirrors trySCIONConnect but
// uses the embedded connector instead of an external daemon.
func tryEmbeddedDaemon(ctx context.Context, topoPath string, logf logger.Logf, netMon *netmon.Monitor) (*scionConn, error) {
	stateDir := scionStateDir()
	ec, err := newEmbeddedConnector(ctx, topoPath, stateDir, logf, netMon)
	if err != nil {
		return nil, fmt.Errorf("creating embedded connector: %w", err)
	}

	return finishSCIONConnect(ctx, ec, ec.snetTopology(), logf, netMon)
}
