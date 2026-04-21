// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/fetcher"
	daemontrust "github.com/scionproto/scion/pkg/daemon/private/trust"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/drkey"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	scionlog "github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/revcache"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/compat"
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

	// scionCertsDirEnv overrides the directory that TRC blobs are loaded
	// from. If unset, the directory is derived from the loaded topology
	// file's parent (i.e. /etc/scion/certs when TS_SCION_TOPOLOGY is
	// /etc/scion/topology.json), falling back to $stateDir/certs for
	// bootstrapped topologies.
	scionCertsDirEnv = envknob.RegisterString("TS_SCION_CERTS_DIR")
)

// errNoTRCs is returned by newEmbeddedConnector when no TRC blobs are
// available in the state directory. With real segment verification in place
// the connector cannot usefully start without at least one TRC.
var errNoTRCs = errors.New("no TRCs available; run bootstrap or set TS_SCION_BOOTSTRAP_URL")

// scionLogDiscardOnce silences scionproto's package-global zap logger on
// first embedded-connector construction. Without this, daemontrust.NewEngine
// and friends log directly to stderr via an uninitialized logger.
var scionLogDiscardOnce sync.Once

func silenceSCIONLog() {
	scionLogDiscardOnce.Do(scionlog.Discard)
}

// embeddedConnector implements daemon.Connector using an embedded topology
// loader and path fetcher, eliminating the need for an external SCION daemon
// process.
type embeddedConnector struct {
	topo     *topology.Loader
	fetcher  fetcher.Fetcher
	pathDB   storage.PathDB
	revCache revcache.RevCache
	trustDB  storage.TrustDB
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
func (ec *embeddedConnector) Paths(ctx context.Context, dst, src addr.IA, f daemontypes.PathReqFlags) ([]snet.Path, error) {
	return ec.fetcher.GetPaths(ctx, src, dst, f.Refresh)
}

// ASInfo is not supported by the embedded connector.
func (ec *embeddedConnector) ASInfo(_ context.Context, _ addr.IA) (daemontypes.ASInfo, error) {
	return daemontypes.ASInfo{}, serrors.New("not supported by embedded connector")
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
	if ec.trustDB != nil {
		ec.trustDB.Close()
	}
	return nil
}

// newEmbeddedConnector creates a new embeddedConnector from a topology file.
// It wires up the path fetcher pipeline following the daemon's own assembly
// (daemon/cmd/daemon/main.go), including TRC-backed segment verification via
// daemontrust.NewEngine. The connector requires at least one TRC blob under
// stateDir/certs/ to start; callers should bootstrap first when the state
// directory is empty.
func newEmbeddedConnector(ctx context.Context, topoPath, stateDir string, logf logger.Logf, netMon *netmon.Monitor) (*embeddedConnector, error) {
	silenceSCIONLog()

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

	// 4. Build the trust engine backed by the on-disk TRC/chain store. The
	// engine supplies both the verifier (which checks each segment against a
	// TRC) and the inspector (which reports AS attributes from the trust DB).
	//
	// TRC location: prefer TS_SCION_CERTS_DIR if set; otherwise use the
	// topology file's sibling "certs" directory (matches the stock SCION
	// daemon's /etc/scion layout). This keeps hosts that already have TRCs
	// under /etc/scion/certs/ from needing to copy them into stateDir.
	certsDir := resolveSCIONCertsDir(topoPath)
	if !certsDirHasTRC(certsDir) {
		pathDB.Close()
		revCache.Close()
		return nil, fmt.Errorf("%s: %w", certsDir, errNoTRCs)
	}
	trustDBPath := filepath.Join(stateDir, "scion-trustdb.sqlite")
	trustDB, err := storage.NewTrustStorage(storage.DBConfig{Connection: trustDBPath})
	if err != nil {
		pathDB.Close()
		revCache.Close()
		return nil, fmt.Errorf("creating trust storage at %s: %w", trustDBPath, err)
	}
	engine, err := daemontrust.NewEngine(topoCtx, certsDir, topo.IA(), trustDB, dialer)
	if err != nil {
		trustDB.Close()
		pathDB.Close()
		revCache.Close()
		return nil, fmt.Errorf("building trust engine: %w", err)
	}

	// 5. Create the segment fetcher requester (gRPC to local CS) and the path
	// fetcher with real TRC-based segment verification.
	requester := &segfetchergrpc.Requester{
		Dialer: dialer,
	}

	f := fetcher.NewFetcher(fetcher.FetcherConfig{
		IA:            topo.IA(),
		MTU:           topo.MTU(),
		Core:          topo.Core(),
		NextHopper:    topo,
		RPC:           requester,
		PathDB:        pathDB,
		Inspector:     engine,
		Verifier:      compat.Verifier{Verifier: trust.Verifier{Engine: engine}},
		RevCache:      revCache,
		QueryInterval: 5 * time.Minute,
	})

	ec := &embeddedConnector{
		topo:     topo,
		fetcher:  f,
		pathDB:   pathDB,
		revCache: revCache,
		trustDB:  trustDB,
		cancel:   topoCancel,
	}
	success = true
	return ec, nil
}

// certsDirHasTRC reports whether the given directory contains at least one
// *.trc blob. Bootstrap writes TRCs under stateDir/certs/ using ID-based
// filenames (e.g. isd19-b1-s1.trc); the real scionproto loader globs *.trc.
func certsDirHasTRC(dir string) bool {
	matches, err := filepath.Glob(filepath.Join(dir, "*.trc"))
	return err == nil && len(matches) > 0
}

// resolveSCIONCertsDir returns the directory to load TRC blobs from. The
// explicit TS_SCION_CERTS_DIR envknob wins when set; otherwise the directory
// is derived from the topology file's parent (so /etc/scion/topology.json
// resolves to /etc/scion/certs, matching the stock SCION daemon layout, and
// $stateDir/topology.json resolves to $stateDir/certs, matching what
// bootstrap writes).
func resolveSCIONCertsDir(topoPath string) string {
	if d := scionCertsDirEnv(); d != "" {
		return d
	}
	return filepath.Join(filepath.Dir(topoPath), "certs")
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
