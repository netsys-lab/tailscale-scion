// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

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
	"github.com/scionproto/scion/pkg/snet"
	segfetchergrpc "github.com/scionproto/scion/private/segment/segfetcher/grpc"
	infra "github.com/scionproto/scion/private/segment/verifier"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/storage"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
	"google.golang.org/grpc/resolver"
	"tailscale.com/paths"
)

// embeddedConnector implements daemon.Connector and snet.Topology using an
// embedded topology loader and path fetcher, eliminating the need for an
// external SCION daemon process.
type embeddedConnector struct {
	topo     *topology.Loader
	fetcher  fetcher.Fetcher
	pathDB   storage.PathDB
	revCache revcache.RevCache
	cancel   context.CancelFunc // cancels the topology loader goroutine
}

// Compile-time interface checks.
var (
	_ daemon.Connector = (*embeddedConnector)(nil)
	_ snet.Topology    = (*embeddedConnector)(nil)
)

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
func newEmbeddedConnector(ctx context.Context, topoPath, stateDir string) (*embeddedConnector, error) {
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

	// 2. Create storage backends.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		topoCancel()
		return nil, fmt.Errorf("creating state directory %s: %w", stateDir, err)
	}

	dbPath := filepath.Join(stateDir, "scion-pathdb.sqlite")
	pathDB, err := storage.NewPathStorage(storage.DBConfig{Connection: dbPath})
	if err != nil {
		topoCancel()
		return nil, fmt.Errorf("creating path storage at %s: %w", dbPath, err)
	}

	revCache := storage.NewRevocationStorage()

	// 3. Create gRPC dialer that resolves CS addresses from the topology.
	dialer := &libgrpc.TCPDialer{
		SvcResolver: func(dst addr.SVC) []resolver.Address {
			targets := []resolver.Address{}
			for _, entry := range topo.ControlServiceAddresses() {
				targets = append(targets, resolver.Address{Addr: entry.String()})
			}
			return targets
		},
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

	return &embeddedConnector{
		topo:     topo,
		fetcher:  f,
		pathDB:   pathDB,
		revCache: revCache,
		cancel:   topoCancel,
	}, nil
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

// scionTopologyPath returns the path to the SCION topology file, checking
// TS_SCION_TOPOLOGY first, then falling back to /etc/scion/topology.json.
func scionTopologyPath() string {
	if p := os.Getenv("TS_SCION_TOPOLOGY"); p != "" {
		return p
	}
	return "/etc/scion/topology.json"
}

// scionStateDir returns the directory for SCION state (PathDB, etc.),
// checking TS_SCION_STATE_DIR first, then falling back to a "scion"
// subdirectory under the platform's default tailscaled state directory.
func scionStateDir() string {
	if d := os.Getenv("TS_SCION_STATE_DIR"); d != "" {
		return d
	}
	return filepath.Join(paths.DefaultTailscaledStateDir(), "scion")
}

// tryEmbeddedDaemon attempts to set up a SCION connection using the embedded
// connector with the given topology file. This mirrors trySCIONConnect but
// uses the embedded connector instead of an external daemon.
func tryEmbeddedDaemon(ctx context.Context, topoPath string) (*scionConn, error) {
	stateDir := scionStateDir()
	ec, err := newEmbeddedConnector(ctx, topoPath, stateDir)
	if err != nil {
		return nil, fmt.Errorf("creating embedded connector: %w", err)
	}

	return finishSCIONConnect(ctx, ec, ec)
}
