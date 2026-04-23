// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_scion

// This file is the stub counterpart to the SCION transport code in
// wgengine/magicsock. When the ts_omit_scion build tag is active, the real
// SCION implementation is compiled out and every SCION type referenced from
// non-gated code (endpoint.go, magicsock.go) must have a stub here.
//
// Invariants this file must uphold, checked on every change:
//   - Every SCION-named type referenced outside //go:build !ts_omit_scion has
//     a stub here with the same kind (struct, alias, integer type).
//   - `scionPathKey` must be uint64 so its zero value / arithmetic semantics
//     match the production type (see TestScionPathKeyWidth).
//   - Every method on *Conn or *endpoint declared in a SCION-gated file must
//     have a no-op stub here returning zero values of the same type.
//
// Regressions will typically surface as compile errors when tailscaled is
// built with `-tags ts_omit_scion`. The CI matrix is expected to cover both
// build variants (task P3-25). When adding a new SCION field, method, or
// type in a gated file, grep non-gated files for any cross-reference and
// add the corresponding stub here before merging.

package magicsock

import (
	"context"
	"time"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
)

// Stub types for ts_omit_scion builds.

type scionPathKey uint64

func (k scionPathKey) IsSet() bool { return false }

type scionBatchRW interface{}

type scionConn struct {
	shimXPC scionBatchRW
}

func (sc *scionConn) close() error { return nil }

type scionPathInfo struct{}

func (pi *scionPathInfo) String() string { return "" }

type scionAddrKey struct{}
type scionPathFPKey struct{}
type scionEndpointState struct{}
type scionIAKey = uint64
type scionRefreshBackoff struct{}

const scionWireMTU = tstun.WireMTU(1280)

// Stub Conn methods.

func (c *Conn) initSCIONLocked(_ context.Context)                                       {}
func (c *Conn) initSCIONConnReady()                                                      {}
func (c *Conn) signalSCIONConnReady()                                                    {}
func (c *Conn) initSCIONLazyEndpointLimiter()                                            {}
func (c *Conn) allowSCIONLazyEndpoint() bool                                             { return true }
func (c *Conn) closeSCIONLocked()                                                        {}
func (c *Conn) closeSCIONBindLocked()                                                    {}
func (c *Conn) receiveSCION(_ [][]byte, _ []int, _ []wgconn.Endpoint) (int, error)       { return 0, nil }
func (c *Conn) receiveSCIONShim(_ [][]byte, _ []int, _ []wgconn.Endpoint) (int, error)  { return 0, nil }
func (c *Conn) sendSCION(_ scionPathKey, _ []byte) (bool, error)                         { return false, nil }
func (c *Conn) unregisterSCIONPath(_ scionPathKey)                                       {}

// Stub endpoint methods.

func (de *endpoint) heartbeatSCIONLocked(_ mono.Time)                                    {}
func (de *endpoint) sendDiscoPingsSCIONLocked(_ mono.Time) bool                          { return false }
func (de *endpoint) cliPingSCIONLocked(_ mono.Time, _ int, _ *pingResultAndCallback)     {}
func (de *endpoint) discoPingTimeoutSCIONLocked(_ sentPing)                              {}
func (de *endpoint) handlePongSCIONLocked(_ epAddr, _ time.Duration, _ mono.Time)        {}
func (de *endpoint) handlePongPromoteSCIONLocked(_ addrQuality)                          {}
func (de *endpoint) updateFromNodeSCIONLocked(_ tailcfg.NodeView) []scionPathKey         { return nil }
func (de *endpoint) stopAndResetSCIONLocked() ([]scionPathKey, scionIAKey)               { return nil, 0 }
func (de *endpoint) sendSCIONData(_ epAddr, _ [][]byte, _ int) error                     { return nil }
func (de *endpoint) scionAddrStr(e epAddr) string                                       { return e.String() }
func (de *endpoint) populateSCIONPathsLocked(_ *ipnstate.PeerStatus)                    {}

// SCIONService returns false when SCION is omitted.
func (c *Conn) SCIONService() (svc tailcfg.Service, ok bool) { return tailcfg.Service{}, false }

func (c *Conn) RefreshSCION()                                              {}
func (c *Conn) ReconfigureSCION(_ SCIONConfig)                             {}
func (c *Conn) SCIONStatus() (connected bool, localIA string)              { return false, "" }
func (c *Conn) SCIONLastConnectError() (msg string, when time.Time)        { return "", time.Time{} }

type SCIONRefreshBackoffSnapshot struct{}

func (c *Conn) SCIONRefreshStatus() (time.Time, []SCIONRefreshBackoffSnapshot) {
	return time.Time{}, nil
}

// Stub standalone functions used by betterAddr in endpoint.go.

var preferSCION = func() bool { return false }

func scionPreferenceBonus() int              { return 0 }
func scionDiversityThreshold() time.Duration { return 0 }
