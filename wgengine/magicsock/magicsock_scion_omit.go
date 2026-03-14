// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_scion

package magicsock

import (
	"context"
	"time"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
)

// Stub types for ts_omit_scion builds.

type scionPathKey uint32

func (k scionPathKey) IsSet() bool { return false }

type scionConn struct{}

func (sc *scionConn) close() error { return nil }

type scionPathInfo struct{}
type scionAddrKey struct{}
type scionEndpointState struct{}

// Stub Conn methods.

func (c *Conn) initSCIONLocked(_ context.Context)                                       {}
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
func (de *endpoint) stopAndResetSCIONLocked() []scionPathKey                             { return nil }
func (de *endpoint) sendSCIONData(_ epAddr, _ [][]byte, _ int) error                     { return nil }

// SCIONService returns false when SCION is omitted.
func (c *Conn) SCIONService() (svc tailcfg.Service, ok bool) { return tailcfg.Service{}, false }

// Stub standalone functions used by betterAddr in endpoint.go.

var preferSCION = func() bool { return false }

func scionPreferenceBonus() int              { return 0 }
func scionDiversityThreshold() time.Duration { return 0 }
