// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"time"
)

// initSCIONLocked tries to set up a SCION connection if not already connected.
// On success, stores the scionConn and starts the background path refresher.
// c.mu must be held.
func (c *Conn) initSCIONLocked(ctx context.Context) {
	if c.pconnSCION.Load() != nil {
		return
	}
	sc, err := trySCIONConnect(ctx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION not available: %v", err)
		c.recordSCIONConnectError(err)
		return
	}
	c.logf("magicsock: SCION available, local IA: %s", sc.localIA)
	c.pconnSCION.Store(sc)
	c.recordSCIONConnectError(nil)
	c.signalSCIONConnReady()
	go c.refreshSCIONPaths()
}

// closeSCIONLocked closes the SCION connection if open and sets pconnSCION
// to nil so that receiveSCION and retrySCIONConnect see it as disconnected.
// Also purges per-endpoint scionState so that status queries do not return
// stale paths tied to the now-closed connection. c.mu must be held.
func (c *Conn) closeSCIONLocked() {
	if sc := c.pconnSCION.Load(); sc != nil {
		sc.close()
		c.pconnSCION.Store(nil)
	}
	c.clearAllSCIONEndpointStateLocked()
}

// clearAllSCIONEndpointStateLocked walks the peerMap and drops every
// endpoint's scionState + path registrations. Safe to call when the SCION
// socket is torn down (so future connects start from a clean slate) and
// when a reconfigure deliberately disables SCION. c.mu must be held.
func (c *Conn) clearAllSCIONEndpointStateLocked() {
	var toUnregister []scionPathKey
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.mu.Lock()
		if ep.scionState != nil {
			for k := range ep.scionState.paths {
				toUnregister = append(toUnregister, k)
			}
			ep.scionState = nil
		}
		ep.mu.Unlock()
	})
	for _, k := range toUnregister {
		c.unregisterSCIONPath(k)
	}
}

// closeSCIONBindLocked sets an immediate read deadline on the SCION socket
// to unblock receiveSCION, without closing it. Called from connBind.Close.
// c.mu must be held (via connBind.mu).
func (c *Conn) closeSCIONBindLocked() {
	if sc := c.pconnSCION.Load(); sc != nil {
		// Set an immediate read deadline to unblock receiveSCION.
		// We don't close the SCION socket here; Conn.Close handles that.
		sc.conn.SetReadDeadline(time.Now())
		// Also unblock the dispatcher shim's ReadBatch if present.
		if sc.shimConn != nil {
			sc.shimConn.SetReadDeadline(time.Now())
		}
	}
}
