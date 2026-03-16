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
		return
	}
	c.logf("magicsock: SCION available, local IA: %s", sc.localIA)
	c.pconnSCION.Store(sc)
	go c.refreshSCIONPaths()
}

// closeSCIONLocked closes the SCION connection if open and sets pconnSCION
// to nil so that receiveSCION and retrySCIONConnect see it as disconnected.
// c.mu must be held.
func (c *Conn) closeSCIONLocked() {
	if sc := c.pconnSCION.Load(); sc != nil {
		sc.close()
		c.pconnSCION.Store(nil)
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
