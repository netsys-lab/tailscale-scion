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
// On failure, spawns a retry goroutine (Phase 3): a brief bootstrap-server
// outage or daemon restart at boot should not leave SCION permanently
// disabled until manual intervention. The retry loop is CAS-guarded via
// scionStartupRetryActive so concurrent calls (e.g. from netMon rebind)
// do not spawn parallel retries.
// c.mu must be held.
func (c *Conn) initSCIONLocked(ctx context.Context) {
	if scionDisabled() {
		return
	}
	if c.pconnSCION.Load() != nil {
		return
	}
	sc, err := trySCIONConnect(ctx, c.logf, c.netMon)
	if err != nil {
		c.logf("magicsock: SCION not available: %v", err)
		c.recordSCIONConnectError(err)
		if c.scionStartupRetryActive.CompareAndSwap(false, true) {
			go c.retrySCIONStartup(ctx)
		}
		return
	}
	c.logf("magicsock: SCION available, local IA: %s", sc.localIA)
	c.pconnSCION.Store(sc)
	c.recordSCIONConnectError(nil)
	c.signalSCIONConnReady()
	go c.refreshSCIONPaths()
	go c.scionColdRetryLoop()
}

// scionStartupRetrySleep returns the backoff sleep before the Nth SCION
// connect retry attempt (1-indexed): 5s, 10s, 20s, 40s, 60s (capped). Kept
// separate for unit-testability of the backoff curve.
func scionStartupRetrySleep(attempt int) time.Duration {
	const (
		base = 5 * time.Second
		cap_ = 60 * time.Second
	)
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 4 {
		shift = 4
	}
	d := base * time.Duration(1<<shift)
	if d > cap_ {
		d = cap_
	}
	return d
}

// retrySCIONStartup runs until SCION connects or the Conn shuts down. Not
// to be confused with reconnectSCION (triggered mid-session by send
// errors). This loop exists specifically to recover from a failed initial
// bootstrap without requiring manual ReconfigureSCION.
func (c *Conn) retrySCIONStartup(ctx context.Context) {
	defer c.scionStartupRetryActive.Store(false)
	for attempt := 1; ; attempt++ {
		sleep := scionStartupRetrySleep(attempt)
		select {
		case <-c.donec:
			return
		case <-time.After(sleep):
		}
		if scionDisabled() {
			// User turned SCION off while a retry loop was in flight; bail.
			return
		}
		if c.pconnSCION.Load() != nil {
			// Another code path (reconnectSCION, ReconfigureSCION) got there
			// first; we're done.
			return
		}
		sc, err := trySCIONConnect(ctx, c.logf, c.netMon)
		if err != nil {
			c.logf("magicsock: SCION connect retry %d failed (next in %v): %v",
				attempt, scionStartupRetrySleep(attempt+1), err)
			c.recordSCIONConnectError(err)
			continue
		}
		c.logf("magicsock: SCION connect retry %d succeeded, local IA: %s", attempt, sc.localIA)
		c.pconnSCION.Store(sc)
		c.recordSCIONConnectError(nil)
		c.signalSCIONConnReady()
		go c.refreshSCIONPaths()
		// Peers that arrived via netmap updates before SCION came up were
		// skipped by updateFromNodeSCIONLocked because pconnSCION was nil
		// at the time. Walk the current netmap and kick discovery for any
		// SCION-advertising peer that isn't yet tracked. Without this, those
		// peers would remain on UDP/DERP until their next netmap refresh.
		go c.discoverNewSCIONPeers()
		return
	}
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
