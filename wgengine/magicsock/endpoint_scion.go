// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"cmp"
	"slices"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
)

// heartbeatSCIONLocked handles SCION-specific heartbeat logic.
// When the best address is not SCION, it heartbeats all SCION paths so they
// can compete via betterAddr. When the best IS SCION and there are multiple
// paths, it probes non-best paths via round-robin.
// de.mu must be held.
func (de *endpoint) heartbeatSCIONLocked(now mono.Time) {
	if de.scionState == nil || de.c.pconnSCION == nil {
		return
	}
	if !de.bestAddr.isSCION() {
		// Even when the current best path is "good enough" to skip a full ping
		// round, heartbeat all SCION paths so they can compete via betterAddr.
		// Without this, SCION never gets pinged once a low-latency direct path
		// suppresses wantFullPingLocked.
		for pk, ps := range de.scionState.paths {
			if !ps.lastPing.IsZero() && now.Sub(ps.lastPing) < discoPingInterval {
				continue
			}
			ps.lastPing = now
			ps.pingsSent++
			scionEp := epAddr{
				ap:       de.scionState.hostAddr,
				scionKey: pk,
			}
			de.startDiscoPingLocked(scionEp, now, pingHeartbeat, 0, nil)
		}
	} else if len(de.scionState.paths) > 1 {
		// Probe non-best SCION paths one at a time via round-robin so
		// latency data stays fresh for re-evaluation.
		de.probeSCIONNonBestLocked(now)
	}
}

// sendDiscoPingsSCIONLocked pings all SCION paths for this peer during a
// full discovery round. Returns true if SCION is available for this peer.
// de.mu must be held.
func (de *endpoint) sendDiscoPingsSCIONLocked(now mono.Time) bool {
	if de.scionState == nil || de.c.pconnSCION == nil {
		return false
	}
	for pk, ps := range de.scionState.paths {
		if !ps.lastPing.IsZero() && now.Sub(ps.lastPing) < discoPingInterval {
			continue
		}
		ps.lastPing = now
		ps.pingsSent++
		scionEp := epAddr{
			ap:       de.scionState.hostAddr,
			scionKey: pk,
		}
		de.startDiscoPingLocked(scionEp, now, pingDiscovery, 0, nil)
	}
	return true
}

// cliPingSCIONLocked pings all SCION paths when the user runs "tailscale ping".
// de.mu must be held.
func (de *endpoint) cliPingSCIONLocked(now mono.Time, size int, resCB *pingResultAndCallback) {
	if de.scionState == nil || de.c.pconnSCION == nil {
		return
	}
	for pk := range de.scionState.paths {
		scionEp := epAddr{
			ap:       de.scionState.hostAddr,
			scionKey: pk,
		}
		de.startDiscoPingLocked(scionEp, now, pingCLI, size, resCB)
	}
}

// discoPingTimeoutSCIONLocked handles disco ping timeout for SCION paths,
// tracking consecutive loss and demoting unhealthy paths.
// de.mu must be held.
func (de *endpoint) discoPingTimeoutSCIONLocked(sp sentPing) {
	if !sp.to.scionKey.IsSet() || de.scionState == nil {
		return
	}
	ps, ok := de.scionState.paths[sp.to.scionKey]
	if !ok {
		return
	}
	ps.consecutiveLoss++
	if ps.consecutiveLoss >= 3 && ps.healthy {
		ps.healthy = false
		de.c.logf("magicsock: SCION path %d unhealthy for %v (loss: %d)",
			sp.to.scionKey, de.publicKey.ShortString(), ps.consecutiveLoss)
		de.demoteSCIONPathLocked(sp.to.scionKey)
	}
}

// handlePongSCIONLocked records a pong measurement for a SCION path and
// triggers re-evaluation of path latencies.
// de.mu must be held.
func (de *endpoint) handlePongSCIONLocked(src epAddr, latency time.Duration, now mono.Time) {
	if !src.scionKey.IsSet() || de.scionState == nil {
		return
	}
	if ps, ok := de.scionState.paths[src.scionKey]; ok {
		ps.addPongReply(scionPongReply{
			latency: latency,
			pongAt:  now,
		})
		ps.pongsReceived++
		ps.consecutiveLoss = 0
		if !ps.healthy {
			ps.healthy = true
			de.c.logf("magicsock: SCION path %d recovered for %v", src.scionKey, de.publicKey.ShortString())
		}
	}
	de.reEvalSCIONPathsLocked(now)
}

// handlePongPromoteSCIONLocked updates the SCION activePath after bestAddr
// switches to a SCION path via pong promotion.
// de.mu must be held.
func (de *endpoint) handlePongPromoteSCIONLocked(thisPong addrQuality) {
	if !thisPong.epAddr.scionKey.IsSet() || de.scionState == nil {
		return
	}
	de.scionState.activePath = thisPong.epAddr.scionKey
	go de.c.updateActiveSCIONPathLocking(de.scionState.peerIA, de.scionState.hostAddr, thisPong.epAddr.scionKey)
}

// updateFromNodeSCIONLocked handles the SCION-specific parts of updateFromNode:
// detects new/changed SCION service advertisements, triggers path discovery,
// and computes SCION preference. Returns old SCION path keys that need cleanup
// outside de.mu (lock order: c.mu before de.mu).
// de.mu must be held.
func (de *endpoint) updateFromNodeSCIONLocked(n tailcfg.NodeView) []scionPathKey {
	var oldSCIONKeys []scionPathKey
	if peerIA, hostAddr, ok := scionServiceFromPeer(n); ok {
		if de.scionState == nil || de.scionState.peerIA != peerIA || de.scionState.hostAddr != hostAddr {
			// New or changed SCION address — discover paths asynchronously
			// to avoid blocking updateFromNode (which holds the endpoint lock).
			if de.c.pconnSCION != nil {
				de.c.logf("magicsock: SCION peer %s at %s, discovering paths...", peerIA, hostAddr)
				go de.discoverSCIONPathAsync(peerIA, hostAddr)
			} else {
				de.c.logf("magicsock: peer has SCION (%s) but local SCION not available", peerIA)
			}
		}
	} else if de.scionState != nil {
		// Peer no longer advertises SCION.
		for k := range de.scionState.paths {
			oldSCIONKeys = append(oldSCIONKeys, k)
		}
		de.scionState = nil
	}

	// Check if SCION should be preferred for this peer.
	peerSCIONPrefer := n.CapMap().Contains(tailcfg.NodeAttrSCIONPrefer)
	selfSCIONPrefer := de.c.self.Valid() && de.c.self.CapMap().Contains(tailcfg.NodeAttrSCIONPrefer)
	de.scionPreferred = peerSCIONPrefer && selfSCIONPrefer && de.scionState != nil

	return oldSCIONKeys
}

// stopAndResetSCIONLocked extracts SCION path keys for cleanup before the
// endpoint state is cleared. Returns keys that need cleanup outside de.mu.
// de.mu must be held.
func (de *endpoint) stopAndResetSCIONLocked() []scionPathKey {
	if de.scionState == nil {
		return nil
	}
	var keys []scionPathKey
	for k := range de.scionState.paths {
		keys = append(keys, k)
	}
	de.scionState = nil
	return keys
}

// sendSCIONData sends WireGuard data over a SCION path, handling error
// recovery (re-discovery) and metrics. Called from send() after de.mu is released.
func (de *endpoint) sendSCIONData(udpAddr epAddr, buffs [][]byte, offset int) error {
	_, err := de.c.sendSCIONBatch(udpAddr, buffs, offset)
	if err != nil {
		de.noteBadEndpoint(udpAddr)
		// Trigger re-discovery so we don't wait up to 30s for the
		// periodic refreshSCIONPaths to fix an expired path.
		// discoverSCIONPathAsync self-throttles to once per 5s.
		de.mu.Lock()
		st := de.scionState
		de.mu.Unlock()
		if st != nil {
			go de.discoverSCIONPathAsync(st.peerIA, st.hostAddr)
		}
	} else if de.c.metrics != nil {
		var txBytes int
		for _, b := range buffs {
			txBytes += len(b[offset:])
		}
		de.c.metrics.outboundPacketsSCIONTotal.Add(int64(len(buffs)))
		de.c.metrics.outboundBytesSCIONTotal.Add(int64(txBytes))
	}
	return err
}

// probeSCIONNonBestLocked probes one non-active SCION path per call using
// round-robin ordering. This keeps latency data fresh for paths that aren't
// currently the active path, enabling re-evaluation to detect better options.
// de.mu must be held.
func (de *endpoint) probeSCIONNonBestLocked(now mono.Time) {
	if de.scionState == nil {
		return
	}

	// Collect non-active path keys and sort for deterministic ordering.
	var nonBest []scionPathKey
	for k := range de.scionState.paths {
		if k != de.scionState.activePath {
			nonBest = append(nonBest, k)
		}
	}
	if len(nonBest) == 0 {
		return
	}
	slices.SortFunc(nonBest, func(a, b scionPathKey) int {
		return cmp.Compare(a, b)
	})

	// Pick one via round-robin.
	idx := de.scionState.probeRoundRobin % len(nonBest)
	de.scionState.probeRoundRobin++
	pk := nonBest[idx]
	ps := de.scionState.paths[pk]

	// Rate limit per path.
	if !ps.lastPing.IsZero() && now.Sub(ps.lastPing) < discoPingInterval {
		return
	}
	ps.lastPing = now
	ps.pingsSent++
	scionEp := epAddr{
		ap:       de.scionState.hostAddr,
		scionKey: pk,
	}
	de.startDiscoPingLocked(scionEp, now, pingHeartbeat, 0, nil)
}

// demoteSCIONPathLocked is called when a SCION path is marked unhealthy.
// It finds the best remaining healthy path by measured latency and switches
// activePath and bestAddr if the demoted path was active/best.
// de.mu must be held.
func (de *endpoint) demoteSCIONPathLocked(demotedKey scionPathKey) {
	if de.scionState == nil {
		return
	}

	// Find best healthy path by measured latency.
	var bestKey scionPathKey
	var bestLatency time.Duration
	for k, ps := range de.scionState.paths {
		if k == demotedKey || !ps.healthy {
			continue
		}
		lat := ps.latency()
		if !bestKey.IsSet() || lat < bestLatency {
			bestKey = k
			bestLatency = lat
		}
	}

	// Only act if the demoted path was the active path.
	if de.scionState.activePath != demotedKey {
		return
	}

	if bestKey.IsSet() {
		de.scionState.activePath = bestKey
		newAddr := addrQuality{
			epAddr:         epAddr{ap: de.scionState.hostAddr, scionKey: bestKey},
			latency:        bestLatency,
			wireMTU:        scionWireMTU,
			scionPreferred: de.scionPreferred,
		}
		de.c.logf("magicsock: SCION path demoted, switching to %s for %v", de.scionAddrStr(newAddr.epAddr), de.publicKey.ShortString())
		de.setBestAddrLocked(newAddr)
		go de.c.updateActiveSCIONPathLocking(de.scionState.peerIA, de.scionState.hostAddr, bestKey)
	} else {
		// No healthy SCION paths remain. Clear SCION bestAddr to fall back.
		de.scionState.activePath = 0
		if de.bestAddr.isSCION() {
			de.c.logf("magicsock: no healthy SCION paths for %v, clearing bestAddr", de.publicKey.ShortString())
			de.clearBestAddrLocked()
		}
	}
}

// scionReEvalInterval is the minimum time between SCION path re-evaluations.
const scionReEvalInterval = 2 * time.Second

// reEvalSCIONPathsLocked re-evaluates all SCION paths by measured latency
// after a pong is recorded. Throttled to scionReEvalInterval. If a healthier,
// lower-latency path is found, switches bestAddr and activePath. Incumbent
// bias prevents flapping between paths with similar latency.
// de.mu must be held.
func (de *endpoint) reEvalSCIONPathsLocked(now mono.Time) {
	if de.scionState == nil || len(de.scionState.paths) < 2 {
		return
	}
	if !de.scionState.lastFullEvalAt.IsZero() && now.Sub(de.scionState.lastFullEvalAt) < scionReEvalInterval {
		return
	}
	de.scionState.lastFullEvalAt = now

	// Check all paths have at least 1 pong measurement.
	for _, ps := range de.scionState.paths {
		if ps.pongCount == 0 {
			return
		}
	}

	// Find the healthy path with lowest measured latency.
	var bestKey scionPathKey
	var bestLatency time.Duration
	for k, ps := range de.scionState.paths {
		if !ps.healthy {
			continue
		}
		lat := ps.latency()
		if !bestKey.IsSet() || lat < bestLatency {
			bestKey = k
			bestLatency = lat
		}
	}

	if !bestKey.IsSet() || bestKey == de.scionState.activePath {
		return
	}

	// Require meaningful improvement over active path to avoid flapping
	// between paths with similar latency. The candidate must be ≥20% faster
	// or ≥2ms faster (whichever threshold is smaller).
	if activePS, ok := de.scionState.paths[de.scionState.activePath]; ok && activePS.healthy {
		activeLat := activePS.latency()
		threshold := activeLat / 5 // 20%
		if minThreshold := 2 * time.Millisecond; threshold < minThreshold {
			threshold = minThreshold
		}
		if activeLat-bestLatency < threshold {
			return
		}
	}

	candidate := addrQuality{
		epAddr:         epAddr{ap: de.scionState.hostAddr, scionKey: bestKey},
		latency:        bestLatency,
		wireMTU:        scionWireMTU,
		scionPreferred: de.scionPreferred,
	}

	if betterAddr(candidate, de.bestAddr) {
		de.c.logf("magicsock: SCION re-eval: switching to %s (latency %v) for %v",
			de.scionAddrStr(candidate.epAddr), bestLatency.Round(time.Millisecond), de.publicKey.ShortString())
		de.debugUpdates.Add(EndpointChange{
			When: time.Now(),
			What: "reEvalSCIONPathsLocked-switch",
			From: de.bestAddr,
			To:   candidate,
		})
		de.setBestAddrLocked(candidate)
		de.scionState.activePath = bestKey
		go de.c.updateActiveSCIONPathLocking(de.scionState.peerIA, de.scionState.hostAddr, bestKey)
	}
}

// scionAddrStr returns a human-readable string for a SCION epAddr using
// cached path info from de.scionState. Falls back to e.String().
// de.mu must be held.
func (de *endpoint) scionAddrStr(e epAddr) string {
	if !e.scionKey.IsSet() || de.scionState == nil {
		return e.String()
	}
	if ps, ok := de.scionState.paths[e.scionKey]; ok && ps.displayStr != "" {
		return ps.displayStr
	}
	return e.String()
}
