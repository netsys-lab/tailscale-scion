// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/types/key"
)

func Test_peerMap_oneRelayEpAddrPerNK(t *testing.T) {
	pm := newPeerMap()
	nk := key.NewNode().Public()
	ep := &endpoint{
		nodeID:    1,
		publicKey: nk,
	}
	ed := &endpointDisco{key: key.NewDisco().Public()}
	ep.disco.Store(ed)
	pm.upsertEndpoint(ep, key.DiscoPublic{})
	vni := packet.VirtualNetworkID{}
	vni.Set(1)
	relayEpAddrA := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:1"), vni: vni}
	relayEpAddrB := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:2"), vni: vni}
	pm.setNodeKeyForEpAddr(relayEpAddrA, nk)
	pm.setNodeKeyForEpAddr(relayEpAddrB, nk)
	if len(pm.byEpAddr) != 1 {
		t.Fatalf("expected 1 epAddr in byEpAddr, got: %d", len(pm.byEpAddr))
	}
	got := pm.relayEpAddrByNodeKey[nk]
	if got != relayEpAddrB {
		t.Fatalf("expected relay epAddr %v, got: %v", relayEpAddrB, got)
	}
}

// Test_peerMap_setNodeKeyForEpAddrIfAbsent verifies that the no-clobber
// variant (a) writes when the mapping is absent, (b) is idempotent when the
// mapping already points at the same node key, and (c) refuses and
// increments metricPeerMapAddrCollision when a different node already owns
// the address. This is the safeguard for SCION plain-addr dual-registration
// where two peers could otherwise fight over a shared underlay IP:port.
func Test_peerMap_setNodeKeyForEpAddrIfAbsent(t *testing.T) {
	pm := newPeerMap()

	nkA := key.NewNode().Public()
	epA := &endpoint{nodeID: 1, publicKey: nkA}
	epA.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	pm.upsertEndpoint(epA, key.DiscoPublic{})

	nkB := key.NewNode().Public()
	epB := &endpoint{nodeID: 2, publicKey: nkB}
	epB.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	pm.upsertEndpoint(epB, key.DiscoPublic{})

	shared := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:32766")}

	// (a) First write succeeds.
	if !pm.setNodeKeyForEpAddrIfAbsent(shared, nkA) {
		t.Fatal("first write should succeed")
	}
	if pi := pm.byEpAddr[shared]; pi == nil || pi.ep.publicKey != nkA {
		t.Fatal("mapping not installed for nkA")
	}

	before := metricPeerMapAddrCollision.Value()

	// (b) Re-writing the same mapping is idempotent.
	if !pm.setNodeKeyForEpAddrIfAbsent(shared, nkA) {
		t.Fatal("idempotent rewrite should succeed")
	}
	if metricPeerMapAddrCollision.Value() != before {
		t.Error("idempotent rewrite should not count as collision")
	}

	// (c) Attempt to clobber with a different node key is refused.
	if pm.setNodeKeyForEpAddrIfAbsent(shared, nkB) {
		t.Fatal("clobber attempt should be refused")
	}
	if got := metricPeerMapAddrCollision.Value() - before; got != 1 {
		t.Errorf("collision counter delta = %d; want 1", got)
	}
	// Mapping must still point at nkA.
	if pi := pm.byEpAddr[shared]; pi == nil || pi.ep.publicKey != nkA {
		t.Fatal("refused write must not mutate mapping")
	}
}
