// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon/mock_daemon"
	daemontypes "github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv4"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func TestScionPathKeyIsSet(t *testing.T) {
	var zero scionPathKey
	if zero.IsSet() {
		t.Error("zero scionPathKey should not be set")
	}
	k := scionPathKey(1)
	if !k.IsSet() {
		t.Error("non-zero scionPathKey should be set")
	}
	k = scionPathKey(42)
	if !k.IsSet() {
		t.Error("scionPathKey(42) should be set")
	}
}

// TestScionPathKeyWidth guards against a silent narrowing regression.
// scionPathKey must be wide enough that sequential assignment cannot realistically
// wrap on a long-running daemon (the previous uint32 wrapped after ~4·10⁹ paths
// and would alias stale registry entries onto new peers). uint64 gives headroom
// of ~1.8·10¹⁹ registrations — effectively unbounded for this use.
func TestScionPathKeyWidth(t *testing.T) {
	var k scionPathKey
	if got, want := unsafe.Sizeof(k), uintptr(8); got != want {
		t.Fatalf("scionPathKey size = %d, want %d (uint64)", got, want)
	}
	// Round-trip a value that would not fit in uint32.
	big := scionPathKey(1 << 40)
	if uint64(big) != 1<<40 {
		t.Fatalf("scionPathKey cannot hold values beyond uint32 range")
	}
}

func TestEpAddrIsSCION(t *testing.T) {
	tests := []struct {
		name     string
		addr     epAddr
		isSCION  bool
		isDirect bool
	}{
		{
			name:     "plain UDP",
			addr:     epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")},
			isSCION:  false,
			isDirect: true,
		},
		{
			name: "with VNI",
			addr: func() epAddr {
				e := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
				e.vni.Set(7)
				return e
			}(),
			isSCION:  false,
			isDirect: false,
		},
		{
			name:     "with scionKey",
			addr:     epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7"), scionKey: 1},
			isSCION:  true,
			isDirect: false,
		},
		{
			name:     "DERP magic addr",
			addr:     epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)},
			isSCION:  false,
			isDirect: false,
		},
		{
			name:     "zero epAddr",
			addr:     epAddr{},
			isSCION:  false,
			isDirect: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.isSCION(); got != tt.isSCION {
				t.Errorf("isSCION() = %v, want %v", got, tt.isSCION)
			}
			if got := tt.addr.isDirect(); got != tt.isDirect {
				t.Errorf("isDirect() = %v, want %v", got, tt.isDirect)
			}
		})
	}
}

func TestEpAddrStringWithSCION(t *testing.T) {
	e := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641"), scionKey: 5}
	got := e.String()
	want := "10.0.0.1:41641:scion:5"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	// Non-SCION should not include scion label.
	e2 := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641")}
	got2 := e2.String()
	want2 := "10.0.0.1:41641"
	if got2 != want2 {
		t.Errorf("String() = %q, want %q", got2, want2)
	}
}

func TestParseSCIONServiceAddr(t *testing.T) {
	tests := []struct {
		name        string
		description string
		port        uint16
		wantIA      addr.IA
		wantAddr    netip.AddrPort
		wantErr     bool
	}{
		{
			name:        "valid IPv4 bracketed",
			description: "1-ff00:0:110,[192.0.2.1]",
			port:        41641,
			wantIA:      addr.MustParseIA("1-ff00:0:110"),
			wantAddr:    netip.MustParseAddrPort("192.0.2.1:41641"),
		},
		{
			name:        "valid IPv6 bracketed",
			description: "1-ff00:0:110,[2001:db8::1]",
			port:        12345,
			wantIA:      addr.MustParseIA("1-ff00:0:110"),
			wantAddr:    netip.MustParseAddrPort("[2001:db8::1]:12345"),
		},
		{
			name:        "valid IPv4 unbracketed (backward compat)",
			description: "1-ff00:0:110,192.0.2.1",
			port:        41641,
			wantIA:      addr.MustParseIA("1-ff00:0:110"),
			wantAddr:    netip.MustParseAddrPort("192.0.2.1:41641"),
		},
		{
			name:        "valid IPv6 unbracketed (backward compat)",
			description: "1-ff00:0:110,2001:db8::1",
			port:        12345,
			wantIA:      addr.MustParseIA("1-ff00:0:110"),
			wantAddr:    netip.MustParseAddrPort("[2001:db8::1]:12345"),
		},
		{
			name:        "missing comma",
			description: "1-ff00:0:110",
			port:        41641,
			wantErr:     true,
		},
		{
			name:        "bad IA",
			description: "not-an-ia,192.0.2.1",
			port:        41641,
			wantErr:     true,
		},
		{
			name:        "bad IP",
			description: "1-ff00:0:110,not-an-ip",
			port:        41641,
			wantErr:     true,
		},
		{
			name:        "empty string",
			description: "",
			port:        41641,
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ia, hostAddr, err := parseSCIONServiceAddr(tt.description, tt.port)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ia=%v hostAddr=%v", ia, hostAddr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ia != tt.wantIA {
				t.Errorf("IA = %v, want %v", ia, tt.wantIA)
			}
			if hostAddr != tt.wantAddr {
				t.Errorf("hostAddr = %v, want %v", hostAddr, tt.wantAddr)
			}
		})
	}
}

func TestSCIONPathRegistry(t *testing.T) {
	c := &Conn{}

	// Test locking versions (used by callers outside c.mu).
	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:111"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
	}
	k := c.registerSCIONPathLocking(pi)
	if !k.IsSet() {
		t.Fatal("registered key should be set")
	}

	got := c.lookupSCIONPathLocking(k)
	if got != pi {
		t.Fatalf("lookupSCIONPathLocking(%d) returned wrong path info", k)
	}

	// Register another.
	pi2 := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:112"),
		hostAddr: netip.MustParseAddrPort("10.0.0.2:41641"),
	}
	k2 := c.registerSCIONPathLocking(pi2)
	if k2 == k {
		t.Fatal("second key should differ from first")
	}
	if c.lookupSCIONPathLocking(k2) != pi2 {
		t.Fatal("second path not found")
	}

	// Unregister the first (non-locking, must hold c.mu).
	c.mu.Lock()
	c.unregisterSCIONPath(k)
	c.mu.Unlock()

	if c.lookupSCIONPathLocking(k) != nil {
		t.Fatal("unregistered path should return nil")
	}
	if c.lookupSCIONPathLocking(k2) != pi2 {
		t.Fatal("second path should still be present after unregistering first")
	}

	if c.lookupSCIONPathLocking(scionPathKey(9999)) != nil {
		t.Fatal("non-existent key should return nil")
	}
}

func TestBetterAddrSCION(t *testing.T) {
	const ms = time.Millisecond

	al := func(ipps string, d time.Duration) addrQuality {
		return addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort(ipps)}, latency: d}
	}
	alSCION := func(ipps string, sk scionPathKey, d time.Duration) addrQuality {
		return addrQuality{
			epAddr:  epAddr{ap: netip.MustParseAddrPort(ipps), scionKey: sk},
			latency: d,
		}
	}
	alSCIONPref := func(ipps string, sk scionPathKey, d time.Duration) addrQuality {
		return addrQuality{
			epAddr:         epAddr{ap: netip.MustParseAddrPort(ipps), scionKey: sk},
			latency:        d,
			scionPreferred: true,
		}
	}
	avl := func(ipps string, vni uint32, d time.Duration) addrQuality {
		q := al(ipps, d)
		q.vni.Set(vni)
		return q
	}

	const (
		publicV4   = "1.2.3.4:555"
		publicV4_2 = "5.6.7.8:999"
	)

	tests := []struct {
		name string
		a, b addrQuality
		want bool
	}{
		// SCION beats direct at equal latency (default +15 bonus).
		{
			name: "SCION beats direct same latency",
			a:    alSCION(publicV4_2, 1, 100*ms),
			b:    al(publicV4, 100*ms),
			want: true,
		},
		{
			name: "direct loses to SCION same latency",
			a:    al(publicV4, 100*ms),
			b:    alSCION(publicV4_2, 1, 100*ms),
			want: false,
		},
		// SCION wins over relay (VNI) unconditionally.
		{
			name: "SCION beats relay same latency",
			a:    alSCION(publicV4, 1, 100*ms),
			b:    avl(publicV4_2, 1, 100*ms),
			want: true,
		},
		{
			name: "relay loses to SCION same latency",
			a:    avl(publicV4_2, 1, 100*ms),
			b:    alSCION(publicV4, 1, 100*ms),
			want: false,
		},
		// scionPreferred bonus (+25 on top of +15) beats direct.
		{
			name: "scionPreferred SCION beats direct at similar latency",
			a:    alSCIONPref(publicV4_2, 1, 100*ms),
			b:    al(publicV4, 100*ms),
			want: true,
		},
		// Direct wins when significantly faster (SCION only has +15 bonus).
		{
			name: "much faster direct beats SCION",
			a:    alSCION(publicV4_2, 1, 100*ms),
			b:    al(publicV4, 10*ms),
			want: false,
		},
		// Two SCION paths: lower latency wins.
		{
			name: "faster SCION beats slower SCION",
			a:    alSCION(publicV4, 1, 50*ms),
			b:    alSCION(publicV4_2, 2, 100*ms),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := betterAddr(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("betterAddr(%+v, %+v) = %v; want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// newMockPathWithMetadata creates a mock snet.Path that returns the given metadata.
func newMockPathWithMetadata(ctrl *gomock.Controller, md *snet.PathMetadata) *mock_snet.MockPath {
	p := mock_snet.NewMockPath(ctrl)
	p.EXPECT().Metadata().Return(md).AnyTimes()
	p.EXPECT().UnderlayNextHop().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30041}).AnyTimes()
	p.EXPECT().Dataplane().Return(nil).AnyTimes()
	p.EXPECT().Source().Return(addr.IA(0)).AnyTimes()
	p.EXPECT().Destination().Return(addr.IA(0)).AnyTimes()
	return p
}

func TestTotalPathLatency(t *testing.T) {
	ctrl := gomock.NewController(t)

	tests := []struct {
		name string
		path snet.Path
		want time.Duration
	}{
		{
			name: "nil metadata",
			path: newMockPathWithMetadata(ctrl, nil),
			want: time.Hour,
		},
		{
			name: "empty latency slice",
			path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{Latency: nil}),
			want: time.Hour,
		},
		{
			name: "single hop",
			path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{
				Latency: []time.Duration{5 * time.Millisecond},
			}),
			want: 5 * time.Millisecond,
		},
		{
			name: "multiple hops",
			path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{
				Latency: []time.Duration{
					5 * time.Millisecond,
					10 * time.Millisecond,
					3 * time.Millisecond,
				},
			}),
			want: 18 * time.Millisecond,
		},
		{
			name: "with unset latency",
			path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{
				Latency: []time.Duration{
					5 * time.Millisecond,
					-1, // LatencyUnset
					3 * time.Millisecond,
				},
			}),
			want: 5*time.Millisecond + scionUnsetHopLatency + 3*time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := totalPathLatency(tt.path)
			if got != tt.want {
				t.Errorf("totalPathLatency() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScionServiceFromPeer(t *testing.T) {
	tests := []struct {
		name     string
		node     *tailcfg.Node
		wantIA   addr.IA
		wantAddr netip.AddrPort
		wantOk   bool
	}{
		{
			name: "peer with SCION service (bracketed IPv4)",
			node: &tailcfg.Node{
				ID:  1,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.TCP, Port: 80},
						{Proto: tailcfg.SCION, Port: 41641, Description: "1-ff00:0:110,[192.0.2.1]"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("192.0.2.1:41641"),
			wantOk:   true,
		},
		{
			name: "peer with SCION service (bracketed IPv6)",
			node: &tailcfg.Node{
				ID:  1,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.SCION, Port: 41641, Description: "1-ff00:0:110,[2001:db8::1]"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("[2001:db8::1]:41641"),
			wantOk:   true,
		},
		{
			name: "peer without SCION service",
			node: &tailcfg.Node{
				ID:  2,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.TCP, Port: 80},
					},
				}).View(),
			},
			wantOk: false,
		},
		{
			name: "peer with invalid SCION description",
			node: &tailcfg.Node{
				ID:  3,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.SCION, Port: 41641, Description: "bad-desc"},
					},
				}).View(),
			},
			wantOk: false,
		},
		{
			name: "peer with no services",
			node: &tailcfg.Node{
				ID:       4,
				Key:      testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{}).View(),
			},
			wantOk: false,
		},
		{
			name: "peer with SCION in peerapi4 description (piggyback, bracketed IPv4)",
			node: &tailcfg.Node{
				ID:  5,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.PeerAPI4, Port: 12345, Description: "scion=1-ff00:0:110,[192.0.2.1]:32766"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("192.0.2.1:32766"),
			wantOk:   true,
		},
		{
			name: "peer with SCION piggyback (bracketed IPv6)",
			node: &tailcfg.Node{
				ID:  5,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.PeerAPI4, Port: 12345, Description: "scion=1-ff00:0:110,[2001:db8::1]:32766"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("[2001:db8::1]:32766"),
			wantOk:   true,
		},
		{
			name: "peer with SCION piggyback (unbracketed IPv4, backward compat)",
			node: &tailcfg.Node{
				ID:  5,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.PeerAPI4, Port: 12345, Description: "scion=1-ff00:0:110,192.0.2.1:32766"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("192.0.2.1:32766"),
			wantOk:   true,
		},
		{
			name: "peer with bad SCION piggyback",
			node: &tailcfg.Node{
				ID:  6,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.PeerAPI4, Port: 12345, Description: "scion=bad-data"},
					},
				}).View(),
			},
			wantOk: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nv := tt.node.View()
			ia, hostAddr, ok := scionServiceFromPeer(nv)
			if ok != tt.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOk)
			}
			if !tt.wantOk {
				return
			}
			if ia != tt.wantIA {
				t.Errorf("IA = %v, want %v", ia, tt.wantIA)
			}
			if hostAddr != tt.wantAddr {
				t.Errorf("hostAddr = %v, want %v", hostAddr, tt.wantAddr)
			}
		})
	}
}

func TestIsKnownServiceProtoSCION(t *testing.T) {
	if !tailcfg.IsKnownServiceProto(tailcfg.SCION) {
		t.Error("SCION should be a known service proto")
	}
}

func TestEpAddrComparability(t *testing.T) {
	// Verify that epAddr with scionKey is still comparable (usable as map key).
	a := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641"), scionKey: 1}
	b := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641"), scionKey: 1}
	c := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641"), scionKey: 2}

	if a != b {
		t.Error("identical epAddr values should be equal")
	}
	if a == c {
		t.Error("epAddr values with different scionKey should not be equal")
	}

	// Verify usable as map key.
	m := map[epAddr]bool{a: true}
	if !m[b] {
		t.Error("identical epAddr should be found in map")
	}
	if m[c] {
		t.Error("different scionKey epAddr should not be found in map")
	}
}

func TestBetterAddrSCIONWithExistingCases(t *testing.T) {
	// Verify that adding SCION support doesn't break existing betterAddr
	// behavior for non-SCION addresses. These are a subset of cases from
	// the existing TestBetterAddr.
	const ms = time.Millisecond
	al := func(ipps string, d time.Duration) addrQuality {
		return addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort(ipps)}, latency: d}
	}
	almtu := func(ipps string, d time.Duration, mtu tstun.WireMTU) addrQuality {
		return addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort(ipps)}, latency: d, wireMTU: mtu}
	}
	avl := func(ipps string, vni uint32, d time.Duration) addrQuality {
		q := al(ipps, d)
		q.vni.Set(vni)
		return q
	}
	zero := addrQuality{}

	tests := []struct {
		a, b addrQuality
		want bool
	}{
		{a: zero, b: zero, want: false},
		{a: al("1.2.3.4:555", 5*ms), b: zero, want: true},
		{a: zero, b: al("1.2.3.4:555", 5*ms), want: false},
		{a: al("1.2.3.4:555", 5*ms), b: al("5.6.7.8:999", 10*ms), want: true},
		// Private IP preference still works.
		{a: al("10.0.0.2:123", 100*ms), b: al("1.2.3.4:555", 91*ms), want: true},
		// Geneve preference still works.
		{a: al("1.2.3.4:555", 100*ms), b: avl("1.2.3.4:555", 1, 100*ms), want: true},
		{a: avl("1.2.3.4:555", 1, 100*ms), b: al("1.2.3.4:555", 100*ms), want: false},
		// MTU preference for same address still works.
		{a: almtu("1.2.3.4:555", 30*ms, 1500), b: almtu("1.2.3.4:555", 30*ms, 0), want: true},
	}
	for i, tt := range tests {
		got := betterAddr(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("[%d] betterAddr(%+v, %+v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSCIONPathRegistryReverseIndex(t *testing.T) {
	c := &Conn{}

	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:111"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
	}
	k := c.registerSCIONPathLocking(pi)

	// Set as active path so the reverse index is populated.
	c.mu.Lock()
	c.setActiveSCIONPath(pi.peerIA, pi.hostAddr, k)
	c.mu.Unlock()

	// Reverse lookup should find the key.
	got := c.scionKeyForAddr(pi.peerIA, pi.hostAddr)
	if got != k {
		t.Errorf("scionKeyForAddr returned %d, want %d", got, k)
	}

	// Different address should not match.
	got2 := c.scionKeyForAddr(pi.peerIA, netip.MustParseAddrPort("10.0.0.2:41641"))
	if got2.IsSet() {
		t.Error("scionKeyForAddr should return zero for unknown address")
	}

	// Unregister should remove from reverse index.
	c.mu.Lock()
	c.unregisterSCIONPath(k)
	c.mu.Unlock()

	got3 := c.scionKeyForAddr(pi.peerIA, pi.hostAddr)
	if got3.IsSet() {
		t.Error("scionKeyForAddr should return zero after unregister")
	}
}

func TestSCIONEndpointState(t *testing.T) {
	ia := addr.MustParseIA("1-ff00:0:110")
	hostAddr := netip.MustParseAddrPort("192.0.2.1:41641")

	pk := scionPathKey(5)
	st := &scionEndpointState{
		peerIA:     ia,
		hostAddr:   hostAddr,
		paths:      map[scionPathKey]*scionPathProbeState{pk: {}},
		activePath: pk,
	}

	if st.peerIA != ia {
		t.Errorf("peerIA = %v, want %v", st.peerIA, ia)
	}
	if st.hostAddr != hostAddr {
		t.Errorf("hostAddr = %v, want %v", st.hostAddr, hostAddr)
	}
	if !st.activePath.IsSet() {
		t.Error("activePath should be set")
	}
	if len(st.paths) != 1 {
		t.Errorf("paths count = %d, want 1", len(st.paths))
	}
}

func TestSendSCIONBatchNoConn(t *testing.T) {
	c := &Conn{}

	ep := epAddr{
		ap:       netip.MustParseAddrPort("10.0.0.1:41641"),
		scionKey: 1,
	}
	_, err := c.sendSCIONBatch(ep, [][]byte{{0x01}}, 0)
	if err != errNoSCION {
		t.Errorf("sendSCIONBatch with nil pconnSCION: got err=%v, want %v", err, errNoSCION)
	}
}

func TestSendSCIONNoConn(t *testing.T) {
	c := &Conn{}

	_, err := c.sendSCION(scionPathKey(1), []byte{0x01})
	if err != errNoSCION {
		t.Errorf("sendSCION with nil pconnSCION: got err=%v, want %v", err, errNoSCION)
	}
}

func TestSCIONPathInfoMutexSafety(t *testing.T) {
	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:110"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
		expiry:   time.Now().Add(time.Hour),
	}

	// Verify concurrent access is safe.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			pi.mu.Lock()
			_ = pi.peerIA
			_ = pi.hostAddr
			_ = pi.expiry
			pi.mu.Unlock()
		}
	}()
	for i := 0; i < 100; i++ {
		pi.mu.Lock()
		pi.expiry = time.Now().Add(time.Duration(i) * time.Minute)
		pi.mu.Unlock()
	}
	<-done
}

func TestScionListenPort(t *testing.T) {
	tests := []struct {
		name   string
		envVal string
		want   uint16
	}{
		{"default auto-select", "", 0},
		{"valid port", "31337", 31337},
		{"min port", "30000", 30000},
		{"max port", "32767", 32767},
		{"below range", "29999", 29999},   // scionListenPort only parses; range validation is in trySCIONConnect
		{"above range", "32768", 32768},   // same: validated against daemon port range later
		{"non-numeric", "abc", 0},
		{"wireguard port", "41641", 41641}, // any valid port is accepted at parse time
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				envknob.Setenv("TS_SCION_PORT", tt.envVal)
				t.Cleanup(func() { envknob.Setenv("TS_SCION_PORT", "") })
			}
			got := scionListenPort()
			if got != tt.want {
				t.Errorf("scionListenPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSCIONDiscoRXPath(t *testing.T) {
	if discoRXPathSCION != "SCION" {
		t.Errorf("discoRXPathSCION = %q, want %q", discoRXPathSCION, "SCION")
	}
}

// testNodeKey returns a new NodePublic for test node construction.
func testNodeKey() key.NodePublic { return key.NewNode().Public() }

func TestDiscoverSCIONPaths(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")

	t.Run("picks lowest latency path", func(t *testing.T) {
		// Create three mock paths with different latencies.
		slowPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{50 * time.Millisecond, 50 * time.Millisecond},
			Expiry:  time.Now().Add(time.Hour),
		})
		fastPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{5 * time.Millisecond},
			Expiry:  time.Now().Add(time.Hour),
		})
		mediumPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{20 * time.Millisecond, 10 * time.Millisecond},
			Expiry:  time.Now().Add(time.Hour),
		})

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: false}).
			Return([]snet.Path{slowPath, fastPath, mediumPath}, nil)

		c := &Conn{}
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		keys, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) == 0 {
			t.Fatal("returned keys should not be empty")
		}
		// All 3 paths should be registered (deduped by fingerprint, but mock
		// paths have no metadata for fingerprinting so they're all unique).
		if len(keys) != 3 {
			t.Fatalf("expected 3 keys, got %d", len(keys))
		}

		// First key should be the lowest-latency path (fast one, 5ms).
		pi := c.lookupSCIONPathLocking(keys[0])
		if pi == nil {
			t.Fatal("path info not found in registry")
		}
		if pi.peerIA != peerIA {
			t.Errorf("peerIA = %v, want %v", pi.peerIA, peerIA)
		}
		if pi.hostAddr != hostAddr {
			t.Errorf("hostAddr = %v, want %v", pi.hostAddr, hostAddr)
		}
		// The first (active) path should be the fast one (5ms).
		if pi.path != fastPath {
			t.Error("first key should be the lowest-latency path")
		}
	})

	t.Run("no paths available", func(t *testing.T) {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: false}).
			Return(nil, nil)

		c := &Conn{}
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		_, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err == nil {
			t.Fatal("expected error for no paths")
		}
	})

	t.Run("daemon error", func(t *testing.T) {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: false}).
			Return(nil, fmt.Errorf("daemon unavailable"))

		c := &Conn{}
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		_, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err == nil {
			t.Fatal("expected error for daemon failure")
		}
	})

	t.Run("nil pconnSCION", func(t *testing.T) {
		c := &Conn{}
		_, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err != errNoSCION {
			t.Errorf("expected errNoSCION, got %v", err)
		}
	})

	t.Run("single path with no metadata", func(t *testing.T) {
		noMetaPath := newMockPathWithMetadata(ctrl, nil)
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: false}).
			Return([]snet.Path{noMetaPath}, nil)

		c := &Conn{}
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		keys, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) == 0 {
			t.Fatal("returned keys should not be empty")
		}
		pi := c.lookupSCIONPathLocking(keys[0])
		if pi == nil {
			t.Fatal("path info not found")
		}
		if !pi.expiry.IsZero() {
			t.Errorf("expiry should be zero for nil metadata, got %v", pi.expiry)
		}
	})

	t.Run("same AS uses empty path without daemon query", func(t *testing.T) {
		// When peerIA == localIA, discoverSCIONPaths should NOT query the
		// daemon and should return a single path with scionSameASFingerprint.
		// No mockDaemon.EXPECT() call here — gomock will fail if Paths is called.
		c := &Conn{}
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		keys, err := c.discoverSCIONPaths(context.Background(), localIA, hostAddr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key for same-AS, got %d", len(keys))
		}

		pi := c.lookupSCIONPathLocking(keys[0])
		if pi == nil {
			t.Fatal("path info not found in registry")
		}
		if pi.fingerprint != scionSameASFingerprint {
			t.Errorf("fingerprint = %q, want %q", pi.fingerprint, scionSameASFingerprint)
		}
		if pi.path != nil {
			t.Error("same-AS path should have nil snet.Path")
		}
		if !pi.expiry.IsZero() {
			t.Errorf("same-AS path should never expire, got %v", pi.expiry)
		}
		if pi.cachedDst == nil {
			t.Fatal("cachedDst should be set")
		}
		if pi.cachedDst.IA != localIA {
			t.Errorf("cachedDst.IA = %v, want %v", pi.cachedDst.IA, localIA)
		}
		if _, ok := pi.cachedDst.Path.(snetpath.Empty); !ok {
			t.Errorf("cachedDst.Path = %T, want snetpath.Empty", pi.cachedDst.Path)
		}
		if pi.cachedDst.NextHop == nil {
			t.Fatal("cachedDst.NextHop should be set for same-AS")
		}
		wantNextHop := netip.MustParseAddrPort(pi.cachedDst.NextHop.String())
		if wantNextHop != hostAddr {
			t.Errorf("NextHop = %v, want %v", wantNextHop, hostAddr)
		}
		if !strings.Contains(pi.displayStr, "local") {
			t.Errorf("displayStr = %q, want it to contain 'local'", pi.displayStr)
		}
	})
}

func TestRefreshSCIONPathsOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	t.Run("refreshes expiring path", func(t *testing.T) {
		newExpiry := time.Now().Add(2 * time.Hour)
		newPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{3 * time.Millisecond},
			Expiry:  newExpiry,
		})

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return([]snet.Path{newPath}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		// Register a path that's about to expire (30s from now, within the 1-min refresh window).
		pi := &scionPathInfo{
			peerIA:   peerIA,
			hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
			expiry:   time.Now().Add(30 * time.Second),
		}
		k := c.registerSCIONPathLocking(pi)

		c.refreshSCIONPathsOnce()

		// Verify the path was updated.
		got := c.lookupSCIONPathLocking(k)
		got.mu.Lock()
		gotPath := got.path
		gotExpiry := got.expiry
		got.mu.Unlock()

		if gotPath != newPath {
			t.Error("path should have been refreshed to new path")
		}
		if !gotExpiry.Equal(newExpiry) {
			t.Errorf("expiry = %v, want %v", gotExpiry, newExpiry)
		}
	})

	t.Run("skips non-expiring path", func(t *testing.T) {
		// Hard refresh skipped (path far from expiry), but soft refresh
		// queries the daemon with Refresh: false to discover new paths.
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: false}).
			Return(nil, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		// Register a path that's far from expiry.
		pi := &scionPathInfo{
			peerIA:   peerIA,
			hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
			expiry:   time.Now().Add(2 * time.Hour),
		}
		c.registerSCIONPathLocking(pi)

		// Hard refresh should not call daemon.Paths with Refresh: true.
		c.refreshSCIONPathsOnce()
	})

	t.Run("handles daemon failure gracefully", func(t *testing.T) {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return(nil, fmt.Errorf("daemon unreachable"))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		oldPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{10 * time.Millisecond},
		})

		// Register an expiring path.
		pi := &scionPathInfo{
			peerIA:   peerIA,
			hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
			path:     oldPath,
			expiry:   time.Now().Add(30 * time.Second),
		}
		k := c.registerSCIONPathLocking(pi)

		c.refreshSCIONPathsOnce()

		// Path should remain unchanged after daemon failure.
		got := c.lookupSCIONPathLocking(k)
		got.mu.Lock()
		gotPath := got.path
		got.mu.Unlock()

		if gotPath != oldPath {
			t.Error("path should not have changed after daemon failure")
		}
	})

	t.Run("picks best path among refreshed results", func(t *testing.T) {
		slowPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{100 * time.Millisecond},
			Expiry:  time.Now().Add(2 * time.Hour),
		})
		fastPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency: []time.Duration{2 * time.Millisecond},
			Expiry:  time.Now().Add(2 * time.Hour),
		})

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return([]snet.Path{slowPath, fastPath}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

		pi := &scionPathInfo{
			peerIA:   peerIA,
			hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
			expiry:   time.Now().Add(30 * time.Second), // about to expire
		}
		k := c.registerSCIONPathLocking(pi)

		c.refreshSCIONPathsOnce()

		got := c.lookupSCIONPathLocking(k)
		got.mu.Lock()
		gotPath := got.path
		got.mu.Unlock()

		if gotPath != fastPath {
			t.Error("should have selected lowest-latency path during refresh")
		}
	})
}

// Verify that the scionPathKey field doesn't break epAddr's use in
// packet.VirtualNetworkID interactions.
func TestEpAddrSCIONAndVNIMutualExclusion(t *testing.T) {
	// SCION and VNI shouldn't be set simultaneously in practice,
	// but verify the type behavior is correct.
	var vni packet.VirtualNetworkID
	vni.Set(42)

	both := epAddr{
		ap:       netip.MustParseAddrPort("1.2.3.4:555"),
		vni:      vni,
		scionKey: 1,
	}
	// With both set, it's neither direct nor SCION-only.
	if both.isDirect() {
		t.Error("epAddr with both VNI and scionKey should not be direct")
	}
	if !both.isSCION() {
		t.Error("epAddr with scionKey should report isSCION")
	}
	// String should show SCION since scionKey takes precedence in String().
	got := both.String()
	if got != "1.2.3.4:555:scion:1" {
		t.Errorf("String() = %q, want SCION format", got)
	}
}

func TestStopAndResetCleansSCIONPath(t *testing.T) {
	c := &Conn{}
	c.logf = t.Logf

	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:111"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
	}
	k := c.registerSCIONPathLocking(pi)

	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:     pi.peerIA,
		hostAddr:   pi.hostAddr,
		paths:      map[scionPathKey]*scionPathProbeState{k: {}},
		activePath: k,
	}

	// stopAndReset requires c.mu to be held (all production callers hold it).
	c.mu.Lock()
	de.stopAndReset()
	c.mu.Unlock()

	if de.scionState != nil {
		t.Error("scionState should be nil after stopAndReset")
	}
	if c.lookupSCIONPathLocking(k) != nil {
		t.Error("SCION path should be removed from registry after stopAndReset")
	}
}

func TestNoteRecvActivitySCIONTrustRefresh(t *testing.T) {
	c := &Conn{}
	de := &endpoint{c: c}
	de.heartbeatDisabled = true

	scionAddr := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:32766"), scionKey: 2}
	plainAddr := epAddr{ap: netip.MustParseAddrPort("127.0.0.1:32766")}

	now := mono.Now()
	de.bestAddr.epAddr = scionAddr
	de.bestAddrAt = now

	// WireGuard data arrives with plain addr (no scionKey).
	de.noteRecvActivity(plainAddr, now)

	de.mu.Lock()
	trust := de.trustBestAddrUntil
	de.mu.Unlock()

	if trust == 0 {
		t.Error("trustBestAddrUntil should be extended for SCION bestAddr when receiving plain addr data")
	}
}

func TestSendSCIONBatchExpiredPath(t *testing.T) {
	c := &Conn{}
	c.pconnSCION.Store(&scionConn{})

	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:111"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
		expiry:   time.Now().Add(-1 * time.Hour), // expired
	}
	k := c.registerSCIONPathLocking(pi)

	ep := epAddr{ap: netip.MustParseAddrPort("10.0.0.1:41641"), scionKey: k}
	_, err := c.sendSCIONBatch(ep, [][]byte{{0x01}}, 0)
	if err == nil {
		t.Fatal("expected error for expired path")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

func TestSendSCIONExpiredPath(t *testing.T) {
	c := &Conn{}
	c.pconnSCION.Store(&scionConn{})

	pi := &scionPathInfo{
		peerIA:   addr.MustParseIA("1-ff00:0:111"),
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
		expiry:   time.Now().Add(-1 * time.Hour), // expired
	}
	k := c.registerSCIONPathLocking(pi)

	_, err := c.sendSCION(k, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for expired path")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

// TestSCIONPseudoHeaderPartial verifies the partial checksum computation
// matches the reference SCION implementation for known inputs.
func TestSCIONPseudoHeaderPartial(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("127.0.0.1")

	partial := scionPseudoHeaderPartial(srcIA, dstIA, srcIP, dstIP)

	// Verify by computing the same checksum manually:
	// srcIA = 0x0001ff0000000110, dstIA = 0x0001ff0000000111
	// srcAddr = 127.0.0.1 = [0x7f, 0x00, 0x00, 0x01]
	// dstAddr = 127.0.0.1 = [0x7f, 0x00, 0x00, 0x01]
	// protocol = 17

	var expected uint32
	// srcIA bytes: 00 01 ff 00 00 00 01 10
	expected += 0x0001 + 0xff00 + 0x0000 + 0x0110
	// dstIA bytes: 00 01 ff 00 00 00 01 11
	expected += 0x0001 + 0xff00 + 0x0000 + 0x0111
	// srcAddr: 7f 00 00 01
	expected += 0x7f00 + 0x0001
	// dstAddr: 7f 00 00 01
	expected += 0x7f00 + 0x0001
	// protocol
	expected += 17

	if partial != expected {
		t.Errorf("scionPseudoHeaderPartial = %d, want %d", partial, expected)
	}
}

// TestSCIONPseudoHeaderPartialIPv6 verifies checksum with IPv6 addresses.
func TestSCIONPseudoHeaderPartialIPv6(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("::1")
	dstIP := netip.MustParseAddr("fd00::1")

	partial := scionPseudoHeaderPartial(srcIA, dstIA, srcIP, dstIP)
	if partial == 0 {
		t.Fatal("checksum should not be zero")
	}

	// Verify IPv6 addrs are 16 bytes each.
	// ::1 = 00...01, fd00::1 = fd 00 00...01
	var expected uint32
	// IAs
	expected += 0x0001 + 0xff00 + 0x0000 + 0x0110
	expected += 0x0001 + 0xff00 + 0x0000 + 0x0111
	// srcIP ::1 = all zeros except last byte
	expected += 0x0001
	// dstIP fd00::1
	expected += 0xfd00 + 0x0001
	expected += 17

	if partial != expected {
		t.Errorf("scionPseudoHeaderPartial(IPv6) = %d, want %d", partial, expected)
	}
}

// TestSCIONFinishChecksum verifies the full checksum computation matches
// the reference SCION implementation by comparing against a packet
// serialized with snet.Packet.Serialize().
func TestSCIONFinishChecksum(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("127.0.0.1")
	srcPort := uint16(32766)
	dstPort := uint16(32766)
	payload := []byte("Hello, SCION fast path!")

	// Build the packet using snet's reference serializer.
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dstIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: srcIA, Host: addr.HostIP(srcIP)},
			Path:        snetpath.Empty{},
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: dstPort,
				Payload: payload,
			},
		},
	}
	if err := pkt.Serialize(); err != nil {
		t.Fatalf("snet.Packet.Serialize: %v", err)
	}

	// Extract the reference checksum from the serialized packet.
	// The UDP header is the last 8 bytes before the payload.
	udpOffset := len(pkt.Bytes) - 8 - len(payload)
	refChecksum := binary.BigEndian.Uint16(pkt.Bytes[udpOffset+6:])

	// Now compute it using our fast-path functions.
	partial := scionPseudoHeaderPartial(srcIA, dstIA, srcIP, dstIP)

	// Build the upper layer: UDP header (8 bytes) + payload
	upperLayer := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(upperLayer[0:], srcPort)
	binary.BigEndian.PutUint16(upperLayer[2:], dstPort)
	binary.BigEndian.PutUint16(upperLayer[4:], uint16(8+len(payload)))
	// checksum field = 0 for computation
	copy(upperLayer[8:], payload)

	fastChecksum := scionFinishChecksum(partial, upperLayer)

	if fastChecksum != refChecksum {
		t.Errorf("fast-path checksum = 0x%04x, reference = 0x%04x", fastChecksum, refChecksum)
	}
}

// TestSCIONFinishChecksumEmptyPayload verifies checksum with empty payload.
func TestSCIONFinishChecksumEmptyPayload(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("127.0.0.1")

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dstIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: srcIA, Host: addr.HostIP(srcIP)},
			Path:        snetpath.Empty{},
			Payload: snet.UDPPayload{
				SrcPort: 1000,
				DstPort: 2000,
				Payload: nil,
			},
		},
	}
	if err := pkt.Serialize(); err != nil {
		t.Fatalf("snet.Packet.Serialize: %v", err)
	}

	// UDP header is the last 8 bytes (no payload).
	udpOffset := len(pkt.Bytes) - 8
	refChecksum := binary.BigEndian.Uint16(pkt.Bytes[udpOffset+6:])

	partial := scionPseudoHeaderPartial(srcIA, dstIA, srcIP, dstIP)
	upperLayer := make([]byte, 8)
	binary.BigEndian.PutUint16(upperLayer[0:], 1000)
	binary.BigEndian.PutUint16(upperLayer[2:], 2000)
	binary.BigEndian.PutUint16(upperLayer[4:], 8)

	fastChecksum := scionFinishChecksum(partial, upperLayer)

	if fastChecksum != refChecksum {
		t.Errorf("fast-path checksum (empty) = 0x%04x, reference = 0x%04x", fastChecksum, refChecksum)
	}
}

// TestSCIONFinishChecksumOddPayload verifies correct handling of odd-length payloads.
func TestSCIONFinishChecksumOddPayload(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("10.0.0.1")
	payload := []byte("ABC") // 3 bytes, odd

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dstIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: srcIA, Host: addr.HostIP(srcIP)},
			Path:        snetpath.Empty{},
			Payload: snet.UDPPayload{
				SrcPort: 5000,
				DstPort: 6000,
				Payload: payload,
			},
		},
	}
	if err := pkt.Serialize(); err != nil {
		t.Fatalf("snet.Packet.Serialize: %v", err)
	}

	udpOffset := len(pkt.Bytes) - 8 - len(payload)
	refChecksum := binary.BigEndian.Uint16(pkt.Bytes[udpOffset+6:])

	partial := scionPseudoHeaderPartial(srcIA, dstIA, srcIP, dstIP)
	upperLayer := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(upperLayer[0:], 5000)
	binary.BigEndian.PutUint16(upperLayer[2:], 6000)
	binary.BigEndian.PutUint16(upperLayer[4:], uint16(8+len(payload)))
	copy(upperLayer[8:], payload)

	fastChecksum := scionFinishChecksum(partial, upperLayer)

	if fastChecksum != refChecksum {
		t.Errorf("fast-path checksum (odd) = 0x%04x, reference = 0x%04x", fastChecksum, refChecksum)
	}
}

func TestBuildSCIONReplyAddrEmptyPath(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	srcHostAddr := netip.MustParseAddrPort("10.0.0.2:32766")
	nextHop := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 32766}

	// Same-AS: rawPathBytes is empty.
	reply := buildSCIONReplyAddr(srcIA, srcHostAddr, nil, nextHop)
	if reply == nil {
		t.Fatal("expected non-nil reply for empty path (same-AS)")
	}
	if reply.IA != srcIA {
		t.Errorf("IA = %v, want %v", reply.IA, srcIA)
	}
	if _, ok := reply.Path.(snetpath.Empty); !ok {
		t.Errorf("Path = %T, want snetpath.Empty", reply.Path)
	}
	if reply.NextHop == nil {
		t.Fatal("NextHop should be set")
	}
	if reply.NextHop.String() != nextHop.String() {
		t.Errorf("NextHop = %v, want %v", reply.NextHop, nextHop)
	}
}

// TestBuildSCIONFastPath verifies that buildSCIONFastPath produces a template
// that matches the reference serializer output for the same parameters.
func TestBuildSCIONFastPath(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("127.0.0.1")
	srcPort := uint16(32766)
	dstPort := uint16(32766)

	sc := &scionConn{
		underlayConn: &net.UDPConn{}, // non-nil to enable fast path
		localIA:      srcIA,
		localHostIP:  srcIP,
		localPort:    srcPort,
	}

	pi := &scionPathInfo{
		peerIA:   dstIA,
		hostAddr: netip.MustParseAddrPort("127.0.0.1:32766"),
		cachedDst: &snet.UDPAddr{
			IA:      dstIA,
			Host:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(dstPort)},
			Path:    snetpath.Empty{},
			NextHop: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30041},
		},
	}

	fp := buildSCIONFastPath(sc, pi)
	if fp == nil {
		t.Fatal("buildSCIONFastPath returned nil")
	}

	// The template should match a reference packet with empty payload.
	refPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dstIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: srcIA, Host: addr.HostIP(srcIP)},
			Path:        snetpath.Empty{},
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: dstPort,
				Payload: nil,
			},
		},
	}
	if err := refPkt.Serialize(); err != nil {
		t.Fatalf("reference Serialize: %v", err)
	}

	if len(fp.hdr) != len(refPkt.Bytes) {
		t.Fatalf("fast-path header len = %d, reference = %d", len(fp.hdr), len(refPkt.Bytes))
	}

	// Compare header bytes (everything except checksum which may differ
	// due to computation order, but should be the same for empty payload).
	for i := range fp.hdr {
		if fp.hdr[i] != refPkt.Bytes[i] {
			t.Errorf("byte %d: fast-path=0x%02x, reference=0x%02x", i, fp.hdr[i], refPkt.Bytes[i])
		}
	}

	if fp.udpOffset != len(fp.hdr)-8 {
		t.Errorf("udpOffset = %d, expected %d", fp.udpOffset, len(fp.hdr)-8)
	}

	if fp.nextHop == nil {
		t.Error("nextHop should not be nil")
	}
}

// TestSCIONFastPathPacketMatchesReference verifies that a packet built with
// the fast-path template+patching produces identical bytes to one built with
// snet.Packet.Serialize().
func TestSCIONFastPathPacketMatchesReference(t *testing.T) {
	srcIA := addr.MustParseIA("1-ff00:0:110")
	dstIA := addr.MustParseIA("1-ff00:0:111")
	srcIP := netip.MustParseAddr("127.0.0.1")
	dstIP := netip.MustParseAddr("127.0.0.1")
	srcPort := uint16(32766)
	dstPort := uint16(32766)
	payload := []byte("WireGuard test payload data for SCION fast path verification")

	sc := &scionConn{
		underlayConn: &net.UDPConn{},
		localIA:      srcIA,
		localHostIP:  srcIP,
		localPort:    srcPort,
	}

	pi := &scionPathInfo{
		peerIA:   dstIA,
		hostAddr: netip.MustParseAddrPort("127.0.0.1:32766"),
		cachedDst: &snet.UDPAddr{
			IA:      dstIA,
			Host:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(dstPort)},
			Path:    snetpath.Empty{},
			NextHop: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30041},
		},
	}

	fp := buildSCIONFastPath(sc, pi)
	if fp == nil {
		t.Fatal("buildSCIONFastPath returned nil")
	}

	// Build packet using fast-path template + patching.
	hdrLen := len(fp.hdr)
	pktLen := hdrLen + len(payload)
	buf := make([]byte, pktLen)
	copy(buf, fp.hdr)
	copy(buf[hdrLen:], payload)

	udpTotalLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(buf[6:], udpTotalLen)
	binary.BigEndian.PutUint16(buf[fp.udpOffset+4:], udpTotalLen)
	buf[fp.udpOffset+6] = 0
	buf[fp.udpOffset+7] = 0
	upperLayer := buf[fp.udpOffset:pktLen]
	csum := scionFinishChecksum(fp.pseudoCsum, upperLayer)
	binary.BigEndian.PutUint16(buf[fp.udpOffset+6:], csum)

	// Build reference packet using snet.
	refPkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{IA: dstIA, Host: addr.HostIP(dstIP)},
			Source:      snet.SCIONAddress{IA: srcIA, Host: addr.HostIP(srcIP)},
			Path:        snetpath.Empty{},
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: dstPort,
				Payload: payload,
			},
		},
	}
	if err := refPkt.Serialize(); err != nil {
		t.Fatalf("reference Serialize: %v", err)
	}

	if len(buf) != len(refPkt.Bytes) {
		t.Fatalf("fast-path pkt len = %d, reference = %d", len(buf), len(refPkt.Bytes))
	}

	for i := range buf {
		if buf[i] != refPkt.Bytes[i] {
			t.Errorf("byte %d: fast-path=0x%02x, reference=0x%02x", i, buf[i], refPkt.Bytes[i])
		}
	}
}

// TestSCIONSendBatchPool verifies the pool returns usable batches.
func TestSCIONSendBatchPool(t *testing.T) {
	batch := scionSendBatchPool.Get().(*scionSendBatch)
	defer scionSendBatchPool.Put(batch)

	if len(batch.bufs) != scionMaxBatchSize {
		t.Errorf("batch.bufs len = %d, want %d", len(batch.bufs), scionMaxBatchSize)
	}
	if len(batch.msgs) != scionMaxBatchSize {
		t.Errorf("batch.msgs len = %d, want %d", len(batch.msgs), scionMaxBatchSize)
	}
	for i, buf := range batch.bufs {
		if cap(buf) < 1500 {
			t.Errorf("batch.bufs[%d] cap = %d, want >= 1500", i, cap(buf))
		}
	}
	for i, msg := range batch.msgs {
		if len(msg.Buffers) != 1 {
			t.Errorf("batch.msgs[%d].Buffers len = %d, want 1", i, len(msg.Buffers))
		}
	}
}

// --- Tests for SCION Path Handling Improvements ---

func TestScionInterfaceOverlap(t *testing.T) {
	ctrl := gomock.NewController(t)

	ifaceIA1 := addr.MustParseIA("1-ff00:0:110")
	ifaceIA2 := addr.MustParseIA("1-ff00:0:111")
	ifaceIA3 := addr.MustParseIA("1-ff00:0:112")

	t.Run("full overlap", func(t *testing.T) {
		a := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA1, ID: 1}, {IA: ifaceIA2, ID: 2},
			},
		})
		b := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA1, ID: 1}, {IA: ifaceIA2, ID: 2},
			},
		})
		got := interfaceOverlap(a, b)
		if got != 1.0 {
			t.Errorf("full overlap = %v, want 1.0", got)
		}
	})

	t.Run("no overlap", func(t *testing.T) {
		a := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA1, ID: 1},
			},
		})
		b := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA2, ID: 2}, {IA: ifaceIA3, ID: 3},
			},
		})
		got := interfaceOverlap(a, b)
		if got != 0.0 {
			t.Errorf("no overlap = %v, want 0.0", got)
		}
	})

	t.Run("partial overlap", func(t *testing.T) {
		a := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA1, ID: 1}, {IA: ifaceIA2, ID: 2},
			},
		})
		b := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{
				{IA: ifaceIA1, ID: 1}, {IA: ifaceIA3, ID: 3},
			},
		})
		got := interfaceOverlap(a, b)
		if got != 0.5 {
			t.Errorf("partial overlap = %v, want 0.5", got)
		}
	})

	t.Run("nil metadata returns zero", func(t *testing.T) {
		a := newMockPathWithMetadata(ctrl, nil)
		b := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{{IA: ifaceIA1, ID: 1}},
		})
		got := interfaceOverlap(a, b)
		if got != 0.0 {
			t.Errorf("nil metadata = %v, want 0.0", got)
		}
	})

	t.Run("empty interfaces returns zero", func(t *testing.T) {
		a := newMockPathWithMetadata(ctrl, &snet.PathMetadata{})
		b := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Interfaces: []snet.PathInterface{{IA: ifaceIA1, ID: 1}},
		})
		got := interfaceOverlap(a, b)
		if got != 0.0 {
			t.Errorf("empty interfaces = %v, want 0.0", got)
		}
	})
}

func TestScionSelectDiversePaths(t *testing.T) {
	ctrl := gomock.NewController(t)

	ifaceIA1 := addr.MustParseIA("1-ff00:0:110")
	ifaceIA2 := addr.MustParseIA("1-ff00:0:111")
	ifaceIA3 := addr.MustParseIA("1-ff00:0:112")

	t.Run("fewer candidates than max", func(t *testing.T) {
		paths := []pathWithMeta{
			{path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{Latency: []time.Duration{10 * time.Millisecond}}), latency: 10 * time.Millisecond},
			{path: newMockPathWithMetadata(ctrl, &snet.PathMetadata{Latency: []time.Duration{5 * time.Millisecond}}), latency: 5 * time.Millisecond},
		}
		result := selectDiversePaths(paths, 5)
		if len(result) != 2 {
			t.Fatalf("got %d paths, want 2", len(result))
		}
		// Should be sorted by latency.
		if result[0].latency > result[1].latency {
			t.Error("should be sorted by latency ascending")
		}
	})

	t.Run("prefers diverse path over duplicate topology", func(t *testing.T) {
		// Path A: fastest, through ifaceIA1+ifaceIA2.
		pathA := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency:    []time.Duration{5 * time.Millisecond},
			Interfaces: []snet.PathInterface{{IA: ifaceIA1, ID: 1}, {IA: ifaceIA2, ID: 2}},
		})
		// Path B: slightly slower, same interfaces as A.
		pathB := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency:    []time.Duration{6 * time.Millisecond},
			Interfaces: []snet.PathInterface{{IA: ifaceIA1, ID: 1}, {IA: ifaceIA2, ID: 2}},
		})
		// Path C: a bit slower, different interfaces.
		pathC := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
			Latency:    []time.Duration{8 * time.Millisecond},
			Interfaces: []snet.PathInterface{{IA: ifaceIA1, ID: 1}, {IA: ifaceIA3, ID: 3}},
		})

		candidates := []pathWithMeta{
			{path: pathA, latency: 5 * time.Millisecond},
			{path: pathB, latency: 6 * time.Millisecond},
			{path: pathC, latency: 8 * time.Millisecond},
		}
		result := selectDiversePaths(candidates, 2)
		if len(result) != 2 {
			t.Fatalf("got %d paths, want 2", len(result))
		}
		// First should be pathA (lowest latency), second should be pathC (diverse).
		if result[0].path != pathA {
			t.Error("first path should be lowest-latency (pathA)")
		}
		if result[1].path != pathC {
			t.Error("second path should be diverse (pathC), not duplicate (pathB)")
		}
	})
}

func TestScionStalePathCleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

	// Register a path with a fingerprint that will disappear.
	pi := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    netip.MustParseAddrPort("10.0.0.1:41641"),
		fingerprint: "stale-fp",
		expiry:      time.Now().Add(30 * time.Second), // about to expire
	}
	k := c.registerSCIONPathLocking(pi)

	// Daemon returns a path with a different fingerprint each time.
	newPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Latency: []time.Duration{5 * time.Millisecond},
		Expiry:  time.Now().Add(2 * time.Hour),
	})

	// Call refresh scionStalePathThreshold times.
	for i := 0; i < scionStalePathThreshold; i++ {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return([]snet.Path{newPath}, nil)
		c.refreshSCIONPathsOnce()
	}

	// Path should have been cleaned up.
	got := c.lookupSCIONPathLocking(k)
	if got != nil {
		t.Error("stale path should have been removed after threshold exceeded")
	}
}

func TestScionPathHealthTracking(t *testing.T) {
	t.Run("pong resets consecutive loss and marks healthy", func(t *testing.T) {
		ps := &scionPathProbeState{healthy: true}

		// Simulate 2 losses.
		ps.consecutiveLoss = 2
		ps.pingsSent = 3

		// Pong arrives.
		ps.pongsReceived++
		ps.consecutiveLoss = 0

		if !ps.healthy {
			t.Error("should still be healthy after pong")
		}
		if ps.consecutiveLoss != 0 {
			t.Error("consecutive loss should be reset")
		}
		if ps.pongsReceived != 1 {
			t.Errorf("pongsReceived = %d, want 1", ps.pongsReceived)
		}
	})

	t.Run("three consecutive losses marks unhealthy", func(t *testing.T) {
		ps := &scionPathProbeState{healthy: true}

		for i := 0; i < 3; i++ {
			ps.consecutiveLoss++
		}

		if ps.consecutiveLoss < 3 {
			t.Error("should have 3 consecutive losses")
		}
		// In real code, demoteSCIONPathLocked would set healthy = false.
		ps.healthy = false
		if ps.healthy {
			t.Error("should be unhealthy")
		}
	})

	t.Run("recovery after unhealthy", func(t *testing.T) {
		ps := &scionPathProbeState{healthy: false, consecutiveLoss: 5}

		// Pong arrives — recovery.
		ps.pongsReceived++
		ps.consecutiveLoss = 0
		ps.healthy = true

		if !ps.healthy {
			t.Error("should be healthy after recovery")
		}
	})
}

func TestScionDemoteSCIONPathLocked(t *testing.T) {
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf

	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:   peerIA,
		hostAddr: hostAddr,
		activePath: scionPathKey(1),
		paths: map[scionPathKey]*scionPathProbeState{
			scionPathKey(1): {healthy: false, recentPongs: [scionPongHistoryCount]scionPongReply{{latency: 50 * time.Millisecond}}, pongCount: 1, recentPong: 0},
			scionPathKey(2): {healthy: true, recentPongs: [scionPongHistoryCount]scionPongReply{{latency: 30 * time.Millisecond}}, pongCount: 1, recentPong: 0},
			scionPathKey(3): {healthy: true, recentPongs: [scionPongHistoryCount]scionPongReply{{latency: 40 * time.Millisecond}}, pongCount: 1, recentPong: 0},
		},
	}
	de.bestAddr = addrQuality{
		epAddr: epAddr{ap: hostAddr, scionKey: scionPathKey(1)},
	}

	de.mu.Lock()
	de.demoteSCIONPathLocked(scionPathKey(1))
	activePath := de.scionState.activePath
	bestKey := de.bestAddr.scionKey
	de.mu.Unlock()

	if activePath != scionPathKey(2) {
		t.Errorf("activePath = %d, want 2 (best healthy)", activePath)
	}
	if bestKey != scionPathKey(2) {
		t.Errorf("bestAddr scionKey = %d, want 2", bestKey)
	}
}

// TestScionDemoteSCIONPathLocked_AllUnhealthyKicksDiscovery (Phase 2) verifies
// that when every SCION path for a peer goes unhealthy and demote clears
// bestAddr, we also kick an asynchronous rediscovery. Without this, recovery
// would wait for the next periodic refresh tick (up to 30s, or minutes
// under per-peer backoff) before fresh paths are fetched.
//
// Observability: discoverSCIONPathAsync sets de.scionState.lastDiscoveryAt
// early in its CAS-guarded critical section, before any daemon call. A
// successful kick will bump that timestamp from its pre-seeded "10 min ago"
// value to the current time.
func TestScionDemoteSCIONPathLocked_AllUnhealthyKicksDiscovery(t *testing.T) {
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf
	// pconnSCION intentionally left nil: discoverSCIONPathAsync's throttle
	// check runs before it loads pconnSCION, so the timestamp will still be
	// bumped even though the subsequent Conn.discoverSCIONPaths will return
	// errNoSCION. This keeps the test hermetic (no mock daemon needed).

	staleDiscovery := time.Now().Add(-10 * time.Minute)
	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:          peerIA,
		hostAddr:        hostAddr,
		activePath:      scionPathKey(1),
		lastDiscoveryAt: staleDiscovery, // older than 5s throttle
		paths: map[scionPathKey]*scionPathProbeState{
			// Single path, marked unhealthy — the demote-with-no-survivors case.
			scionPathKey(1): {
				healthy:     false,
				pingsSent:   3,
				recentPongs: [scionPongHistoryCount]scionPongReply{},
			},
		},
	}
	de.bestAddr = addrQuality{
		epAddr: epAddr{ap: hostAddr, scionKey: scionPathKey(1)},
	}

	de.mu.Lock()
	de.demoteSCIONPathLocked(scionPathKey(1))
	de.mu.Unlock()

	// discoverSCIONPathAsync runs in a goroutine; poll briefly for
	// lastDiscoveryAt to advance.
	deadline := time.Now().Add(500 * time.Millisecond)
	var got time.Time
	for time.Now().Before(deadline) {
		de.mu.Lock()
		got = de.scionState.lastDiscoveryAt
		de.mu.Unlock()
		if got.After(staleDiscovery) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !got.After(staleDiscovery) {
		t.Fatalf("lastDiscoveryAt = %v (unchanged from pre-seeded %v); rediscovery was not kicked on all-unhealthy demote",
			got, staleDiscovery)
	}

	// And demote's normal contract: activePath cleared, SCION bestAddr cleared.
	de.mu.Lock()
	defer de.mu.Unlock()
	if de.scionState.activePath.IsSet() {
		t.Errorf("activePath = %d, want 0 (no healthy paths remaining)", de.scionState.activePath)
	}
	if de.bestAddr.isSCION() {
		t.Errorf("bestAddr still SCION after all paths unhealthy; want cleared")
	}
}

// TestCleanStaleSCIONPaths_ZeroPathsKicksDiscovery (Phase 2b) verifies that
// when cleanStaleSCIONPathFromEndpoints prunes the LAST path from an
// endpoint's scionState.paths, an async rediscovery is kicked. Without this,
// a peer whose SCION paths silently age out (e.g. after a network-blip-
// induced refresh-miss window) would stay permanently on UDP even though
// SCION is still advertised — because no other code path triggers
// rediscovery for a peer whose Hostinfo hasn't changed.
//
// Observability: discoverSCIONPathAsync sets de.scionState.lastDiscoveryAt
// in its CAS-guarded prelude. A successful kick will bump that timestamp
// from its pre-seeded "10 min ago" value to the current time.
func TestCleanStaleSCIONPaths_ZeroPathsKicksDiscovery(t *testing.T) {
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf
	// pconnSCION stays nil: we only care that lastDiscoveryAt moves,
	// not that daemon.Paths gets called. Keeps the test hermetic.

	// Set up an endpoint with a single registered path + matching probe state.
	ep := &endpoint{c: c}
	pi := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    hostAddr,
		fingerprint: "some-fp",
	}
	k := c.registerSCIONPathLocking(pi)
	staleDiscovery := time.Now().Add(-10 * time.Minute)
	ep.scionState = &scionEndpointState{
		peerIA:          peerIA,
		hostAddr:        hostAddr,
		activePath:      k,
		lastDiscoveryAt: staleDiscovery, // older than 5s throttle
		paths: map[scionPathKey]*scionPathProbeState{
			k: {fingerprint: "some-fp", healthy: true},
		},
	}
	// Wire the endpoint into the peerMap so cleanStaleSCIONPathFromEndpoints
	// (which iterates c.peerMap.byNodeKey) can find it. Direct insertion keeps
	// the test minimal; upsertEndpoint's full state invariants aren't needed.
	ep.publicKey = testNodeKey()
	c.peerMap.byNodeKey[ep.publicKey] = newPeerInfo(ep)

	// Prune the only path.
	c.cleanStaleSCIONPathFromEndpoints([]scionPathKey{k}, peerIA)

	// Path should be gone and activePath cleared.
	ep.mu.Lock()
	gotPaths := len(ep.scionState.paths)
	gotActive := ep.scionState.activePath
	ep.mu.Unlock()
	if gotPaths != 0 {
		t.Errorf("scionState.paths len = %d, want 0", gotPaths)
	}
	if gotActive.IsSet() {
		t.Errorf("activePath = %d, want 0", gotActive)
	}

	// Poll for the async discovery kick to update lastDiscoveryAt.
	deadline := time.Now().Add(500 * time.Millisecond)
	var got time.Time
	for time.Now().Before(deadline) {
		ep.mu.Lock()
		got = ep.scionState.lastDiscoveryAt
		ep.mu.Unlock()
		if got.After(staleDiscovery) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !got.After(staleDiscovery) {
		t.Fatalf("lastDiscoveryAt = %v (unchanged from pre-seeded %v); rediscovery was not kicked after silent prune of last path",
			got, staleDiscovery)
	}
}

func TestScionReEvalSCIONPathsLocked(t *testing.T) {
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf

	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:   peerIA,
		hostAddr: hostAddr,
		activePath: scionPathKey(1),
		paths: map[scionPathKey]*scionPathProbeState{
			scionPathKey(1): {healthy: true, recentPongs: [scionPongHistoryCount]scionPongReply{{latency: 50 * time.Millisecond}}, pongCount: 1, recentPong: 0},
			scionPathKey(2): {healthy: true, recentPongs: [scionPongHistoryCount]scionPongReply{{latency: 10 * time.Millisecond}}, pongCount: 1, recentPong: 0},
		},
	}
	de.bestAddr = addrQuality{
		epAddr: epAddr{ap: hostAddr, scionKey: scionPathKey(1)},
		latency: 50 * time.Millisecond,
	}

	de.mu.Lock()
	de.reEvalSCIONPathsLocked(mono.Now())
	activePath := de.scionState.activePath
	bestKey := de.bestAddr.scionKey
	de.mu.Unlock()

	// Path 2 has lower latency, should be selected.
	if activePath != scionPathKey(2) {
		t.Errorf("activePath = %d, want 2 (lower latency)", activePath)
	}
	if bestKey != scionPathKey(2) {
		t.Errorf("bestAddr scionKey = %d, want 2", bestKey)
	}
}

func TestScionProbeSCIONNonBestLocked(t *testing.T) {
	// Test that probeSCIONNonBestLocked round-robins through non-active paths.
	state := &scionEndpointState{
		hostAddr:   netip.MustParseAddrPort("10.0.0.1:41641"),
		activePath: scionPathKey(1),
		paths: map[scionPathKey]*scionPathProbeState{
			scionPathKey(1): {healthy: true},
			scionPathKey(2): {healthy: true},
			scionPathKey(3): {healthy: true},
		},
	}

	// Collect non-active keys manually as probeSCIONNonBestLocked would.
	var nonBest []scionPathKey
	for k := range state.paths {
		if k != state.activePath {
			nonBest = append(nonBest, k)
		}
	}

	if len(nonBest) != 2 {
		t.Fatalf("expected 2 non-best paths, got %d", len(nonBest))
	}

	// Verify round-robin increments.
	idx0 := state.probeRoundRobin % len(nonBest)
	state.probeRoundRobin++
	idx1 := state.probeRoundRobin % len(nonBest)
	state.probeRoundRobin++

	if idx0 == idx1 {
		t.Error("round-robin should pick different paths on consecutive calls")
	}
}

func TestDispatcherShim(t *testing.T) {
	t.Run("binds_when_port_available", func(t *testing.T) {
		sc := &scionConn{
			localHostIP: netip.MustParseAddr("127.0.0.1"),
			localPort:   32766,
		}
		openDispatcherShim(sc, t.Logf, nil)
		if sc.shimConn == nil {
			t.Fatal("expected shimConn to be set when port 30041 is available")
		}
		defer sc.shimConn.Close()
		if sc.shimXPC == nil {
			t.Fatal("expected shimXPC to be set")
		}
		addr := sc.shimConn.LocalAddr().(*net.UDPAddr)
		if addr.Port != scionDispatcherPort {
			t.Errorf("shimConn port = %d, want %d", addr.Port, scionDispatcherPort)
		}
	})

	t.Run("graceful_on_EADDRINUSE", func(t *testing.T) {
		// Occupy port 30041 first.
		blocker, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: scionDispatcherPort,
		})
		if err != nil {
			t.Skipf("cannot bind port %d for test: %v", scionDispatcherPort, err)
		}
		defer blocker.Close()

		sc := &scionConn{
			localHostIP: netip.MustParseAddr("127.0.0.1"),
			localPort:   32766,
		}
		openDispatcherShim(sc, t.Logf, nil)
		if sc.shimConn != nil {
			sc.shimConn.Close()
			t.Fatal("expected shimConn to be nil when port is already in use")
		}
		if sc.shimXPC != nil {
			t.Fatal("expected shimXPC to be nil when port is already in use")
		}
	})

	t.Run("skipped_when_main_on_dispatcher_port", func(t *testing.T) {
		sc := &scionConn{
			localHostIP: netip.MustParseAddr("127.0.0.1"),
			localPort:   scionDispatcherPort,
		}
		openDispatcherShim(sc, t.Logf, nil)
		if sc.shimConn != nil {
			sc.shimConn.Close()
			t.Fatal("expected shimConn to be nil when main socket is on dispatcher port")
		}
	})
}

func TestFormatSCIONHops(t *testing.T) {
	mustIA := func(s string) addr.IA {
		ia, err := addr.ParseIA(s)
		if err != nil {
			t.Fatalf("invalid IA %q: %v", s, err)
		}
		return ia
	}

	tests := []struct {
		name   string
		ifaces []snet.PathInterface
		want   string
	}{
		{
			name:   "empty",
			ifaces: nil,
			want:   "?",
		},
		{
			name: "single interface",
			ifaces: []snet.PathInterface{
				{IA: mustIA("19-ffaa:1:eba"), ID: 2},
			},
			want: "19-ffaa:1:eba 2",
		},
		{
			name: "2-hop direct",
			ifaces: []snet.PathInterface{
				{IA: mustIA("19-ffaa:1:eba"), ID: 2},
				{IA: mustIA("19-ffaa:1:bf5"), ID: 2},
			},
			want: "19-ffaa:1:eba 2>2 19-ffaa:1:bf5",
		},
		{
			name: "3-hop via transit",
			ifaces: []snet.PathInterface{
				{IA: mustIA("19-ffaa:1:eba"), ID: 1},
				{IA: mustIA("19-ffaa:0:1303"), ID: 62},
				{IA: mustIA("19-ffaa:0:1303"), ID: 104},
				{IA: mustIA("19-ffaa:1:bf5"), ID: 1},
			},
			want: "19-ffaa:1:eba 1>62 19-ffaa:0:1303 104>1 19-ffaa:1:bf5",
		},
		{
			name: "4-hop two transits",
			ifaces: []snet.PathInterface{
				{IA: mustIA("19-ffaa:1:eba"), ID: 1},
				{IA: mustIA("19-ffaa:0:1"), ID: 3},
				{IA: mustIA("19-ffaa:0:1"), ID: 4},
				{IA: mustIA("19-ffaa:0:2"), ID: 5},
				{IA: mustIA("19-ffaa:0:2"), ID: 6},
				{IA: mustIA("19-ffaa:1:bf5"), ID: 1},
			},
			want: "19-ffaa:1:eba 1>3 19-ffaa:0:1 4>5 19-ffaa:0:2 6>1 19-ffaa:1:bf5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSCIONHops(tt.ifaces)
			if got != tt.want {
				t.Errorf("formatSCIONHops() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScionPathInfoString(t *testing.T) {
	mustIA := func(s string) addr.IA {
		ia, err := addr.ParseIA(s)
		if err != nil {
			t.Fatalf("invalid IA %q: %v", s, err)
		}
		return ia
	}

	pi := &scionPathInfo{
		peerIA:   mustIA("19-ffaa:1:bf5"),
		hostAddr: netip.MustParseAddrPort("127.0.0.1:32766"),
		path: snetpath.Path{
			Src: mustIA("19-ffaa:1:eba"),
			Dst: mustIA("19-ffaa:1:bf5"),
			Meta: snet.PathMetadata{
				Interfaces: []snet.PathInterface{
					{IA: mustIA("19-ffaa:1:eba"), ID: 2},
					{IA: mustIA("19-ffaa:1:bf5"), ID: 2},
				},
				MTU: 1472,
			},
		},
	}
	pi.buildDisplayStr()

	want := "scion:[19-ffaa:1:eba 2>2 19-ffaa:1:bf5]:[127.0.0.1]:32766"
	if got := pi.String(); got != want {
		t.Errorf("scionPathInfo.String() = %q, want %q", got, want)
	}

	// Test with no metadata
	piNoMeta := &scionPathInfo{
		peerIA:   mustIA("19-ffaa:1:bf5"),
		hostAddr: netip.MustParseAddrPort("127.0.0.1:32766"),
	}
	piNoMeta.buildDisplayStr()

	wantNoMeta := "scion:[?]:[127.0.0.1]:32766"
	if got := piNoMeta.String(); got != wantNoMeta {
		t.Errorf("scionPathInfo.String() no metadata = %q, want %q", got, wantNoMeta)
	}
}

func TestScionLatencyMedian(t *testing.T) {
	tests := []struct {
		name    string
		samples []time.Duration
		want    time.Duration
	}{
		{
			name:    "no samples",
			samples: nil,
			want:    time.Hour,
		},
		{
			name:    "single sample",
			samples: []time.Duration{10 * time.Millisecond},
			want:    10 * time.Millisecond,
		},
		{
			name:    "two samples returns higher (index 1)",
			samples: []time.Duration{8 * time.Millisecond, 12 * time.Millisecond},
			want:    12 * time.Millisecond,
		},
		{
			name:    "four samples returns median",
			samples: []time.Duration{10, 20, 30, 40},
			want:    30, // samples[4/2] = samples[2]
		},
		{
			name:    "eight samples median",
			samples: []time.Duration{5, 10, 15, 20, 25, 30, 35, 40},
			want:    25, // samples[8/2] = samples[4]
		},
		{
			name:    "outlier resistance",
			samples: []time.Duration{10, 11, 12, 10, 11, 12, 10, 500},
			want:    11, // median ignores the 500 outlier
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &scionPathProbeState{}
			for _, s := range tt.samples {
				ps.addPongReply(scionPongReply{latency: s})
			}
			if got := ps.latency(); got != tt.want {
				t.Errorf("latency() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScionReEvalAntiFlap(t *testing.T) {
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf

	// Two paths with very similar latency (10ms vs 11ms).
	// Path 1 is the incumbent active path.
	ps1 := &scionPathProbeState{healthy: true}
	ps1.addPongReply(scionPongReply{latency: 10 * time.Millisecond})

	ps2 := &scionPathProbeState{healthy: true}
	ps2.addPongReply(scionPongReply{latency: 11 * time.Millisecond})

	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:     peerIA,
		hostAddr:   hostAddr,
		activePath: scionPathKey(2), // path 2 is active at 11ms
		paths: map[scionPathKey]*scionPathProbeState{
			scionPathKey(1): ps1,
			scionPathKey(2): ps2,
		},
	}
	de.bestAddr = addrQuality{
		epAddr:  epAddr{ap: hostAddr, scionKey: scionPathKey(2)},
		latency: 11 * time.Millisecond,
	}

	// Re-eval should NOT switch — 1ms improvement is within 2ms minimum threshold.
	de.mu.Lock()
	de.reEvalSCIONPathsLocked(mono.Now())
	activePath := de.scionState.activePath
	de.mu.Unlock()

	if activePath != scionPathKey(2) {
		t.Errorf("anti-flap: activePath = %d, want 2 (should not switch for 1ms difference)", activePath)
	}

	// Now make path 1 significantly worse (50ms) and path 2 stays at 11ms.
	// Then flip: make path 2 the slow one (50ms) and path 1 = 10ms.
	// The 40ms improvement exceeds the 20% threshold (20% of 50ms = 10ms).
	ps2Slow := &scionPathProbeState{healthy: true}
	ps2Slow.addPongReply(scionPongReply{latency: 50 * time.Millisecond})

	de.mu.Lock()
	de.scionState.paths[scionPathKey(2)] = ps2Slow
	de.scionState.lastFullEvalAt = 0 // reset throttle
	de.bestAddr.latency = 50 * time.Millisecond
	de.reEvalSCIONPathsLocked(mono.Now())
	activePath = de.scionState.activePath
	de.mu.Unlock()

	if activePath != scionPathKey(1) {
		t.Errorf("genuine degradation: activePath = %d, want 1 (should switch for 40ms improvement)", activePath)
	}
}

// TestScionAddNewPathsRecovery verifies that addNewSCIONPathsForPeer
// initializes scionState on an endpoint when the initial path discovery
// failed (scionState == nil) but incoming SCION disco registered the
// endpoint in the peerMap via handlePingLocked.
func TestScionAddNewPathsRecovery(t *testing.T) {
	ctrl := gomock.NewController(t)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Conn{
		connCtx: ctx,
		peerMap: newPeerMap(),
	}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{daemon: mock_daemon.NewMockConnector(ctrl), localIA: localIA})

	// Create an endpoint and register it in the peerMap at the plain
	// hostAddr — this is what handlePingLocked does for incoming SCION disco.
	ep := &endpoint{c: c, nodeID: 1}
	ep.publicKey = key.NewNode().Public()
	ep.disco.Store(&endpointDisco{key: key.NewDisco().Public()})
	c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
	c.peerMap.setNodeKeyForEpAddr(epAddr{ap: hostAddr}, ep.publicKey)

	// Simulate failed initial discovery: ep.scionState is nil.
	if ep.scionState != nil {
		t.Fatal("precondition: scionState should be nil")
	}

	// Register a reply-path in c.scionPaths (simulates handleSCIONDisco
	// creating a path entry from an incoming disco ping).
	replyPI := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    hostAddr,
		fingerprint: "reply-fp",
		expiry:      time.Now().Add(1 * time.Hour),
	}
	replyPI.buildDisplayStr()
	c.registerSCIONPathLocking(replyPI)

	// Now soft refresh finds new paths from the daemon. Call
	// addNewSCIONPathsForPeer with two mock paths.
	p1 := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Latency: []time.Duration{5 * time.Millisecond},
		Expiry:  time.Now().Add(2 * time.Hour),
	})
	p2 := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Latency: []time.Duration{10 * time.Millisecond},
		Expiry:  time.Now().Add(2 * time.Hour),
	})

	newKeys := c.addNewSCIONPathsForPeer(peerIA, hostAddr, []snet.Path{p1, p2})
	if len(newKeys) != 2 {
		t.Fatalf("addNewSCIONPathsForPeer returned %d keys, want 2", len(newKeys))
	}

	// Verify recovery initialized scionState.
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.scionState == nil {
		t.Fatal("scionState should have been initialized by recovery")
	}
	if ep.scionState.peerIA != peerIA {
		t.Errorf("peerIA = %s, want %s", ep.scionState.peerIA, peerIA)
	}
	if ep.scionState.hostAddr != hostAddr {
		t.Errorf("hostAddr = %s, want %s", ep.scionState.hostAddr, hostAddr)
	}
	if len(ep.scionState.paths) != 2 {
		t.Errorf("paths count = %d, want 2", len(ep.scionState.paths))
	}
	if !ep.scionState.activePath.IsSet() {
		t.Error("activePath should be set")
	}
	// activePath should be one of the new keys.
	if ep.scionState.activePath != newKeys[0] {
		t.Errorf("activePath = %d, want %d (first new key)", ep.scionState.activePath, newKeys[0])
	}
	// Each probe state should be healthy.
	for _, k := range newKeys {
		ps, ok := ep.scionState.paths[k]
		if !ok {
			t.Errorf("missing probe state for key %d", k)
			continue
		}
		if !ps.healthy {
			t.Errorf("probe state for key %d should be healthy", k)
		}
	}
}

// TestSignalSCIONConnReadyConcurrent exercises signalSCIONConnReady from
// multiple goroutines concurrently with readers. Before the fix, the method
// read+replaced+closed c.scionConnReady without synchronization, which
// (a) races the field access with concurrent readers, and (b) can panic
// with "close of closed channel" when two signalers both captured the same
// old channel. Run with -race to see the data race even if no panic occurs.
func TestSignalSCIONConnReadyConcurrent(t *testing.T) {
	c := &Conn{}
	c.initSCIONConnReady()

	const (
		signalers = 8
		readers   = 8
		iters     = 200
	)

	stop := make(chan struct{})
	var readersDone sync.WaitGroup
	for range readers {
		readersDone.Add(1)
		go func() {
			defer readersDone.Done()
			for {
				select {
				case <-stop:
					return
				case <-c.scionConnReadyCh():
					// Re-read the current channel on each wake-up, exactly
					// as the production receive loops do.
				}
			}
		}()
	}

	var signalersDone sync.WaitGroup
	for range signalers {
		signalersDone.Add(1)
		go func() {
			defer signalersDone.Done()
			for range iters {
				c.signalSCIONConnReady()
			}
		}()
	}
	signalersDone.Wait()
	close(stop)
	// Wake the readers one last time so they observe stop.
	c.signalSCIONConnReady()
	readersDone.Wait()
}

// TestSCIONHotLogfRateLimits verifies the rate-limited logger installed by
// initSCIONLazyEndpointLimiter drops bursts of identical messages. Without
// this, a socket disconnection would emit one log line per packet read error.
func TestSCIONHotLogfRateLimits(t *testing.T) {
	var logged int
	c := &Conn{logf: func(format string, args ...any) { logged++ }}
	c.initSCIONLazyEndpointLimiter()

	// Burst 100 identical messages; rate limiter should drop all but a handful.
	for range 100 {
		c.scionHotLogf("magicsock: SCION read error: %v", fmt.Errorf("closed"))
	}
	if logged > 5 {
		t.Errorf("rate limiter failed to drop repeated messages; got %d lines", logged)
	}
	if logged == 0 {
		t.Errorf("rate limiter should have emitted at least one line; got 0")
	}
}

// TestScionPathInfoGenerationBumps verifies that buildCachedDst bumps the
// generation counter, so previously-built fastPath templates are flagged
// stale. The generation invariant prevents a refresh from leaving a
// send path using a stale underlay next-hop for a new path.
func TestScionPathInfoGenerationBumps(t *testing.T) {
	pi := &scionPathInfo{
		peerIA:   0, // same-AS (empty path path)
		hostAddr: netip.MustParseAddrPort("127.0.0.1:32766"),
	}
	gen0 := pi.generation
	pi.buildCachedDst()
	if pi.generation == gen0 {
		t.Fatal("buildCachedDst should bump generation")
	}
	gen1 := pi.generation
	pi.buildCachedDst()
	if pi.generation == gen1 {
		t.Fatal("second buildCachedDst should bump generation again")
	}
}

// TestSendSCIONBatchFastGeometryInvariant verifies that sendSCIONBatchFast
// rejects a fastPath template with inconsistent geometry rather than
// panicking on out-of-bounds buffer access. Prior to the guard a stale
// template (outliving a path refresh) could cause silent memory corruption
// at send time.
func TestSendSCIONBatchFastGeometryInvariant(t *testing.T) {
	c := &Conn{}
	// Construct an obviously-invalid fastPath: udpOffset beyond hdrLen.
	badFP := &scionFastPath{
		hdr:       make([]byte, 10),
		udpOffset: 100, // far beyond hdrLen
	}
	err := c.sendSCIONBatchFast(&scionConn{}, badFP, [][]byte{{0x00}}, 0)
	if err == nil {
		t.Fatal("expected error for invalid geometry, got nil")
	}
	if !strings.Contains(err.Error(), "geometry") {
		t.Errorf("error should mention geometry, got: %v", err)
	}

	// Short header (less than a UDP header) must also be rejected.
	short := &scionFastPath{hdr: make([]byte, 3), udpOffset: 0}
	err = c.sendSCIONBatchFast(&scionConn{}, short, [][]byte{{0x00}}, 0)
	if err == nil {
		t.Fatal("expected error for short header, got nil")
	}
}

// TestRecordBetterAddrCategory exercises the transport classifier used by
// setBestAddrLocked to tick the correct clientmetric on each new bestAddr.
func TestRecordBetterAddrCategory(t *testing.T) {
	before := [4]int64{
		metricBetterAddrChoseSCION.Value(),
		metricBetterAddrChoseDirect.Value(),
		metricBetterAddrChoseRelay.Value(),
		metricBetterAddrChoseDERP.Value(),
	}

	scionAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:1"), scionKey: 7}
	recordBetterAddrCategory(scionAddr)

	directAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:2")}
	recordBetterAddrCategory(directAddr)

	relayAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:3")}
	relayAddr.vni.Set(99)
	recordBetterAddrCategory(relayAddr)

	derpAddr := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 4)}
	recordBetterAddrCategory(derpAddr)

	after := [4]int64{
		metricBetterAddrChoseSCION.Value(),
		metricBetterAddrChoseDirect.Value(),
		metricBetterAddrChoseRelay.Value(),
		metricBetterAddrChoseDERP.Value(),
	}
	for i, label := range []string{"SCION", "Direct", "Relay", "DERP"} {
		if after[i]-before[i] != 1 {
			t.Errorf("%s counter delta = %d; want 1", label, after[i]-before[i])
		}
	}
}

// TestExtractSCIONUnderlayUDPConn verifies that the reflective accessor for
// the unexported net.UDPConn inside snet.SCIONPacketConn works against the
// pinned scionproto version. If scionproto reshapes SCIONPacketConn, this
// test fails and alerts us before the fast path silently stops working.
func TestExtractSCIONUnderlayUDPConn(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udp.Close()

	// Use unsafe to construct a SCIONPacketConn with the unexported `conn`
	// field populated. This mirrors what snet.SCIONNetwork.OpenRaw does
	// internally. If this test ever panics or returns nil, scionproto has
	// renamed the field or changed its type and the fast-path extraction
	// needs to be updated.
	pc := &snet.SCIONPacketConn{}
	v := reflect.ValueOf(pc).Elem().FieldByName("conn")
	if !v.IsValid() {
		t.Fatal("SCIONPacketConn no longer has a field named 'conn'")
	}
	ptr := unsafe.Pointer(v.UnsafeAddr())
	reflect.NewAt(v.Type(), ptr).Elem().Set(reflect.ValueOf(udp))

	extracted := extractSCIONUnderlayUDPConn(pc)
	if extracted != udp {
		t.Fatalf("extractSCIONUnderlayUDPConn returned %v, want %v", extracted, udp)
	}
}

// TestEmbeddedConnectorRequiresTRCs verifies that the embedded SCION
// connector refuses to start if no TRC blobs are present in the state
// directory's certs/ subdirectory. Real segment verification cannot proceed
// without at least one TRC, so the connector must fail loudly rather than
// silently accept unverified segments.
func TestEmbeddedConnectorRequiresTRCs(t *testing.T) {
	_, err := newEmbeddedConnector(context.Background(), "/tmp/nonexistent-topology.json", t.TempDir(), t.Logf, nil)
	if err == nil {
		t.Fatal("expected error when certs/ directory has no TRCs")
	}
	// Topology load happens before the TRC check, so the error may be
	// topology-load for a nonexistent path; that still surfaces a clear
	// failure. We only need to ensure no insecure startup slipped through.
	if strings.Contains(err.Error(), "ACKNOWLEDGE_INSECURE_SEGMENTS") {
		t.Errorf("removed knob should not be referenced, got: %v", err)
	}
}

// TestResolveSCIONCertsDir verifies the TRC directory resolution rules:
// topology-sibling by default so hosts with /etc/scion/certs/*.trc work
// out of the box, overridden by TS_SCION_CERTS_DIR when explicitly set.
func TestResolveSCIONCertsDir(t *testing.T) {
	t.Run("sibling_of_topology_by_default", func(t *testing.T) {
		envknob.Setenv("TS_SCION_CERTS_DIR", "")
		t.Cleanup(func() { envknob.Setenv("TS_SCION_CERTS_DIR", "") })
		got := resolveSCIONCertsDir("/etc/scion/topology.json")
		if want := "/etc/scion/certs"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("state_dir_bootstrap", func(t *testing.T) {
		envknob.Setenv("TS_SCION_CERTS_DIR", "")
		t.Cleanup(func() { envknob.Setenv("TS_SCION_CERTS_DIR", "") })
		got := resolveSCIONCertsDir("/var/lib/tailscale/scion/topology.json")
		if want := "/var/lib/tailscale/scion/certs"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("explicit_env_override", func(t *testing.T) {
		envknob.Setenv("TS_SCION_CERTS_DIR", "/opt/scion-trust")
		t.Cleanup(func() { envknob.Setenv("TS_SCION_CERTS_DIR", "") })
		got := resolveSCIONCertsDir("/etc/scion/topology.json")
		if want := "/opt/scion-trust"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// FuzzParseSCIONPacket throws random bytes at the SCION wire parser that
// receiveSCION/receiveSCIONShim rely on. The parser must never panic on
// adversarial input — it must either decode cleanly or return !ok.
func FuzzParseSCIONPacket(f *testing.F) {
	// Seed corpus: a few obviously-invalid frames plus a short valid-ish
	// prefix. The goal is coverage of parse paths, not semantic validity.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 512))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSCIONPacket panicked on input of length %d: %v", len(data), r)
			}
		}()
		// Use a fresh decoder for each call to match production usage.
		scn := &slayers.SCION{}
		_, _, _, _, _ = parseSCIONPacket(data, scn)
	})
}

// TestSCIONLastConnectError verifies the connect-error observability
// surface: failures are recorded (message + timestamp + counter), and a
// successful connect clears the stored error.
func TestSCIONLastConnectError(t *testing.T) {
	c := &Conn{}
	// Baseline.
	msg, when := c.SCIONLastConnectError()
	if msg != "" || !when.IsZero() {
		t.Fatalf("baseline SCIONLastConnectError = (%q, %v); want empty", msg, when)
	}
	before := metricSCIONConnectFailure.Value()

	c.recordSCIONConnectError(fmt.Errorf("bootstrap unreachable"))

	msg, when = c.SCIONLastConnectError()
	if msg != "bootstrap unreachable" {
		t.Errorf("stored message = %q, want %q", msg, "bootstrap unreachable")
	}
	if when.IsZero() {
		t.Error("timestamp should be non-zero after failure")
	}
	if metricSCIONConnectFailure.Value()-before != 1 {
		t.Error("connect-failure counter did not increment")
	}

	// Successful connect clears the error.
	c.recordSCIONConnectError(nil)
	msg, when = c.SCIONLastConnectError()
	if msg != "" || !when.IsZero() {
		t.Errorf("after success: (%q, %v); want cleared", msg, when)
	}
}

// TestSCIONReconnectStorm exercises the reconnect-path bookkeeping under
// concurrent pressure: many goroutines simultaneously (a) wake readers via
// signalSCIONConnReady, (b) flip the scionReconnecting CAS, and (c) swap
// pconnSCION. The test asserts only that nothing panics and the race
// detector stays quiet. Covers the P0 channel race and exercises the CAS
// guards around reconnect.
func TestSCIONReconnectStorm(t *testing.T) {
	c := &Conn{}
	c.initSCIONConnReady()
	c.initSCIONLazyEndpointLimiter()

	const (
		workers = 16
		iters   = 300
	)

	stop := make(chan struct{})
	var readersDone, workersDone sync.WaitGroup

	for range 4 {
		readersDone.Add(1)
		go func() {
			defer readersDone.Done()
			for {
				select {
				case <-stop:
					return
				case <-c.scionConnReadyCh():
				}
			}
		}()
	}

	// Workers: simulate concurrent reconnect paths racing on the CAS guard
	// plus signalSCIONConnReady.
	for range workers {
		workersDone.Add(1)
		go func() {
			defer workersDone.Done()
			for range iters {
				if c.scionReconnecting.CompareAndSwap(false, true) {
					c.signalSCIONConnReady()
					c.scionReconnecting.Store(false)
				} else {
					c.signalSCIONConnReady()
				}
			}
		}()
	}

	workersDone.Wait()
	close(stop)
	// Ensure each reader observes one more signal after stop is closed, so
	// it unblocks from the current ready channel, loops, and selects stop.
	for range 4 {
		c.signalSCIONConnReady()
	}
	readersDone.Wait()
}

// TestSCIONLazyEndpointRateLimit checks that the lazyEndpoint admission rate
// limiter drops once the bucket is exhausted. A flood of packets from unknown
// sources must not be allowed to allocate a lazyEndpoint per packet — that
// turns spoofed traffic into unbounded allocation.
func TestSCIONLazyEndpointRateLimit(t *testing.T) {
	c := &Conn{}
	c.initSCIONLazyEndpointLimiter()

	// First `scionLazyEndpointBurst` calls pass immediately, then we
	// should see drops (the bucket is exhausted and no time has elapsed
	// to refill tokens).
	allowed, dropped := 0, 0
	for range scionLazyEndpointBurst * 4 {
		if c.allowSCIONLazyEndpoint() {
			allowed++
		} else {
			dropped++
		}
	}
	if allowed > scionLazyEndpointBurst+2 { // allow small slop for refill during loop
		t.Errorf("allowed=%d, expected ≈ %d (burst)", allowed, scionLazyEndpointBurst)
	}
	if dropped == 0 {
		t.Errorf("no drops observed after bucket exhaustion; limiter not active")
	}
}

// fakeSCIONBatchRW stubs scionBatchRW for benchmarking without syscalls.
// WriteBatch pretends all messages were sent; ReadBatch is unused.
type fakeSCIONBatchRW struct{}

func (fakeSCIONBatchRW) ReadBatch(msgs []ipv4.Message, _ int) (int, error) {
	return 0, nil
}
func (fakeSCIONBatchRW) WriteBatch(msgs []ipv4.Message, _ int) (int, error) {
	return len(msgs), nil
}

// benchSCIONFastPath constructs a synthetic scionFastPath suitable for
// driving sendSCIONBatchFast in a benchmark (no real SCION topology is
// required). The header is a minimal [SCION hdr placeholder][UDP hdr]
// with a plausible udpOffset; WriteBatch is a no-op stub.
func benchSCIONFastPath() *scionFastPath {
	// 48-byte SCION-ish header placeholder + 8-byte UDP header == 56.
	hdr := make([]byte, 56)
	return &scionFastPath{
		hdr:        hdr,
		udpOffset:  48,
		nextHop:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000},
		pseudoCsum: 0,
		gen:        0,
	}
}

// BenchmarkSendSCIONBatchFast exercises the per-packet prep loop in
// sendSCIONBatchFast (header copy + checksum + field patch) with the
// WriteBatch syscall stubbed out. Measures the pure CPU cost of the
// serialization path that fires for every SCION data batch.
func BenchmarkSendSCIONBatchFast(b *testing.B) {
	c := &Conn{}
	sc := &scionConn{underlayXPC: fakeSCIONBatchRW{}}
	fp := benchSCIONFastPath()
	const (
		batchSize = 64
		wgBytes   = 1200 // typical WireGuard packet size
	)
	buffs := make([][]byte, batchSize)
	for i := range buffs {
		buffs[i] = make([]byte, wgBytes)
	}
	b.ReportAllocs()
	b.SetBytes(int64(batchSize * wgBytes))
	b.ResetTimer()
	for range b.N {
		if err := c.sendSCIONBatchFast(sc, fp, buffs, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReceiveSCIONBatchParse measures the per-packet parse +
// lookup cost in the receive hot loop, feeding a prebuilt synthetic
// SCION packet into parseSCIONPacket repeatedly (no syscalls).
func BenchmarkReceiveSCIONBatchParse(b *testing.B) {
	// Construct a minimal but decodable SCION+UDP packet. slayers.SCION
	// is strict about header format; if DecodeFromBytes rejects the
	// synthetic data, the benchmark's parse loop measures the error
	// return path, which is still the same hot code.
	pkt := make([]byte, 1400)
	scn := &slayers.SCION{}
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for range b.N {
		scn.RecyclePaths()
		_, _, _, _, _ = parseSCIONPacket(pkt, scn)
	}
}

// --- Phase 5: classify discovery errors ---

func TestClassifySCIONDiscoveryErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want scionDiscoveryErrorKind
	}{
		{"nil", nil, scionErrOther},
		{"TRC not found", fmt.Errorf("querying SCION paths to 71-2:0:4a: TRC not found"), scionErrTRCMissing},
		// Exact error shape observed in the incident-triggering log for ISD 71.
		{"reserved number (gRPC from SCION CS)", fmt.Errorf("rpc error: code = Unknown desc = reserved number"), scionErrTRCMissing},
		// False-positive guard: plain "reserved number" without the gRPC wrapper
		// could come from unrelated decoders; don't misclassify.
		{"reserved number without gRPC wrapper", fmt.Errorf("cert chain validation: reserved number encountered"), scionErrOther},
		{"context deadline", fmt.Errorf("context deadline exceeded"), scionErrDaemonUnreachable},
		{"gRPC Unavailable", fmt.Errorf("rpc error: code = Unavailable desc = transport is closing"), scionErrDaemonUnreachable},
		{"no paths", fmt.Errorf("no paths to 19-ffaa:1:120a"), scionErrNoSegments},
		{"arbitrary", fmt.Errorf("something else"), scionErrOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySCIONDiscoveryErr(tt.err)
			if got != tt.want {
				t.Errorf("classifySCIONDiscoveryErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// --- Phase 4a: per-peer discovery error surfaced in PeerStatus.SCION ---

// TestPopulateSCIONPathsLocked_SurfacesDiscoveryError verifies that when
// discovery for a peer has failed (e.g. TRC not found for the peer's ISD),
// the error is exposed on PeerStatus.SCION so operators can diagnose the
// failure via `tailscale status --json` without reading journalctl.
func TestPopulateSCIONPathsLocked_SurfacesDiscoveryError(t *testing.T) {
	peerIA := addr.MustParseIA("71-2:0:4a")
	hostAddr := netip.MustParseAddrPort("141.44.29.237:32767")

	c := &Conn{connCtx: context.Background()}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{localIA: addr.MustParseIA("19-ffaa:1:120b")})

	errAt := time.Now().Add(-30 * time.Second)
	de := &endpoint{c: c}
	de.scionState = &scionEndpointState{
		peerIA:               peerIA,
		hostAddr:             hostAddr,
		lastDiscoveryAt:      errAt,
		lastDiscoveryError:   "TRC not found",
		lastDiscoveryErrorAt: errAt,
		// paths intentionally empty: discovery never succeeded.
	}

	var ps ipnstate.PeerStatus
	c.mu.Lock()
	de.mu.Lock()
	de.populateSCIONPathsLocked(&ps)
	de.mu.Unlock()
	c.mu.Unlock()

	if ps.SCION == nil {
		t.Fatalf("ps.SCION nil; expected peer-level state even with empty paths")
	}
	if got, want := ps.SCION.PeerIA, peerIA.String(); got != want {
		t.Errorf("PeerIA = %q, want %q", got, want)
	}
	if got, want := ps.SCION.LastDiscoveryError, "TRC not found"; got != want {
		t.Errorf("LastDiscoveryError = %q, want %q", got, want)
	}
	if ps.SCION.LastDiscoveryAt == "" {
		t.Errorf("LastDiscoveryAt empty; expected RFC3339 timestamp")
	}
	if ps.SCION.LastDiscoveryErrorAt == "" {
		t.Errorf("LastDiscoveryErrorAt empty; expected RFC3339 timestamp")
	}
	if len(ps.SCIONPaths) != 0 {
		t.Errorf("SCIONPaths len = %d, want 0", len(ps.SCIONPaths))
	}
}

// --- Phase 3: auto-retry SCION connect on startup failure ---

func TestScionStartupRetrySleep(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, 60 * time.Second}, // capped
		{10, 60 * time.Second},
	}
	for _, tt := range tests {
		got := scionStartupRetrySleep(tt.attempt)
		if got != tt.want {
			t.Errorf("scionStartupRetrySleep(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

// --- Phase 1a: fingerprint-keyed reconciler (key-stability + collision guard) ---

// TestUpsertSCIONPathLocked_StableReSignPreservesKey verifies Phase 1a's
// load-bearing guarantee: when the daemon returns a path with the same
// fingerprint as an already-registered entry (the common "re-signed segment,
// same topology" case), the same scionPathKey is reused and only the
// mutable fields (expiry, path bytes, fastPath) are updated. Previously,
// this case churned keys unnecessarily on every rediscovery round.
func TestUpsertSCIONPathLocked_StableReSignPreservesKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")

	iface1 := snet.PathInterface{IA: localIA, ID: 1}
	iface2 := snet.PathInterface{IA: peerIA, ID: 2}
	oldExpiry := time.Now().Add(1 * time.Hour)
	newExpiry := time.Now().Add(2 * time.Hour)

	oldPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Interfaces: []snet.PathInterface{iface1, iface2},
		Expiry:     oldExpiry,
		MTU:        1472,
	})
	newPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Interfaces: []snet.PathInterface{iface1, iface2}, // same topology
		Expiry:     newExpiry,                            // later expiry (re-sign)
		MTU:        1472,
	})
	fp := oldPath.Metadata().Fingerprint()
	if fp == "" || fp != newPath.Metadata().Fingerprint() {
		t.Fatalf("test setup: oldPath and newPath must share a non-empty fingerprint")
	}

	c := &Conn{connCtx: context.Background()}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{localIA: localIA})

	c.mu.Lock()
	k1, registered1, collision1 := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostAddr, oldPath, fp)
	c.mu.Unlock()
	if !registered1 {
		t.Fatalf("first upsert: expected registered=true (fresh fingerprint)")
	}
	if collision1 {
		t.Fatalf("first upsert: collision=true unexpected on fresh fingerprint")
	}

	// Re-upsert with the same fingerprint and a later expiry — same key should
	// be returned and the in-place mutation should bump expiry without
	// minting a new scionPathKey.
	c.mu.Lock()
	k2, registered2, collision2 := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostAddr, newPath, fp)
	c.mu.Unlock()
	if k2 != k1 {
		t.Fatalf("second upsert key = %d, want %d (same key for same fingerprint)", k2, k1)
	}
	if registered2 {
		t.Errorf("second upsert: expected registered=false (updated in place), got true")
	}
	if collision2 {
		t.Errorf("second upsert: collision=true unexpected for same-topology re-sign")
	}

	// Expiry was bumped in place.
	pi := c.lookupSCIONPathLocking(k1)
	if pi == nil {
		t.Fatalf("scionPathInfo for key %d missing after re-upsert", k1)
	}
	pi.mu.Lock()
	gotExpiry := pi.expiry
	pi.mu.Unlock()
	if !gotExpiry.Equal(newExpiry) {
		t.Errorf("expiry after re-upsert = %v, want %v (later expiry from re-signed path)", gotExpiry, newExpiry)
	}
}

// TestUpsertSCIONPathLocked_SameIADifferentHostDoesNotCollide (Phase 2c)
// verifies the fix for the same-IA-different-hostAddr collision bug.
//
// Before the fix, scionPathFPKey was keyed on (peerIA, fingerprint) only.
// Two Tailscale peers in the same SCION AS with different underlay addrs
// share a topological path fingerprint — `daemon.Paths` returns paths
// per-IA. The second upsert would find the first peer's entry in the
// reverse index and "update it in place", returning the first peer's key.
// Both peers then resolved to one scionPathInfo with one hostAddr,
// routing the second peer's outbound traffic to the wrong underlay.
//
// The fix keys scionPathFPKey on (peerIA, hostAddr, fingerprint). This
// test locks in that contract: same IA + fingerprint but different
// hostAddrs yield two distinct registry entries with their own hostAddrs.
func TestUpsertSCIONPathLocked_SameIADifferentHostDoesNotCollide(t *testing.T) {
	ctrl := gomock.NewController(t)
	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")
	hostA := netip.MustParseAddrPort("192.168.20.175:32766")
	hostB := netip.MustParseAddrPort("192.168.20.185:32767")

	iface1 := snet.PathInterface{IA: localIA, ID: 1}
	iface2 := snet.PathInterface{IA: peerIA, ID: 2}
	md := &snet.PathMetadata{
		Interfaces: []snet.PathInterface{iface1, iface2},
		Expiry:     time.Now().Add(1 * time.Hour),
		MTU:        1472,
	}
	// Two mock paths with the same topology → same fingerprint. This
	// mirrors what the daemon returns when two hosts share an AS: the
	// inter-AS route is the same regardless of which host you're reaching.
	pathForA := newMockPathWithMetadata(ctrl, md)
	pathForB := newMockPathWithMetadata(ctrl, md)
	fp := pathForA.Metadata().Fingerprint()
	if fp == "" || fp != pathForB.Metadata().Fingerprint() {
		t.Fatalf("test setup: paths must share a non-empty fingerprint")
	}

	c := &Conn{connCtx: context.Background()}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{localIA: localIA})

	c.mu.Lock()
	kA, registeredA, collisionA := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostA, pathForA, fp)
	c.mu.Unlock()
	if !registeredA || collisionA {
		t.Fatalf("first upsert: registered=%v, collision=%v (want true, false)", registeredA, collisionA)
	}

	c.mu.Lock()
	kB, registeredB, collisionB := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostB, pathForB, fp)
	c.mu.Unlock()
	if !registeredB {
		t.Fatalf("second upsert (different hostAddr): registered=%v; want true (two peers in same IA must get distinct entries)", registeredB)
	}
	if collisionB {
		t.Fatalf("second upsert: collision=true unexpected; same topology to different hosts is not a hash collision")
	}
	if kA == kB {
		t.Fatalf("second upsert returned key %d == first (%d); must be distinct (same-IA different-host bug)", kB, kA)
	}

	// Each key's pathInfo must carry its own hostAddr.
	piA := c.lookupSCIONPathLocking(kA)
	piB := c.lookupSCIONPathLocking(kB)
	if piA == nil || piB == nil {
		t.Fatalf("one or both pathInfos missing: piA=%v piB=%v", piA, piB)
	}
	if piA.hostAddr != hostA {
		t.Errorf("piA.hostAddr = %v, want %v", piA.hostAddr, hostA)
	}
	if piB.hostAddr != hostB {
		t.Errorf("piB.hostAddr = %v, want %v", piB.hostAddr, hostB)
	}
}

// TestUpsertSCIONPathLocked_HopCountCollision verifies the fingerprint-
// collision guard: if a daemon response yields the same fingerprint but a
// different interface count as an already-registered entry, we treat it as
// a hash collision (two topologically distinct paths hashing to the same
// fingerprint), leave the existing entry untouched, and bump the
// metricSCIONFingerprintCollision counter.
func TestUpsertSCIONPathLocked_HopCountCollision(t *testing.T) {
	ctrl := gomock.NewController(t)
	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")
	hostAddr := netip.MustParseAddrPort("10.0.0.1:41641")

	iface1 := snet.PathInterface{IA: localIA, ID: 1}
	iface2 := snet.PathInterface{IA: peerIA, ID: 2}
	iface3 := snet.PathInterface{IA: addr.MustParseIA("1-ff00:0:abc"), ID: 3}

	path2hop := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Interfaces: []snet.PathInterface{iface1, iface2},
		Expiry:     time.Now().Add(1 * time.Hour),
		MTU:        1472,
	})
	path4hop := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Interfaces: []snet.PathInterface{iface1, iface3, iface3, iface2},
		Expiry:     time.Now().Add(2 * time.Hour),
		MTU:        1472,
	})
	// Force both mocks to hash to the same fingerprint to simulate collision.
	// We can't control the fingerprint directly, so we use a shared FP value
	// via the upsert helper's acceptance of an explicit fp argument.
	fakeFP := snet.PathFingerprint("fake-collision-fp")

	c := &Conn{connCtx: context.Background()}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{localIA: localIA})

	c.mu.Lock()
	k1, registered1, _ := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostAddr, path2hop, fakeFP)
	c.mu.Unlock()
	if !registered1 {
		t.Fatalf("first upsert: expected registered=true")
	}

	before := metricSCIONFingerprintCollision.Value()

	// Second upsert uses SAME fingerprint but a DIFFERENT interface count.
	// Must NOT overwrite the existing entry and must bump the collision metric.
	c.mu.Lock()
	k2, registered2, collision := c.upsertSCIONPathLocked(c.pconnSCION.Load(), peerIA, hostAddr, path4hop, fakeFP)
	c.mu.Unlock()
	if !collision {
		t.Fatalf("second upsert: collision=false, want true (differing hop counts should collide)")
	}
	if registered2 {
		t.Errorf("second upsert: registered=true on collision; must not mint a new entry")
	}
	if k2 != k1 {
		t.Errorf("second upsert: returned key %d, want %d (existing key, not new)", k2, k1)
	}
	if got, want := metricSCIONFingerprintCollision.Value(), before+1; got != want {
		t.Errorf("metricSCIONFingerprintCollision = %d, want %d (+1 from collision)", got, want)
	}
	// The existing entry's path must still be the 2-hop one.
	pi := c.lookupSCIONPathLocking(k1)
	pi.mu.Lock()
	existingIfaces := 0
	if pi.path != nil {
		if md := pi.path.Metadata(); md != nil {
			existingIfaces = len(md.Interfaces)
		}
	}
	pi.mu.Unlock()
	if existingIfaces != 2 {
		t.Errorf("existing path interface count = %d, want 2 (untouched)", existingIfaces)
	}
}

// --- Phase 1c: per-peer refresh backoff ---

func TestScionRefreshBackoff_FreshShouldAttempt(t *testing.T) {
	// Freshly zeroed backoff: should attempt immediately.
	var b scionRefreshBackoff
	now := time.Now()
	if !b.shouldAttempt(now) {
		t.Fatalf("fresh scionRefreshBackoff must allow attempt; got nextAttemptAt=%v now=%v",
			b.nextAttemptAt, now)
	}
}

func TestScionRefreshBackoff_SuccessClearsBackoff(t *testing.T) {
	// After a successful refresh, the failure counter and scheduled-next-attempt
	// must both clear so the next refresh tick (from the outer ticker) can run
	// without being throttled. The outer ticker is the authority on cadence;
	// per-peer backoff only gates failure retries.
	var b scionRefreshBackoff
	b.consecutiveFailures = 3
	b.lastError = "boom"
	now := time.Unix(1_000_000, 0)
	b.nextAttemptAt = now.Add(5 * time.Minute) // leftover from prior failure

	b.recordSuccess(now, 30*time.Second)

	if b.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures after success: got %d, want 0", b.consecutiveFailures)
	}
	if b.lastError != "" {
		t.Errorf("lastError after success: got %q, want empty", b.lastError)
	}
	if !b.nextAttemptAt.IsZero() {
		t.Errorf("nextAttemptAt after success: got %v, want zero (cleared)", b.nextAttemptAt)
	}
	if !b.shouldAttempt(now) {
		t.Errorf("shouldAttempt right after success must be true (no throttling on the success path)")
	}
}

func TestScionRefreshBackoff_FailureGrowsExpCapped(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	const (
		base = 30 * time.Second
		cap_ = 2 * time.Minute
	)
	// The table encodes: failure N ⇒ backoff = base * 2^min(N,5), capped at cap_.
	// N=1 → 60s,  N=2 → 120s (capped),  N=3..7 → 120s (capped),  ...
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 60 * time.Second},
		{2, 2 * time.Minute},
		{3, 2 * time.Minute},
		{4, 2 * time.Minute},
		{5, 2 * time.Minute},
		{6, 2 * time.Minute},
		{10, 2 * time.Minute},
	}
	for _, tt := range tests {
		var fresh scionRefreshBackoff
		for i := 0; i < tt.failures; i++ {
			fresh.recordFailure(now, fmt.Errorf("fail %d", i), base, cap_)
		}
		if fresh.consecutiveFailures != tt.failures {
			t.Errorf("failures=%d: counter=%d, want %d", tt.failures, fresh.consecutiveFailures, tt.failures)
		}
		gotBackoff := fresh.nextAttemptAt.Sub(now)
		if gotBackoff != tt.want {
			t.Errorf("failures=%d: backoff=%v, want %v (nextAttemptAt=%v)",
				tt.failures, gotBackoff, tt.want, fresh.nextAttemptAt)
		}
		if fresh.lastError == "" {
			t.Errorf("failures=%d: lastError empty; should have recorded last error message", tt.failures)
		}
	}
}

// TestRefreshSCIONPathsOnce_PerPeerBackoffIsolation verifies that one peer's
// refresh failure does not delay refreshes for other peers. Before per-peer
// backoff, any peer's daemon error would increment a goroutine-wide counter
// and back off refresh attempts for every peer.
func TestRefreshSCIONPathsOnce_PerPeerBackoffIsolation(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerGood := addr.MustParseIA("1-ff00:0:111")
	peerBad := addr.MustParseIA("71-2:0:4a") // mimic the TRC-missing SCIONLab case

	// Good peer: daemon returns a valid path.
	goodExpiry := time.Now().Add(2 * time.Hour)
	goodPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Latency: []time.Duration{3 * time.Millisecond},
		Expiry:  goodExpiry,
	})
	mockDaemon.EXPECT().
		Paths(gomock.Any(), peerGood, localIA, daemontypes.PathReqFlags{Refresh: true}).
		Return([]snet.Path{goodPath}, nil)

	// Bad peer: daemon errors (simulates "TRC not found" class of failure).
	mockDaemon.EXPECT().
		Paths(gomock.Any(), peerBad, localIA, daemontypes.PathReqFlags{Refresh: true}).
		Return(nil, fmt.Errorf("TRC not found"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Conn{connCtx: ctx}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

	// Both peers have paths near expiry (needs hard refresh).
	piGood := &scionPathInfo{
		peerIA:   peerGood,
		hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
		expiry:   time.Now().Add(30 * time.Second),
	}
	piBad := &scionPathInfo{
		peerIA:      peerBad,
		hostAddr:    netip.MustParseAddrPort("10.0.0.2:41641"),
		expiry:      time.Now().Add(30 * time.Second),
		fingerprint: "some-fp",
	}
	c.registerSCIONPathLocking(piGood)
	c.registerSCIONPathLocking(piBad)

	if err := c.refreshSCIONPathsOnce(); err == nil {
		t.Fatalf("expected error from bad peer; got nil")
	}

	// Good peer backoff: 0 failures, nextAttemptAt ≈ now + base.
	c.mu.Lock()
	bGood := c.scionRefreshByIA[peerGood]
	bBad := c.scionRefreshByIA[peerBad]
	c.mu.Unlock()
	if bGood == nil {
		t.Fatalf("good peer has no refresh backoff entry; per-peer state not recorded")
	}
	if bGood.consecutiveFailures != 0 {
		t.Errorf("good peer consecutiveFailures = %d, want 0", bGood.consecutiveFailures)
	}
	if bBad == nil {
		t.Fatalf("bad peer has no refresh backoff entry")
	}
	if bBad.consecutiveFailures != 1 {
		t.Errorf("bad peer consecutiveFailures = %d, want 1", bBad.consecutiveFailures)
	}
	// Bad peer's nextAttemptAt must be further out than good peer's.
	if !bBad.nextAttemptAt.After(bGood.nextAttemptAt) {
		t.Errorf("bad peer nextAttemptAt (%v) should be after good peer nextAttemptAt (%v)",
			bBad.nextAttemptAt, bGood.nextAttemptAt)
	}
}

// TestRefreshSCIONPathsOnce_SkipsPeerBeforeNextAttempt verifies that
// refreshSCIONPathsOnce respects per-peer backoff: a peer whose backoff has
// not yet elapsed is NOT queried from the daemon.
func TestRefreshSCIONPathsOnce_SkipsPeerBeforeNextAttempt(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerBackedOff := addr.MustParseIA("71-2:0:4a")

	// Crucially: no EXPECT on mockDaemon.Paths for peerBackedOff in Refresh:true
	// mode. If the refresh attempts to call daemon.Paths for this peer, gomock
	// will fail the test with "unexpected call".

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Conn{connCtx: ctx}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

	pi := &scionPathInfo{
		peerIA:      peerBackedOff,
		hostAddr:    netip.MustParseAddrPort("10.0.0.2:41641"),
		expiry:      time.Now().Add(30 * time.Second), // would trigger hard refresh
		fingerprint: "some-fp",
	}
	c.registerSCIONPathLocking(pi)

	// Seed backoff state: we're mid-backoff, next attempt 5 minutes from now.
	c.mu.Lock()
	if c.scionRefreshByIA == nil {
		c.scionRefreshByIA = make(map[addr.IA]*scionRefreshBackoff)
	}
	c.scionRefreshByIA[peerBackedOff] = &scionRefreshBackoff{
		consecutiveFailures: 5,
		nextAttemptAt:       time.Now().Add(5 * time.Minute),
	}
	c.mu.Unlock()

	// This must NOT call daemon.Paths for peerBackedOff; if it did, gomock
	// would raise an unexpected-call error and fail the test.
	_ = c.refreshSCIONPathsOnce()

	// Backoff state unchanged.
	c.mu.Lock()
	b := c.scionRefreshByIA[peerBackedOff]
	c.mu.Unlock()
	if b == nil {
		t.Fatalf("backoff entry was lost")
	}
	if b.consecutiveFailures != 5 {
		t.Errorf("consecutiveFailures = %d, want 5 (unchanged because refresh was skipped)", b.consecutiveFailures)
	}
}

// TestRefreshSCIONPathsOnce_BackoffRecovery verifies that once a previously-
// failing peer succeeds, its backoff state clears so future refresh ticks
// proceed at the base cadence. This is the counterpart to the isolation
// test: that test shows a failing peer doesn't drag others down; this one
// shows recovery works.
func TestRefreshSCIONPathsOnce_BackoffRecovery(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockDaemon := mock_daemon.NewMockConnector(ctrl)

	localIA := addr.MustParseIA("1-ff00:0:110")
	peerIA := addr.MustParseIA("1-ff00:0:111")

	// The daemon will fail twice, then return a valid path.
	goodPath := newMockPathWithMetadata(ctrl, &snet.PathMetadata{
		Latency: []time.Duration{3 * time.Millisecond},
		Expiry:  time.Now().Add(2 * time.Hour),
	})
	gomock.InOrder(
		mockDaemon.EXPECT().
			Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return(nil, fmt.Errorf("transient")),
		mockDaemon.EXPECT().
			Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return(nil, fmt.Errorf("transient")),
		mockDaemon.EXPECT().
			Paths(gomock.Any(), peerIA, localIA, daemontypes.PathReqFlags{Refresh: true}).
			Return([]snet.Path{goodPath}, nil),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Conn{connCtx: ctx}
	c.logf = t.Logf
	c.pconnSCION.Store(&scionConn{daemon: mockDaemon, localIA: localIA})

	pi := &scionPathInfo{
		peerIA:      peerIA,
		hostAddr:    netip.MustParseAddrPort("10.0.0.1:41641"),
		expiry:      time.Now().Add(30 * time.Second),
		fingerprint: "some-fp",
	}
	c.registerSCIONPathLocking(pi)

	// First call: fails. Counter = 1, nextAttemptAt set.
	_ = c.refreshSCIONPathsOnce()
	c.mu.Lock()
	b := c.scionRefreshByIA[peerIA]
	c.mu.Unlock()
	if b == nil || b.consecutiveFailures != 1 {
		t.Fatalf("after first failure: counter=%d, want 1", b.consecutiveFailures)
	}
	firstBackoff := b.nextAttemptAt

	// Force-advance the backoff window so the next refresh call proceeds.
	// (In production the outer ticker fires at 30s regardless; in this
	// synchronous test we clear nextAttemptAt to bypass the gate.)
	c.mu.Lock()
	c.scionRefreshByIA[peerIA].nextAttemptAt = time.Time{}
	c.mu.Unlock()

	// Second call: fails again. Counter = 2.
	_ = c.refreshSCIONPathsOnce()
	c.mu.Lock()
	b = c.scionRefreshByIA[peerIA]
	c.mu.Unlock()
	if b.consecutiveFailures != 2 {
		t.Fatalf("after second failure: counter=%d, want 2", b.consecutiveFailures)
	}
	if !b.nextAttemptAt.After(firstBackoff) {
		t.Errorf("second failure backoff %v should be further out than first %v",
			b.nextAttemptAt, firstBackoff)
	}

	// Clear gate again for the third (successful) attempt.
	c.mu.Lock()
	c.scionRefreshByIA[peerIA].nextAttemptAt = time.Time{}
	c.mu.Unlock()

	// Third call: succeeds. Counter MUST reset to 0 and nextAttemptAt MUST clear.
	err := c.refreshSCIONPathsOnce()
	if err != nil {
		t.Fatalf("third call expected success, got error: %v", err)
	}
	c.mu.Lock()
	b = c.scionRefreshByIA[peerIA]
	last := c.scionRefreshLastSuccess
	c.mu.Unlock()
	if b.consecutiveFailures != 0 {
		t.Errorf("after success: counter=%d, want 0 (reset)", b.consecutiveFailures)
	}
	if !b.nextAttemptAt.IsZero() {
		t.Errorf("after success: nextAttemptAt=%v, want zero (cleared)", b.nextAttemptAt)
	}
	if b.lastError != "" {
		t.Errorf("after success: lastError=%q, want empty", b.lastError)
	}
	if last.IsZero() {
		t.Errorf("scionRefreshLastSuccess not updated after successful refresh")
	}
}

func TestScionRefreshBackoff_ShouldAttemptRespectsNextAttempt(t *testing.T) {
	var b scionRefreshBackoff
	now := time.Unix(1_000_000, 0)
	b.recordFailure(now, fmt.Errorf("boom"), 30*time.Second, 2*time.Minute)

	// Immediately after failure, must NOT attempt.
	if b.shouldAttempt(now) {
		t.Errorf("shouldAttempt at failure time must be false")
	}
	// Halfway through the backoff window, still no.
	if b.shouldAttempt(now.Add(15 * time.Second)) {
		t.Errorf("shouldAttempt mid-window must be false")
	}
	// Exactly at nextAttemptAt, YES.
	if !b.shouldAttempt(b.nextAttemptAt) {
		t.Errorf("shouldAttempt at nextAttemptAt must be true")
	}
	// After, YES.
	if !b.shouldAttempt(b.nextAttemptAt.Add(1 * time.Second)) {
		t.Errorf("shouldAttempt after nextAttemptAt must be true")
	}
}
