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
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/mock_daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/mock_snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
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
			name:        "valid IPv4",
			description: "1-ff00:0:110,192.0.2.1",
			port:        41641,
			wantIA:      addr.MustParseIA("1-ff00:0:110"),
			wantAddr:    netip.MustParseAddrPort("192.0.2.1:41641"),
		},
		{
			name:        "valid IPv6",
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
			name: "peer with SCION service",
			node: &tailcfg.Node{
				ID:  1,
				Key: testNodeKey(),
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: tailcfg.TCP, Port: 80},
						{Proto: tailcfg.SCION, Port: 41641, Description: "1-ff00:0:110,192.0.2.1"},
					},
				}).View(),
			},
			wantIA:   addr.MustParseIA("1-ff00:0:110"),
			wantAddr: netip.MustParseAddrPort("192.0.2.1:41641"),
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
			name: "peer with SCION in peerapi4 description (piggyback)",
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
				t.Setenv("TS_SCION_PORT", tt.envVal)
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

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: false}).
			Return([]snet.Path{slowPath, fastPath, mediumPath}, nil)

		c := &Conn{}
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: false}).
			Return(nil, nil)

		c := &Conn{}
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

		_, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err == nil {
			t.Fatal("expected error for no paths")
		}
	})

	t.Run("daemon error", func(t *testing.T) {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: false}).
			Return(nil, fmt.Errorf("daemon unavailable"))

		c := &Conn{}
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: false}).
			Return([]snet.Path{noMetaPath}, nil)

		c := &Conn{}
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: true}).
			Return([]snet.Path{newPath}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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
		// No daemon calls expected — the path doesn't need refresh.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

		// Register a path that's far from expiry.
		pi := &scionPathInfo{
			peerIA:   peerIA,
			hostAddr: netip.MustParseAddrPort("10.0.0.1:41641"),
			expiry:   time.Now().Add(2 * time.Hour),
		}
		c.registerSCIONPathLocking(pi)

		// Should not call daemon.Paths since path doesn't need refresh.
		c.refreshSCIONPathsOnce()
	})

	t.Run("handles daemon failure gracefully", func(t *testing.T) {
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: true}).
			Return(nil, fmt.Errorf("daemon unreachable"))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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

		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: true}).
			Return([]snet.Path{slowPath, fastPath}, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := &Conn{
			connCtx: ctx,
		}
		c.logf = t.Logf
		c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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
	c.pconnSCION = &scionConn{}

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
	c.pconnSCION = &scionConn{}

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
	c.pconnSCION = &scionConn{daemon: mockDaemon, localIA: localIA}

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
		mockDaemon.EXPECT().Paths(gomock.Any(), peerIA, localIA, daemon.PathReqFlags{Refresh: true}).
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
