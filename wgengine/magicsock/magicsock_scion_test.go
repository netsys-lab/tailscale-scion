// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
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

	st := &scionEndpointState{
		peerIA:   ia,
		hostAddr: hostAddr,
		pathKey:  scionPathKey(5),
	}

	if st.peerIA != ia {
		t.Errorf("peerIA = %v, want %v", st.peerIA, ia)
	}
	if st.hostAddr != hostAddr {
		t.Errorf("hostAddr = %v, want %v", st.hostAddr, hostAddr)
	}
	if !st.pathKey.IsSet() {
		t.Error("pathKey should be set")
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
		{"below range", "29999", 0},
		{"above range", "32768", 0},
		{"non-numeric", "abc", 0},
		{"wireguard port", "41641", 0},
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

		k, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !k.IsSet() {
			t.Fatal("returned key should be set")
		}

		pi := c.lookupSCIONPathLocking(k)
		if pi == nil {
			t.Fatal("path info not found in registry")
		}
		if pi.peerIA != peerIA {
			t.Errorf("peerIA = %v, want %v", pi.peerIA, peerIA)
		}
		if pi.hostAddr != hostAddr {
			t.Errorf("hostAddr = %v, want %v", pi.hostAddr, hostAddr)
		}
		// The selected path should be the fast one (5ms).
		if pi.path != fastPath {
			t.Error("should have selected the lowest-latency path")
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

		k, err := c.discoverSCIONPaths(context.Background(), peerIA, hostAddr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		pi := c.lookupSCIONPathLocking(k)
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
		peerIA:   pi.peerIA,
		hostAddr: pi.hostAddr,
		pathKey:  k,
	}

	de.stopAndReset()

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
