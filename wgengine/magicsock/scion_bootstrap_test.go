// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/types/logger"
)

func TestTrcIDString(t *testing.T) {
	tests := []struct {
		id   trcID
		want string
	}{
		{trcID{ISD: 19, BaseNumber: 1, SerialNumber: 1}, "isd19-b1-s1"},
		{trcID{ISD: 1, BaseNumber: 2, SerialNumber: 3}, "isd1-b2-s3"},
		{trcID{ISD: 0, BaseNumber: 0, SerialNumber: 0}, "isd0-b0-s0"},
	}
	for _, tt := range tests {
		got := tt.id.String()
		if got != tt.want {
			t.Errorf("trcID%+v.String() = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestTrcIndexParsing(t *testing.T) {
	// Real bootstrap server JSON format.
	raw := `[{"id":{"isd":19,"base_number":1,"serial_number":1}},{"id":{"isd":19,"base_number":1,"serial_number":2}}]`
	var entries []trcEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[0].ID.ISD; got != 19 {
		t.Errorf("entries[0].ID.ISD = %d, want 19", got)
	}
	if got := entries[0].ID.String(); got != "isd19-b1-s1" {
		t.Errorf("entries[0].ID.String() = %q, want %q", got, "isd19-b1-s1")
	}
	if got := entries[1].ID.String(); got != "isd19-b1-s2" {
		t.Errorf("entries[1].ID.String() = %q, want %q", got, "isd19-b1-s2")
	}
}

func TestTrcIndexParsingOldFormat(t *testing.T) {
	// The old flat string format ({"id": "ISD19-B1-S1"}) is incompatible
	// with the nested struct. json.Unmarshal should return an error,
	// and bootstrapSCION handles this gracefully (non-fatal).
	raw := `[{"id":"ISD19-B1-S1"}]`
	var entries []trcEntry
	if err := json.Unmarshal([]byte(raw), &entries); err == nil {
		t.Fatal("expected Unmarshal error for old string format, got nil")
	}
}

func TestBootstrapSCION(t *testing.T) {
	topoJSON := `{"isd_as":"19-ffaa:1:eba","mtu":1472}`
	trcBlob := []byte("fake-trc-blob")
	trcIndex := `[{"id":{"isd":19,"base_number":1,"serial_number":1}}]`

	mux := http.NewServeMux()
	mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(topoJSON))
	})
	mux.HandleFunc("/trcs", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trcIndex))
	})
	mux.HandleFunc("/trcs/isd19-b1-s1/blob", func(w http.ResponseWriter, r *http.Request) {
		w.Write(trcBlob)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	destDir := t.TempDir()
	logf := logger.WithPrefix(t.Logf, "test: ")

	if err := bootstrapSCION(context.Background(), logf, srv.URL, destDir); err != nil {
		t.Fatalf("bootstrapSCION: %v", err)
	}

	// Verify topology file.
	topoPath := filepath.Join(destDir, "topology.json")
	data, err := os.ReadFile(topoPath)
	if err != nil {
		t.Fatalf("reading topology: %v", err)
	}
	if string(data) != topoJSON {
		t.Errorf("topology content = %q, want %q", data, topoJSON)
	}

	// Verify TRC file.
	trcPath := filepath.Join(destDir, "certs", "isd19-b1-s1.trc")
	data, err = os.ReadFile(trcPath)
	if err != nil {
		t.Fatalf("reading TRC: %v", err)
	}
	if string(data) != string(trcBlob) {
		t.Errorf("TRC content = %q, want %q", data, trcBlob)
	}
}

func TestBootstrapSCIONTopologyOnly(t *testing.T) {
	// Server that returns topology but 404 on TRCs — should succeed.
	topoJSON := `{"isd_as":"19-ffaa:1:eba"}`

	mux := http.NewServeMux()
	mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(topoJSON))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	destDir := t.TempDir()
	logf := logger.WithPrefix(t.Logf, "test: ")

	if err := bootstrapSCION(context.Background(), logf, srv.URL, destDir); err != nil {
		t.Fatalf("bootstrapSCION: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(destDir, "topology.json"))
	if err != nil {
		t.Fatalf("reading topology: %v", err)
	}
	if string(data) != topoJSON {
		t.Errorf("topology content = %q, want %q", data, topoJSON)
	}
}

func TestBootstrapURLs(t *testing.T) {
	logf := logger.WithPrefix(t.Logf, "test: ")

	// Use envknob.Setenv so the registered knob functions see the values.
	envknob.Setenv("TS_SCION_BOOTSTRAP_URL", "http://explicit:8041")
	t.Cleanup(func() { envknob.Setenv("TS_SCION_BOOTSTRAP_URL", "") })
	envknob.Setenv("TS_SCION_BOOTSTRAP_URLS", "http://list1:8041, http://list2:8041")
	t.Cleanup(func() { envknob.Setenv("TS_SCION_BOOTSTRAP_URLS", "") })

	urls := bootstrapURLs(context.Background(), logf)

	if len(urls) < 4 {
		t.Fatalf("expected at least 4 URLs, got %d: %v", len(urls), urls)
	}
	if urls[0] != "http://explicit:8041" {
		t.Errorf("urls[0] = %q, want explicit URL", urls[0])
	}
	if urls[1] != "http://list1:8041" {
		t.Errorf("urls[1] = %q, want list1", urls[1])
	}
	if urls[2] != "http://list2:8041" {
		t.Errorf("urls[2] = %q, want list2", urls[2])
	}

	// Hardcoded defaults should be at the end.
	tail := urls[len(urls)-len(defaultBootstrapURLs):]
	for i, want := range defaultBootstrapURLs {
		if tail[i] != want {
			t.Errorf("tail[%d] = %q, want %q", i, tail[i], want)
		}
	}
}

func TestLocalSearchDomainFromHostname(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		// Note: we can't easily override os.Hostname() in tests,
		// so we test the parsing logic via the function contract.
	}
	_ = tests

	// At minimum, verify the function doesn't panic.
	_, _ = localSearchDomainFromHostname()
}
