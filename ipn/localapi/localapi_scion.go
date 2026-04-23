// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2026 netsys-lab
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package localapi

import (
	"encoding/json"
	"net/http"
	"time"
)

func init() {
	Register("scion-status", (*Handler).serveSCIONStatus)
}

// SCIONStatusResponse is the JSON response for GET /localapi/v0/scion-status.
type SCIONStatusResponse struct {
	Connected bool   `json:"Connected"`
	LocalIA   string `json:"LocalIA,omitempty"`
	// LastConnectError is the most recent SCION connect-attempt failure
	// message (empty if SCION is connected or has never failed). Operators
	// use this field to diagnose "why is SCION down?" without reading the
	// raw log stream.
	LastConnectError string `json:"LastConnectError,omitempty"`
	// LastConnectErrorAt is the wall-clock time of the failure recorded in
	// LastConnectError, encoded as RFC3339 when non-zero.
	LastConnectErrorAt string `json:"LastConnectErrorAt,omitempty"`
	// RefreshLastSuccessAt is the wall-clock time (RFC3339) of the most
	// recent refresh tick that succeeded for at least one peer. A large
	// gap indicates the refresh goroutine is stuck or all peers are
	// failing.
	RefreshLastSuccessAt string `json:"RefreshLastSuccessAt,omitempty"`
	// RefreshBackoffByIA is a per-peer-ISD map of refresh backoff state.
	// Only peers with non-empty backoff entries (ConsecutiveFailures > 0,
	// or a pending next attempt) are present — healthy peers are omitted
	// to keep the response compact.
	RefreshBackoffByIA map[string]RefreshBackoffState `json:"RefreshBackoffByIA,omitempty"`
}

// RefreshBackoffState describes one peer's refresh backoff window.
type RefreshBackoffState struct {
	ConsecutiveFailures int    `json:"ConsecutiveFailures"`
	NextAttemptAt       string `json:"NextAttemptAt,omitempty"` // RFC3339
	LastError           string `json:"LastError,omitempty"`
	LastErrorAt         string `json:"LastErrorAt,omitempty"` // RFC3339
	// LastErrorKind is a short stable classification:
	// "trc-missing" | "no-segments" | "daemon-unreachable" | "" (other).
	LastErrorKind string `json:"LastErrorKind,omitempty"`
}

func (h *Handler) serveSCIONStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mc := h.b.MagicConn()
	if mc == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	connected, localIA := mc.SCIONStatus()
	lastErr, lastErrAt := mc.SCIONLastConnectError()
	refreshLastSuccess, refreshBackoff := mc.SCIONRefreshStatus()
	resp := SCIONStatusResponse{
		Connected:        connected,
		LocalIA:          localIA,
		LastConnectError: lastErr,
	}
	if !lastErrAt.IsZero() {
		resp.LastConnectErrorAt = lastErrAt.UTC().Format(time.RFC3339)
	}
	if !refreshLastSuccess.IsZero() {
		resp.RefreshLastSuccessAt = refreshLastSuccess.UTC().Format(time.RFC3339)
	}
	if len(refreshBackoff) > 0 {
		resp.RefreshBackoffByIA = make(map[string]RefreshBackoffState, len(refreshBackoff))
		for _, b := range refreshBackoff {
			state := RefreshBackoffState{
				ConsecutiveFailures: b.ConsecutiveFailures,
				LastError:           b.LastError,
				LastErrorKind:       b.LastErrorKind,
			}
			if !b.NextAttemptAt.IsZero() {
				state.NextAttemptAt = b.NextAttemptAt.UTC().Format(time.RFC3339)
			}
			if !b.LastErrorAt.IsZero() {
				state.LastErrorAt = b.LastErrorAt.UTC().Format(time.RFC3339)
			}
			resp.RefreshBackoffByIA[b.IA] = state
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}