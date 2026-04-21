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
	resp := SCIONStatusResponse{
		Connected:        connected,
		LocalIA:          localIA,
		LastConnectError: lastErr,
	}
	if !lastErrAt.IsZero() {
		resp.LastConnectErrorAt = lastErrAt.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}