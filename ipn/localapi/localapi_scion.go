// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2026 netsys-lab
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package localapi

import (
	"encoding/json"
	"net/http"
)

func init() {
	Register("scion-status", (*Handler).serveSCIONStatus)
}

// SCIONStatusResponse is the JSON response for GET /localapi/v0/scion-status.
type SCIONStatusResponse struct {
	Connected bool   `json:"Connected"`
	LocalIA   string `json:"LocalIA,omitempty"`
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SCIONStatusResponse{
		Connected: connected,
		LocalIA:   localIA,
	})
}