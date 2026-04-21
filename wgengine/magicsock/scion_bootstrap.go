// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion

package magicsock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/envknob"
	"tailscale.com/types/logger"
)

const (
	// bootstrapHTTPTimeout is the timeout for HTTP requests to the bootstrap server.
	bootstrapHTTPTimeout = 10 * time.Second

	// scionDiscoverySRV is the SRV record name for SCION discovery.
	scionDiscoverySRV = "_sciondiscovery._tcp"

	// Bootstrap response-size budgets. The server is untrusted input; a
	// malicious response must not be able to exhaust memory or fill the
	// state directory.
	//
	// bootstrapTopologySizeMax caps the topology.json fetch. Real-world
	// SCION topology files are a few KB; 1 MiB is ample headroom.
	bootstrapTopologySizeMax = 1 << 20 // 1 MiB
	// bootstrapTRCIndexSizeMax caps the JSON index listing TRCs.
	bootstrapTRCIndexSizeMax = 1 << 20 // 1 MiB
	// bootstrapTRCBlobSizeMax caps a single TRC blob fetch.
	bootstrapTRCBlobSizeMax = 1 << 20 // 1 MiB
	// bootstrapMaxTRCEntries caps the number of TRC blobs fetched per
	// bootstrap call, even if the server advertises more.
	bootstrapMaxTRCEntries = 64
	// bootstrapTotalBudget caps the aggregate bytes fetched across a single
	// bootstrap call (topology + index + all TRC blobs). Prevents a
	// malicious server from making the client fetch bootstrapTRCBlobSizeMax
	// × bootstrapMaxTRCEntries ≈ 64 MiB in one go.
	bootstrapTotalBudget = 16 << 20 // 16 MiB
)

// defaultBootstrapURLs contains well-known bootstrap server URLs for major
// SCION deployments. Populated as deployments are identified; DNS discovery
// is the primary automatic mechanism.
var defaultBootstrapURLs []string = []string{
	"http://141.44.25.151:8041", // ovgu.de
	"http://128.143.201.144:8041", // uva
	"http://netsec-w37w3w.inf.ethz.ch:8041", // ethz.ch
}

var (
	scionBootstrapURL  = envknob.RegisterString("TS_SCION_BOOTSTRAP_URL")
	scionBootstrapURLs = envknob.RegisterString("TS_SCION_BOOTSTRAP_URLS")
)

// bootstrapStateVersion is the current on-disk bootstrap schema version. It
// is written to version.json next to topology.json so that a future change
// to the stored shape (new files, renamed fields, incompatible SCION
// dependency upgrade) can detect and rebuild stale state instead of reusing
// it and producing mysterious failures at startup.
const bootstrapStateVersion = 2

// bootstrapStateMeta is the payload stored in version.json.
type bootstrapStateMeta struct {
	Version int `json:"version"`
}

// invalidateBootstrapIfStale wipes destDir when its version.json is missing
// or does not match the current bootstrapStateVersion. Called before each
// bootstrap run so the client never reuses data written by an incompatible
// predecessor.
func invalidateBootstrapIfStale(logf logger.Logf, destDir string) {
	metaPath := filepath.Join(destDir, "version.json")
	data, err := os.ReadFile(metaPath)
	if err == nil {
		var meta bootstrapStateMeta
		if err := json.Unmarshal(data, &meta); err == nil && meta.Version == bootstrapStateVersion {
			return // in-schema; keep.
		}
	}
	// Either missing, corrupt, or out-of-date. Clear the directory so the
	// fresh bootstrap below installs a clean state.
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return // nothing to clean (doesn't exist yet).
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(destDir, e.Name()))
	}
	logf("scion: bootstrap: state directory %s was stale or unversioned; cleared", destDir)
}

// writeBootstrapVersion stamps destDir with the current bootstrap schema
// version. Called on every successful bootstrap.
func writeBootstrapVersion(destDir string) error {
	data, err := json.Marshal(bootstrapStateMeta{Version: bootstrapStateVersion})
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(filepath.Join(destDir, "version.json"), data, 0o644)
}

// bootstrapSCION fetches topology.json and TRCs from a bootstrap server,
// saving them to destDir.
func bootstrapSCION(ctx context.Context, logf logger.Logf, serverURL string, destDir string) error {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("creating bootstrap directory %s: %w", destDir, err)
	}
	invalidateBootstrapIfStale(logf, destDir)

	client := &http.Client{Timeout: bootstrapHTTPTimeout}

	// totalFetched tracks the aggregate bytes pulled across this bootstrap
	// call so a malicious server cannot chain many per-resource-capped
	// responses into an effectively unbounded download.
	var totalFetched int64

	// Fetch topology.
	topoURL := strings.TrimRight(serverURL, "/") + "/topology"
	topoData, err := httpGet(ctx, client, topoURL, bootstrapTopologySizeMax)
	if err != nil {
		return fmt.Errorf("fetching topology from %s: %w", topoURL, err)
	}
	totalFetched += int64(len(topoData))
	topoPath := filepath.Join(destDir, "topology.json")
	if err := atomicfile.WriteFile(topoPath, topoData, 0o644); err != nil {
		return fmt.Errorf("writing topology to %s: %w", topoPath, err)
	}
	logf("scion: bootstrap: fetched topology (%d bytes) from %s", len(topoData), serverURL)

	// Fetch TRC index. TRCs are required: segment verification will not
	// start without at least one TRC present, so a bootstrap server that
	// cannot serve them is not usable and the caller should try the next.
	trcsURL := strings.TrimRight(serverURL, "/") + "/trcs"
	trcsData, err := httpGet(ctx, client, trcsURL, bootstrapTRCIndexSizeMax)
	if err != nil {
		return fmt.Errorf("fetching TRC index from %s: %w", trcsURL, err)
	}
	totalFetched += int64(len(trcsData))

	certsDir := filepath.Join(destDir, "certs")
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		return fmt.Errorf("creating certs directory %s: %w", certsDir, err)
	}

	// Parse TRC index and fetch each TRC blob.
	var trcIndex []trcEntry
	if err := json.Unmarshal(trcsData, &trcIndex); err != nil {
		return fmt.Errorf("parsing TRC index from %s: %w", trcsURL, err)
	}

	// Cap the number of TRC entries we'll attempt. A malicious server
	// could otherwise advertise thousands of IDs and drive the client to
	// fetch all of them.
	if len(trcIndex) > bootstrapMaxTRCEntries {
		logf("scion: bootstrap: TRC index has %d entries, truncating to %d",
			len(trcIndex), bootstrapMaxTRCEntries)
		trcIndex = trcIndex[:bootstrapMaxTRCEntries]
	}

	fetched := 0
	for _, entry := range trcIndex {
		if totalFetched >= bootstrapTotalBudget {
			logf("scion: bootstrap: total-bytes budget (%d) exhausted, stopping TRC fetch", bootstrapTotalBudget)
			break
		}
		if entry.ID.ISD == 0 {
			continue // skip unparseable entries
		}
		idStr := entry.ID.String()
		blobURL := strings.TrimRight(serverURL, "/") + "/trcs/" + idStr + "/blob"
		blob, err := httpGet(ctx, client, blobURL, bootstrapTRCBlobSizeMax)
		if err != nil {
			continue // Best-effort per blob; overall success requires fetched > 0 below.
		}
		totalFetched += int64(len(blob))
		trcPath := filepath.Join(certsDir, idStr+".trc")
		if err := atomicfile.WriteFile(trcPath, blob, 0o644); err != nil {
			continue
		}
		fetched++
	}
	logf("scion: bootstrap: fetched %d/%d TRCs from %s (total %d bytes)",
		fetched, len(trcIndex), serverURL, totalFetched)
	if fetched == 0 {
		return fmt.Errorf("bootstrap from %s produced no TRCs", serverURL)
	}

	if err := writeBootstrapVersion(destDir); err != nil {
		// Non-fatal: the bootstrap succeeded, but next boot won't detect
		// staleness automatically. Log so an operator sees it.
		logf("scion: bootstrap: failed to write version stamp: %v", err)
	}
	return nil
}

// trcEntry represents an entry in the TRC index returned by the bootstrap server.
// The server returns {"id": {"isd": 19, "base_number": 1, "serial_number": 1}}.
type trcEntry struct {
	ID trcID `json:"id"`
}

// trcID represents the composite identifier for a TRC.
type trcID struct {
	ISD          int `json:"isd"`
	BaseNumber   int `json:"base_number"`
	SerialNumber int `json:"serial_number"`
}

// String returns a filesystem-safe representation of the TRC ID,
// e.g. "isd19-b1-s1".
func (id trcID) String() string {
	return fmt.Sprintf("isd%d-b%d-s%d", id.ISD, id.BaseNumber, id.SerialNumber)
}

// discoverBootstrapURL attempts DNS-based discovery of a SCION bootstrap server.
// It follows the JPAN discovery chain:
//  1. SRV lookup for _sciondiscovery._tcp.<domain>
//  2. TXT lookup for _sciondiscovery._tcp.<domain> for port override
func discoverBootstrapURL(ctx context.Context, logf logger.Logf) (string, error) {
	// Determine local search domain from system resolver.
	domain, err := localSearchDomain()
	if err != nil {
		return "", fmt.Errorf("determining search domain: %w", err)
	}
	if domain == "" {
		return "", fmt.Errorf("no search domain found")
	}

	r := &net.Resolver{}

	// Try SRV lookup.
	_, addrs, err := r.LookupSRV(ctx, "sciondiscovery", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("SRV lookup for %s.%s failed: %w", scionDiscoverySRV, domain, err)
	}

	host := strings.TrimRight(addrs[0].Target, ".")
	port := fmt.Sprintf("%d", addrs[0].Port)

	// Check for TXT record port override.
	if txtPort, err := lookupDiscoveryPort(ctx, r, domain); err == nil && txtPort != "" {
		port = txtPort
	}

	url := fmt.Sprintf("http://%s:%s", host, port)
	logf("scion: bootstrap: discovered %s via DNS SRV for %s", url, domain)
	return url, nil
}

// lookupDiscoveryPort queries TXT records for the discovery port override.
func lookupDiscoveryPort(ctx context.Context, r *net.Resolver, domain string) (string, error) {
	name := scionDiscoverySRV + "." + domain
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	for _, txt := range txts {
		if strings.HasPrefix(txt, "x-sciondiscovery=") {
			return strings.TrimPrefix(txt, "x-sciondiscovery="), nil
		}
	}
	return "", fmt.Errorf("no x-sciondiscovery TXT record found")
}

// localSearchDomainFromHostname infers the search domain from the
// system hostname. Used as a fallback on platforms where the primary
// DNS discovery method fails.
func localSearchDomainFromHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		return hostname[i+1:], nil
	}
	return "", fmt.Errorf("no domain suffix in hostname %q", hostname)
}

// httpGet performs an HTTP GET request and returns the response body, capped
// at maxBytes. Callers supply maxBytes so that each kind of bootstrap resource
// (topology, TRC index, TRC blob) has its own ceiling rather than sharing a
// single generous limit.
func httpGet(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// LimitReader + ReadAll enforces the per-resource cap regardless of
	// what Content-Length the server advertised.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= maxBytes {
		// Flag as suspicious: the cap was reached exactly, which indicates
		// the server produced a response at least as large as our ceiling.
		return nil, fmt.Errorf("response exceeded %d byte cap from %s", maxBytes, url)
	}
	return body, nil
}

// bootstrapURLs returns the list of bootstrap URLs to try, from explicit
// configuration, DNS discovery, and hardcoded defaults.
func bootstrapURLs(ctx context.Context, logf logger.Logf) []string {
	var urls []string

	// Explicit URL from environment.
	if u := scionBootstrapURL(); u != "" {
		urls = append(urls, u)
	}

	// Comma-separated list from environment.
	if u := scionBootstrapURLs(); u != "" {
		for _, url := range strings.Split(u, ",") {
			url = strings.TrimSpace(url)
			if url != "" {
				urls = append(urls, url)
			}
		}
	}

	// DNS-discovered URL.
	if discovered, err := discoverBootstrapURL(ctx, logf); err == nil {
		urls = append(urls, discovered)
	}

	// Hardcoded defaults.
	urls = append(urls, defaultBootstrapURLs...)

	logf("scion: bootstrap: %d URLs to try", len(urls))
	return urls
}
