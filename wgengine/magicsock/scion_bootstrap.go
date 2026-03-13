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
)

// defaultBootstrapURLs contains well-known bootstrap server URLs for major
// SCION deployments. Populated as deployments are identified; DNS discovery
// is the primary automatic mechanism.
var defaultBootstrapURLs []string = []string{
	"http://141.44.25.151:8041",
	"http://128.143.201.144:8041",
}

var (
	scionBootstrapURL  = envknob.RegisterString("TS_SCION_BOOTSTRAP_URL")
	scionBootstrapURLs = envknob.RegisterString("TS_SCION_BOOTSTRAP_URLS")
)

// bootstrapSCION fetches topology.json and TRCs from a bootstrap server,
// saving them to destDir.
func bootstrapSCION(ctx context.Context, logf logger.Logf, serverURL string, destDir string) error {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("creating bootstrap directory %s: %w", destDir, err)
	}

	client := &http.Client{Timeout: bootstrapHTTPTimeout}

	// Fetch topology.
	topoURL := strings.TrimRight(serverURL, "/") + "/topology"
	topoData, err := httpGet(ctx, client, topoURL)
	if err != nil {
		return fmt.Errorf("fetching topology from %s: %w", topoURL, err)
	}
	topoPath := filepath.Join(destDir, "topology.json")
	if err := atomicfile.WriteFile(topoPath, topoData, 0o644); err != nil {
		return fmt.Errorf("writing topology to %s: %w", topoPath, err)
	}
	logf("scion: bootstrap: fetched topology from %s", serverURL)

	// Fetch TRC index.
	trcsURL := strings.TrimRight(serverURL, "/") + "/trcs"
	trcsData, err := httpGet(ctx, client, trcsURL)
	if err != nil {
		// TRCs are optional for Phase 1 (accept-all verification).
		logf("scion: bootstrap: TRC index not available from %s: %v", serverURL, err)
		return nil
	}

	certsDir := filepath.Join(destDir, "certs")
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		return fmt.Errorf("creating certs directory %s: %w", certsDir, err)
	}

	// Parse TRC index and fetch each TRC blob.
	var trcIndex []trcEntry
	if err := json.Unmarshal(trcsData, &trcIndex); err != nil {
		// Non-fatal: TRC index may not be JSON array on all servers.
		logf("scion: bootstrap: failed to parse TRC index: %v", err)
		return nil
	}

	fetched := 0
	for _, entry := range trcIndex {
		if entry.ID.ISD == 0 {
			continue // skip unparseable entries
		}
		idStr := entry.ID.String()
		blobURL := strings.TrimRight(serverURL, "/") + "/trcs/" + idStr + "/blob"
		blob, err := httpGet(ctx, client, blobURL)
		if err != nil {
			continue // Best-effort TRC download.
		}
		trcPath := filepath.Join(certsDir, idStr+".trc")
		if err := atomicfile.WriteFile(trcPath, blob, 0o644); err != nil {
			continue
		}
		fetched++
	}
	logf("scion: bootstrap: fetched %d/%d TRCs from %s", fetched, len(trcIndex), serverURL)

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

// httpGet performs an HTTP GET request and returns the response body.
func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
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

	// Limit response body to 10MB to prevent excessive memory usage.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
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
