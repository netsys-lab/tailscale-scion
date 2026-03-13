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
	"runtime"
	"strings"
	"time"

	"tailscale.com/net/dns/resolvconffile"
)

const (
	// bootstrapHTTPTimeout is the timeout for HTTP requests to the bootstrap server.
	bootstrapHTTPTimeout = 10 * time.Second

	// defaultBootstrapPort is the default port for SCION discovery servers.
	defaultBootstrapPort = "8041"

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


// bootstrapSCION fetches topology.json and TRCs from a bootstrap server,
// saving them to destDir.
func bootstrapSCION(ctx context.Context, serverURL string, destDir string) error {
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
	if err := os.WriteFile(topoPath, topoData, 0o644); err != nil {
		return fmt.Errorf("writing topology to %s: %w", topoPath, err)
	}

	// Fetch TRC index.
	trcsURL := strings.TrimRight(serverURL, "/") + "/trcs"
	trcsData, err := httpGet(ctx, client, trcsURL)
	if err != nil {
		// TRCs are optional for Phase 1 (accept-all verification).
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
		return nil
	}

	for _, entry := range trcIndex {
		blobURL := strings.TrimRight(serverURL, "/") + "/trcs/" + entry.ID + "/blob"
		blob, err := httpGet(ctx, client, blobURL)
		if err != nil {
			continue // Best-effort TRC download.
		}
		trcPath := filepath.Join(certsDir, entry.ID+".trc")
		_ = os.WriteFile(trcPath, blob, 0o644)
	}

	return nil
}

// trcEntry represents an entry in the TRC index returned by the bootstrap server.
type trcEntry struct {
	ID string `json:"id"`
}

// discoverBootstrapURL attempts DNS-based discovery of a SCION bootstrap server.
// It follows the JPAN discovery chain:
//  1. SRV lookup for _sciondiscovery._tcp.<domain>
//  2. TXT lookup for _sciondiscovery._tcp.<domain> for port override
//  3. Fallback to port 8041
func discoverBootstrapURL(ctx context.Context) (string, error) {
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
	if err == nil && len(addrs) > 0 {
		host := strings.TrimRight(addrs[0].Target, ".")
		port := fmt.Sprintf("%d", addrs[0].Port)

		// Check for TXT record port override.
		if txtPort, err := lookupDiscoveryPort(ctx, r, domain); err == nil && txtPort != "" {
			port = txtPort
		}

		return fmt.Sprintf("http://%s:%s", host, port), nil
	}

	// Fallback: try the domain itself on the default port.
	return fmt.Sprintf("http://%s:%s", domain, defaultBootstrapPort), nil
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

// localSearchDomain returns the first search domain from the system's DNS
// configuration, using Tailscale's cross-platform resolv.conf parser.
func localSearchDomain() (string, error) {
	if runtime.GOOS == "windows" || runtime.GOOS == "android" {
		return localSearchDomainFromHostname()
	}
	cfg, err := resolvconffile.ParseFile(resolvconffile.Path)
	if err != nil {
		return "", err
	}
	if len(cfg.SearchDomains) > 0 {
		return cfg.SearchDomains[0].WithoutTrailingDot(), nil
	}
	return "", nil
}

// localSearchDomainFromHostname infers the search domain from the
// system hostname. Used on platforms without resolv.conf.
// Note: on Windows, os.Hostname() typically returns a short NetBIOS name
// without a domain suffix, so this will usually return an error.
func localSearchDomainFromHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	if i := strings.IndexByte(hostname, '.'); i >= 0 {
		return hostname[i+1:], nil
	}
	return "", fmt.Errorf("no search domain found")
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
func bootstrapURLs(ctx context.Context) []string {
	var urls []string

	// Explicit URL from environment.
	if u := os.Getenv("TS_SCION_BOOTSTRAP_URL"); u != "" {
		urls = append(urls, u)
	}

	// Comma-separated list from environment.
	if u := os.Getenv("TS_SCION_BOOTSTRAP_URLS"); u != "" {
		for _, url := range strings.Split(u, ",") {
			url = strings.TrimSpace(url)
			if url != "" {
				urls = append(urls, url)
			}
		}
	}

	// DNS-discovered URL.
	if discovered, err := discoverBootstrapURL(ctx); err == nil {
		urls = append(urls, discovered)
	}

	// Hardcoded defaults.
	urls = append(urls, defaultBootstrapURLs...)

	return urls
}
