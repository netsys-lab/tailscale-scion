// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion && (linux || darwin || freebsd || openbsd || netbsd)

package magicsock

import (
	"tailscale.com/net/dns/resolvconffile"
)

// localSearchDomain returns the first search domain from the system's DNS
// configuration, using Tailscale's resolv.conf parser.
func localSearchDomain() (string, error) {
	cfg, err := resolvconffile.ParseFile(resolvconffile.Path)
	if err != nil {
		return localSearchDomainFromHostname()
	}
	if len(cfg.SearchDomains) > 0 {
		return cfg.SearchDomains[0].WithoutTrailingDot(), nil
	}
	return localSearchDomainFromHostname()
}
