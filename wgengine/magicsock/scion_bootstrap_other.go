// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion && !(linux || darwin || freebsd || openbsd || netbsd || windows)

package magicsock

// localSearchDomain returns the search domain on platforms without
// resolv.conf or winipcfg (e.g. Android). Falls back to hostname parsing.
func localSearchDomain() (string, error) {
	return localSearchDomainFromHostname()
}
