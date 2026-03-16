// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_scion && windows

package magicsock

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// localSearchDomain returns the DNS suffix from the default network adapter
// on Windows, using winipcfg.GetAdaptersAddresses. Falls back to hostname
// parsing if no adapter suffix is found.
func localSearchDomain() (string, error) {
	iface, err := getWindowsDefaultAdapter()
	if err == nil && iface != nil {
		if suffix := iface.DNSSuffix(); suffix != "" {
			return suffix, nil
		}
	}
	return localSearchDomainFromHostname()
}

// getWindowsDefaultAdapter returns the default IPv4 network adapter.
func getWindowsDefaultAdapter() (*winipcfg.IPAdapterAddresses, error) {
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, err
	}

	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}

	// Index adapters by LUID, filtering to operational non-loopback interfaces.
	byLUID := make(map[winipcfg.LUID]*winipcfg.IPAdapterAddresses)
	for _, iface := range ifs {
		if iface.OperStatus == winipcfg.IfOperStatusUp && iface.IfType != winipcfg.IfTypeSoftwareLoopback {
			byLUID[iface.LUID] = iface
		}
	}

	// Find the default route (prefix length 0) with the lowest metric.
	bestMetric := ^uint32(0)
	var best *winipcfg.IPAdapterAddresses
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		iface := byLUID[route.InterfaceLUID]
		if iface == nil {
			continue
		}
		if route.Metric < bestMetric {
			bestMetric = route.Metric
			best = iface
		}
	}
	return best, nil
}
