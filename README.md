# Tailscale (SCION)

Tailscale fork with SCION path-aware transport.

## What This Is

A fork of [tailscale/tailscale](https://github.com/tailscale/tailscale) that adds [SCION](https://www.scion.org/) as a transport layer alongside WireGuard's existing UDP. Peers on SCION-enabled ASes gets path-aware routing with latency-based path selection.

> **This project is not affiliated with or endorsed by Tailscale Inc.**

## Status

Experimental. Platforms: Linux, macOS, Windows, FreeBSD, OpenBSD, NetBSD, Android (via [tailscale-android-scion](https://github.com/netsys-lab/tailscale-android-scion)).

## Releases

Pre-built binaries for Linux (amd64/arm64), macOS, and Windows are available on the [Releases](https://github.com/netsys-lab/tailscale-scion/releases) page. Android APK releases are available from [tailscale-android-scion](https://github.com/netsys-lab/tailscale-android-scion/releases).

For CLI usage, see the [Tailscale CLI reference](https://tailscale.com/docs/reference/tailscale-cli) — all standard `tailscale` and `tailscaled` commands work the same.

## Quick Start (Linux)

```bash
# Build
go install tailscale.com/cmd/tailscale{,d}

# Run with the embedded SCION daemon (bootstraps topology + TRCs)
TS_SCION_BOOTSTRAP_URL=http://your-bootstrap-server:8041 \
  tailscaled

# Verify SCION is connected
curl -s --unix-socket /var/run/tailscale/tailscaled.sock \
  http://local-tailscaled.sock/localapi/v0/scion-status
# {"Connected":true,"LocalIA":"19-ffaa:1:eba"}
```

If `/etc/scion/topology.json` and `/etc/scion/certs/*.trc` already exist (e.g. from a locally managed SCION daemon), no bootstrap is needed — the embedded connector loads TRCs from the topology file's sibling `certs/` directory by default. Override with `TS_SCION_CERTS_DIR` if TRCs live elsewhere.

## Android

See [netsys-lab/tailscale-android-scion](https://github.com/netsys-lab/tailscale-android-scion) for the Android client with SCION settings UI and live path display.

## Connection Flow

SCION runs entirely in-process via an embedded connector. Startup:

1. **Local topology** -- if `TS_SCION_TOPOLOGY` or `/etc/scion/topology.json` exists, load it and read TRCs from `${TS_SCION_STATE_DIR}/certs/*.trc`.
2. **Bootstrap** -- otherwise, fetch topology and TRCs from: explicit URL → DNS SRV discovery → hardcoded defaults. Then start the embedded connector with the fetched state.

Path segments returned by the SCION control plane are cryptographically verified against the bootstrapped TRCs before use.

See [docs/architecture.md](docs/architecture.md) for details.

## Configuration

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `TS_PREFER_SCION` | `false` | Unconditionally prefer SCION over all other paths |
| `TS_SCION_PREFERENCE` | `15` | betterAddr points bonus for SCION (0 to disable) |
| `TS_SCION_PORT` | (auto) | Local SCION/UDP listen port |
| `TS_SCION_LISTEN_ADDR` | (auto) | Listen address override |

### Bootstrap & Topology

| Variable | Default | Description |
|----------|---------|-------------|
| `TS_SCION_TOPOLOGY` | (auto) | Path to `topology.json` (defaults to `/etc/scion/topology.json` on Linux) |
| `TS_SCION_CERTS_DIR` | (auto) | Directory of TRC blobs (`*.trc`). Defaults to the topology file's sibling `certs/` dir (e.g. `/etc/scion/certs`) |
| `TS_SCION_BOOTSTRAP_URL` | (unset) | Single bootstrap server URL |
| `TS_SCION_BOOTSTRAP_URLS` | (unset) | Comma-separated bootstrap server URLs |
| `TS_SCION_STATE_DIR` | (auto) | State directory for bootstrap data, PathDB, and TrustDB SQLite |

### Advanced

| Variable | Default | Description |
|----------|---------|-------------|
| `TS_SCION_MAX_PROBE_PATHS` | `5` | Max SCION paths to probe per peer |
| `TS_SCION_DIVERSITY_THRESHOLD` | `50` | Latency penalty threshold (ms) for path diversity |
| `TS_SCION_NO_FAST_PATH` | `false` | Disable pre-serialized fast-path sends |
| `TS_SCION_NO_DISPATCHER_SHIM` | `false` | Disable legacy dispatcher port 30041 shim |

## Build Tags

Build without SCION support using the `ts_omit_scion` tag:

```bash
go install -tags ts_omit_scion tailscale.com/cmd/tailscale{,d}
```

This compiles out all SCION code, producing a smaller binary with no `scionproto/scion` dependency.


## Architecture

See [docs/architecture.md](docs/architecture.md) for component overview, data flow, and design decisions.

## License

BSD-3-Clause. Based on [tailscale/tailscale](https://github.com/tailscale/tailscale).
SCION networking provided by [scionproto/scion](https://github.com/scionproto/scion) (Apache-2.0).

This project is not affiliated with or endorsed by Tailscale Inc.
WireGuard is a registered trademark of Jason A. Donenfeld.