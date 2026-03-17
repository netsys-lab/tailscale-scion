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

# Run with embedded SCION daemon + bootstrap
TS_SCION_EMBEDDED=1 \
TS_SCION_BOOTSTRAP_URL=http://your-bootstrap-server:8041 \
  tailscaled

# Verify SCION is connected
curl -s --unix-socket /var/run/tailscale/tailscaled.sock \
  http://local-tailscaled.sock/localapi/v0/scion-status
# {"Connected":true,"LocalIA":"19-ffaa:1:eba"}
```

If you have a local SCION daemon (sciond) running, no environment variables are needed -- Tailscale will connect to it automatically at `127.0.0.1:30255`.

## Android

See [netsys-lab/tailscale-android-scion](https://github.com/netsys-lab/tailscale-android-scion) for the Android client with SCION settings UI and live path display.

## Connection Flow

SCION connects using a cascading fallback:

1. **External daemon** -- connects to sciond at `SCION_DAEMON_ADDRESS`. *Skipped if `TS_SCION_EMBEDDED=1`.*
2. **Embedded daemon** -- loads local topology file (`TS_SCION_TOPOLOGY` or `/etc/scion/topology.json`). *Skipped if `TS_SCION_FORCE_BOOTSTRAP=1`.*
3. **Bootstrap** -- fetches topology from: explicit URL → DNS SRV discovery → hardcoded defaults. Then starts embedded daemon with the fetched topology.

See [docs/architecture.md](docs/architecture.md) for details.

## Configuration

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SCION_DAEMON_ADDRESS` | `127.0.0.1:30255` | External SCION daemon gRPC address |
| `TS_SCION_EMBEDDED` | `false` | Skip external daemon, use embedded connector only |
| `TS_PREFER_SCION` | `false` | Unconditionally prefer SCION over all other paths |
| `TS_SCION_PREFERENCE` | `15` | betterAddr points bonus for SCION (0 to disable) |
| `TS_SCION_PORT` | (auto) | Local SCION/UDP listen port |
| `TS_SCION_LISTEN_ADDR` | (auto) | Listen address override |

### Bootstrap & Topology

| Variable | Default | Description |
|----------|---------|-------------|
| `TS_SCION_TOPOLOGY` | (auto) | Path to `topology.json` (defaults to `/etc/scion/topology.json` on Linux) |
| `TS_SCION_BOOTSTRAP_URL` | (unset) | Single bootstrap server URL |
| `TS_SCION_BOOTSTRAP_URLS` | (unset) | Comma-separated bootstrap server URLs |
| `TS_SCION_FORCE_BOOTSTRAP` | `false` | Skip local topology, go straight to bootstrap |
| `TS_SCION_STATE_DIR` | (auto) | State directory for bootstrap data and PathDB |

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