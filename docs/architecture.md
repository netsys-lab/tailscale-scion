# SCION Integration Architecture

## Component Overview

SCION is added as a third transport in `magicsock.Conn`, alongside the existing IPv4/IPv6 UDP and DERP relay transports. The `endpoint.betterAddr` mechanism selects the best path across all three.


### Key Files (`wgengine/magicsock/`)

| File | Role |
|------|------|
| `magicsock_scion.go` | Connection setup, path registry, send/receive, `ReconfigureSCION()` |
| `magicsock_scion_conn.go` | SCION connection lifecycle (init, close, bind) |
| `endpoint_scion.go` | Per-peer SCION state, heartbeat, path probing, pong handling |
| `scion_bootstrap.go` | Topology/TRC fetch from bootstrap servers, DNS SRV discovery |
| `scion_embedded.go` | In-process SCION daemon (no external sciond needed) |
| `magicsock_scion_omit.go` | No-op stubs for `ts_omit_scion` builds |
| `ipn/localapi/localapi_scion.go` | `GET /localapi/v0/scion-status` handler |
| `ipn/ipnlocal/local.go` | SCION service advertisement + peerapi4 piggyback (lines 4892-4906) |

## Connection Flow

`trySCIONConnect()` uses the embedded connector in all modes:

1. **Embedded daemon with local topology** -- checks for topology file at:
   - `TS_SCION_TOPOLOGY` (explicit path)
   - `/etc/scion/topology.json` (Linux default)
   - `<stateDir>/scion/topology.json` (from prior bootstrap)

   Creates an in-process `embeddedConnector` with topology loader, segment fetcher, and a TRC-backed trust engine. TRCs are loaded from `<stateDir>/certs/*.trc`; the connector refuses to start when no TRCs are present.

2. **Bootstrap + embedded** -- tries each URL from `bootstrapURLs()` in order:
   1. Explicit `TS_SCION_BOOTSTRAP_URL`
   2. Comma-separated `TS_SCION_BOOTSTRAP_URLS`
   3. DNS SRV: `_sciondiscovery._tcp.<local-search-domain>`
   4. Hardcoded defaults (ovgu.de, uva, ethz.ch)

   For each URL: fetches `topology.json` + TRCs (both required; URLs that cannot serve TRCs are skipped) → saves to stateDir → creates embedded connector with bootstrapped topology.

## Data Flow

**Outbound**: `endpoint.send()` → if bestAddr is SCION → `sendSCION()` → pre-serialized SCION header + WireGuard payload → UDP to first-hop border router.

**Inbound**: `receiveSCION()` → parse SCION header (slayers) → extract source IA + host → route to endpoint via reverse index → deliver WireGuard payload.

**Path discovery**: `refreshSCIONPaths()` runs every 30s → queries daemon `Paths()` → discovers up to 5 paths per peer (`TS_SCION_MAX_PROBE_PATHS`) → probes latency via disco pings → `betterAddr` promotes best path (with configurable SCION preference bonus).

## Key Design Decisions

- **Third transport, not replacement.** SCION runs alongside IPv4/IPv6 UDP. Fallback is automatic -- if SCION is unavailable, direct or relay paths are used.

- **Path selection via `betterAddr`.** SCION paths get a configurable preference bonus (`TS_SCION_PREFERENCE`, default 15 points). +25 additional points when both peers have the `NodeAttrSCIONPrefer` capability. Incumbent bias prevents flapping (candidate must be >=20% or >=2ms faster).

- **Embedded daemon.** `scion_embedded.go` implements `daemon.Connector` with an in-process topology loader, segment fetcher, and trust engine (`daemontrust.NewEngine`). Path segments are cryptographically verified against bootstrapped TRCs. No external sciond process required.

- **Bootstrap discovery.** `scion_bootstrap.go` discovers topology via DNS SRV (`_sciondiscovery._tcp`) or hardcoded fallback URLs. Both `topology.json` and TRC blobs are required for bootstrap success; servers that cannot serve TRCs are skipped.

- **Fast-path sends.** Pre-serialized SCION+UDP header templates (`scionFastPath`) avoid per-packet allocation. Batch send via `sendmmsg` where available. Disable with `TS_SCION_NO_FAST_PATH`.

- **Build tag `ts_omit_scion`.** Compiles out all SCION code via no-op stubs. Feature flag `buildfeatures.HasSCION` set at compile time. Produces smaller binary with no scionproto dependency.

- **Service advertisement via peerapi4 piggyback.** The Tailscale coordination server only relays `peerapi4`/`peerapi6` services to peers — it drops unknown service types. To work without coord server changes, SCION address info is piggybacked onto the `peerapi4` service's `Description` field as `scion=ISD-AS,[hostIP]:port` (see `ipn/ipnlocal/local.go:4892-4906`). Bracket notation around the IP ensures unambiguous parsing for both IPv4 and IPv6 underlay addresses. A standalone `tailcfg.ServiceProto("scion")` entry is also advertised for future coord server support. On the receiving side, `scionServiceFromPeer()` checks for a dedicated SCION service first, then falls back to parsing the peerapi4 piggyback (with backward compatibility for unbracketed format).

- **Cross-platform.** Platform-specific DNS search domain resolution in `scion_bootstrap_unix.go` (Linux, macOS, BSDs), `scion_bootstrap_windows.go`, and `scion_bootstrap_other.go` (Android fallback).