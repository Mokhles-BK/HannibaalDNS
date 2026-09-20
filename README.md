# HannibaalDNS

A small, modular DNS resolver with per-client (per-IP) filtering, anomaly
detection, and a dashboard. It answers the same query through three transports
— **UDP**, **DNS-over-HTTPS (DoH)**, and **DNS-over-TLS (DoT)** — all sharing
one resolution engine, so filtering, per-client profiles, and query logging
are identical no matter which transport a client uses.

## Architecture

```
query arrives (UDP:5053 | DoH:5000 | DoT:853)
        │
        ▼
   dns_resolver.resolve_query(raw_bytes, client_ip, upstream, engine)
        │
        ├── engine.is_blocked(domain, client_ip)   ← per-client profiles + global blocklist
        ├── blocked  → NXDOMAIN + log
        └── allowed  → forward to upstream DNS, copy answers, log
```

- **`dns_resolver.py`** — the single shared resolution function. Extracted from
  `dns_server.py` so UDP, DoH, and DoT all run the same code.
- **`filtering.py`** — `FilteringEngine`: loads the StevenBlack hosts blocklist,
  refreshes it on a schedule, and checks per-client profiles *before* the global
  list. A client IP is never required; queries without one still work.
- **`database.py`** — `Database`: WAL-mode SQLite with a background writer
  thread (`query_log`, `anomaly_log`, `client_profiles`).
- **`anomaly_detection.py`** — entropy-based anomaly scoring with dedup and
  cooldown, so a burst of queries for one domain produces one `anomaly_log`
  row instead of a flood.
- **`dns_server.py`** — plain UDP resolver on port 5053 (dnslib `DNSServer`).
- **`phase5/backend/app.py`** — Flask API serving the DoH endpoints
  (`/dns-query` GET/POST) plus the dashboard JSON API.
- **`dot_server.py`** — DNS-over-TLS on port 853 (TCP socket wrapped in TLS,
  RFC 7858; 2-byte length framing per RFC 7766 / RFC 1035 §4.2.2).
- **`phase5/frontend/`** — Create React App dashboard (Overview / Allowlist-Denylist /
  Analytics), built to `phase5/frontend/build/`.

## Transports

| Transport | Port  | Server            | Status |
|-----------|-------|-------------------|--------|
| UDP       | 5053  | `python dns_server.py` | ✅ verified |
| DoH       | 5000  | `python phase5/backend/app.py` | ✅ verified |
| DoT       | 853   | `python dot_server.py` | ✅ verified |

All three apply the same filtering: `google.com` resolves, `doubleclick.net`
(global blocklist) returns NXDOMAIN, and a per-client allowlist overrides the
global blocklist.

## Running

```bash
# UDP resolver
python dns_server.py                # 127.0.0.1:5053, upstream 8.8.8.8

# DoH API + dashboard backend
python phase5/backend/app.py        # 0.0.0.0:5000

# DoT resolver
python dot_server.py                # 0.0.0.0:853, upstream 8.8.8.8

# Dashboard (from phase5/frontend)
npm install && npm start              # proxies to http://localhost:5000
```

DoT starts with a **self-signed** certificate (`hannibaaldns.crt` /
`hannibaaldns.key`, CN `hannibaaldns.local`), generated automatically on first
run (openssl, or the `cryptography` package if available). The server does not
validate client certificates.

> **⚠️ Real-world DoT clients will reject this cert by default.** Phones,
> routers, `systemd-resolved`, `unbound`, and most DNS clients perform TLS
> certificate verification against a trusted root store, and a self-signed
> cert is not in any of them — they will refuse the connection with a TLS
> error. This server only works "out of the box" for clients that either
> **pin the certificate** (point at `hannibaaldns.crt` directly) or have
> **validation disabled**. If you want phones and laptops to use DoT without
> each one being configured by hand, install a CA-issued certificate (or run
> a local CA and trust it fleet-wide) before pointing a resolver at port 853.

## Dashboard API

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Last-hour totals / blocked / avg response time |
| `GET /api/queries` | Recent queries |
| `GET /api/anomalies` | Recent anomaly-log rows |
| `GET /api/clients` | Per-client query counts |
| `GET/POST /api/clients/<ip>/lists` | Per-client allowlist / denylist |
| `GET /api/analytics/summary` | Blocked % over a time window |
| `GET /api/analytics/top-domains` | Domain breakdown, filterable by blocked |

## Testing

```bash
python test_filtering.py      # blocklist + per-client profile unit tests
python verify_live_wiring.py  # per-client filtering with real source-IP binding
python test_bug1_decoupling.py
python verify_entropy_thresholds.py
```

`test_dns_server.py` and `test_phase3.py` exercise a live UDP server.

**Stub upstream** (`tools/stub_upstream.py`) — a test-only authoritative
nameserver that always answers `198.51.100.7` for any A query. Use it to
verify config overrides without hitting the internet:

```bash
# Terminal 1
HANNIBAALNS_UPSTREAM_PORT=15353 python tools/stub_upstream.py

# Terminal 2
HANNIBAALNS_UPSTREAM_DNS=127.0.0.1 HANNIBAALNS_UPSTREAM_PORT=15353 python dns_server.py

# Terminal 3 (client)
dig @127.0.0.1 -p 5053 google.com A
# Expect: 198.51.100.7 (stub's signature answer)
``` Note:
`test_phase3.py` has a known harness bug — it sets up client profiles keyed on
`192.168.1.100/101` but never binds a source socket, so every query is logged
as `127.0.0.1` and the profile lookup misses. `verify_live_wiring.py` is the
correct version of that test (it binds the client socket to a specific source
IP); prefer it.

## DoT — implemented, not deferred

DNS-over-TLS (RFC 7858, port 853) was listed in the original Phase 1 spec and
was **implemented** rather than deferred. Rationale for completeness over
elegance: a resolver that only speaks plain UDP cannot answer "do I have a
privacy-preserving transport?", and the cost of adding DoT was small once
`dns_resolver.resolve_query()` existed as a shared function — it is ~60 lines
of TLS-wrapping and length-framing around the same code path the other two
transports already used. The self-signed cert is a pragmatic choice for a
local/homelab resolver; swap in a real cert or a `cryptography`-backed
generator for production use.

## Status

Phase 1–4 (UDP resolver, per-client filtering, anomaly detection) complete and
verified. Phase 5 (DoH API + dashboard + DoT) complete and verified end-to-end
across all three transports.