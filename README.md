# HannibaalDNS

A small, modular DNS resolver with per-client (per-IP) filtering, a
multi-list blocklist registry, anomaly detection, and a dashboard. It
answers the same query through three transports — **UDP**,
**DNS-over-HTTPS (DoH)**, and **DNS-over-TLS (DoT)** — all sharing one
resolution engine, so filtering, per-client profiles, and query logging are
identical no matter which transport a client uses.

## Architecture

```
query arrives (UDP:5053 | DoH:5000 | DoT:853)
        │
        ▼
   dns_resolver.resolve_query(raw_bytes, client_ip, upstream, engine)
        │
        ├── engine.check(domain, client_ip)   ← per-client profiles + blocklist registry
        ├── blocked  → NXDOMAIN + log (with blocked_by: which list matched)
        └── allowed  → forward to upstream DNS, copy answers, log
```

- **`dns_resolver.py`** — the single shared resolution function. Extracted from
  `dns_server.py` so UDP, DoH, and DoT all run the same code.
- **`filtering.py`** — `FilteringEngine`: wraps the blocklist registry
  (`blocklist_manager.py`) and per-client profiles, and checks per-client
  allow/deny *before* the registry. A client IP is never required; queries
  without one still work.
- **`blocklist_manager.py`** — the blocklist registry. **Starts empty** —
  nothing is blocked until at least one list is registered (see "Running"
  below). Any http(s) URL can be registered, in any of 5 formats (hosts,
  domains, adblock, dnsmasq, wildcard); `config.BLOCKLIST_PRESETS` are just
  UI shortcuts for a few well-known lists. Refreshes use conditional GET
  and fail open: a failed download or parse never clears an existing list,
  it just logs a warning and keeps serving the last good copy.
- **`database.py`** — `Database`: WAL-mode SQLite with a background writer
  thread (`query_log`, `anomaly_log`, `client_profiles`, `blocklists`) and a
  daily retention-purge thread (`config.LOG_RETENTION_DAYS`, default 30).
- **`anomaly_detection.py`** — entropy-based anomaly scoring with dedup and
  cooldown, so a burst of queries for one domain produces one `anomaly_log`
  row instead of a flood. Per-domain tracking is pruned once a domain goes
  quiet, so memory stays bounded by *active* traffic, not every domain ever
  seen.
- **`dns_server.py`** — plain UDP resolver on port 5053 (dnslib `DNSServer`).
- **`phase5/backend/app.py`** — Flask API serving the DoH endpoints
  (`/dns-query`, plus device-named `/dns-query/<name>`) and the dashboard
  JSON API (blocklists, per-client lists, analytics, log controls).
- **`dot_server.py`** — DNS-over-TLS on port 853 (TCP socket wrapped in TLS,
  RFC 7858; 2-byte length framing per RFC 7766 / RFC 1035 §4.2.2).
- **`phase5/frontend/`** — Create React App dashboard (Overview /
  Allowlist-Denylist / Blocklists / Analytics), built to
  `phase5/frontend/build/`.
- **`config.py`** — every setting in one place (upstream DNS, ports, DB
  path, log retention). Every value is overridable with a
  `HANNIBAALNS_*` environment variable; see "Configuration" below.

## Transports

| Transport | Port  | Server            | Status |
|-----------|-------|-------------------|--------|
| UDP       | 5053  | `python dns_server.py` | ✅ verified |
| DoH       | 5000  | `python phase5/backend/app.py` | ✅ verified |
| DoT       | 853   | `python dot_server.py` | ✅ verified |

All three apply the same filtering: a per-client allowlist overrides
everything else, a per-client denylist blocks regardless of the registry,
and otherwise a domain is blocked if it (or a parent domain) appears in
**any enabled registered blocklist** — see "Running" for why that last
part requires a step before anything actually gets blocked.

## Running

```bash
# 1. UDP resolver
python dns_server.py                # 127.0.0.1:5053, upstream 8.8.8.8

# 2. DoH API + dashboard backend
python phase5/backend/app.py        # 0.0.0.0:5000

# 3. DoT resolver
python dot_server.py                # 0.0.0.0:853, upstream 8.8.8.8

# 4. Dashboard (from phase5/frontend)
npm install && npm start              # proxies to http://localhost:5000
```

**Nothing is blocked until you register a blocklist.** The registry starts
empty on a fresh DB — this is a deliberate change from the old single-URL
default, so you always know exactly what's blocking what. Either use the
**Blocklists** tab in the dashboard, or register one from the command line
(localhost only — this endpoint refuses non-local callers):

```bash
curl -X POST http://127.0.0.1:5000/api/blocklists \
  -H 'Content-Type: application/json' \
  -d '{"name": "StevenBlack hosts",
       "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
       "format": "hosts", "enabled": true}'
```

After that, `doubleclick.net` (and its subdomains) return NXDOMAIN and a
per-client allowlist entry for it overrides that.

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

## Configuration

Every setting lives in `config.py` with a default that matches the old
hardcoded values, so nothing changes unless you override it. Override any
of them with an environment variable, e.g.:

```bash
HANNIBAALNS_UPSTREAM_DNS=1.1.1.1 HANNIBAALNS_DNS_PORT=5053 python dns_server.py
```

| Variable | Default | Meaning |
|---|---|---|
| `HANNIBAALNS_UPSTREAM_DNS` | `8.8.8.8` | Upstream resolver |
| `HANNIBAALNS_UPSTREAM_PORT` | `53` | Upstream port |
| `HANNIBAALNS_UPSTREAM_TIMEOUT` | `3` | Seconds before a dead upstream returns SERVFAIL |
| `HANNIBAALNS_UDP_PORT` / `_DOH_PORT` / `_DOT_PORT` | `5053` / `5000` / `853` | Transport ports |
| `HANNIBAALNS_DOT_BIND_HOST` | `0.0.0.0` | DoT bind address |
| `HANNIBAALNS_DB_PATH` | `hannibaaldns.db` | SQLite path, shared by all three transports |
| `HANNIBAALNS_LOG_RETENTION_DAYS` | `30` | Auto-purge window for `query_log`/`anomaly_log`; `0` disables auto-purge (manual purge via the API still works) |

## Dashboard API

Endpoints marked 🔒 only accept requests from `127.0.0.1`/`::1` — the
dashboard has no auth, so anything that registers a URL to fetch, or
mutates logs/lists, is restricted to localhost callers.

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Last-hour totals / blocked / avg response time |
| `GET /api/queries` | Recent queries (includes `blocked_by`) |
| `GET /api/anomalies` | Recent anomaly-log rows |
| `GET /api/clients` | Per-client query counts |
| `GET/POST /api/clients/<ip>/lists` | Per-client allowlist / denylist |
| `GET /api/analytics/summary` | Blocked % over a time window |
| `GET /api/analytics/top-domains` | Domain breakdown, filterable by blocked |
| `GET /api/blocklists` | List the blocklist registry |
| 🔒 `POST /api/blocklists` | Register a list (any http(s) URL) |
| 🔒 `DELETE /api/blocklists/<id>` | Remove a list |
| 🔒 `POST /api/blocklists/<id>/toggle` | Enable/disable a list |
| 🔒 `POST /api/blocklists/<id>/refresh` | Refresh one list (fail-open) |
| 🔒 `POST /api/blocklists/refresh` | Refresh every list |
| 🔒 `POST /api/logs/purge` | Delete log rows older than N days (default: retention setting) |
| 🔒 `POST /api/logs/clear` | Delete all log rows (`{"confirm": true}` required) |
| `GET /api/logs/export` | CSV export of `query_log` or `anomaly_log` (`?type=`, optional `?hours=`) |
| `GET/POST /dns-query` | DoH (RFC 8484) |
| `GET/POST /dns-query/<device_name>` | DoH scoped to a named device — gives clients behind the same NAT IP separate profiles/logging (logged as `device:<name>`) |

## Testing

```bash
python test_filtering.py      # blocklist registry + per-client profile unit tests
python verify_live_wiring.py  # per-client filtering with real source-IP binding
python test_bug1_decoupling.py
python smoke_all.py           # end-to-end smoke test against already-running servers
```

`test_dns_server.py` exercises a live UDP server.

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
```

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

Phase 1–4 (UDP resolver, per-client filtering, anomaly detection) and Phase
5 (DoH, DoT, dashboard) complete and verified. v1.0 scope: multi-blocklist
registry, blocklists dashboard page, and log controls (retention purge, CSV
export, clear logs, per-device DoH) complete and verified end-to-end.
Remaining before `v1.0`: hardening pass (anomaly-detection memory bound
done; fail-open blocklist refresh already covered by the registry design).
