"""
Multi-blocklist registry for HannibaalDNS (v1.0 step 5a).

Any http(s) URL can be registered by name/url/format via the dashboard API
(phase5/backend/app.py). Presets in config.BLOCKLIST_PRESETS are just UI
shortcuts -- this manager does not treat them specially and does not
whitelist URLs; any URL a user submits is checked live before acceptance.

Design (see CLAUDE.md "Blocklist manager design (step 5a)"):
  - Registry table `blocklists`: id, name, url, format, enabled,
    entry_count, last_updated, etag.
  - Formats: hosts, domains, adblock, dnsmasq, wildcard. Normalized to
    lowercase domains.
  - Index: one dict domain -> int bitmask of list IDs (bit N = list id N),
    so a domain's attribution is recoverable without duplicating strings.
  - Matching walks parent suffixes so blocking a domain blocks its
    subdomains (a.b.example.com -> b.example.com -> example.com).
  - Refresh uses conditional GET (ETag). A failed download NEVER clears an
    existing list -- the old in-memory domains and on-disk cache are kept
    (fail open), and the failure is logged.
  - Registry starts EMPTY. Nothing is blocked until a list is registered.

One addition beyond the original design note, worth knowing about: UDP,
DoT, and DoH each run in a SEPARATE process and each builds its own
FilteringEngine -> own BlocklistManager instance. They share the sqlite DB
and the on-disk cache directory, but only the DoH/dashboard process's
BlocklistManager ever calls add_list()/remove_list(). Without help, a list
added through the dashboard would never be seen by the UDP/DoT processes,
because their in-memory `_rows` dict is only populated once at startup.
sync_registry() (called periodically by FilteringEngine's refresh loop)
re-reads which list IDs exist in the DB and adds/removes/toggles them in
memory, so a change made via the dashboard reaches the other two
processes within about a minute, without a restart.
"""
import os
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

import config

SUPPORTED_FORMATS = {"hosts", "domains", "adblock", "dnsmasq", "wildcard"}

# Hard safety caps for "add any URL" (CLAUDE.md: http(s) only, size cap,
# request timeout -- the dashboard restricts the add-endpoint to localhost,
# but a bad or huge URL should still fail cleanly rather than hang or
# exhaust memory).
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 64 MB
REQUEST_TIMEOUT = 20  # seconds

CACHE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(config.DB_PATH)) or ".",
    "blocklist_cache",
)


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Format parsers. Each takes raw text and returns a set of lowercase,
# trailing-dot-stripped domains. Best-effort: unparseable lines are skipped,
# not fatal -- only a whole-file yield of zero domains is treated as an
# error by the caller (add_list / refresh_list).
# ---------------------------------------------------------------------------

def _parse_hosts(content):
    """0.0.0.0 domain / 127.0.0.1 domain -- classic /etc/hosts blocklist."""
    domains = set()
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, domain = parts[0], parts[1]
        if ip not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
            continue
        domain = domain.lower().rstrip(".")
        if domain and domain not in ("localhost", "localhost.localdomain", "local"):
            domains.add(domain)
    return domains


def _parse_domains(content):
    """Plain domain list, one per line, '#' comments allowed."""
    domains = set()
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            domains.add(line.lower().rstrip("."))
    return domains


def _parse_adblock(content):
    """
    Adblock/uBlock-style: ||domain^ or ||domain^$extra. Exception rules
    (@@||domain^) are skipped -- this manager only ever blocks; un-blocking
    a specific domain is already covered by the per-client allowlist
    (see FilteringEngine.check precedence), not by a third-party list.
    """
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("@@"):
            continue
        if not line.startswith("||"):
            continue
        body = line[2:]
        for sep in ("^", "$", "/"):
            idx = body.find(sep)
            if idx != -1:
                body = body[:idx]
        domain = body.lower().rstrip(".")
        if domain and all(c.isalnum() or c in ".-_" for c in domain):
            domains.add(domain)
    return domains


def _parse_dnsmasq(content):
    """
    dnsmasq-style. Handles the shapes seen in the wild:
      address=/domain/0.0.0.0   (or .../#, .../::)
      local=/domain/
    Falls back to treating a bare non-comment line as a plain domain,
    since some lists labeled "dnsmasq format" (e.g. HaGeZi's light.txt)
    are really just a plain domain list.
    """
    domains = set()
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("address=/", "local=/", "server=/")):
            parts = line.split("/", 2)
            if len(parts) >= 2 and parts[1]:
                domains.add(parts[1].lower().rstrip("."))
            continue
        domain = line.lower().rstrip(".")
        if domain and " " not in domain:
            domains.add(domain)
    return domains


def _parse_wildcard(content):
    """*.domain, one per line. Normalized to the bare domain -- matching
    already walks subdomains, so *.example.com and example.com are the
    same rule here."""
    domains = set()
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("*."):
            line = line[2:]
        domain = line.lower().rstrip(".")
        if domain:
            domains.add(domain)
    return domains


PARSERS = {
    "hosts": _parse_hosts,
    "domains": _parse_domains,
    "adblock": _parse_adblock,
    "dnsmasq": _parse_dnsmasq,
    "wildcard": _parse_wildcard,
}


class BlocklistManager:
    """
    Owns the `blocklists` registry table, the on-disk domain cache, and the
    merged domain -> bitmask index used for fast lookups.
    """

    def __init__(self, db_path=None):
        self.db_path = config.DB_PATH if db_path is None else db_path
        self.lock = threading.RLock()
        self._list_domains = {}   # list_id -> frozenset(domain)
        self._rows = {}           # list_id -> dict (DB columns, no domains)
        self._index = {}          # domain -> int bitmask
        self._enabled_mask = 0
        os.makedirs(CACHE_DIR, exist_ok=True)
        self._init_db()
        self._load_from_db()

    # -- schema -------------------------------------------------------

    def _init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocklists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    format TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    entry_count INTEGER NOT NULL DEFAULT 0,
                    last_updated TEXT,
                    etag TEXT
                )
            """)
            conn.commit()
            conn.close()

    def _load_from_db(self):
        """Startup: load registry rows and their cached domain sets (if
        any) from disk. Does NOT re-download -- a stale-but-present list is
        better than an empty one while waiting for the next refresh; fail
        open extends to process restarts, not just failed HTTP requests."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM blocklists").fetchall()
            conn.close()
            for row in rows:
                list_id = row["id"]
                self._rows[list_id] = dict(row)
                self._list_domains[list_id] = self._read_cache(list_id)
            self._rebuild_index()

    def sync_registry(self):
        """
        Re-read the registry table for list IDs added/removed/toggled by
        ANOTHER process (UDP, DoT, and DoH/dashboard each run separately,
        but only the dashboard process calls add_list/remove_list). This
        only adds newly-appeared rows (loading their cache immediately if
        present), drops removed ones, and syncs the enabled flag. Content
        refresh for lists already known is refresh_list/refresh_all's job.
        Call this periodically (FilteringEngine's refresh loop does) so a
        change made via the dashboard reaches the other processes without
        a restart.
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            db_rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM blocklists")}
            conn.close()

            changed = False
            for list_id, row in db_rows.items():
                if list_id not in self._rows:
                    self._rows[list_id] = row
                    self._list_domains[list_id] = self._read_cache(list_id)
                    changed = True
                elif self._rows[list_id]["enabled"] != row["enabled"]:
                    self._rows[list_id]["enabled"] = row["enabled"]
                    changed = True

            for list_id in list(self._rows.keys()):
                if list_id not in db_rows:
                    del self._rows[list_id]
                    self._list_domains.pop(list_id, None)
                    changed = True

            if changed:
                self._rebuild_index()

    # -- disk cache (fail-open persistence) ----------------------------

    def _cache_path(self, list_id):
        return os.path.join(CACHE_DIR, f"{list_id}.txt")

    def _read_cache(self, list_id):
        path = self._cache_path(list_id)
        if not os.path.exists(path):
            return frozenset()
        try:
            with open(path, "r", encoding="utf-8") as f:
                return frozenset(line.strip() for line in f if line.strip())
        except OSError as e:
            print(f"[BlocklistManager] Failed to read cache for list {list_id}: {e}")
            return frozenset()

    def _write_cache(self, list_id, domains):
        path = self._cache_path(list_id)
        tmp_path = path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(domains)))
            os.replace(tmp_path, path)  # atomic on POSIX and Windows
        except OSError as e:
            print(f"[BlocklistManager] Failed to write cache for list {list_id}: {e}")

    # -- index ----------------------------------------------------------

    def _rebuild_index(self):
        """Must be called with self.lock held. O(total domains); this runs
        on registry changes, never on the per-query hot path."""
        index = {}
        enabled_mask = 0
        for list_id, row in self._rows.items():
            bit = 1 << list_id
            if row["enabled"]:
                enabled_mask |= bit
            for domain in self._list_domains.get(list_id, ()):
                index[domain] = index.get(domain, 0) | bit
        self._index = index
        self._enabled_mask = enabled_mask

    # -- fetch/parse ------------------------------------------------------

    def _fetch(self, url, etag=None):
        """Returns (content_str, new_etag, not_modified). Raises on error."""
        req = urllib.request.Request(url, headers={"User-Agent": "HannibaalDNS/1.0"})
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                raw = resp.read(MAX_DOWNLOAD_BYTES + 1)
                if len(raw) > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"list exceeds {MAX_DOWNLOAD_BYTES} byte cap")
                new_etag = resp.headers.get("ETag")
                return raw.decode("utf-8", errors="replace"), new_etag, False
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return None, etag, True
            raise

    def _parse(self, content, fmt):
        parser = PARSERS.get(fmt)
        if parser is None:
            raise ValueError(f"unsupported format: {fmt}")
        return parser(content)

    # -- public API (matches phase5/backend/app.py's usage) ---------------

    def list_lists(self):
        with self.lock:
            return [self._row_public(list_id) for list_id in sorted(self._rows)]

    def _get_row(self, list_id):
        with self.lock:
            return self._row_public(list_id)

    def _row_public(self, list_id):
        row = self._rows[list_id]
        return {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "format": row["format"],
            "enabled": bool(row["enabled"]),
            "entry_count": row["entry_count"],
            "last_updated": row["last_updated"],
            "etag": row["etag"],
        }

    def add_list(self, name, url, fmt, enabled=True):
        """
        Registers ANY http(s) URL, not just config.BLOCKLIST_PRESETS --
        those are only UI shortcuts. Raises ValueError (caller maps this
        to a 4xx) on: unsupported format, non-http(s) URL, a URL already
        registered (message contains "already registered", used by
        app.py to pick 409 vs 400), an unreachable URL, or a URL that
        parses to zero domains.
        """
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(f"format must be one of {sorted(SUPPORTED_FORMATS)}")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("url must be http:// or https://")

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            existing = conn.execute(
                "SELECT id FROM blocklists WHERE url = ?", (url,)
            ).fetchone()
            conn.close()
            if existing:
                raise ValueError(f"url already registered (id {existing[0]})")

        # Fetch/parse OUTSIDE the lock: this is a network call and must not
        # block query resolution on this or any other engine's thread.
        try:
            content, etag, _ = self._fetch(url)
        except Exception as e:
            raise ValueError(f"could not download {url}: {e}")
        domains = self._parse(content, fmt)
        if not domains:
            raise ValueError(f"could not parse any domains from {url} as {fmt}")

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cur = conn.execute(
                    """INSERT INTO blocklists
                       (name, url, format, enabled, entry_count, last_updated, etag)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (name, url, fmt, int(bool(enabled)), len(domains), _now_iso(), etag),
                )
                list_id = cur.lastrowid
                conn.commit()
            except sqlite3.IntegrityError:
                # Another thread/request registered the same URL between our
                # existence check above and this INSERT -- that window is
                # unlocked because _fetch() is a network call. Report it the
                # same way the pre-check does, instead of letting this raise
                # as an unhandled 500 out of Flask.
                row = conn.execute(
                    "SELECT id FROM blocklists WHERE url = ?", (url,)
                ).fetchone()
                conn.close()
                raise ValueError(
                    f"url already registered (id {row[0] if row else '?'})"
                )
            conn.close()

            self._rows[list_id] = {
                "id": list_id, "name": name, "url": url, "format": fmt,
                "enabled": int(bool(enabled)), "entry_count": len(domains),
                "last_updated": _now_iso(), "etag": etag,
            }
            self._list_domains[list_id] = frozenset(domains)
            self._write_cache(list_id, domains)
            self._rebuild_index()

        return list_id

    def remove_list(self, list_id):
        with self.lock:
            if list_id not in self._rows:
                return False
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM blocklists WHERE id = ?", (list_id,))
            conn.commit()
            conn.close()
            del self._rows[list_id]
            self._list_domains.pop(list_id, None)
            try:
                os.remove(self._cache_path(list_id))
            except OSError:
                pass
            self._rebuild_index()
            return True

    def set_enabled(self, list_id, enabled):
        with self.lock:
            if list_id not in self._rows:
                return False
            conn = sqlite3.connect(self.db_path)
            conn.execute("UPDATE blocklists SET enabled = ? WHERE id = ?",
                        (int(bool(enabled)), list_id))
            conn.commit()
            conn.close()
            self._rows[list_id]["enabled"] = int(bool(enabled))
            self._rebuild_index()
            return True

    def refresh_list(self, list_id):
        """
        Fail open: on ANY failure (download error, parse error, or a parse
        that yields zero domains), the existing in-memory domains and
        on-disk cache are left untouched, the failure is logged, and False
        is returned. The registry row (entry_count/last_updated/etag) is
        only updated on success.
        """
        with self.lock:
            if list_id not in self._rows:
                raise ValueError(f"no blocklist with id {list_id}")
            row = self._rows[list_id]
            url, fmt, etag = row["url"], row["format"], row["etag"]

        try:
            content, new_etag, not_modified = self._fetch(url, etag=etag)
        except Exception as e:
            print(f"[BlocklistManager] Refresh failed for list {list_id} ({url}): {e}. "
                  f"Keeping previous {len(self._list_domains.get(list_id, ()))} domains.")
            return False

        if not_modified:
            with self.lock:
                self._rows[list_id]["last_updated"] = _now_iso()
                conn = sqlite3.connect(self.db_path)
                conn.execute("UPDATE blocklists SET last_updated = ? WHERE id = ?",
                            (self._rows[list_id]["last_updated"], list_id))
                conn.commit()
                conn.close()
            return True

        try:
            domains = self._parse(content, fmt)
        except Exception as e:
            print(f"[BlocklistManager] Parse failed for list {list_id} ({url}): {e}. "
                  f"Keeping previous {len(self._list_domains.get(list_id, ()))} domains.")
            return False

        if not domains:
            print(f"[BlocklistManager] Refresh for list {list_id} ({url}) parsed to 0 "
                  f"domains -- treating as failure, keeping previous list.")
            return False

        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "UPDATE blocklists SET entry_count = ?, last_updated = ?, etag = ? WHERE id = ?",
                (len(domains), _now_iso(), new_etag, list_id),
            )
            conn.commit()
            conn.close()
            self._rows[list_id]["entry_count"] = len(domains)
            self._rows[list_id]["last_updated"] = _now_iso()
            self._rows[list_id]["etag"] = new_etag
            self._list_domains[list_id] = frozenset(domains)
            self._write_cache(list_id, domains)
            self._rebuild_index()
        return True

    def refresh_all(self):
        with self.lock:
            # Re-sync first: without this, a list registered by another
            # process between that process's write and this snapshot is
            # silently skipped until the next scheduled pass. sync_registry
            # is cheap (one SELECT) and self.lock is reentrant, so folding
            # it in here closes the race regardless of caller order.
            self.sync_registry()
            ids = list(self._rows.keys())
        all_ok = True
        for list_id in ids:
            try:
                ok = self.refresh_list(list_id)
            except ValueError:
                ok = False
            all_ok = all_ok and ok
        return all_ok

    # -- lookup, used by FilteringEngine.check() ---------------------------

    def match(self, domain):
        """
        Returns (blocked: bool, blocked_by: str|None). Walks from the most
        specific label down to the TLD, so a.b.example.com is blocked by
        an entry for a.b.example.com, b.example.com, OR example.com. Only
        ENABLED lists count.
        """
        domain = domain.lower().rstrip(".")
        parts = domain.split(".")
        with self.lock:
            enabled_mask = self._enabled_mask
            for i in range(len(parts)):
                candidate = ".".join(parts[i:])
                mask = self._index.get(candidate)
                if mask:
                    hit = mask & enabled_mask
                    if hit:
                        names = [self._rows[lid]["name"]
                                for lid in self._rows
                                if hit & (1 << lid)]
                        return True, ", ".join(sorted(names))
            return False, None
