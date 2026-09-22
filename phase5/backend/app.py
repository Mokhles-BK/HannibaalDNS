import os
import base64
import sqlite3
from flask import Flask, request, jsonify, Response

# Import the shared DNS resolver and filtering engine
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from dns_resolver import resolve_query
from filtering import FilteringEngine
from dnslib import DNSError
import config

app = Flask(__name__)

# Initialize shared FilteringEngine instance for DoH (reuses same logic as UDP)
doh_engine = FilteringEngine()

# Upstream DNS/port are read at call time (not import time), so a
# HANNIBAALNS_UPSTREAM_* override set after the module is imported — e.g.
# by a wrapper script — actually changes the upstream used by DoH queries.
def _upstream_dns():
    return config.UPSTREAM_DNS


def _upstream_port():
    return config.UPSTREAM_PORT


def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/stats', methods=['GET'])
def stats():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            COUNT(*) as total_queries,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_queries,
            AVG(response_time) as avg_response_time
        FROM query_log
        WHERE timestamp > datetime('now', '-1 hour')
    """)
    row = cur.fetchone()
    conn.close()
    return jsonify({
        'total_queries': row[0],
        'blocked_queries': row[1],
        'avg_response_time': row[2]
    })

@app.route('/api/queries', methods=['GET'])
def queries():
    limit = request.args.get('limit', default=10, type=int)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT client_ip, domain, query_type, blocked, response_time, timestamp, blocked_by
        FROM query_log
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    columns = [desc[0] for desc in cur.description]
    result = [dict(zip(columns, row)) for row in rows]
    return jsonify(result)

@app.route('/api/anomalies', methods=['GET'])
def anomalies():
    limit = request.args.get('limit', default=10, type=int)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT domain, client_ip, score, reasons, timestamp
        FROM anomaly_log
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    columns = [desc[0] for desc in cur.description]
    result = [dict(zip(columns, row)) for row in rows]
    return jsonify(result)

@app.route('/api/clients', methods=['GET'])
def clients():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT client_ip, COUNT(*) as query_count
        FROM query_log
        GROUP BY client_ip
        ORDER BY query_count DESC
    """)
    rows = cur.fetchall()
    conn.close()
    columns = [desc[0] for desc in cur.description]
    result = [dict(zip(columns, row)) for row in rows]
    return jsonify(result)

# ---------------------------------------------------------------------------
# Allowlist / Denylist management (per-client, NextDNS-style)
# Reuses Database.get_profile() / Database.set_profile(); no global list.
# ---------------------------------------------------------------------------

@app.route('/api/clients/<client_ip>/lists', methods=['GET'])
def get_client_lists(client_ip):
    """Return custom_blocklist and custom_allowlist for this client."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT profile_name, custom_blocklist, custom_allowlist
        FROM client_profiles WHERE ip_address = ?
    ''', (client_ip,))
    row = cur.fetchone()
    conn.close()

    if row:
        blocklist = [d for d in (row[1].split(',') if row[1] else []) if d]
        allowlist = [d for d in (row[2].split(',') if row[2] else []) if d]
    else:
        blocklist, allowlist = [], []

    return jsonify({
        'client_ip': client_ip,
        'profile_name': row[0] if row else 'default',
        'custom_blocklist': blocklist,
        'custom_allowlist': allowlist,
    })


@app.route('/api/clients/<client_ip>/lists', methods=['POST'])
def update_client_lists(client_ip):
    """
    Add or remove a domain from this client's allowlist or denylist.

    Body (JSON), one of:
      {"action": "add",    "list": "allowlist", "domain": "example.com"}
      {"action": "remove", "list": "denylist",  "domain": "example.com"}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON'}), 400

    action = data.get('action')
    list_name = data.get('list')
    domain = (data.get('domain') or '').strip().lower().rstrip('.')

    if action not in ('add', 'remove'):
        return jsonify({'error': "action must be 'add' or 'remove'"}), 400
    if list_name not in ('allowlist', 'denylist'):
        return jsonify({'error': "list must be 'allowlist' or 'denylist'"}), 400
    if not domain:
        return jsonify({'error': 'domain must be a non-empty string'}), 400
    if ',' in domain:
        return jsonify({'error': 'domain must not contain commas'}), 400

    # Read current lists
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT profile_name, custom_blocklist, custom_allowlist
        FROM client_profiles WHERE ip_address = ?
    ''', (client_ip,))
    row = cur.fetchone()
    conn.close()

    profile_name = row[0] if row else 'default'
    blocklist = [d for d in (row[1].split(',') if row and row[1] else []) if d]
    allowlist = [d for d in (row[2].split(',') if row and row[2] else []) if d]

    if list_name == 'allowlist':
        target = allowlist
    else:
        target = blocklist

    if action == 'add':
        if domain in target:
            return jsonify({'status': 'already_present', 'list': list_name,
                            'domain': domain, 'client_ip': client_ip})
        target.append(domain)
    else:  # remove
        if domain not in target:
            return jsonify({'status': 'not_found', 'list': list_name,
                            'domain': domain, 'client_ip': client_ip})
        target.remove(domain)

    try:
        doh_engine.db.set_profile(client_ip, profile_name,
                                  custom_blocklist=blocklist or None,
                                  custom_allowlist=allowlist or None)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({
        'status': 'ok',
        'action': action,
        'list': list_name,
        'domain': domain,
        'client_ip': client_ip,
        'custom_blocklist': blocklist,
        'custom_allowlist': allowlist,
    })


# ---------------------------------------------------------------------------
# Analytics-style breakdown (query_log / anomaly_log only — no GeoIP, no
# DNSSEC%, no encrypted-DNS% since none of that is tracked in the schema)
# ---------------------------------------------------------------------------

@app.route('/api/analytics/top-domains', methods=['GET'])
def top_domains():
    """Top N domains from query_log, split by blocked / resolved."""
    blocked = request.args.get('blocked')
    limit = request.args.get('limit', default=10, type=int)
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000

    where = ''
    params = []
    if blocked is not None:
        if blocked in ('true', '1', 'yes'):
            where = 'WHERE blocked = 1'
        elif blocked in ('false', '0', 'no'):
            where = 'WHERE blocked = 0'
        else:
            return jsonify({'error': "blocked must be 'true' or 'false'"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(f'''
        SELECT domain, COUNT(*) as count
        FROM query_log
        {where}
        GROUP BY domain
        ORDER BY count DESC, domain ASC
        LIMIT ?
    ''', (limit,))
    rows = cur.fetchall()
    conn.close()

    result = [{'domain': r[0], 'count': r[1]} for r in rows]
    return jsonify(result)


@app.route('/api/analytics/summary', methods=['GET'])
def analytics_summary():
    """Total queries, blocked count, percent blocked over a time window."""
    hours = request.args.get('hours', default=24, type=int)
    if hours < 1:
        hours = 1
    if hours > 8760:  # 1 year
        hours = 8760

    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_count
        FROM query_log
        WHERE timestamp > datetime('now', '-' || ? || ' hours')
    ''', (hours,))
    row = cur.fetchone()
    conn.close()

    total = row[0] or 0
    blocked_count = row[1] or 0
    pct = (blocked_count / total * 100.0) if total else 0.0

    return jsonify({
        'window_hours': hours,
        'total_queries': total,
        'blocked_queries': blocked_count,
        'resolved_queries': total - blocked_count,
        'percent_blocked': round(pct, 2),
    })


# DNS-over-HTTPS (RFC 8484) endpoints
@app.route('/dns-query', methods=['GET'])
def doh_get():
    """GET /dns-query?dns=<base64url-encoded-DNS-message>"""
    dns_param = request.args.get('dns')
    if not dns_param:
        return Response('Missing dns parameter', status=400, mimetype='text/plain')

    try:
        # Base64URL decode (RFC 8484)
        dns_bytes = base64.urlsafe_b64decode(dns_param + '=' * (-len(dns_param) % 4))
    except Exception as e:
        return Response(f'Invalid base64url encoding: {e}', status=400, mimetype='text/plain')

    try:
        # Validate the payload is a real DNS message before forwarding it.
        # Without this, a base64url string that decodes to garbage (e.g.
        # '!!!bad' -> 2 bytes) leaks an unhandled DNSError as a 500.
        from dnslib import DNSRecord
        DNSRecord.parse(dns_bytes)
    except DNSError as e:
        return Response(f'Invalid DNS message: {e}', status=400, mimetype='text/plain')

    client_ip = request.remote_addr or 'unknown'
    response_bytes = resolve_query(dns_bytes, client_ip, _upstream_dns(), doh_engine,
                                   _upstream_port())
    return Response(response_bytes, mimetype='application/dns-message')


@app.route('/dns-query', methods=['POST'])
def doh_post():
    """POST /dns-query with Content-Type: application/dns-message"""
    content_type = request.headers.get('Content-Type', '')
    if content_type != 'application/dns-message':
        return Response('Content-Type must be application/dns-message', status=415, mimetype='text/plain')

    dns_bytes = request.get_data()
    if not dns_bytes:
        return Response('Empty request body', status=400, mimetype='text/plain')

    client_ip = request.remote_addr or 'unknown'
    response_bytes = resolve_query(dns_bytes, client_ip, _upstream_dns(), doh_engine,
                                   _upstream_port())
    return Response(response_bytes, mimetype='application/dns-message')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config.DOH_PORT)