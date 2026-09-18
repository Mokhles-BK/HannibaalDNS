import os
import base64
import sqlite3
from flask import Flask, request, jsonify, Response

# Import the shared DNS resolver and filtering engine
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from dns_resolver import resolve_query
from filtering import FilteringEngine

app = Flask(__name__)

# Database path: project root (hannibaaldns.db)
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'hannibaaldns.db'))

# Initialize shared FilteringEngine instance for DoH (reuses same logic as UDP)
doh_engine = FilteringEngine(db_path=DB_PATH)
UPSTREAM_DNS = '8.8.8.8'

def get_db():
    conn = sqlite3.connect(DB_PATH)
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
        SELECT client_ip, domain, query_type, blocked, response_time, timestamp
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

    client_ip = request.remote_addr or 'unknown'
    response_bytes = resolve_query(dns_bytes, client_ip, UPSTREAM_DNS, doh_engine)
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
    response_bytes = resolve_query(dns_bytes, client_ip, UPSTREAM_DNS, doh_engine)
    return Response(response_bytes, mimetype='application/dns-message')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)