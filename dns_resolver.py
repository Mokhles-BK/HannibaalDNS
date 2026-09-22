"""
Shared DNS resolution logic for both UDP and DoH endpoints.
Refactored from dns_server.py to avoid duplication.
"""
import time
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, DNSError, RCODE
import config


def resolve_query(raw_request_bytes: bytes, client_ip: str, upstream_dns: str,
                  engine, upstream_port=None) -> bytes:
    """
    Core DNS resolution logic shared by UDP, DoH, and DoT endpoints.

    Args:
        raw_request_bytes: Raw DNS query message bytes
        client_ip: Client IP address for filtering and logging
        upstream_dns: Upstream DNS server IP
        engine: FilteringEngine instance for blocking checks
        upstream_port: Upstream DNS server port (default: config.UPSTREAM_PORT)

    Returns:
        Raw DNS response message bytes
    """
    if upstream_port is None:
        upstream_port = config.UPSTREAM_PORT
    # dnslib's RR.pack()/reply.pack() returns bytearray; Flask's WSGI server
    # requires real bytes, so normalize the return type here.
    request = DNSRecord.parse(raw_request_bytes)
    qname = str(request.q.qname).rstrip('.')
    qtype = QTYPE[request.q.qtype]

    # Check filtering engine
    start_time = time.time()
    blocked, blocked_by = engine.check(qname, client_ip)
    response_time = time.time() - start_time

    if blocked:
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        engine.db.log_query(client_ip, qname, qtype, True, response_time, blocked_by)
        return bytes(reply.pack())

    reply = request.reply()
    # Forward the query to the upstream DNS server
    try:
        upstream_request = DNSRecord.question(qname, qtype=qtype)
        raw_response = upstream_request.send(
            upstream_dns, upstream_port, timeout=config.UPSTREAM_TIMEOUT)
        upstream_response = DNSRecord.parse(raw_response)

        # Set the transaction ID to match the request
        reply.header.id = request.header.id

        if upstream_response:
            # Copy answer records directly from upstream response
            for rr in upstream_response.rr:
                reply.add_answer(rr)

        response_time = time.time() - start_time
        engine.db.log_query(client_ip, qname, qtype, False, response_time)
    except Exception as e:
        # Return SERVFAIL if there's an error. Always print what happened —
        # this was silently swallowed before, which made the DoT upstream
        # hang undiagnosable for a long time. Never remove this print again
        # without replacing it with an equivalent log/DB field.
        print(f"Upstream resolution failed for {qname}: {type(e).__name__}: {e}")
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        response_time = time.time() - start_time
        engine.db.log_query(client_ip, qname, qtype, False, response_time)

    return bytes(reply.pack())