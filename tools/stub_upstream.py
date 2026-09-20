"""Stub upstream DNS server that answers everything with a distinctive A
record so we can prove real queries reach it. Binds to 127.0.0.1 on
config.UPSTREAM_PORT (default 53, override via HANNIBAALNS_UPSTREAM_PORT)."""
import os
import sys
# config.py is in the project root (one level up from tools/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import socket
from dnslib import DNSRecord, RR, A, QTYPE

PORT = config.UPSTREAM_PORT
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', PORT))
print(f"stub upstream listening on 127.0.0.1:{PORT}")
while True:
    data, addr = sock.recvfrom(512)
    req = DNSRecord.parse(data)
    print(f"STUB received query from {addr[0]}:{addr[1]}: {req.q.qname}", flush=True)
    reply = req.reply()
    reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.A, rdata=A('198.51.100.7'), ttl=60))
    sock.sendto(reply.pack(), addr)
