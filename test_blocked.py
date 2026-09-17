import socket
from dnslib import DNSRecord, QTYPE

def test_blocked_domain(host='127.0.0.1', port=5053, query_domain='doubleclick.net'):
    print(f"Testing blocked domain at {host}:{port} for {query_domain}...")
    request = DNSRecord.question(query_domain, qtype='A')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(request.pack(), (host, port))
        data, _ = sock.recvfrom(512)
        response = DNSRecord.parse(data)
        print(f"Status: {response.header.rcode}")
        print(f"Answer section: {response.rr}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    test_blocked_domain()