import socket
from dnslib import DNSRecord, DNSQuestion, QTYPE

def test_dns_server(host='127.0.0.1', port=5053, query_domain='google.com'):
    print(f"Testing DNS server at {host}:{port} with query for {query_domain}...")

    # Create a DNS request
    request = DNSRecord.question(query_domain, qtype='A')

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        # Send the request
        sock.sendto(request.pack(), (host, port))

        # Receive the response
        data, _ = sock.recvfrom(512)
        response = DNSRecord.parse(data)

        print(f"Response received: {response}")
    except socket.timeout:
        print("Timeout: No response from DNS server")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    test_dns_server()