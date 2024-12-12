import socket

def dns_tunneling_request(subdomain, dns_server="8.8.8.8"):
    domain = f"{subdomain}.127.0.0.1/api/dnstunneling"  # Replace with your target domain

    # Build the DNS query
    transaction_id = b"\xaa\xaa"  # Transaction ID
    flags = b"\x01\x00"  # Standard query
    questions = b"\x00\x01"  # One question
    answer_rrs = b"\x00\x00"
    authority_rrs = b"\x00\x00"
    additional_rrs = b"\x00\x00"
    
    # Build the question section
    qname = b"".join(bytes([len(label)]) + label.encode("utf-8") for label in domain.split("."))
    qtype = b"\x00\x01"  # QTYPE A
    qclass = b"\x00\x01"  # QCLASS IN
    
    # Full DNS packet
    dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + b"\x00" + qtype + qclass

    # Send the DNS query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(dns_query, (dns_server, 53))
    response, _ = sock.recvfrom(1024)

    print(f"Received DNS response: {response}")

dns_tunneling_request("testdata")
