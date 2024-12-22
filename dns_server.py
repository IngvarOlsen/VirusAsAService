import socket
import sys
from dnslib import DNSRecord, QTYPE, RR, A
import base64
from datetime import datetime
import requests

def run_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 53))
    except Exception as e:
        print(f"[DNS] Error: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"[DNS] Failed to bind port 53: {e}")
        sys.exit(1)
    print("[DNS] DNS server running")
    while True:
        try:
            data, addr = sock.recvfrom(512)  # typical DNS packet size
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"\n[DNS] [{timestamp}] Received {len(data)} bytes from {addr}")
            try:
                dns_req = DNSRecord.parse(data)
                print(f"[DNS] Parsed DNS request:\n{dns_req}")
                # Build a reply
                reply = dns_req.reply()
                # Extract subdomain as base64 
                qname_str = str(dns_req.q.qname).rstrip('.')
                labels = qname_str.split('.')
                if labels:
                    base64_label = labels[0]  
                    try:
                        decoded = base64.urlsafe_b64decode(base64_label).decode('utf-8', errors='ignore')
                        print(f"[DNS] Decoded subdomain = {decoded}")
                        r = requests.post("http://127.0.0.1:443/api/dnstunneltest", json={"payload": decoded})
                        print("[DNS] Posted data to Flask, response:", r.status_code)
                    except Exception as decode_err:
                        print(f"[DNS] Base64 decode error: {decode_err}")
                raw_reply = reply.pack()
                sock.sendto(raw_reply, addr)
                print(f"[DNS] Sent {len(raw_reply)} bytes back to {addr}")
    
            except Exception as parse_err:
                print(f"[DNS] Failed to parse/handle DNS query: {parse_err}")

        except KeyboardInterrupt:
            print("\n[DNS] Stopping DNS server.")
            break
        except Exception as e:
            print(f"[DNS] Error: {e}")

    sock.close()
    print("[DNS] DNS server shut down.")
