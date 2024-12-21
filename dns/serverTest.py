import socket
import sys
from datetime import datetime
from dnslib import DNSRecord, QTYPE, RR, A
import base64

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 53))
    except PermissionError:
        print("Run as root or use sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"Failed to bind: {e}")
        sys.exit(1)

    print("[Info] Listening on port 53 (UDP). Press Ctrl+C to stop.")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"\n[{now}] Received {len(data)} bytes from {addr}")
            
            try:
                dns_msg = DNSRecord.parse(data)
                print("DNS Query:")
                print(dns_msg)

                # Build a reply
                reply = dns_msg.reply()

                # Extract first label from QNAME
                qname_str = str(dns_msg.q.qname).rstrip('.')
                # e.g. "dGVzdA==.dns.bitlus.online"
                labels = qname_str.split('.')
                if len(labels) >= 1:
                    base64_label = labels[0]
                    try:
                        print("base64_label0: ", base64_label)
                        decoded_data = base64.urlsafe_b64decode(base64_label).decode('ascii', errors='ignore')
                        print(f"Decoded data: {decoded_data}")
                    except Exception as decode_err:
                        print(f"Base64 decode failed: {decode_err}")

                # If it's an A record query, add a dummy IP
                if dns_msg.q.qtype == QTYPE.A:
                    reply.add_answer(RR(
                        rname=dns_msg.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=60,
                        rdata=A("127.0.0.1")
                    ))
                
                raw_reply = reply.pack()
                sock.sendto(raw_reply, addr)
                print(f"Sent DNS response ({len(raw_reply)} bytes) to {addr}")

            except Exception as parse_err:
                print(f"Failed to parse DNS: {parse_err}")

        except KeyboardInterrupt:
            print("\n[Exit] Stopping DNS server.")
            break
        except Exception as e:
            print(f"Error: {e}")

    sock.close()

if __name__ == "__main__":
    main()
