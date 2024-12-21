import socket
import sys
from datetime import datetime
from dnslib import DNSRecord, QTYPE, RR, A  
import base64

def main():
    # Bind to all interfaces on UDP port 53
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 53))
    except PermissionError:
        print("You need to run this as root or with sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"Error binding to port 53: {e}")
        sys.exit(1)

    print("[Info] Listening on port 53 (UDP). Press Ctrl+C to stop.")
    while True:
        try:
            data, addr = sock.recvfrom(512)  # 512 is enough for typical DNS packets
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print(f"\n[{now}] Received {len(data)} bytes from {addr}")
            print("Raw packet (hex):", data.hex())
            try:
                dns_msg = DNSRecord.parse(data)
                print("DNS Query/Response:")
                print(dns_msg)

                reply = dns_msg.reply()

                qname_str = str(dns_msg.q.qname)
                print(f"QNAME: {qname_str}")

                # Parse out the subdomain base64
                dns_msg = DNSRecord.parse(data)
                qname_str = str(dns_msg.q.qname)  # e.g. "dGVzdA.dns.bitlus.online."
                labels = qname_str.strip('.').split('.')  # ["dGVzdA", "dns", "bitlus", "online"]

                # The first label might be the base64 data
                subdomain_b64 = labels[0]
                try:
                    decoded_data = base64.urlsafe_b64decode(subdomain_b64).decode('utf-8', errors='ignore')
                    print("Decoded data from subdomain:", decoded_data)
                except Exception as decode_err:
                    print("Failed to decode base64 subdomain:", decode_err)

                # Check if query is type A
                if dns_msg.q.qtype == QTYPE.A:
                    # Add an A-record pointing 127.0.0.1
                    reply.add_answer(RR(
                        rname=dns_msg.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=60,
                        rdata=A("127.0.0.1")
                    ))
                else:
                    # For any other
                    pass
                # Pack the reply
                raw_reply = reply.pack()
                # Send the DNS reply to the client
                sock.sendto(raw_reply, addr)
                print(f"Sent a DNS response ({len(raw_reply)} bytes) back to {addr}")

            except Exception as parse_err:
                print(f"Failed to parse or build DNS packet: {parse_err}")

        except KeyboardInterrupt:
            print("\n[Exit] Stopping listener.")
            break
        except Exception as e:
            print(f"Error: {e}")

    sock.close()

if __name__ == "__main__":
    main()
