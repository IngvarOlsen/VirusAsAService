import socket
import sys
from datetime import datetime
from dnslib import DNSRecord

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

            # Print raw data in hex
            print("Raw packet (hex):", data.hex())

            # Attempt to parse with dnslib for additional info
            try:
                dns_msg = DNSRecord.parse(data)
                print("DNS Query/Response:")
                print(dns_msg)
            except Exception as e:
                print(f"Failed to parse DNS packet: {e}")

        except KeyboardInterrupt:
            print("\n[Exit] Stopping listener.")
            break
        except Exception as e:
            print(f"Error: {e}")

    sock.close()

if __name__ == "__main__":
    main()