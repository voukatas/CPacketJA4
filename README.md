# CPacketJA4

CPacketJA4 is a network traffic analyzer and fingerprinting tool that generates JA4 fingerprints from TLS Client Hello messages. It captures live traffic, parses packets, and extracts critical handshake information, such as cipher suites, extensions, and protocol versions. PacketJA4 is designed for security researchers, network engineers, and anyone interested in analyzing TLS/QUIC traffic.

> **Disclaimer**: This project is in the **experimental phase**. It does not fully support TCP reassembly or handle fragmented UDP/QUIC packets. Use it for educational or experimental purposes and not in production environments.

## Features

- **Live Traffic Capture**: Uses `libpcap` to capture network packets in real-time.
- **Protocol Support**: Handles IPv4, IPv6, TCP ( UDP traffic on the road)
- **JA4 Fingerprinting**: Generates JA4 fingerprints from TLS (and QUIC handshakes is close)
- **Efficient Parsing**: Excludes GREASE values, extracts signature algorithms, and identifies supported extensions.

## Current Limitations

- **TCP Reassembly**: PacketJA4 does not support reassembling TCP streams. Only single packets containing a complete TLS Client Hello message are processed.
- **UDP/QUIC Fragmentation**: It does not handle fragmented UDP or QUIC packets, and partial handshakes may not be processed correctly.
- **Experimental Stage**: As this is a work-in-progress, unexpected behavior may occur with certain traffic patterns.

## Getting Started

### Prerequisites

To build and run PacketJA4, you need the following:
- A Linux-based system.
- Development tools (`gcc`, `make`, etc.).
- Libraries:
  - `libpcap` (packet capture)
  - `libssl` (for hashing)

Install dependencies on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install libpcap-dev libssl-dev build-essential
```

# Installation
```bash
git clone https://github.com/yourusername/PacketJA4.git
cd PacketJA4
```
Build & Run
```bash
make
sudo ./c_packet_ja4
```
Run tests
```bash
make test
./test_payloads
```
> Note: Root or elevated permissions are required to capture live traffic.Note: Root or elevated permissions are required to capture live traffic.

# Usage
PacketJA4 captures traffic on the lo interface by default. You can change the interface in the main() function.

# Show Time

```bash
cd scripts/
# Generate a certificate
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.crt -days 365
cat server.key server.crt > server.pem

# Run the https python server
python3 https_server.py

# Start the packet sniffer
sudo ./c_packet_ja4

# Send an https GET Request and check the output on the windows where the c_packet_ja4 is running 
curl https://localhost:4445/ -k
```
