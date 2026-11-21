#!/usr/bin/env python3
"""Minimal SNTP client: prints the server's stratum, exits 1 on no reply."""
import socket
import struct
import sys

host = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(b"\x1b" + 47 * b"\0", (host, 123))
try:
    data, _ = sock.recvfrom(512)
except socket.timeout:
    print("no reply")
    sys.exit(1)
stratum = data[1]
seconds = struct.unpack("!I", data[40:44])[0]
print(f"stratum={stratum} transmit_seconds={seconds}")
