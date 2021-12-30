#!/usr/bin/env python3

import struct
import sys
import subprocess

try:
    if len(sys.argv) < 2:
        print("Usage: {} <REGISTER>".format(sys.argv[0]))
        print("Example: {} 33654132".format(sys.argv[0]))
        exit()
    register = int(sys.argv[1], 16)
    ascii_data = struct.pack("<I", register).decode("ASCII")
    result = subprocess.check_output(["/usr/bin/msf-pattern_offset", "-q", ascii_data]).strip().decode("ASCII")
    print(result)
except Exception as e:
    print("HONK!")
    print(str(e))
