#!/usr/bin/env python3

import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 60h                  ;"  #
    
    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder
    
    " next_module:                      "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?
    "   jne   next_module               ;"  #   No: try next module.
    "   ret                              "  #
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)

encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))