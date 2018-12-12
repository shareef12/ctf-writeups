#!/usr/bin/env python2

import sys
from pwn import *

conn = remote("challenge.acictf.com", 31802)

#context.log_level = "debug"

CHOICES = {
    "up": "^",
    "down": "V",
    "left": "<",
    "right": ">",
}

def main():
    conn.recvuntil("----\n")

    for _ in xrange(40):
        sys.stdout.write(".")
        prompt = conn.recvline().strip()
        conn.sendline(CHOICES[prompt])
        conn.recvline()

    print
    print conn.recvall()


if __name__ == "__main__":
    main()
