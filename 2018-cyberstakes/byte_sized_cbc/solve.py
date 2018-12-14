#!/usr/bin/env python2

"""
CBC chaining (rolling xor). Looks like they incorrectly implemented
the CBC algorithm as the last byte isn't actually chained. Also, no
need to guess the IV because the first byte is known by the flag
format.
"""

from pwn import *

def main():
    with open("ciphertext.txt", "rb") as f:
        ct = f.read()

    pt = ""
    for i in xrange(len(ct) - 1):
        pt += chr(ord(ct[i]) ^ ord(ct[i+1]))

    log.success("Flag: A{:s}}}".format(pt))


if __name__ == "__main__":
    main()
