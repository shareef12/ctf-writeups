#!/usr/bin/env python2

"""
Caesar cipher with an alphabet from 0x20 (space) to 0x7f.
"""

from pwn import *

ct = "dfl?'SV)Z[WY)V*T%(\S)XW(T%TXS'YA"
pt = ""
for c in ct:
    pt += chr(((ord(c) - 0x20 + 60) % 0x5f) + 0x20)
log.success("Flag: {:s}".format(pt))
