# Ascii Salad - Points: 50 - (Solves 319)

**Category**: Cryptography

**Description**: Cobra Commander is sending a flag to one of his goons. Break
their simple code to find the flag here `challenge.acictf.com:15577`.  Example
connection command: `nc challenge.acictf.com 15577`

**Hints**:
- Cobra Commander thinks a lot of himself... its reasonable he would use a
  classic cipher named after an emperor.
- Clearly these guys are using more characters than just the alphabet -- is
  there a chart with lots of possible characters on it?
- The order of the characters on the chart matters, just like the order of the
  letters in the alphabet for the classic cipher. Can you identify good start
  and end points on the chart to rotate around?
- Even with more characters than the alphabet, there are not THAT many options.
  Could you brute force their weak scheme?

## Solution

Connecting to the provided server, we are sent a printable ascii string. We
appear to get the same string each time and the service is not interactive.

```
$ nc challenge.acictf.com 15577
Message: dfl?'SV)Z[WY)V*T%(\S)XW(T%TXS'YA
$ nc challenge.acictf.com 15577
Message: dfl?'SV)Z[WY)V*T%(\S)XW(T%TXS'YA
```

Based on the challenge name and hints, it sounds like this challenge is
suspiciously similar to a classic caesar cipher. Since the ciphertext and the
flag contain special characters, they are likely using an extended table.

Since printable characters generally occur between 0x20 and 0x7f, it might
make sense to use these as boundaries for our alphabet. Tweaking the parameters
in a [script](solve.py) to decrypt the ciphertext yields the flag.

```python
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
```

```
$ ./solve.py
[+] Flag: ACI{c03e7846e3f1ad90e54d1a150c6}
```
