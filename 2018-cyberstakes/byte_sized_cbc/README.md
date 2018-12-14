# Byte Sized CBC - Points: 50 - (Solves: 97)

**Category**: Cryptography

**Description**: Break the CBC 'encryption' scheme running at
`challenge.acictf.com:1751`. The author is so confident that they will just
hand you the key upon connection.

**Hints**:
- Cipher Block Chaining ties the output of each block's 'encryption' to the
  next block.
- How many different IVs could there be if a block is only one byte long?
- What if the 'block cipher'
  (https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:CBC_encryption.svg)
  doesn't do anything?

## Solution

Connecting to the given service appears to return an encrypted flag encoded
with base64. Oddly, the output contains non-printable characters. This seems to
be a bug in the challenge itself. Once we get a good response, we can save the
base64 data to a file and solve the challenge offline since the server isn't
interactive.

The hints seem to indicate the ciphertext is encrypted with a rolling xor
(imagine CBC encryption where blocks are one byte long and the block cipher is
a no-op). We can review the ever-handy CBC image from wikipedia as a refresher.

![CBC Decryption](img/cbc_decryption.png)

Assuming block cipher decryption is a no-op, we can apply the rolling xor
decryption by xor'ing every n'th character of the ciphertext with the n+1'th
character to derive the n+1'th plaintext byte. Since we know that the flag
starts with "ACI{", we don't need to brute force the 256 potential IV values.

We can decrypt the ciphertext with the following blob:

```
pt = ""
for i in xrange(len(ct) - 1):
    pt += chr(ord(ct[i]) ^ ord(ct[i+1]))

log.success("Flag: A{:s}}}".format(pt))
```

Wrapping this in a short [script](solve.py) produces the flag.

```
$ ./solve.py
[+] Flag: ACI{c6d1012ea9f05cca863d5c0ca3a}
```
