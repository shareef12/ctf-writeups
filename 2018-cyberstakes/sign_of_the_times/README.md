# Sign of the times - Points: 125 - (Solves: 27)

**Category**: Binary Exploitation

**Description**: Further recon has identified a data indexing service at
`challenge.acictf.com:14000` that looks vulnerable... See what you can do with
the server we managed to leak!

**Hints**:
- There's an array being accessed. Look at how the array is being accessed. Is
  there anything wrong there?
- Look at the memory around the array. Is there anything of interest?
- Keep endianness and the size of your overwrites in mind!

## Solution

We are given a 32-bit binary with a stack canary and NX enabled.

```
$ checksec codeserver
[*] '/home/user/ctf-writeups/2018-cyberstakes/sign_of_the_times/codeserver'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Reverse engineering the binary shows that it sets up a stack based data
structure with the following format:

```
struct codes {
    char filepath[4096];
    int codes[10];
}
```

The filepath is initialized to `secret_codes_to_the_base.txt`, and the codes
are read from this file. We have the ability to print the codes in the
structure, read the file stored in `filepath`, or set the code at an index 0-9
to an arbitrary value.

Looking deeper at the `set_code` function, there aren't any validation checks
on the index supplied by the user! This gives us an arbitrary content 4-byte
write relative to the address of our stack buffer. This gives us the ability to
manipulate anything on the stack at a known offset, or paired with a leak,
convert this to an arbitrary write primitive.

Since we only need the flag, we could probably just overwrite the `filepath`
member of this struct to get an arbitrary file read. This is easy to do by
passing a negative index to the code to write. We do this in a short pwntools
[script](solve.py).
