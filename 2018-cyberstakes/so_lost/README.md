# So Lost - Points: 10 - (Solves: 306)

**Category**: Misc

**Description**: Looks like you've hit the end of the #Tutorial. As you head
off into the rest of the competition prove you're not lost. The service is
listening at `challenge.acictf.com:31802` and will send you directions (up, down,
left, right). All you have to do is recognize the direction and respond with
the corresponding character (^,V,<,>).

**Hints**:
- For many challenges you will have to perform some form of interaction with a
  service.
- Often a simple scripting language like python is a good place to start
  writing a client.
- Libraries like pwntools can make your job much easier

## Solution

Connecting to the service, we see that it expects us to translate the provided
characters. We only have 15 seconds to do so, and need to conduct 40
iterations.

```
$ nc challenge.acictf.com 31802
Are you lost, or am I?
I'll send you a direction (up, down, left, right) and you point me that way by
responding (^,V,<,>).
Lets go!
--------------------------------------------------------------------------------
left
<
Awesome! My un-lost meter is rising (1/40)
up
^
Awesome! My un-lost meter is rising (2/40)
left
Bummer, you took took long. I want to get un-lost fast.
I only have 15 seconds max. Please try again.
```

We can code up this logic in a short pwntools [script](solve.py) with a lookup
table.

```
$ ./solve.py
[+] Opening connection to challenge.acictf.com on port 31802: Done
........................................
[+] Receiving all data: Done (186B)
[*] Closed connection to challenge.acictf.com port 31802
--------------------------------------------------------------------------------
Congratulations! Fully un-lost. Go out and crush this competition
flag: ACI{0ab74b9759bc22f4ee07718cd2f}
```
