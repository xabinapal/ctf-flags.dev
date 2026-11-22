---
title: The Broken Time Capsule
challenge_type: Rev
difficulty: Hard
author: ethandhomnic
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  We recovered a command-line restoration tool and a damaged time-capsule backup. The tool claims the backup is unreadable, but it may be waiting for the right sequence.

  Usage: ./time_capsule <slot-1> <slot-2> <slot-3> <slot-4> backup.tc (each slot is a decimal byte)

  Recover the message and submit it as the flag.
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/the-broken-time-capsule/dis.tar.gz
---

## Recon

We get a stripped, statically-linked x86-64 ELF (`time_capsule`, musl) and a 1227-byte
`backup.tc`. The tool takes four decimal slot bytes and the backup path, prints one of
two errors, and only on the correct four bytes outputs the hidden message.

`main` (`0x401060`) parses the four slot arguments and calls a worker at `0x401290`.
Opening the file and checking its size happens right at the top of that worker:

```bash
$ r2 -A time_capsule
[0x00401060]> aaa; s 0x401290; pdf
```

```text
│  0x0040129d  lea  rsi, [0x408000]   ; "rb"  (fopen mode)
│  0x004012ab  call fcn.00401c04     ; fopen(path, "rb")
│  0x004012b0  test rax, rax
│  0x004012b3  je   fcn.0040140c     ; -> "The clock face is unreadable."
│  ...
│  0x004012d6  lea  rax, [rax - 0xa] ; filesize - 10
│  0x004012da  cmp  rax, 0x1ff6      ; must equal 7*p + 2*height + code_len
```

The interesting part is that the backup file is not data to restore: it is a small
*program*. The worker validates a header, then interprets the body as bytecode.

## Exploitation

### The file format

| Offset | Size | Meaning |
|---|--:|---|
| 0x00 | 4 | magic `TCAP` |
| 0x04 | 1 | version, must be `0x02` |
| 0x05 | 1 | `p`, number of VM instructions |
| 0x06 | 1 | `height`, ops per output byte, 1..32 |
| 0x07 | 1 | must be `0xC3` |
| 0x08 | 2 | `code_len` (LE), encrypted message length |
| 0x0A | 7·p | VM code, 7 bytes per instruction |

The tail is a 20-byte op stream plus a 42-byte keystream. For `backup.tc`: `p = 165`,
`height = 10`, `code_len = 42`. The "record-like" strings and `0123456789ABCDEF` in the
file are red herrings.

### The virtual machine

Each instruction is `opcode, reg_a, reg_b, imm32` over eight 32-bit registers
`r0..r7`. The opcode jump table at `.rodata:0x408048` decodes to:

```text
0x10 MOV r[a], imm       0x26 ADD r[a], imm
0x11 LOAD r[a] = slot[b] 0x27 XOR r[a], imm
0x12 MOV r[a], r[b]      0x28 MUL r[a], imm
0x20 ADD r[a], r[b]      0x29 AND r[a], imm
0x21 XOR r[a], r[b]      0x30/0x31 JZ/JNZ r[a], rel
0x22 MUL r[a], r[b]      0x32 JMP rel
0x23 SUB r[a], r[b]      0x40 CHECK r[a] == imm
0x24/0x25 ROL/SHR r[a]   0xFE HALT
```

A failing `CHECK`, an invalid opcode/PC/register, an instruction-budget overrun, or
halting without exactly two passing `CHECK`s all give the "damaged" error.

We reimplemented this interpreter in Python (`run(meta, slots)`: a 1:1 map of the table
above), so we can execute the program and read the register file at `HALT`.

Disassembling the 165 instructions shows four symmetric "rounds" mixing each slot into
`r0` (constants cribbed from SHA-256 IVs and SplitMix64), then the same again into `r4`,
ending in two checks:

```text
122: CHECK r0 == 0x2EC29234
123: CHECK r4 == 0x04DE2A9C
```

Each round is `x = (acc + slot_i + C_i) ^ K_i`, `x = rol(x, R_i)`, `x *= M_i` (odd),
`x ^= x >> S_i`, plus a parity branch on `(slot_i + C_i) & 1` that selects
`x ^= XO_i` or `x += AE_i`. After the CHECKs both registers are mixed through four more
rounds, and `r0`/`r4` at `HALT` seed the message decryption.

### Solving the slots without a 2³² brute force

Every round is invertible, so we split the search. We walk rounds 0–1 forward (slot 0 and
1, 2¹⁶ results) and rounds 3–2 backward from the `CHECK` constant (slot 3 and 2), then
join the two halves in a meet-in-the-middle. The parity branch uses `(slot + C) & 1`, not
`slot & 1`, and one constant reads little-endian from the byte stream.

Helpers used below: `MASK = 0xffffffff`, `rol32(x,n)` (32-bit left rotation), `mulinv(a) = pow(a, -1, 1<<32)` for odd `a`, `meta = parse('backup.tc')`, and `run(meta, slots)` (the Python VM from above).

```python
TARGET0 = 0x2ec29234
R0 = [  # (C, K, R, M, S, XO, AE) per round
    (0x243f6a88, 0xa4093822,  7, 0x85ebca6b, 11, 0x9e3779b9, 0xa5a5a5a5),
    (0x85a308d3, 0x299f31d0, 13, 0xc2b2ae35, 15, 0x7f4a7c15, 0x3c6ef372),
    (0x13198a2e, 0x082efa98, 21, 0x27d4eb2f,  9, 0xd1b54a35, 0xbb67ae85),
    (0x03707344, 0xec4e6c89, 11, 0x165667b1, 13, 0x94d049bb, 0x6a09e667),
]

def mix(x, i, odd):
    _, K, R, M, S, XO, AE = R0[i]
    x = rol32(x ^ K, R); x = (x * M) & MASK; x ^= x >> S
    return (x ^ XO) if odd else ((x + AE) & MASK)

def unmix(x, i, odd):
    _, K, R, M, S, XO, AE = R0[i]
    x = (x ^ XO) if odd else ((x - AE) & MASK)
    pre = x
    for _ in range(32 // S + 1):        # undo x ^= x >> S (fixpoint)
        x = (pre ^ (x >> S)) & MASK
    x = (x * mulinv(M)) & MASK          # M is odd
    x = ((x >> R) | (x << (32 - R))) & MASK   # undo rol
    return x ^ K

# forward: slots 0..1
fwd = {}
for s0 in range(256):
    x = (0x6a09e667 + s0 + R0[0][0]) & MASK
    x = mix(x, 0, (s0 + R0[0][0]) & 1)
    for s1 in range(256):
        y = (x + s1 + R0[1][0]) & MASK
        y = mix(y, 1, (s1 + R0[1][0]) & 1)
        fwd[y] = fwd.get(y, []) + [((s0, s1), x)]

# backward: slots 3..2 from the CHECK constant
for s3 in range(256):
    a3 = unmix(TARGET0, 3, (s3 + R0[3][0]) & 1)
    b3 = (a3 - s3 - R0[3][0]) & MASK
    for s2 in range(256):
        a2 = unmix(b3, 2, (s2 + R0[2][0]) & 1)
        b2 = (a2 - s2 - R0[2][0]) & MASK
        if b2 in fwd:
            for (s0, s1), _ in fwd[b2]:
                slots = (s0, s1, s2, s3)
                if run(meta, slots)[0]:     # full VM check
                    print(slots)            # (53, 167, 18, 233)
```

Exactly one tuple passes the full VM (both `CHECK`s, clean `HALT`): `(53, 167, 18, 233)`.

### Recovering the 42-byte message

At `HALT` the chaining value is `h0 = rol32(r4, 11) ^ r0`. For each output byte `i` we
compute `key_i = rol32((slot[i&3] ^ (i*0x9E3779B9)) + h_i, (i%11)+5)`, then apply the
op stream to the keystream byte. Each op pair is `(opcode, B)`; `sel = key_i >>
((B & 3) * 8)` picks one byte of `key_i`. The operations are `0x41` (XOR with
`slot[B]`), `0x52` (add `B`), `0x63` (rotate left by `B & 7`), `0x74` (XOR with `sel`),
`0x85` (subtract `B`), `0x96` (add `sel`), and `0xA7` (XOR with `B*i`). The hash then
advances as `h_{i+1} = rol32(((i*0x45D9F3B + out_i) ^ key_i), 7) + ks_i - 0x5CBECE94`.

Running both the Python pipeline and the real binary with `(53, 167, 18, 233)` produces
the same 42-byte message.

## Flag capture

```bash
$ ./time_capsule 53 167 18 233 backup.tc
wctf{the_clock_keeps_its_secrets_dce922ea}
```
