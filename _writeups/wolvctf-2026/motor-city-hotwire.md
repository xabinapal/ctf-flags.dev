---
title: Motor City Hotwire
challenge_type: Rev
difficulty: Medium
author: ufosaysoof
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  We pulled this firmware off a control module during a teardown in the Motor City. Help us find its secret.

  The download is a stripped ARM Thumb ELF for offline analysis. There is no live CAN interface or network service; its request and response behavior can be studied by disassembly or emulation.
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/motor-city-hotwire/dis.tar.gz
---

## Recon

The handout is a tiny stripped, bare-metal ARM Thumb ELF (6,952 bytes, entry `0x8001`, `.text` at `0x8000`). Its `.rodata` strings `67 02`, `7F 27 35` and the hex table `0123456789ABCDEF` identify the protocol: UDS/ISO-14229 **SecurityAccess (service 0x27)**, a seed/key handshake that asks us for a key to prove we know the secret.

The request dispatch sits in `main`, right in the open:

```bash
$ llvm-objdump -d firmware.bin
```

```text
    8472: 7813         ldrb   r3, [r2]        ; first byte of the request
    8474: 2b27         cmp    r3, #0x27       ; must be service 0x27
    8476: d016         beq    0x84a6
    84a6: 7853         ldrb   r3, [r2, #0x1]  ; sub-function
    84a8: 2b01         cmp    r3, #0x1        ; 0x01 = request seed
    84aa: f000 80a2    beq.w  0x85f2
    84ae: 2b02         cmp    r3, #0x2        ; 0x02 = send key
    84b2: 2909         cmp    r1, #0x9        ; needs >= 10 parsed bytes
```

- **Sub 0x01** replies with a fixed seed, `67 01 1a 2b 3c 4d 5e 6f 77 88` on the wire (the seed itself is `1a2b3c4d5e6f7788`).
- **Sub 0x02** loads the 8 key bytes after `27 02` and runs the ARX check.

## Exploitation

The "check" is unusual: there is no comparison against an expected key. The
firmware instead mixes our key through a 16-round ARX function and XORs the result
with two embedded constants to build the flag message. Any key produces *some*
output; only the intended key yields readable ASCII. So the job is to invert the
transform: find the key whose output matches those constants.

### The round function

`F(x, i)` is small and table-driven. The tables are generated at runtime and dumped from
the emulator: `S_low` @ `0x9920`, `S2` @ `0x9960`, `T_A` @ `0x9A60`, `T_B` @ `0x9AA0`,
`T_C` @ `0x9AE0`, `T_D` @ `0x9B20`, `T_E` @ `0x9B60`. (`ror32`/`rol32` are 32-bit
rotations; `MASK = 0xffffffff`.)

```python
p = (S_low[i] * x) & 0xffffffff
m = S2[p & 0xff] | S2[(p >> 8) & 0xff] << 8 | S2[(p >> 16) & 0xff] << 16 | S2[(p >> 24) & 0xff] << 24
m = ror32(m, (32 - T_A[i]) % 32)
return ((m + T_B[i]) & 0xffffffff) ^ T_C[i]
```

The main loop keeps two words `state = BE32(k4..k7)` and `aux = BE32(k0..k3)`, and
for each of 16 rounds (`w = T_D[i]`, all odd; `t = T_E[i]`):

```text
    8518: f7ff fd7a     bl      0x8010          @ F(tmp, i)
    8522: ea84 0700     eor.w   r7, r4, r0      @ aux' = state ^ F(...)
    8536: fb03 f404     mul     r4, r3, r4      @ tmp = aux * w
    853a: 2a00         cmp     r2, #0x0        @ t == 0?
    8540: f7ff fd66     bl      0x8010          @ F(state, i)
```

- `t != 0`: `tmp = aux*w; aux' = state ^ F(tmp, i); state' = tmp`
- `t == 0`: `tmp = aux*w; aux' = state; state' = tmp ^ F(state, i)`

Finally the firmware computes `A = 0x5e6f7788 ^ state_final` and `B = 0x1a2b3c4d ^
aux_final`. These two words become the first eight bytes of a 20-byte message (together
with `state0`, `aux0`, and a counter) that the firmware hashes through its modified
SHA-256 and then XORs with a `.rodata` blob to build the flag. For that output to read
as the flag we need `A` and `B` to be zero, which pins the target final state to
`(0x5e6f7788, 0x1a2b3c4d)`. Inverting the 16 rounds from that target gives the key.

### Inverting the handshake

Every round is invertible, so a 2⁶⁴ key search is unnecessary. The `T_D` words are odd
(multiplication is invertible mod 2³²), `S2` is a permutation, and the add/rotate/xor
steps all invert. Running the 16 rounds backwards:

```python
def arx_bwd(state, aux):
    for i in range(15, -1, -1):
        w, t = TD[i], TE[i]
        winv = pow(w, -1, 1 << 32)
        if t == 0:
            s_old = aux
            a_old = ((state ^ F(s_old, i)) * winv) & 0xffffffff
        else:
            a_old = (state * winv) & 0xffffffff
            s_old = aux ^ F(state, i)
        state, aux = s_old, a_old
    return state, aux

s0, a0 = arx_bwd(0x5e6f7788, 0x1a2b3c4d)
key = struct.pack(">2I", a0, s0)   # key is aux0 || state0
print(key.hex())                   # 1b869bc58e96b90b
```

We confirmed the inverse by round-tripping random pairs through the forward and
backward passes before trusting the result.

### Emulating the flag

The tables `S_low`, `S2`, `T_A..T_E` are generated at runtime in `.bss` by the firmware's
PRNG, so to recover them we emulate the binary (Unicorn, mapped at `0x7000`, Thumb
entry `0x8000`). The rest of the flag is built by hashing the key and the flag-mask
bytes through a *modified* SHA-256 (same IV and K table, tweaked), XORing a `.rodata`
blob with those digests before replying after `67 02`. Rather than reimplement that
modified hash, we emulate the exchange itself: feeding `"2701"` to request the seed and
then `"2702" + key` on the two `read()` call sites.

## Flag capture

The emulated module authenticates and prints its secret:

```text
67 01 1A 2B 3C 4D 5E 6F 77 88
67 02
wctf{5M0OTH_0P3R4TORRRRR_6ef709d1ac21}
```
