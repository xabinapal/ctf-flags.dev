---
layout: post
title: "Echo Capture - Warmup Reverse"
summary: Dissecting a signal repeater binary to recover the encoded flag.
competition: signalfest-2024
category: reverse engineering
attachments:
  - title: Challenge artifacts
    url: /assets/files/signalfest-2024/echo-capture/echo-capture-artifacts.txt
    description: Placeholder bundle of binaries and scripts shipped with the task.
---

## Recon

The challenge ships a stripped 64-bit ELF that loops on a serial handler. Running `strings` on the binary
showed a repeating `echo::capture` marker that hinted at a custom XOR stream.

```bash
$ checksec echo-capture
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH  FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH  echo-capture
```

## Approach

1. Attach `gdb` and capture the keystream generated during the prompt handshake.
2. Dump the bytes surrounding the `echo::capture` marker to derive the XOR pad.
3. Write a quick Python script to replay the input and decode the response.

```python
from pwn import *

target = process(["./echo-capture"])
target.sendline(b"AAAA\n")
response = target.recvuntil(b"}\n")
print(response)
```

## Outcome

The decoded stream yielded `flag{link_the_echoes}` confirming the approach. Future hard mode variants likely
randomize the pad per session, so the next step is to hook into the PRNG seeding.
