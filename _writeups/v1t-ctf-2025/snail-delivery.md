---
title: Snail Delivery
challenge_type: Rev
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Enter your flag and the snail will deliver it to headquarters for verification. But be careful - it moves slowly!
attachments:
  - title: snail
    url: /assets/files/v1t-ctf-2025/snail-delivery/snail
---

## Recon

We receive a binary that, when run, prompts for a flag and then plays a painfully slow ASCII animation. With each step, the animation pauses for a longer time before continuing.

```bash
$ ./snail
Enter the flag: test
The snail is sending the flag to headquarters to check...
_____@>
```

When examining the binary in Ghidra and looking at the `main` function, there is something interesting located right in the center of the snail animation loop.

![Slow loop](/assets/files/v1t-ctf-2025/snail-delivery/ghidra_1.png)

Inside the animation loop, there is a variable called `local_c` that doubles with each iteration: 2, 4, 8, 16, and so on. By the time the loop finishes, its value reaches `2^16` (or `0x010000`). The program then splits this value into three separate bytes and puts them into the same large buffer that stores the input.

Immediately afterward, the program allocates memory and makes a copy of our input, but each character is XORed with one of those three bytes in a repeating three-byte cycle.

![Input copy](/assets/files/v1t-ctf-2025/snail-delivery/ghidra_2.png)

Next, the program sets up a large array containing a 6-byte key and a 38-byte data block. It then XORs the data block with the key and checks if the result matches our input.

![XOR logic](/assets/files/v1t-ctf-2025/snail-delivery/ghidra_3.png)

## Exploitation

By reversing the XOR process, we can figure out what our input needs to be:

```python
expected = [
    0x65, 0x74, 0x0c, 0xd1, 0xbe, 0x81,
    0x27, 0x2c, 0x14, 0xf5, 0xa9, 0xdc,
    0x7f, 0x74, 0x0e, 0x99, 0xbf, 0x96,
    0x4c, 0x36, 0x14, 0x9a, 0xba, 0xb0,
    0x27, 0x23, 0x27, 0x99, 0xfb, 0xdb,
    0x21, 0x75, 0x4f, 0x9c, 0xff, 0x8e,
    0x71, 0x38
]

key = [0x12, 0x45, 0x78, 0xab, 0xcd, 0xef]

flag = ''.join([chr(v ^ key[i % 6]) for i, v in enumerate(expected)])
print(flag)
```

```bash
$ python3 extract_flag.py
w1tzsn5il^d3m1v2ry^sl1w_5f_26430772ac}
```

This looks like it could be the flag, but it is clear that something is not correct.

## Flag capture

If we recall our earlier analysis, what we actually checked was our input, not the flag itself. When we enter this exact input, the program outputs the input previously XORed with the 3-byte cycle, rather than the original one.

We could let the program run and wait a very long time to get the flag, or we can simply apply that second XOR to recover it instantly.

```python
expected = [
    0x65, 0x74, 0x0c, 0xd1, 0xbe, 0x81,
    0x27, 0x2c, 0x14, 0xf5, 0xa9, 0xdc,
    0x7f, 0x74, 0x0e, 0x99, 0xbf, 0x96,
    0x4c, 0x36, 0x14, 0x9a, 0xba, 0xb0,
    0x27, 0x23, 0x27, 0x99, 0xfb, 0xdb,
    0x21, 0x75, 0x4f, 0x9c, 0xff, 0x8e,
    0x71, 0x38
]

key = [0x12, 0x45, 0x78, 0xab, 0xcd, 0xef]
key2 = [0x01, 0x00, 0x00]

flag = ''.join([chr(v ^ key[i % 6] ^ key2[i % 3]) for i, v in enumerate(expected)])
print(flag)
```

```bash
$ python3 extract_flag.py
v1t{sn4il_d3l1v3ry_sl0w_4f_36420762ab}
```