---
title: RotBrain
challenge_type: Misc
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Ts fr lwk pmo gng
attachments:
  - title: gnp.egami
    url: /assets/files/v1t_ctf_2025/rotbrain/gnp.egami
---

## Recon

The file provided, `gnp.egami`, is just `image.png` written backwards. If you look at a hexdump of this file, you will see that the usual PNG file header is at the end, and its bytes are in reverse order.

```bash
$ hexdump -C gnp.egami | tail -n 5
000016e0  67 04 00 00 00 c3 a9 1c  c3 8e c2 ae 00 42 47 52  |g............BGR|
000016f0  73 01 00 00 00 5b 26 0f  64 00 00 00 06 08 27 00  |s....[&.d.....'.|
00001700  00 00 c3 9c 00 00 00 52  44 48 49 0d 00 00 00 0a  |.......RDHI.....|
00001710  1a 0a 0d 47 4e 50 c2 89                           |...GNP..|
```

## Exploitation

First, let's reverse the contents of the file.

```python
data = b''
with open('gnp.egami', 'rb') as f:
    while item := f.read(1):
        data = item + data

with open('image.png', 'wb') as f:
    f.write(data)
```

```bash
$ python extract_flag.png

$ hexdump -C image.png | head -n 5
00000000  89 c2 50 4e 47 0d 0a 1a  0a 00 00 00 0d 49 48 44  |..PNG........IHD|
00000010  52 00 00 00 9c c3 00 00  00 27 08 06 00 00 00 64  |R........'.....d|
00000020  0f 26 5b 00 00 00 01 73  52 47 42 00 ae c2 8e c3  |.&[....sRGB.....|
00000030  1c a9 c3 00 00 00 04 67  41 4d 41 00 00 b1 c2 8f  |.......gAMA.....|
00000040  c2 0b bc c3 61 05 00 00  00 09 70 48 59 73 00 00  |....a.....pHYs..|
```

But something is off. The PNG signature, which should be `89 50 4E 47 0D 0A 1A 0A`, contains some unexpected extra bytes. It turns out that whenever there is a byte in the range `0x80` to `0xbf`, an extra `0xc2` or `0xc3` gets added. After a bit of digging, we discovered these extra bytes are part of UTF-8 encoding.

This means the file was accidentally treated as text rather than binary while being reversed. The easiest approach is to open the file in text mode as UTF-8, then reverse its contents and write the result back as binary:

```python
data = b''
with open('gnp.egami', 'r', encoding='utf-8', newline='') as f:
    while item := f.read(1):
        data = ord(item).to_bytes(1, byteorder='big') + data

with open('image.png', 'wb') as f:
    f.write(data)
```

**Note:** Setting `newline=''` is necessary to prevent Python from converting Windows line endings (`\r\n`, which is `0x0d0a`) into Unix line endings (`\n`, which is `0x0a`).

## Flag capture

Run the script to generate the correct image file. Once the image is created, open it and you will see the flag inside.

```bash
$ python3 extract_flag.py
```

![Flag](/assets/files/v1t-ctf-2025/rotbrain/image.png)

```
Flag: v1t{r3v_1mg_4ge}
```