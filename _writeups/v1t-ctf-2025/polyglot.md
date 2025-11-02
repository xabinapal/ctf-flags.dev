---
title: Polyglot
challenge_type: Misc
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Look, read, and most importantly, **WATCH** the duck!
attachments:
  - title: polyglot.png
    url: /assets/files/v1t-ctf-2025/modulo-mystery/polyglot.png
    description: |-
      File can only open in Windows
---

## Recon

We are given an image file of a duck. It looks fine at first, but for a `1024x1024` pixel image, a file size of `6MB` seems excessive. Let's investigate to see if there is any hidden content.

```bash
$ binwalk --extract --carve polyglot.png
polyglot.png
------------------------------------------------------------------------------------
DECIMAL      HEXADECIMAL      DESCRIPTION
------------------------------------------------------------------------------------
25971        0x6573           PNG image, total size: 1416708 bytes
2225039      0x21F38F         PDF document, version 1.7
6158648      0x5DF938         ZIP archive, version: 2.0, file count: 1, total size: 142262 bytes
------------------------------------------------------------------------------------
[+] Extraction of png data at offset 0x6573 completed successfully
[+] Extraction of zip data at offset 0x5DF938 completed successfully
------------------------------------------------------------------------------------

Analyzed 1 file for 111 file signatures (251 magic patterns) in 80.0 milliseconds

$ tree extractions
extractions
├── polyglot.png_0_unknown.raw
├── polyglot.png_1442679_unknown.raw
├── polyglot.png_2225039_pdf.raw
├── polyglot.png_25971_png.raw
├── polyglot.png_6158648_zip.raw
└── polyglot.png.extracted
    ├── 5DF938
    │   └── angri.jpg
    └── 6573
        └── image.png
```

There are some interesting details here. Most importantly, the PNG image **does not** begin at offset zero. This suggests there is additional data at the beginning of the file that `binwalk` does not detect. Let's take a look at the hexdump to see if we can identify it:

```bash
$ hexdump -C polyglot.png | head -n 20
00000000  00 00 01 00 01 00 00 00  00 00 00 00 20 00 04 9e  |............ ...|
00000010  15 00 73 65 00 00 54 68  65 72 65 20 6e 6f 20 66  |..se..There no f|
00000020  6c 61 67 20 68 65 72 65  20 62 72 6f 74 68 65 72  |lag here brother|
00000030  3c 21 2d 2d 0a 25 50 44  46 2d 31 2e 37 0d 00 00  |<!--.%PDF-1.7...|
00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00  0a 31 20 30 20 6f 62 6a  |.........1 0 obj|
00000060  0a 3c 3c 2f 4c 65 6e 67  74 68 20 32 32 32 34 38  |.<</Length 22248|
00000070  39 37 3e 3e 0a 73 74 72  65 61 6d 0a 00 00 00 00  |97>>.stream.....|
00000080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000000f0  69 73 6f 6d 69 73 6f 32  61 76 63 31 6d 70 34 31  |isomiso2avc1mp41|
00000100  00 00 00 20 66 74 79 70  69 73 6f 6d 00 00 02 00  |... ftypisom....|
00000110  69 73 6f 6d 69 73 6f 32  61 76 63 31 6d 70 34 31  |isomiso2avc1mp41|
00000120  00 00 00 08 66 72 65 65  00 00 62 d3 6d 6f 6f 76  |....free..b.moov|
00000130  00 00 00 6c 6d 76 68 64  00 00 00 00 00 00 00 00  |...lmvhd........|
00000140  00 00 00 00 00 00 03 e8  00 00 54 d6 00 01 00 00  |..........T.....|
00000150  01 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  |................|
00000160  00 00 00 00 00 00 00 00  00 00 00 00 00 01 00 00  |................|
00000170  00 00 00 00 00 00 00 00  00 00 00 00 40 00 00 00  |............@...|
00000180  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

Besides the message `There no flag here brother`, we also see the string `isomiso2avc1mp41`, which combines several MP4 format identifiers. This could indicate that the file contains a video. Let's check to confirm.

```bash
$ ffprobe polyglot.png
ffprobe version 7.1.1 Copyright (c) 2007-2025 the FFmpeg developers
Input #0, mov,mp4,m4a,3gp,3g2,mj2, from 'polyglot.png':
  Metadata:
    major_brand     : isom
    minor_version   : 512
    compatible_brands: isomiso2avc1mp41
    encoder         : Lavf61.7.100
    comment         : Create videos with https://clipchamp.com/en/video-editor - free online video editor, video compressor, video converter.
  Duration: 00:00:21.72, start: 0.000000, bitrate: 2321 kb/s
  Stream #0:0[0x1](und): Video: h264 (High) (avc1 / 0x31637661), yuv420p(progressive), 540x540 [SAR 1:1 DAR 1:1], 161 kb/s, 30 fps, 30 tbr, 15360 tbn (default)
      Metadata:
        handler_name    : VideoHandler
        vendor_id       : [0][0][0][0]
        encoder         : Lavc61.19.101 libx264
  Stream #0:1[0x2](und): Audio: aac (LC) (mp4a / 0x6134706D), 48000 Hz, stereo, fltp, 126 kb/s (default)
      Metadata:
        handler_name    : SoundHandler
        vendor_id       : [0][0][0][0]
```

It really is a video! Let's extract it with `ffmpeg` and open it with VLC:

```bash
$ ffmpeg -i polyglot.png -c copy -an polyglot.mp4
ffmpeg version 7.1.1 Copyright (c) 2000-2025 the FFmpeg developers

Stream mapping:
  Stream #0:0 -> #0:0 (copy)
Output #0, mp4, to 'polyglot.mp4':
  Metadata:
    major_brand     : isom
    minor_version   : 512
    compatible_brands: isomiso2avc1mp41
    comment         : Create videos with https://clipchamp.com/en/video-editor - free online video editor, video compressor, video converter.
    encoder         : Lavf61.7.100
  Stream #0:0(und): Video: h264 (High) (avc1 / 0x31637661), yuv420p(progressive), 540x540 [SAR 1:1 DAR 1:1], q=2-31, 161 kb/s, 30 fps, 30 tbr, 15360 tbn (default)
      Metadata:
        handler_name    : VideoHandler
        vendor_id       : [0][0][0][0]
        encoder         : Lavc61.19.101 libx264
[out#0/mp4 @ 0x6000015c4000] video:428KiB audio:0KiB subtitle:0KiB other streams:0KiB global headers:0KiB muxing overhead: 1.981245%
frame=  651 fps=0.0 q=-1.0 Lsize=     437KiB time=00:00:21.63 bitrate= 165.4kbits/s speed=1.27e+04x

$ vlc polyglot.mp4
```

A few seconds into the video, a password appears:

![Password embedded in video](/assets/files/v1t-ctf-2025/polyglot/polyglot.mp4.png)

Now, let's look at the other files that were extracted with `binwalk`, beginning with the PDF:

![PDF contents](/assets/files/v1t-ctf-2025/polyglot/polyglot.pdf.png)

The PDF contains a short poem that suggests trying `steghide`. Since we already have a password, `HideTheDuck123@`, the obvious next step is to check the `angri.jpg` image we extracted earlier for any hidden content.

```bash
$ steghide info extractions/polyglot.png.extracted/5DF938/angri.jpg -p 'HideTheDuck123@'
"angri.jpg":
  format: jpeg
  capacity: 7.9 KB
  embedded file "flag.txt":
    size: 28.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

## Flag capture

To retrieve the flag, we simply extract the `flag.txt` file using `steghide` and the provided password.

```bash
$ steghide extract -sf extractions/polyglot.png.extracted/5DF938/angri.jpg -p 'HideTheDuck123@'
wrote extracted data to "flag.txt".

$ cat flag.txt
v1t{duck_l0v3_w4tch1ng_p2r3}
```

{% include writeups/img-50.html %}
