---
title: "Maize Poster"
challenge_type: Crypto
difficulty: easy
author: "s_jams"
writeup_author: "xabito"
competition: wolvctf-2026
summary: |-
  I just got a new poster for my dorm! Though whoever made this put a secret message into it. If you squint really closely at the pixels you might find it.
attachments:
  - title: dis.tar.gz
    url: /assets/files/wolvctf-2026/maize-poster/dis.tar.gz
---

## Recon

The supplied `dis.tar.gz` contains `poster.png`, a 960×740 RGB image. The description's advice to squint at the pixels suggests a small color-channel change rather than appended data or metadata.

After extracting the archive, we count the distinct RGB values:

```bash
$ tar -xzf dis.tar.gz
```

```python
from collections import Counter
from PIL import Image

image = Image.open("poster.png").convert("RGB")
pixels = image.load()
colors = Counter(
    pixels[x, y]
    for y in range(image.height)
    for x in range(image.width)
)

for color, count in colors.most_common():
    print(color, count)
```

There are only three colors, `(255, 203, 5)` and two shades of blue, `(0, 39, 76)` and `(0, 39, 77)`. The last color differs from normal blue by just one in the blue channel, making it effectively invisible to the eye.

Listing the coordinates of the anomalous pixels shows that all of them lie on row `y=0`, between `x=1` and `x=183`. Together with the ordinary blue pixels at the ends, this makes a 184-pixel sequence, or exactly 23 bytes when treated as bits.

We read the blue channel's least significant bit from left to right: 76 gives zero and 77 gives one. Packing every eight bits most-significant-bit first produces printable, flag-shaped text, but its letters are rotated.

The extracted text begins with `jpgs{`. We apply ROT13, which rotates each letter 13 positions, to obtain the expected competition prefix and a flag whose text names both stages: ROT13 and the blue channel.

## Flag capture

The complete extractor is:

```python
import codecs
from PIL import Image

image = Image.open("poster.png").convert("RGB")
pixels = image.load()

bits = [pixels[x, 0][2] & 1 for x in range(184)]
encoded = bytes(
    int("".join(map(str, bits[i:i + 8])), 2)
    for i in range(0, len(bits), 8)
).decode("ascii")

print("Extracted:", encoded)
print("Decoded:", codecs.decode(encoded, "rot_13"))
```

Running it prints the recovered flag:

```bash
$ python3 solve.py
Extracted: jpgs{e0g13_1a_gu3_oyh3}
Decoded: wctf{r0t13_1n_th3_blu3}
```
