---
title: Blank
challenge_type: Stego
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  This image is blank is it?
attachments:
  - title: white.png
    url: /assets/files/v1t-ctf-2025/blank/white.png
---

## Recon

Opening the `white.png` image reveals what appears to be a completely white image, just as the challenge suggests. However, this does not necessarily mean that all the pixels are identical: there may be subtle differences that are invisible to the human eye.

## Flag capture

By extracting all bitplanes from the image, we can reveal the flag hidden within one of them. Tools like [StegOnline](https://georgeom.net/StegOnline) make this process straightforward and user-friendly.

![Image bitplane](/assets/files/v1t-ctf-2025/blank/bitplane.png)

```
Flag: v1t{wh1t3_3y3s}
```