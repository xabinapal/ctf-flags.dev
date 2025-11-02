---
title: Tiny Flag
challenge_type: Web
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Do you see the tiny flag :>
connections:
  - url: https://tommytheduck.github.io/tiny_flag/
---

## Recon

We are presented with a simple website that appears purely decorative, containing nothing of immediate relevance.

![Landing page](/assets/files/v1t-ctf-2025/tiny-flag/web.png)

## Flag capture

What is the smallest element on a webpage that can conceal a flag in plain sight? It's larger than a single pixel, but only just: the favicon!

![Browser tab](/assets/files/v1t-ctf-2025/tiny-flag/tag.png)

By opening and zooming in on [https://tommytheduck.github.io/tiny_flag/favicon.ico](https://tommytheduck.github.io/tiny_flag/favicon.ico), you can clearly see the flag.

![Flag](/assets/files/v1t-ctf-2025/tiny-flag/flag.png)

```
Flag: V1T{T1NY_ICO}
```