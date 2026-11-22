---
title: Spoofify
challenge_type: Web
difficulty: Easy
author: s_jams
writeup_author: "@xabito"
competition: wolvctf-2026
summary: |-
  Spoofify has Free and Premium tiers. Premium listeners get no ads, offline downloads, and an unlock code for this week's unreleased drop.

  You're on Free... or are you?

  Hint: The site has to remember your plan somehow. Check what your browser is sending back on every request.
connections:
  - url: https://spoofify-web.wolvctf-2026.kctf.cloud
---

Spoofify advertises Free and Premium listening plans, and this week's unreleased-track unlock code is reserved for Premium. There is no login flow, so the plan tier has to live somewhere the browser sends back on every request.

![Spoofify homepage showing the Free plan](/assets/files/wolvctf-2026/spoofify/home.png)

## Cookie tampering

The homepage's response reveals how the plan is stored: the very first visit sets a cookie.

```text
set-cookie: sid=free; Path=/
```

We open the browser's developer tools, go to the cookies panel, and find the `sid` cookie with the value `free`. There is no signature or encoding protecting it, so we edit the value to `premium`, reload the page, and the server now renders the Premium view.

![Changing sid from free to premium in the developer tools](/assets/files/wolvctf-2026/spoofify/devtools.png)

## Flag capture

The Premium page includes this week's unlock code, which is the flag:

```text
wctf{pr3m1um_pl4yl1st_n0_p4ym3nt_n33ded}
```
