---
title: reto23
challenge_type: Misc
difficulty: Beginner
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag will appear when connecting to the server but will be encoded in base64.
connections:
  - url: nct25.thehackerconclave.es:26023
---

## Recon

This is a simple network encoding challenge. According to the description, when you connect to the server, the flag will be sent in base64 encoding.

## Flag capture

Connect to the server to receive the flag, which will be displayed in base64 encoding:

```bash
$ nc nct25.thehackerconclave.es 26023
Y29uY2xhdmV7NGU5ZmZhZDQ0NWEzZDc1YmIwZjRjY2UyNDNlYWQ4YzJ9Cg==
```

Now, let's decode it using the `base64` utility:

```bash
$ echo Y29uY2xhdmV7NGU5ZmZhZDQ0NWEzZDc1YmIwZjRjY2UyNDNlYWQ4YzJ9Cg== | base64 -d
conclave{4e9ffad445a3d75bb0f4cce243ead8c2}
```