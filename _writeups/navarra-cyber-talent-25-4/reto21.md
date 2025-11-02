---
title: reto21
challenge_type: Misc
difficulty: Beginner
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag will appear when connecting to the server.
connections:
  - url: nct25.thehackerconclave.es:26021
---

## Recon

This is a very straightforward challenge and serves as an excellent introduction for beginners to learn how CTF challenges function.

## Flag capture

Connect to the server to retrieve the flag:

```bash
$ nc nct25.thehackerconclave.es 26021
conclave{26768bd5da3132de25ac131744825dcc}
```
