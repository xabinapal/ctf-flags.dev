---
title: reto01
challenge_type: Web
difficulty: Easy
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: The flag is saved on this page.
connections:
  - url: http://nct25.thehackerconclave.es:26001
---

## Recon

The challenge description states that the flag is saved on the webpage. This suggests a simple web reconnaissance challenge.

## Flag capture

Upon examining the HTML source code, the flag was found directly in the page contents:

```bash
$ curl http://nct25.thehackerconclave.es:26001/
<div id="flagBox" class="flag-box">
  <span class="flag-scroll">
    conclave{38f4fb7e2f8944500449fa864e9fefda}
  </span>
</div>
```
