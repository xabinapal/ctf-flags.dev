---
title: pyjail
challenge_type: Jail
author: "@GabeG888"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  Can you escape the jail?
connections:
  - url: pyjail.challs.infobahnc.tf:1337
attachments:
  - title: chall.py
    url: /assets/files/infobahn-ctf-2025/pyjail/chall.py
---

## Recon

This challenge presents a Python jail escape scenario. After examining the source code, we learn that the task is to craft a Python snippet of fewer than 15 characters that outputs more than 500 characters. Additionally, the snippet may only contain lowercase letters and spaces.

## Exploitation

Python has a built-in easter egg that prints **The Zen of Python** by Tim Peters. Running the command `import this` will trigger this output. This command adheres to the challenge's input restrictions and produces a large amount of text.

## Flag capture

By simply executing this command, we successfully obtain the flag:

```bash
$ nc pyjail.challs.infobahnc.tf 1337
Enter your solution: import this
b'infobahn{Y0u_3Sc4p3D_Th3_J@1lll_4359849084894}\n'
```

