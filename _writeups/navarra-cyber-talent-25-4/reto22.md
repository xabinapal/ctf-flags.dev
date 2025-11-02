---
title: reto22
challenge_type: Misc
difficulty: Beginner
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is in a file called `/flag/flag.txt`, which is located on a server that you can access.
connections:
  - url: ssh://nct25.thehackerconclave.es:26022
    description: |-
      Username: user1
      Password: user1
---

## Recon

After connecting to the server, we notice that the flag file has overly permissive permissions:

```bash
$ ssh user1@nct25.thehackerconclave.es -p 26022
The authenticity of host '[nct25.thehackerconclave.es]:26022 ([130.206.158.156]:26022)' can't be established.
ED25519 key fingerprint is: SHA256:O5W5Bkkbgjuh0SelpGZ9wWVmFWaNbW74f9+lU5WX6hI
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
user1@nct25.thehackerconclave.es's password: user1
user1@34aa097f1ea2:~$ ls -al /flag/flag.txt
-rw-r--r-- 1 1001 1001 43 Oct 16 09:22 /flag/flag.txt
```

## Flag capture

Since we have read permissions on the flag file, we can simply read its contents directly:

```bash
$ cat /flag/flag.txt
conclave{9bd3698ce32f0dda77b913ab92e3da72}
```
