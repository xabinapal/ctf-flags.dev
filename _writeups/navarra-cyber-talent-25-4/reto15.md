---
title: reto15
challenge_type: Crypto
difficulty: Hard
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is stored in a shared SMB directory. We also know that the hash information will probably not have the entire blob and that the last bytes will be missing.
attachments:
  - title: rockyou.txt.tar.gz
    url: /assets/files/navarra-cyber-talent-25-4/reto15/rockyou.txt.tar.gz
connections:
  - url: smb://nct25.thehackerconclave.es:26015
    description: |-
      Username: dummy
      Password: dummy
---

## Recon

This challenge is similar to [reto14](/competitions/navarra-cyber-talent-25-4/reto14-intended), but with a few interesting twists. Let's start by listing the available SMB shares using the provided `dummy` username and password:

```bash
$ smbclient -L nct25.thehackerconclave.es -p 26015 -N -U dummy%dummy
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
hashes          Disk
flag            Disk
IPC$            IPC       IPC Service (Samba 4.22.4-Debian-4.22.4+dfsg-1~deb13u1)
nobody          Disk      Home Directories
```

First, let's verify whether the `dummy` user has access to the flag share. While it is highly unlikely, it's always prudent to check and rule out the simple cases first:

```bash
$ smbclient //nct25.thehackerconclave.es/flag -p 26015 -N -U dummy%dummy -c 'ls'
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Next, just as we did in the previous challenge, our first step is to retrieve and download the list of user hashes:

```bash
$ smbclient //nct25.thehackerconclave.es/hashes -p 26015 -N -U dummy%dummy -c 'ls'
.              D       0  Thu Oct 16 11:32:11 2025
..             D       0  Thu Oct 16 11:32:11 2025
hashes.txt     N    1069  Thu Oct 16 11:32:11 2025

$ smbclient //nct25.thehackerconclave.es/hashes -p 26015 -N -U dummy%dummy -c 'get hashes.txt'
getting file \hashes.txt of size 1069 as hashes.txt (4.6 KiloBytes/sec) (average 4.6 KiloBytes/sec)

$ cat hashes.txt
pi::WORKGROUP:30877432d1026706:c5c4dcf2cb54f4433d0fb7a77092a4b1:d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78d
dummy::WORKGROUP:30877432d1026706:f13303432300def59140fea00aa1f6ed:d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78d
```

This time, we have two users, each with their respective **Net-NTLMv2** hashes. Unlike standard NTLM hashes that directly represent the user's password, these values are captured from actual authentication sessions. To proceed, let's recall the structure of a Net-NTLMv2 hash:

```
username :: domain : server_challenge : NTProofStr : NTLMv2Blob
```

The `username` and `domain` fields are self-explanatory. The `server_challenge` is a randomly generated nonce supplied by the server to verify the authenticity of the client. To authenticate, the client computes an **HMAC** over both the server challenge and a special data structure called the blob, using the user's password as the HMAC key.

The blob itself contains metadata, including a timestamp, a client-generated random value, and multiple attributes such as the client computer's name. We can observe that both blobs appear to be identical, which indicates they were generated on the same client at the same time. Additionally, according to the challenge description, some trailing bytes are missing from these blobs.

In summary, this computed `NTProofStr` is calculated as `HMAC-MD5(NTLMv2Hash, server_challenge + NTLMv2Blob)`. It enables the client to prove knowledge of their password without actually transmitting the password over the network.


```
pi proof: c5c4dcf2cb54f4433d0fb7a77092a4b1
dummy proof: f13303432300def59140fea00aa1f6ed
```

```
server challenge: 30877432d1026706
ntlm v2 blob: d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78d
```

## Exploitation

To proceed, we need to recover the missing trailing bytes from the blobs in order to brute-force the password for `pi`. Since we already know the password for `dummy`, we can use it to brute-force the missing bytes by computing the expected proof for all possible candidates until we find a match with the real proof.

In summary, our approach is as follows:
1. We generate the NTLMv2 hash for the user `dummy` using the password `dummy`.
2. We iteratively append possible values for the missing trailing bytes to the end of the blob. For each candidate, we compute the HMAC of the server challenge and the modified blob.
3. We continue this process until the computed proof matches the actual proof found in the hash. The corresponding candidate will reveal the correct missing bytes in the blob.

To compute the NTLMv2 hash for a user's password, we use `HMAC-MD5(NTHash, UPPER(username) + domain)`, where `NTHash` is the **MD4** hash of the user's password encoded in **UTF-16LE**. Admittedly, the process is somewhat convoluted.

To automate this process, we will use the following Python script. We will assume that at most 4 bytes are missing, as trying all possibilities for more bytes would require an unrealistic amount of time in a CTF challenge.

```python
import argparse, binascii, hmac, hashlib, time, sys
from Crypto.Hash import MD4

DOMAIN = "WORKGROUP"
USERNAME = "dummy"
PASSWORD = "dummy"

SERVER_CHALLENGE = binascii.unhexlify("30877432d1026706")
NT_PROOF = binascii.unhexlify("f13303432300def59140fea00aa1f6ed")
NT_BLOB = binascii.unhexlify("d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78d")

def compute_nt_hash(password: str) -> bytes:
    h = MD4.new()
    h.update(password.encode('utf-16le'))
    return h.digest()

def compute_ntlmv2_key(nt_hash: bytes, username: str, domain: str) -> bytes:
    identity = (username.upper() + domain).encode('utf-16le')
    return hmac.new(nt_hash, identity, hashlib.md5).digest()

nt_hash = compute_nt_hash(PASSWORD)
ntlmv2_key = compute_ntlmv2_key(nt_hash, USERNAME, DOMAIN)

found = False

for num_bytes in range(4):
    for i in range(256 ** num_bytes):
        suffix = i.to_bytes(num_bytes, 'big')
        candidate_proof = hmac.new(ntlmv2_key, SERVER_CHALLENGE + NT_BLOB + suffix, hashlib.md5).digest()

        if candidate_proof == NT_PROOF:
            print(f"Found missing blob bytes: {suffix.hex()}")
            found = True
            break

    if found:
        break
```

Let's execute the script:

```bash
$ python3 brute_force_blob.py
Found missing blob bytes: f0ca
```

Success! We have determined that two bytes were missing at the end of the blob: `f0ca`. Now that we have reconstructed the complete blob, we can use `hashcat` along with the `rockyou.txt` wordlist to attempt to crack the password. However, before running `hashcat`, we need to append the missing bytes to the end of each line in the hashes file:

```bash
$ sed -i -e 's/$/f0ca/' hashes.txt
```

```bash
$ hashcat -hh | grep NetNTLMv2
 5600 | NetNTLMv2      | Network Protocol
27100 | NetNTLMv2 (NT) | Network Protocol

$ hashcat -m 5600 -a 0 hashes.txt rockyou.txt
DUMMY::WORKGROUP:30877432d1026706:f13303432300def59140fea00aa1f6ed:d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78df0ca:dummy
PI::WORKGROUP:30877432d1026706:c5c4dcf2cb54f4433d0fb7a77092a4b1:d7e805da846a32c3bb81e3c29b62179273c8eb5bb682575ec87a171ac826a6fce48478dcb74f21345d2cce8038a39d5e0853964b50af03b971722f244f58d669cbee3772a077021721a278f64f7fd633dbdde131ca3766e4d58e72e310275dff6c15c0c8e9df469611a11f5125227c3712da86a78c49ea20e32684b27b95e909348334896a68f812d810a485ed03241b4d419b1b673bd4755d05ad7853c1f76eb97706ca828bca0385813dbad3c681d06bd2aa399dac946dc59c0996daeee6f529a279764017f2ed6cfc7403d75e173e4eaede5fe878f78e2978aa2447c462ddaed16dc0cf0b9cd7f78df0ca:cikuphempy
```

We have successfully recovered the password for the `pi` user: `cikuphempy`. Additionally, `hashcat` also identified the password for the `dummy` user, which we already knew. This serves as confirmation that our process worked correctly, since the known value was accurately found.

## Flag capture

Now we only need to download the flag with the cracked `pi` credentials:

```bash
$ smbclient //nct25.thehackerconclave.es/flag -p 26015 -N -U pi%cikuphempy -c 'ls'
.              D       0  Thu Oct 16 11:32:11 2025
..             D       0  Thu Oct 16 11:32:11 2025
flag.txt       N      43  Thu Oct 16 11:32:11 2025

$ smbclient //nct25.thehackerconclave.es/flag -p 26015 -N -U pi%cikuphempy -c 'get flag.txt'
getting file \flag.txt of size 43 as flag.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

$ cat flag.txt
conclave{350b540add646af98e30f7644f203e45}
```