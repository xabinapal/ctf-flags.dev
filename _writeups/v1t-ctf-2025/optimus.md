---
title: Optimus
challenge_type: Rev
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  uu ee ac ac
attachments:
  - title: optimus
    url: /assets/files/v1t-ctf-2025/optimus/optimus
---

## Recon

We are given an ELF binary which, when executed, prompts us to enter the flag:

```bash
$ file optimus
assets/optimus: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bef22db314be57287a814871ff6b1e52060d202a, for GNU/Linux 3.2.0, not stripped

$ ./optimus
Input flag: v1t{no_idea}
WRONG FLAG
```

Let's use Ghidra to decompile the binary and examine the contents of the main function:

![Ghidra Decompilation](/assets/files/v1t-ctf-2025/optimus/ghidra.png)

The first thing we notice is line 19, `local_28 = "0ov13tc{9zxpdr6na13m6a73534th5a}";`. This appears to be a mangled version of the actual flag.

## Exploitation

By taking a closer look at these lines and assigning meaningful variable names, we can clearly understand the functionality of this code:

```c
expected_flag = "0ov13tc{9zxpdr6na13m6a73534th5a}";
uStack_140 = 0x1011f0;
expected_flag_len_sz = strlen("0ov13tc{9zxpdr6na13m6a73534th5a}");
expected_flag_len = (int)expected_flag_len_sz;
prime_index_count = 0;
for (idx = 0; idx < expected_flag_len; idx = idx + 1) {
  uStack_140 = 0x10120d;
  char_is_prime = is_prime(idx);
  if (char_is_prime != '\0') {
    prime_index_count = prime_index_count + 1;
  }
}
```

The code operates on the characters located at prime-numbered indices (i.e., indices 2, 3, 5, etc.) within the string. From this, it appears that the intended solution involves extracting only the characters at these prime indices. Given the short length of the string, this extraction could be performed manually.

However, since we love to automate, here is a Python script that accomplishes the task:

```
from Crypto.Util.number import isPrime

mangled = "0ov13tc{9zxpdr6na13m6a73534th5a}"
flag = ''.join([c for i, c in enumerate(mangled) if isPrime(i)])
print('Flag:', flag)
```


## Flag capture

Now, let's execute the script to retrieve the flag:

```bash
$ python3 extract_flag.py
Flag: v1t{pr1m35}
```
