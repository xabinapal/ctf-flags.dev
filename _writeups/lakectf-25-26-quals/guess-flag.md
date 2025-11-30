---
title: Guess Flag
challenge_type: Crypto
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  You will never guess the flag
connections:
  - url: chall.polygl0ts.ch:6001
attachments:
  - title: Guessflag.py
    url: /assets/files/lakectf-25-26-quals/guess-flag/guessflag.py
---

By reviewing the source code, we found a flaw in how user input is checked. The code compares each character of the user's input with the flag, and stops right away if it detects a mismatch. The important detail is that the program checks only as many characters as the user provides.

```python
for char in user_input:
    if char != flag[index]:
        print("Wrong flag!")
        exit()
    index += 1

print("Correct flag!")
print("flag is : EPFL{" +user_input + "}")
```

When we submit only one character, the program checks just the first character of the flag. If it matches, the program says the flag is correct:

```text
$ nc chall.polygl0ts.ch 6001
Don't even think to guess the flag by brute force, it is 32 digits long!
1
Correct flag!
flag is : EPFL{1}

$ nc chall.polygl0ts.ch 6001
Don't even think to guess the flag by brute force, it is 32 digits long!
11
Wrong flag!
```

## Exploitation

The script below reconstructs the flag one digit at a time. For each position, it tries all possible digits and moves to the next character once it determines the correct one.
 
```python
import socket

HOST = "chall.polygl0ts.ch"
PORT = 6001

flag = ""
flag_length = 32

def recv_until(sock, delim=b"\n"):
    data = b""
    while not data.endswith(delim):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

for i in range(flag_length):
    for d in "0123456789":
        with socket.create_connection((HOST, PORT)) as s:
            recv_until(s, b"\n")
            s.sendall((flag + d + "\n").encode())
            resp = recv_until(s, b"\n").decode(errors="ignore")
        if "Correct" in resp:
            flag += d
            break

print(f"Flag: EPFL{{{flag}}}")
```

## Flag capture

Running the exploit will recover the flag one digit at a time. The entire process takes about two or three minutes.

```bash
$ python extract_flag.py
Flag: EPFL{15392948299929328383828399923990}
```