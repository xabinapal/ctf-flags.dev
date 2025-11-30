---
title: Wordler
challenge_type: Misc
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  yo dawg i heard you like words in your wordle so i put words in your words so words
connections:
  - url: chall.polygl0ts.ch:6052
attachments:
  - title: word_list.txt
    url: /assets/files/lakectf-25-26-quals/wordler/word_list.txt
---

## Recon

The challenge is a Wordle-style game where we must solve for multiple words at the same time, not just one. To win the flag, we need to solve the puzzle within six attempts.

![Challenge example](/assets/files/lakectf-25-26-quals/wordler/challenge.png)

## Exploitation

The following script connects to the server, parses the word structure, and manages internal state to track revealed, present, and absent letters. On the first attempt, it guesses the full alphabet to maximize information. The second guess eliminates absent letters and fills unused spots with other letters to expose possible repeats.

For all following guesses, it finds words of the correct lengths, builds candidate sets that satisfy the feedback constraints so far, and tries combinations that are consistent with all previous clues, repeating this process up to six times or until the flag is obtained.

```python
import re

from itertools import product
from pwn import remote, log

HOST = "chall.polygl0ts.ch"
PORT = 6052

WORDLIST_FILE = "word_list.txt"

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MAX_ATTEMPTS = 6

COLOR_GREEN = "92"
COLOR_YELLOW = "93"
COLOR_GREY = "90"

r = remote(HOST, PORT)
response = r.recvuntil(b"Your guess:").decode()

match = re.search(r"Structure:\s*([^\n]+)", response)
structure_str = match.group(1).strip()
word_lengths = [len(word) for word in structure_str.split('_')]
total_length = sum(word_lengths)

guesses = []
patterns = []
green_letters = [None] * total_length
present_letters = set()
absent_letters = set()
used = set()
words_by_length = None

for attempt in range(MAX_ATTEMPTS):
    if attempt == 0:
        plain_guess = (ALPHABET * ((total_length + 25) // 26))[:total_length]
    elif attempt == 1:
        available_letters = sorted((set(ALPHABET) - absent_letters) | present_letters) or list(ALPHABET)
        plain_guess = "".join(
            g if g else available_letters[(i + attempt) % len(available_letters)]
            for i, g in enumerate(green_letters)
        )
    else:
        if words_by_length is None:
            words_by_length = {}
            with open(WORDLIST_FILE) as f:
                for line in f:
                    word = line.strip().upper()
                    if not word or "_" in word:
                        continue

                    words_by_length.setdefault(len(word), []).append(word)

        forbidden = [set() for _ in range(total_length)]

        # process feedback from prior guesses
        for g, p in zip(guesses, patterns):
            for i, (c, color) in enumerate(zip(g, p)):
                if color == "g":
                    green_letters[i] = c
                elif color == "y":
                    forbidden[i].add(c)

            for c in set(g):
                indices = [idx for idx, x in enumerate(g) if x == c]
                st = [p[idx] for idx in indices]
                if any(x in "gy" for x in st):
                    present_letters.add(c)
                    absent_letters.discard(c)
                elif c not in present_letters:
                    absent_letters.add(c)

        # build candidate word slots for each position
        slots = []
        ok = True
        idx_offs = [sum(word_lengths[:i]) for i in range(len(word_lengths))]

        for offset, length in zip(idx_offs, word_lengths):
            filtered = []
            for w in words_by_length[length]:
                matched = True
                for j in range(length):
                    in_green = green_letters[offset + j]
                    if (in_green is not None and in_green != w[j]) or (w[j] in forbidden[offset + j]):
                        matched = False
                        break

                if matched:
                    filtered.append(w)

            if not filtered:
                ok = False
                break

            slots.append(filtered)

        if not ok:
            available_letters = sorted(
                (set(ALPHABET) - absent_letters) | present_letters
            ) or list(ALPHABET)
            plain_guess = "".join(
                g if g else available_letters[(i + attempt) % len(available_letters)]
                for i, g in enumerate(green_letters)
            )
        else:
            found = None
            for candidate in product(*slots):
                combined = ''.join(candidate)
                used_before = combined in used

                consistent = True
                for g, p in zip(guesses, patterns):
                    secret, guess = combined, g
                    res = ["b"] * len(secret)
                    remaining = {}

                    for i, char in enumerate(secret):
                        if char == guess[i]:
                            res[i] = "g"
                        else:
                            remaining[char] = remaining.get(char, 0) + 1

                    for i in range(len(secret)):
                        if res[i] == "g":
                            continue
                        if remaining.get(guess[i], 0):
                            res[i] = "y"
                            remaining[guess[i]] -= 1

                    if "".join(res) != p:
                        consistent = False
                        break

                if not consistent:
                    continue

                if found is None or not used_before:
                    found = combined
                    if not used_before:
                        break

            if found is None:
                available_letters = sorted(
                    (set(ALPHABET) - absent_letters) | present_letters
                ) or list(ALPHABET)
                plain_guess = "".join(
                    g if g else available_letters[(i + attempt) % len(available_letters)]
                    for i, g in enumerate(green_letters)
                )
            else:
                plain_guess = found

    i = 0
    parts = []
    for length in word_lengths:
        parts.append(plain_guess[i:i+length])
        i += length
    server_guess = '_'.join(parts)

    log.info(f"guess {attempt+1}/{MAX_ATTEMPTS}: {server_guess}")
    r.sendline(server_guess.encode())

    line = r.recvline(timeout=5).decode()
    if not line:
        break

    color = "b"
    pattern = []
    idx = 0
    ii = 0
    while idx < len(plain_guess) and ii < len(line):
        if line[ii] == "\x1b" and line[ii+1] == "[":
            j = ii+2
            while line[j] != "m":
                j += 1
            codes = set(line[ii+2:j].split(";"))
            if COLOR_GREEN in codes:
                color = "g"
            elif COLOR_YELLOW in codes:
                color = "y"
            elif COLOR_GREY in codes:
                color = "b"
            ii = j+1
            continue
        if line[ii].isalpha():
            pattern.append(color)
            idx += 1
        ii += 1
    if len(pattern) < len(plain_guess):
        pattern += ["b"] * (len(plain_guess) - len(pattern))
    pattern = "".join(pattern[:len(plain_guess)])

    log.success(f"pattern: {pattern}")
    guesses.append(plain_guess)
    patterns.append(pattern)

    if "_" not in server_guess:
        used.add(plain_guess)

    for c in set(plain_guess):
        indices = [i for i, x in enumerate(plain_guess) if x == c]
        statuses = [pattern[i] for i in indices]
        if any(s in "gy" for s in statuses):
            present_letters.add(c)
            absent_letters.discard(c)
        elif c not in present_letters:
            absent_letters.add(c)

    for i, (ch, col) in enumerate(zip(plain_guess, pattern)):
        if col == "g":
            green_letters[i] = ch

    if attempt < MAX_ATTEMPTS - 1:
        try:
            r.recvuntil(b"Your guess:", timeout=5)
        except Exception:
            break

log.info(r.recvall(timeout=3).decode())
r.close()
```

**Note:** Apologies for the complex code :P

## Flag capture

Just run the script to see the flag:

```bash
$ python extract_flag.py
[+] Opening connection to chall.polygl0ts.ch on port 6052: Done
[*] guess 1/6: ABCDEFGHIJKL_MNOPQRSTUVW_XYZA
[+] pattern: gbyyybyyybyygyybbyybbbybbby
[*] guess 2/6: ADEGHIKLMNOR_MWACDEGHIKL_MNOR
[+] pattern: gyyyybyybyyygyygyybygbbbybb
[*] guess 3/6: ACKNOWLEDGED_MERCHANDISE_WHEN
[+] pattern: gggggggggggggggggggggggbybb
[*] guess 4/6: ACKNOWLEDGED_MERCHANDISE_CASH
[+] pattern: gggggggggggggggggggggggbggg
[*] guess 5/6: ACKNOWLEDGED_MERCHANDISE_DASH
[+] pattern: ggggggggggggggggggggggggggg
[+] Receiving all data: Done (53B)
[*] Closed connection to chall.polygl0ts.ch port 6052
[*] You win! Heres the flag: EPFL{5CR1P71NG_15_CH34T1NG}
```