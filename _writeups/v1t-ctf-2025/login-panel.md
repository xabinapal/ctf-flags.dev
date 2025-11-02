---
title: Login Panel
challenge_type: Web
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  login
connections:
  - url: https://tommytheduck.github.io/login/
---

## Recon

When we visit the given webpage, we are prompted for a username and password. Looking at the source code reveals how the client-side authentication works:

```javascript
async function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

async function sha256Hex(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(digest);
}

function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

(async () => {
  const ajnsdjkamsf = 'ba773c013e5c07e8831bdb2f1cee06f349ea1da550ef4766f5e7f7ec842d836e'; // replace
  const lanfffiewnu = '48d2a5bbcf422ccd1b69e2a82fb90bafb52384953e77e304bef856084be052b6'; // replace

  const username = prompt('Enter username:');
  const password = prompt('Enter password:');

  if (username === null || password === null) {
    alert('Missing username or password');
    return;
  }

  const uHash = await sha256Hex(username);
  const pHash = await sha256Hex(password);

  if (timingSafeEqualHex(uHash, ajnsdjkamsf) && timingSafeEqualHex(pHash, lanfffiewnu)) {
    alert(username+ '{'+password+'}');
  } else {
    alert('Invalid credentials');
  }
})();
```

This is a "secure" authentication system that uses timing-safe comparisons and other security features, but everything is done on the client side. All we need to do is figure out the username and password from their hashes.

Looking at the code at the end, we see that the flag is displayed by joining the username and password like this: `alert(username+ '{'+password+'}')`. It looks like the username should be `v1t`, so let’s check that:

```bash
$ echo -n "v1t" | sha256sum
ba773c013e5c07e8831bdb2f1cee06f349ea1da550ef4766f5e7f7ec842d836e  -
```

That confirms our guess. We have solved one hash, and there is one more to go.

## Flag capture

Now let us try the second hash using CrackStation.

![Crackstation](/assets/files/v1t-ctf-2025/login-panel/crackstation.png)

Honestly, we thought the password would be more difficult to guess.

```
Flag: v1t{p4ssw0rd}
```