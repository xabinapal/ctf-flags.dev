---
title: reto16
challenge_type: Crypto
difficulty: Hard
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  We have a server that uses SSL to accept connections and give the flag. We know it uses the same RSA keys for everything.
connections:
  - url: https://nct25.thehackerconclave.es:26016
---

## Recon

First, I connected to the TLS service in order to extract the server certificate:

```bash
$ openssl s_client -connect nct25.thehackerconclave.es:26016 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM
-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUX9NuHoHUsdv3mR4BCGqrMbJu2IEwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHY2xpZW50MTAeFw0yNTEwMTYwOTMyMjdaFw0yNjEwMTYw
OTMyMjdaMBIxEDAOBgNVBAMMB2NsaWVudDEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCntC3oLY193K9u3OZU+op7pam8K1tfle54yj7zeG4iHq2d+MsF
Xy14+ICrd7cFT5bYUln4jJOzk36cIKJ/ig/LjXGITTafAR8QB7cL6uJhvjstvpIV
4FxU03fgoNt2sgHBuflvw75qCxUuTqN1U+rCU8Pe5+MmSoMipRYtM8S3tJIKItzU
eO8VJFNMAI8Nz2+YHs/gBg3KVaO4EpDbVGzjja3H2FGqOiBtPxYIUkApqhLuioqT
KSE1xOu2FbRChRSpRWdWYfcsDXyg807aiOuSXp7IwZSLzqsBVr49gPu2lJG1beQy
qvhEzfJ/deX0uN6yNlMxwfFKbvKbbpFRos+NAgMBAAGjUzBRMB0GA1UdDgQWBBRP
zhxZXSoWJlXoCLKOebfQZc5qGjAfBgNVHSMEGDAWgBRPzhxZXSoWJlXoCLKOebfQ
Zc5qGjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBY17afJvUv
rkpDXwjZLWKv+wDS9E2GbOQe9Rt/C9DrnT5+KUuRI982rd6/mhXGK1jNISkYG7Ae
KgXFlEmXOH2ydbZDu8LAbl4YxckfKD/0mKOiNiFM9C89UluKpPhZFh0SosrKRHka
+FizE+NMyIduEz5gzAQXDWR7Pq2EVqQ/xpohvlfraU3vxHzUKnI5cgvy0UraXKKj
Ecye+YwJ3R+g6wEZS8+WcnoshAyhN3QldQWkPihfsjZ5xKEnfAF4vt2J1GWz7336
lrqKtIlAMQtuYOHx/IT0nom7v0zU+Dx8WYklEsH/zYE4UdMnUqM58eX1GuLdyo88
WJcznJ3sF60/
-----END CERTIFICATE-----
```

Next, I proceeded to extract the public key from the certificate:

```bash
$ openssl x509 -in server_cert.pem -pubkey -noout
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7Qt6C2NfdyvbtzmVPqK
e6WpvCtbX5XueMo+83huIh6tnfjLBV8tePiAq3e3BU+W2FJZ+IyTs5N+nCCif4oP
y41xiE02nwEfEAe3C+riYb47Lb6SFeBcVNN34KDbdrIBwbn5b8O+agsVLk6jdVPq
wlPD3ufjJkqDIqUWLTPEt7SSCiLc1HjvFSRTTACPDc9vmB7P4AYNylWjuBKQ21Rs
442tx9hRqjogbT8WCFJAKaoS7oqKkykhNcTrthW0QoUUqUVnVmH3LA18oPNO2ojr
kl6eyMGUi86rAVa+PYD7tpSRtW3kMqr4RM3yf3Xl9LjesjZTMcHxSm7ym26RUaLP
jQIDAQAB
-----END PUBLIC KEY-----
```

Finally, I retrieved the RSA parameters from the public key:

```python
from Crypto.PublicKey import RSA

with open('server_pubkey.pem', 'r') as f:
    pubkey = RSA.import_key(f.read())

n = pubkey.n
e = pubkey.e
```

```
n = 21170646665473283643070518643245701243971154511529593129095440283227062961754506752201709456046151687162789887834488881078747606506989333842966859356205366712724880472892733603529237275256627708326362963232193449443711537929879739342291521194002980771831124971559904494339482999421970083806877416490259494380064373484338560366898675253910868222021553207092306453958304152070281712275544806413496390499418712341721906036544838966891988202845897643333946486975274393480852225836280955853731600510282267854088278656127862879618427494964781108694629371610601288912161013552915324660049109065011122181215887179578886770573
e = 65537
```

## Exploitation

I initially attempted to factor `n` using [FactorDB](https://factordb.com), but no factors were found.

Given that the modulus is 2048 bits, I suspected that the prime factors `p` and `q` might be very close in value, which would make Fermat's factorization algorithm particularly effective. This scenario is a well-known RSA vulnerability that arises when `p` and `q` are generated too closely together.

If `N = p * q` and `p` is approximately equal to `q`, then `N` is close to a perfect square, meaning `N ≈ a²` where `a ≈ √N`. We can rewrite `N` in the form `N = a² - b² = (a - b)(a + b)`, so that `p = a - b` and `q = a + b`. The algorithm proceeds as follows:
1. Begin by setting `a = ⌈√N⌉`.
2. Calculate `b² = a² - N`.
3. If `b²` is a perfect square, then set `p = a - b` and `q = a + b`; these are the factors.
4. If not, increment `a` by 1 and repeat the process.

To implement this attack, I created a straightforward Python script:

```python
import math

n = 21170646665473283643070518643245701243971154511529593129095440283227062961754506752201709456046151687162789887834488881078747606506989333842966859356205366712724880472892733603529237275256627708326362963232193449443711537929879739342291521194002980771831124971559904494339482999421970083806877416490259494380064373484338560366898675253910868222021553207092306453958304152070281712275544806413496390499418712341721906036544838966891988202845897643333946486975274393480852225836280955853731600510282267854088278656127862879618427494964781108694629371610601288912161013552915324660049109065011122181215887179578886770573

a = math.isqrt(n) + 1
b2 = a * a - n

for i in range(100000):
    b = math.isqrt(b2)
    if b * b == b2:
        p = a - b
        q = a + b
        if p * q == n:
            print("p =", p)
            print("q =", q)
            break
    a += 1
    b2 = a * a - n
```

This approach was completely successful, and we were able to recover `p` and `q`:

```
p = 145501363105206968514796704753797653743900089837446153019363260333559594600438153232379324575180042848744276356268105432265499074636909679593665460016815337868260981443718005415540912220329005444638374049724631732920036601741373796997615556788123606609912832970703302797117997632467476257530321559454092264911
q = 145501363105206968514796704753797653743900089837446153019363260333559594600438153232379324575180042848744276356268105432265499074636909679593665460016815337868260981443718005415540912220329005444638374049724631732920036601741373796997615556788123606609912832970703302797117997632467476257530321559454092265443
```

At this point, I was able to calculate the private exponent `d` and reconstruct the RSA private key used by the server:

```python
from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA

p = 145501363105206968514796704753797653743900089837446153019363260333559594600438153232379324575180042848744276356268105432265499074636909679593665460016815337868260981443718005415540912220329005444638374049724631732920036601741373796997615556788123606609912832970703302797117997632467476257530321559454092264911
q = 145501363105206968514796704753797653743900089837446153019363260333559594600438153232379324575180042848744276356268105432265499074636909679593665460016815337868260981443718005415540912220329005444638374049724631732920036601741373796997615556788123606609912832970703302797117997632467476257530321559454092265443
e = 65537

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))

with open('server_privkey.pem', 'wb') as f:
    f.write(key.export_key('PEM'))
```

## Flag capture

The server enforces mutual TLS authentication, and, as we have determined, it uses the same certificate for all purposes. Therefore, we can use the server's certificate and its private key to authenticate ourselves as clients.

We simply concatenate the server certificate and private key into a single file, and then use them to authenticate and connect to the server:

```bash
$ cat server_cert.pem server_privkey.pem > server_full.pem

$ openssl s_client -connect nct25.thehackerconclave.es:26016 \
    -cert server_full.pem \
    -key server_privkey.pem \
    -quiet
Connecting to 130.206.158.156
depth=0 CN=client1
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=client1
verify return:1
conclave{724e68e32b2ddeed32e53bc1cc8653cf}
```
