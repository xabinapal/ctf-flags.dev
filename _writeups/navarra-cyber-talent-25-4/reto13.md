---
title: reto13
challenge_type: Crypto
difficulty: Hard
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  We have an SSH server that uses the same RSA keys for everything. Password access is disabled and we don't know if that user will give us bash or not. We also know that the machine has an internal web server that will presumably return the flag.
connections:
  - url: ssh://nct25.thehackerconclave.es:26013
    description: |-
      Username: dummy
---

## Recon

First, I attempted to connect to the SSH service in order to confirm that password authentication is disabled and that access is only possible using a keypair:

```bash
$ The authenticity of host '[nct25.thehackerconclave.es]:26013 ([130.206.158.156]:26013)' can't be established.
RSA key fingerprint is: SHA256:wXRgwwfAHeh8iMX8OqgTffOagC62Il2bXxIC7t93+Ps
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
dummy@nct25.thehackerconclave.es: dummy
Permission denied (publickey).
```

Since the server uses the same RSA key for all services, it is likely that we can log in if we obtain the server's private key. Therefore, we begin by extracting the server's host public key:

```bash
$ ssh-keyscan -p 26013 -t rsa nct25.thehackerconclave.es
# nct25.thehackerconclave.es:26013 SSH-2.0-OpenSSH_10.0p2 Debian-7
[nct25.thehackerconclave.es]:26013 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAC6Rwk5p9psTByiEYqGBuYF4DdK9lioXBUiI3z/qYh20ZQ6eEbRKde94m9hinuPjWqqBHJfnxTs09KYk/8VX8XONobNeatkZInWPvQPi6HDIfTpBs4izR4dsErrI/HfRn4NsePZbduM/YcuYJc2cwyUS1sYhekBk9b5zzfgli++o/qvJF7pVakaK3tZabSf2qN/cMvufvZDmop9AAqwcDfmTGWo1MI7x3MNUP0XavcU/ubvF8uBuCKlgLEEyo7rfSj/AxryJsEbjhO22jdab6hD8PlFqfRyOBzzqy5Cvuru+7zw9BmNjypawDyBjbjKfZ2ukqIzyOElfvYgWk3/oxWU=
```

## Exploitation

Since we were able to factor `N` using Fermat's factorization algorithm in [`reto16`](/competitions/navarra-cyber-talent-25-4/reto16/), we will apply the same approach here.

```python
import math

from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA

with open('server_pubkey.pub', 'r') as f:
    pubkey = RSA.import_key(f.read())

n = pubkey.n
e = pubkey.e

print("n =", n)
print("e =", e)

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

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))

with open('server_privkey.pem', 'wb') as f:
    f.write(key.export_key('PEM'))
```

We were successful: we found both prime factors, `p` and `q`, and were able to reconstruct the original private key.

```
n = 5878838474649148872917357645436006466733970924745710942159774687590015245747181362161664518482863962067087937071565895818047657740440735092556735720241397386100314223935751949052512068669400412698249528668738295295549277802527617682995417845664535993335926521068098288392677367053348894092018599567261102166316753011800240095593711812242994934130720712339152063068408997424116353707404566010096764992790194062254201520611378874927773651273757662589741814899963777223143384020655347247679469201269876336696335150150057329535773057118442376792608179709298480037530508083083534977261515830920599121199989752979132040549
e = 65537
p = 76673583942901409627969840453545977667956691333284397708473159965355591401619772076207831387796512023315757300975203213536799680229555688007739574457585344771661180342589843346529539290935537742287793071515267198100915419337003824717812035546317103418893982178004482964832597728358031913207661303740050757619
q = 76673583942901409627969840453545977667956691333284397708473159965355591401619772076207831387796512023315757300975203213536799680229555688007739574457585344771661180342589843346529539290935537742287793071515267198100915419337003824717812035546317103418893982178004482964832597728358031913207661303740050758471
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEnwIBAAKCAQAukcJOafabEwcohGKhgbmBeA3SvZYqFwVIiN8/6mIdtGUOnhG0
SnXveJvYYp7j41qqgRyX58U7NPSmJP/FV/FzjaGzXmrZGSJ1j70D4uhwyH06QbOI
s0eHbBK6yPx30Z+DbHj2W3bjP2HLmCXNnMMlEtbGIXpAZPW+c834JYvvqP6ryRe6
VWpGit7WWm0n9qjf3DL7n72Q5qKfQAKsHA35kxlqNTCO8dzDVD9F2r3FP7m7xfLg
bgipYCxBMqO630o/wMa8ibBG44Ttto3Wm+oQ/D5Ran0cjgc86suQr7q7vu88PQZj
Y8qWsA8gY24yn2drpKiM8jhJX72IFpN/6MVlAgMBAAECggEAALtduGnF7G4CIMrj
2fH1/mjqnrNIFuVBugAcsh526Eybgf1N/e1lqRvWJzJ1mNNL634X+vMzkFimt63B
L1LQgqZpMi57s2nHtt1JdTQtvwgHn9DEh5N5vlEegj0CaseqoCAmTojld3DZkp+T
iIW8M2r2YSrJhxWPHy0mwY2lg2C7IU82yQ5dSm+YeuLXspmV5VAF/SqcHedRrpgB
Ix6tvVvk7I1tsfVppOJkbrrPuc6ruy+yd6OduwPXRcGelwS76Itu8Mn//dW/Em1G
PT+PEEvNow3l4duVjZU9LZNbbDOB4OWNwEGCvcpEEkXiuVor/YIOX18yrGQxuffn
UIodCQKBgG0v0qOwyH1dUf9D/as23fCo20wL55Iq8aEauWPeR5UmVu+SgzNyVTC0
rHIDdMU1VxjIlTkl49VHEjm4GYZ6GkeDYDQeBxvDSmCEPCBUdq33u4U0MuQdwN+v
Azix6GShHNj/Hy14X4D4NIFIXtOHDmqtnSfbZ3UsSLW8Yp2z2NfzAoGAbS/So7DI
fV1R/0P9qzbd8KjbTAvnkirxoRq5Y95HlSZW75KDM3JVMLSscgN0xTVXGMiVOSXj
1UcSObgZhnoaR4NgNB4HG8NKYIQ8IFR2rfe7hTQy5B3A368DOLHoZKEc2P8fLXhf
gPg0gUhe04cOaq2dJ9tndSxItbxinbPY20cCgYAeUD+nyIXxID6Ko0LDDSmTDh5M
P6XcE+Yftz6vNmAjTZCnVMLuPpjeO9sAkGsT8Vor/ExJoHZfmSq7MZyMlEvFfPjx
n0CT+aUlpLDYvPpyFCxQsAxM/uG0eG9phyMhBQXwTOxIAHprYP2aww/opD9haLAQ
B77ybggFxLaQWAUk9wKBgGDig41ea7jaGs1gXnIToIJQwy7KjXQlCP2Egia88VXG
jHPO1P7MoA009KPCr1Xii+Ng8RChr3Xrt59h3bx3EmSMjcwRLQuUkaXtEJE7gYfD
ADElbVb/k8qoODqRmv3X/IoMb3TgkBYXqDdjqUkXWVKNtZrNVBMj9WzVucfn8zA3
AoGAWEw7d8Ej75iv+zMTv6RB5vmHRs/v2ai8yrIn81DmW3g+fdUhYv5pjKVWkkka
0ykIPJr/SPTgNTAo4SfO7tpUWa5ywZVHQDd38OfuhRyke0IHHn/YoQmjfGbFAkfC
PiW+sK8Qf9A3mUW3FGrmhmbogO+N0AGnfugEtwYEB/Hj8L0=
-----END RSA PRIVATE KEY-----
```

With the recovered private key, I was able to successfully authenticate to the SSH server; however, it appears that we are limited to a restricted shell.

```bash
$ ssh -i server_privkey.pem -p 26013 dummy@nct25.thehackerconclave.es
Connection to nct25.thehackerconclave.es closed.
```

Since it is not possible to obtain a shell, we need to utilize SSH tunneling instead. As the challenge description referenced an internal web server, I set up a local port forwarding connection:

```
$ ssh -i server_privkey.pem -p 26013 -L 9090:127.0.0.1:80 -N dummy@nct25.thehackerconclave.es
```

## Flag capture

Once SSH tunneling is active, simply navigate to [http://127.0.0.1:9090](http://127.0.0.1:9090) in your web browser to retrieve the flag.

![Flag page](/assets/files/navarra-cyber-talent-25-4/reto13/flag.png)

```
Flag: conclave{126a2060d5afccf11f31213ac09676a3}
```
