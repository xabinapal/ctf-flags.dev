---
title: reto03
challenge_type: Web
difficulty: Easy
author: "@pedrit"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: This page opens portals to different worlds. One of them hides a flag. Will you be able to find it?
connections:
  - url: http://nct25.thehackerconclave.es:26003
---

## Recon

At first glance, the page appears fairly uninteresting. The only interactive element is a piece of text that redirects the user to a random page each time it is clicked.

![Landing page](/assets/files/navarra-cyber-talent-25-4/reto03/website.png)

By inspecting the source code, we can observe the redirect logic implemented as follows:

```javascript
function travel() {
    page = Math.floor(Math.random() * 6);
    switch (page) {
        case 0:
            window.location.href = "/pipo";
            break;
        case 1:
            window.location.href = "/beer404";
            break;
        case 2:
            window.location.href = "/anonymous";
            break;
        case 3:
            window.location.href = "/graph";
            break;
        case 4:
            window.location.href = "/diary";
            break;
        case 5:
            window.location.href = "/motorola";
            break;
        default:
            window.location.href = "/index";
    }
}
```

After checking all of the pages, they appear to be mostly useless, except... 
kudos for the rickroll on one of them. 

It's a good idea to check for other commonly used files on websites, such as `robots.txt`.

![Robots page](/assets/files/navarra-cyber-talent-25-4/reto03/robots.png)

Success! The website is built using the **Django** framework, but it is misconfigured: the `DEBUG = True` setting is enabled. This option should never be active on a production server.

## Exploitation

Upon examining the debug page, we discover an additional endpoint that is not referenced in the `travel` JavaScript function: `^nasec(?:\.html|\.php)?/?`. It would be prudent to investigate this URL.

## Flag capture

Let’s send a request to this endpoint to see what response we receive:

```bash
$ curl -s http://nct25.thehackerconclave.es:26003/nasec | grep -Eo "conclave{.+}"
conclave{94d0c8d32ff0e86678a1f91999a28409}
```