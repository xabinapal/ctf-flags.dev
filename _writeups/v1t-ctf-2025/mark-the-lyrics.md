---
title: Mark the Lyrics
challenge_type: Web
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Can you find the number?
connections:
  - url: http://tommytheduck.github.io/mckey/
---

## Recon

We are presented with a lyrics website featuring an embedded YouTube video.

![Landing page](/assets/files/v1t-ctf-2025/mark-the-lyrics/website.png)

Upon examining the source code, we notice that certain characters are wrapped within `<mark>` HTML elements.

```html
<mark>V</mark>erse <mark>1</mark>: Sơn Tùng M-<mark>T</mark>
```

The first marked characters are `V1T`, which suggests that the flag is composed of all the characters contained within the `<mark>` elements in the DOM.

## Exploitation

We can extract all the text contained within the `<mark>` elements using the browser's developer tools and a simple JavaScript snippet:

```javascript
const marks = document.getElementsByTagName("mark");
let flag = "";

for (mark of marks) {
  flag += mark.innerText;
}

console.log(flag);
```

## Flag capture

After running the script, you will see the flag displayed in the console:

```
Flag: V1T{MCK-pap-cool-ooh-yeah}
```