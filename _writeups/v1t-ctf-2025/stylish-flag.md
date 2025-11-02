---
title: Stylish Flag
challenge_type: Web
writeup_author: "@xabito"
competition: v1t-ctf-2025
summary: |-
  Are you a front end dev?
connections:
  - url: https://tommytheduck.github.io/stylish_flag/
---

## Recon

The website initially displays only a simple message:

![Landing page](/assets/files/v1t-ctf-2025/stylish-flag/web.png)

Examining the source code reveals a few important details: there is a hidden `div` element with the class `flag`, as well as a linked stylesheet named `csss.css`.

```html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <title>Stylish Flag</title>
  <link rel="stylesheet" href="csss.css">
</head>

<body>
  <h1>where is the flag ;-;</h1>
  <br>
  <div hidden class="flag"></div>
</body>

</html>
```

Since the challenge refers to a "stylish" flag, it suggests a connection to CSS. Upon examining the stylesheet, we find that it uses `box-shadow` properties to create pixel art, likely containing the hidden flag.

```css
.flag {
  width: 8px;
  height: 8px;
  background: #0f0;
  transform: rotate(180deg);
  opacity: 0.05;
  box-shadow:
      264px 0px #0f0,
      1200px 0px #0f0,
      0px 8px #0f0,
      32px 8px #0f0,
      88px 8px #0f0,
      96px 8px #0f0,
      160px 8px #0f0,
      168px 8px #0f0,
      ...
```

## Flag capture

By using the browser's developer tools, we can reveal the flag. Simply remove the `hidden` attribute from the `div` element, and the flag will become visible, although it will appear rotated 180º.

To view the image clearly, we need to remove the `transform: rotate(180deg)` and `opacity: 0.05` CSS properties.

![Developer tools](/assets/files/v1t-ctf-2025/stylish-flag/devtools.png)

Now, here is our flag:

![Flag](/assets/files/v1t-ctf-2025/stylish-flag/flag.png)

```
Flag: V1T{H1D30UT_CSS}
```