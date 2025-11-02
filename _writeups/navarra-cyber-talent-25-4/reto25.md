---
title: reto25
challenge_type: Misc
difficulty: Beginner
author: "@4nimanegra"
writeup_author: "@xabito"
competition: navarra-cyber-talent-25-4
summary: |-
  The flag is stored on this page with a password system.
connections:
  - url: http://nct25.thehackerconclave.es:26025
---

## Recon

Upon visiting the main page, we encounter a password-protected login screen, along with a hint indicating that the password is verified client-side using a SHA-1 hash:

![Login page](/assets/files/navarra-cyber-talent-25-4/reto25/login.png)

By inspecting the HTML source code, we can see the entire client-side password validation logic:

```javascript
const PASSWORD = "6e443cabe2b143975970f1f244e2da955d180df7";

loginBtn.addEventListener('click', async () => {
  const v = passwordInput.value || "";
  if (v.trim().length === 0) {
    showError("Introduce una contraseña");
    return;
  }

  try {
    const hash = await sha1(v);
    if (hash === PASSWORD) {
      window.location.href = "flag.php";
    } else {
      showError("Contraseña incorrecta");
    }
  } catch (err) {
    showError("Error de verificación");
    console.error(err);
  }
});
```

## Exploitation

At first glance, it appears that we need to recover the plaintext corresponding to the SHA-1 hash stored in `PASSWORD`. However, since the hint suggests that all validation is performed solely on the client side, it might be possible to simply access the `flag.php` file directly.

## Flag capture

We can directly access the flag page to retrieve the flag:

```bash
$ curl http://nct25.thehackerconclave.es:26025/flag.php | grep -Eo 'conclave\{.+'
conclave{9a8ec4ad36a3ac7855a108efcd4102d1}
```
