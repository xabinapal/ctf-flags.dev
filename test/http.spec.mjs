import { expect, test } from "@playwright/test";

test("Astro preview serves both permalink forms and the custom 404", async ({
  request,
  page,
}) => {
  const permalinks = [
    [
      "/competitions/wolvctf-2026/this-is-wolv-01",
      "/competitions/wolvctf-2026/this-is-wolv-01/",
    ],
    ["/resources/osint", "/resources/osint/"],
    ["/utilities/jwt", "/utilities/jwt/"],
  ];
  for (const [permalink, canonical] of permalinks) {
    for (const path of [permalink, `${permalink}/`]) {
      const response = await request.get(path);
      expect(response.status()).toBe(200);
      expect(await response.text()).toContain(
        `<link rel="canonical" href="https://ctf-flags.dev${canonical}"`,
      );
    }
  }

  await page.route(/^https:\/\//, (route) => route.abort());
  const missing = await page.goto("/nonexistent-preview-test-route/");
  expect(missing?.status()).toBe(404);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Page not found",
  );
  await expect(page.locator("code.eyebrow")).toHaveText("flag{n0t_f0und}");

  const caption = await request.get("/caption.png");
  expect(caption.ok()).toBe(true);
  expect(caption.headers()["content-type"]).toMatch(/^image\/png/);

  const stylesheet = await request.get("/assets/css/style.css");
  expect(stylesheet.status()).toBe(200);
  expect(stylesheet.headers()["content-type"]).toMatch(/^text\/css/);
});

test("pages preload and reuse the same local fonts without swapping faces", async ({
  page,
  baseURL,
}) => {
  const fontsByPage = [];
  for (const path of ["/", "/resources/", "/utilities/"]) {
    await page.goto(path);
    await expect(page.locator('head link[rel="stylesheet"]')).toHaveAttribute(
      "href",
      /^\/assets\/css\/style\.css\?v=[a-f0-9]{12}$/,
    );
    const fonts = await page.evaluate(async () => {
      await Promise.all([
        document.fonts.load('700 16px "Asul"'),
        document.fonts.load('400 16px "Inconsolata"'),
      ]);
      const faces = [...document.styleSheets]
        .flatMap((sheet) => [...sheet.cssRules])
        .filter((rule) => rule instanceof CSSFontFaceRule);
      return [
        ...document.querySelectorAll('link[rel="preload"][as="font"]'),
      ].map((link) => {
        const pathname = new URL(link.href).pathname;
        const face = faces.find((rule) =>
          rule.style.getPropertyValue("src").includes(pathname),
        );
        const family = face?.style
          .getPropertyValue("font-family")
          .replaceAll('"', "");
        return {
          href: link.href,
          crossOrigin: link.crossOrigin,
          display: face?.style.getPropertyValue("font-display"),
          loaded: [...document.fonts].some(
            (font) =>
              font.family.replaceAll('"', "") === family &&
              font.status === "loaded",
          ),
        };
      });
    });
    expect(fonts).toHaveLength(2);
    for (const font of fonts) {
      expect(new URL(font.href).origin).toBe(baseURL);
      expect(font).toMatchObject({
        crossOrigin: "anonymous",
        display: "block",
        loaded: true,
      });
    }
    fontsByPage.push(fonts.map((font) => font.href));
  }
  expect(fontsByPage[1]).toEqual(fontsByPage[0]);
  expect(fontsByPage[2]).toEqual(fontsByPage[0]);
});
