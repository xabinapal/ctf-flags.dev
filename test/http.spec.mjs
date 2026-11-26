import { expect, test } from "@playwright/test";

test("Astro preview serves both permalink forms and the custom 404", async ({
  request,
  page,
}) => {
  const permalink = "/competitions/wolvctf-2026/this-is-wolv-01";
  for (const path of [permalink, `${permalink}/`]) {
    const response = await request.get(path);
    expect(response.status()).toBe(200);
    expect(await response.text()).toContain(
      `<link rel="canonical" href="https://ctf-flags.dev${permalink}/"`,
    );
  }

  await page.route(/^https:\/\//, (route) => route.abort());
  const missing = await page.goto("/nonexistent-preview-test-route/");
  expect(missing?.status()).toBe(404);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "flag{n0t_f0und}",
  );

  const stylesheet = await request.get("/assets/css/style.css");
  expect(stylesheet.status()).toBe(200);
  expect(stylesheet.headers()["content-type"]).toMatch(/^text\/css/);
});

test("the site loads both font families from its own origin", async ({
  page,
  baseURL,
}) => {
  await page.route(
    (url) => url.origin !== baseURL,
    (route) => route.abort(),
  );
  await page.goto("/");
  const loaded = await page.evaluate(async () => {
    const faces = await Promise.all([
      document.fonts.load('400 16px "IBM Plex Mono"'),
      document.fonts.load('600 16px "Space Grotesk"'),
    ]);
    return faces.map((family) =>
      family.some((font) => font.status === "loaded"),
    );
  });
  expect(loaded).toEqual([true, true]);
});
