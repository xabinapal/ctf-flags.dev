import { expect, test } from "@playwright/test";

test.beforeEach(async ({ context, baseURL }) => {
  await context.route(
    (url) => url.origin !== baseURL,
    (route) => route.abort(),
  );
});

test("utilities are usable even when legacy fragment requests are unavailable", async ({
  page,
}) => {
  await page.route("**/partials/**", (route) => route.abort());
  const bundleReady = Promise.withResolvers();
  await page.route("**/_astro/*.js", async (route) => {
    await bundleReady.promise;
    await route.fallback();
  });
  try {
    await page.goto("/utilities/", { waitUntil: "commit" });
    const initialField = page.getByLabel("Base 10 (Decimal)");
    await initialField.waitFor();
    await expect(page.locator("[data-utilities]")).toHaveAttribute("inert", "");
  } finally {
    bundleReady.resolve();
  }

  async function select(name) {
    await page.getByRole("button", { name, exact: true }).click();
    await expect(page).toHaveURL(`/utilities/${name.toLowerCase()}/`);
    return page.getByRole("region", { name, exact: true });
  }

  const samples = [
    ["Number", "Base 10 (Decimal)", "65", "ASCII Text", "A"],
    ["Base", "Plaintext", "Hello", "Base64", "SGVsbG8="],
    ["URL", "Plaintext", "hello world", "URL Encoded", "hello%20world"],
    ["ROT", "Plaintext", "abc", "ROTN", "nop"],
    ["Morse", "Plaintext", "SOS", "Morse Code", "... --- ..."],
    [
      "Timestamp",
      "Unix (seconds)",
      "0",
      "ISO 8601",
      "1970-01-01T00:00:00.000Z",
    ],
  ];
  for (const [name, inputLabel, input, outputLabel, output] of samples) {
    const panel = await select(name);
    await panel.getByLabel(inputLabel, { exact: name !== "ROT" }).fill(input);
    await expect(
      panel.getByLabel(outputLabel, { exact: name !== "ROT" }),
    ).toHaveValue(output);
  }

  const xor = await select("XOR");
  await xor.getByLabel("Key (ASCII)", { exact: true }).fill("B");
  await xor.getByLabel("Input (ASCII)", { exact: true }).fill("A");
  await expect(xor.getByLabel("Output (HEX)", { exact: true })).toHaveValue(
    "03",
  );

  const jwt = await select("JWT");
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString(
    "base64url",
  );
  const payload = Buffer.from(JSON.stringify({ message: "fixture" })).toString(
    "base64url",
  );
  await jwt.getByLabel("JWT Token").fill(`${header}.${payload}.fixture`);
  await expect(jwt.locator("#jwt-payload")).toContainText("fixture");

  const number = await select("Number");
  await expect(number.getByLabel("Base 10 (Decimal)")).toHaveValue("65");
  await page.goBack();
  await expect(page).toHaveURL("/utilities/jwt/");
  await expect(jwt.locator("#jwt-payload")).toContainText("fixture");
  await page.goForward();
  await expect(page).toHaveURL("/utilities/number/");
  await expect(number.getByLabel("Base 10 (Decimal)")).toHaveValue("65");

  await page.getByRole("button", { name: "JWT", exact: true }).click();
  await page.reload();
  await expect(jwt).toBeVisible();
  await expect(page).toHaveTitle("Utilities | ctf-flags.dev");
});

test("resource search and category are restored from links and browser history", async ({
  page,
}) => {
  const resource = page.getByRole("heading", { name: "Audacity", exact: true });
  const search = page.getByRole("textbox", { name: "Search resources" });
  const shared = "/resources/stego/?q=audacity";
  await page.goto(shared);
  await expect(search).toHaveValue("audacity");
  await expect(resource).toBeVisible();
  await expect(
    page.getByRole("button", { name: "stego", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");

  await search.evaluate((element) => {
    element.dataset.beforeTabSwitch = "true";
  });
  await page.getByRole("button", { name: "crypto", exact: true }).click();
  await expect(page).toHaveURL("/resources/crypto/?q=audacity");
  await expect(search).toHaveAttribute("data-before-tab-switch", "true");
  await expect(page).toHaveTitle("Resources | ctf-flags.dev");
  await expect(page.getByText("No resources found")).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(shared);
  await expect(resource).toBeVisible();

  await search.fill("unmatched term");
  await expect(page).toHaveURL("/resources/stego/?q=unmatched+term");
  await page.goBack();
  await expect(search).toHaveValue("audacity");
  await expect(resource).toBeVisible();
  await page.goForward();
  await expect(search).toHaveValue("unmatched term");

  await page.goto("/resources/?q=%20AUDACITY%20");
  await expect(
    page.getByRole("button", { name: "All", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(resource).toBeVisible();
});

test.describe("resource deep links without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("a direct category path shows the selected tab", async ({ page }) => {
    await page.goto("/resources/osint");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "flag{r3s0urc3s}",
    );
    await expect(page.getByRole("heading", { level: 2 })).toHaveText(["osint"]);
  });
});

test.describe("mobile writeups", () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true });

  test("wide writeup content stays within a mobile viewport", async ({
    page,
  }) => {
    await page.goto("/competitions/wolvctf-2026/this-is-wolv-01/");
    const dimensions = await page.evaluate(
      (viewport) => ({
        viewport,
        layout: document.documentElement.clientWidth,
        body: document.body.scrollWidth,
        page: document.documentElement.scrollWidth,
        overflow: [...document.querySelectorAll(".writeup *")]
          .filter((node) => node.getBoundingClientRect().right > viewport + 1)
          .slice(0, 6)
          .map((node) => node.tagName),
      }),
      page.viewportSize().width,
    );
    expect(
      Math.max(dimensions.page, dimensions.body),
      JSON.stringify(dimensions),
    ).toBeLessThanOrEqual(dimensions.viewport + 1);
  });

  test("tables and code scroll locally on narrow screens", async ({ page }) => {
    await page.goto("/competitions/v1t-ctf-2025/modulo-mystery/");
    const table = page
      .getByRole("region", { name: "Scrollable table" })
      .first();
    const tableScroll = await table.evaluate((container) => {
      container.querySelector("table").style.minInlineSize = "680px";
      container.scrollLeft = 40;
      return container.scrollLeft;
    });
    expect(tableScroll).toBe(40);

    const code = page.locator(".writeup-content pre").first();
    const codeScroll = await code.evaluate((container) => {
      container.textContent = "x".repeat(200);
      container.scrollLeft = 40;
      return container.scrollLeft;
    });
    expect(codeScroll).toBe(40);
    expect(
      await page.evaluate(() => document.body.scrollWidth),
    ).toBeLessThanOrEqual(391);
  });
});
