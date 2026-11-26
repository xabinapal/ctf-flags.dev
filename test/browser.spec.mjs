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
  await expect(page).toHaveTitle("JWT utility | ctf-flags.dev");
  await expect(page.locator(".eyebrow + h1")).toHaveText("CTF workbench");
  await expect(page.locator(".eyebrow")).toHaveText("flag{ut1l1t13s}");
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
  const audacity = page.getByRole("link", { name: "Audacity", exact: true });
  await expect(audacity.locator(".external-url-text")).toHaveText(
    `${await audacity.getAttribute("href")}↗`,
  );
  await expect(
    page.getByRole("button", { name: "stego", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");

  await search.evaluate((element) => {
    element.dataset.beforeTabSwitch = "true";
  });
  await page.getByRole("button", { name: "crypto", exact: true }).click();
  await expect(page).toHaveURL("/resources/crypto/?q=audacity");
  await expect(search).toHaveAttribute("data-before-tab-switch", "true");
  await expect(page).toHaveTitle("CRYPTO resources | ctf-flags.dev");
  await expect(page.locator('meta[property="og:url"]')).toHaveAttribute(
    "content",
    "https://ctf-flags.dev/resources/crypto/",
  );
  await expect(page.getByText("No resources found")).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(shared);
  await expect(page).toHaveTitle("STEGO resources | ctf-flags.dev");
  await expect(page.locator('meta[property="og:url"]')).toHaveAttribute(
    "content",
    "https://ctf-flags.dev/resources/stego/",
  );
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
    page.getByRole("button", { name: "all", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await expect(resource).toBeVisible();
});

test.describe("section deep links without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("a direct category path shows the selected tab", async ({ page }) => {
    await page.goto("/resources/osint");
    await expect(page.locator(".eyebrow + h1")).toHaveText("CTF toolkit");
    await expect(page.locator(".eyebrow")).toHaveText("flag{r3s0urc3s}");
    await expect(page.getByRole("heading", { level: 2 })).toHaveText(["osint"]);
    await expect(page.locator("h1 + .summary")).toHaveCount(0);

    await page.goto("/utilities/jwt/");
    await expect(page.locator("h1 + .summary")).toHaveCount(0);
  });
});

test("masthead subtitles and top and bottom breadcrumbs use consistent typography", async ({
  page,
}) => {
  const layouts = [];
  const subtitles = [];
  const textStyle = (node) => {
    const {
      color,
      fontFamily,
      fontSize,
      fontWeight,
      lineHeight,
      textDecorationLine,
    } = getComputedStyle(node);
    return {
      color,
      fontFamily,
      fontSize,
      fontWeight,
      lineHeight,
      textDecorationLine,
    };
  };
  for (const path of [
    "/",
    "/resources/",
    "/utilities/",
    "/competitions/wolvctf-2026/",
    "/competitions/wolvctf-2026/maize-poster/",
  ]) {
    await page.goto(path);
    layouts.push(
      await page.locator(".eyebrow:has(+ h1)").evaluate((eyebrow) => {
        const bounds = eyebrow.getBoundingClientRect();
        const title = eyebrow.nextElementSibling.getBoundingClientRect();
        const { color, fontFamily, fontSize, fontWeight, lineHeight } =
          getComputedStyle(eyebrow);
        return {
          color,
          fontFamily,
          fontSize,
          fontWeight,
          lineHeight,
          height: Math.round(bounds.height),
          titleTop: Math.round(title.top),
          gap: Math.round(title.top - bounds.bottom),
        };
      }),
    );
    if (path === "/resources/" || path === "/utilities/") {
      await expect(page.locator("h1 + .summary")).toHaveCount(0);
    }
    if (path.startsWith("/competitions/")) {
      subtitles.push(
        await page
          .locator("h1 + :is(.summary, .archive-byline)")
          .evaluate(textStyle),
      );
    }
    if (path.startsWith("/competitions/")) {
      const topLink = page
        .getByRole("navigation", { name: "Breadcrumb" })
        .getByRole("link");
      expect(await page.locator(".back-bar a").evaluate(textStyle)).toEqual(
        await topLink.evaluate(textStyle),
      );
    }
  }
  for (const layout of layouts.slice(1)) expect(layout).toEqual(layouts[0]);
  for (const style of subtitles.slice(1)) expect(style).toEqual(subtitles[0]);
});

test("404 and archive back links have the same spacing", async ({ page }) => {
  const backBar = page.locator(".back-bar");
  const spacing = [];
  for (const path of [
    "/404.html",
    "/competitions/wolvctf-2026/",
    "/competitions/wolvctf-2026/maize-poster/",
  ]) {
    await page.goto(path);
    await expect(backBar.getByRole("link")).toHaveText(/Back to/);
    spacing.push(
      await backBar.evaluate((bar) => {
        const previous = bar.previousElementSibling.getBoundingClientRect();
        return bar.getBoundingClientRect().top - previous.bottom;
      }),
    );
  }
  expect(spacing[0]).toBeGreaterThan(0);
  expect(spacing[1]).toBeCloseTo(spacing[0], 0);
  expect(spacing[2]).toBeCloseTo(spacing[0], 0);
});

test("resources and utilities use the same tab styles", async ({ page }) => {
  const tabStyles = async (selector) =>
    page
      .locator(selector)
      .first()
      .evaluate((tab) => {
        const { backgroundColor, color, fontFamily, fontSize, fontWeight } =
          getComputedStyle(tab);
        return { backgroundColor, color, fontFamily, fontSize, fontWeight };
      });
  await page.goto("/resources/");
  const selected = await tabStyles('.resource-tab[aria-pressed="true"]');
  const idle = await tabStyles('.resource-tab[aria-pressed="false"]');
  expect(selected).toMatchObject({
    fontWeight: "600",
    backgroundColor: "rgba(0, 0, 0, 0)",
  });
  expect(idle).toMatchObject({
    fontWeight: "400",
    backgroundColor: "rgba(0, 0, 0, 0)",
  });
  await page.goto("/utilities/");
  expect(await tabStyles('.utility-tab[aria-pressed="true"]')).toEqual(
    selected,
  );
  expect(await tabStyles('.utility-tab[aria-pressed="false"]')).toEqual(idle);
});

test("archive, writeup, and resource metadata use consistent styles", async ({
  page,
}) => {
  await page.goto("/competitions/wolvctf-2026/");
  const category = page.getByRole("heading", { name: "crypto", exact: true });
  const categoryStyle = (heading) =>
    heading.evaluate((node) => {
      const { color, fontFamily, fontSize, fontWeight } =
        getComputedStyle(node);
      return { color, fontFamily, fontSize, fontWeight };
    });
  const archiveStyle = await categoryStyle(category);
  const categoryWidth = (await category.boundingBox()).width;
  expect(categoryWidth).toBeGreaterThanOrEqual(112);
  expect(categoryWidth).toBeLessThanOrEqual(136);

  const ctftimeUrl = "https://ctftime.org/event/3049";
  const ctftime = page.getByRole("link", { name: ctftimeUrl, exact: true });
  await expect(ctftime).toHaveAttribute("href", ctftimeUrl);
  await expect(page.locator(".archive-byline")).toContainText(
    `Nov 21, 2026 – Nov 22, 2026 | ${ctftimeUrl}`,
  );
  const linkStyle = await categoryStyle(ctftime);
  await expect(ctftime.locator(".external-arrow")).toHaveCSS(
    "color",
    linkStyle.color,
  );
  const competitionByline = page.locator(".archive-byline");
  await expect(competitionByline.locator(".byline-separator")).toHaveCSS(
    "color",
    (await categoryStyle(competitionByline)).color,
  );
  await ctftime.hover();
  await expect(ctftime.locator(".external-arrow")).toHaveCSS(
    "translate",
    "2px -2px",
  );

  const row = page.getByRole("link", { name: "Cancelled", exact: true });
  const byline = await row.locator(".writeup-attribution").textContent();
  expect(byline).toBe("medium | by @camelot007 | writeup by @xabito");
  const handles = ["@camelot007", "@xabito"];
  await expect(row.locator(".attribution-name")).toHaveText(handles);
  const nameStyle = await categoryStyle(
    row.locator(".attribution-name").first(),
  );
  const bylineStyle = await categoryStyle(row.locator(".writeup-attribution"));
  expect(nameStyle.color).toBe(linkStyle.color);
  expect(nameStyle.color).not.toBe(bylineStyle.color);
  await row.click();
  const detailByline = page.locator(".archive-byline .writeup-attribution");
  await expect(detailByline).toHaveText(`crypto | ${byline}`);
  expect(await categoryStyle(detailByline)).toEqual(bylineStyle);
  await expect(page.locator(".archive-byline .attribution-name")).toHaveText(
    handles,
  );
  await expect(
    page.locator(".archive-byline .attribution-name").first(),
  ).toHaveCSS("color", nameStyle.color);

  await page.goto("/resources/crypto/");
  expect(await categoryStyle(category)).toEqual(archiveStyle);
  const tab = page.getByRole("button", { name: "crypto", exact: true });
  expect(await categoryStyle(tab)).toEqual(archiveStyle);
  const resourceRow = page.locator(".resource-row:visible").first();
  expect(await categoryStyle(resourceRow.locator(".resource-url"))).toEqual(
    linkStyle,
  );
  await expect(resourceRow.locator(".external-arrow")).toHaveCSS(
    "color",
    linkStyle.color,
  );
  const resourceUrl = resourceRow.locator(".resource-url");
  await expect(resourceUrl.locator("span").first()).toHaveCSS(
    "text-decoration-line",
    "underline",
  );
  const arrowFollowsWrappedUrl = await resourceUrl.evaluate((url) => {
    url.style.inlineSize = "5rem";
    const text = url.querySelector(".external-url-end").firstChild;
    const lastCharacter = document.createRange();
    lastCharacter.setStart(text, text.length - 1);
    lastCharacter.setEnd(text, text.length);
    const end = lastCharacter.getBoundingClientRect();
    const arrow = url.querySelector(".external-arrow").getBoundingClientRect();
    return (
      url.firstElementChild.getClientRects().length > 1 &&
      arrow.top < end.bottom &&
      arrow.bottom > end.top &&
      Math.abs(arrow.left - end.right) < 8
    );
  });
  expect(arrowFollowsWrappedUrl).toBe(true);
  await resourceRow.hover();
  await expect(resourceRow.locator(".external-arrow")).toHaveCSS(
    "translate",
    "2px -2px",
  );

  await page.goto("/competitions/infobahn-ctf-2025/bitset/");
  await expect(page.locator(".archive-byline .attribution-name")).toHaveText([
    "@rewhile",
    "@bawolff",
    "@yuu",
    "@xabito",
  ]);
});

test("competition results match the archive and detail views", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByText("flag{w3lc0m3}", { exact: true })).toBeVisible();
  await expect(page.locator(".eyebrow + h1")).toHaveText("CTF writeups");
  await expect(page.locator(".archive-index-heading p")).toHaveText(
    /^\d+ competitions?$/,
  );
  await expect(page.locator("html")).toHaveCSS("overflow-y", "scroll");
  const event = page.getByRole("link", { name: "WolvCTF 2026", exact: true });
  await expect(event.locator("time")).toHaveCount(2);
  await expect(event.locator(".competition-title p")).toContainText(
    "Jeopardy-style CTF organized by WolvSec",
  );
  const results = (parent) => parent.locator(".results");
  const labels = ["Writeups", "Ranking", "Points"];
  const values = ["30", "55", "2,950"];
  await expect(results(event).locator("dt")).toHaveText(labels);
  await expect(results(event).locator("dd")).toHaveText(values);
  await expect(results(event).locator("[data-podium]")).toHaveCount(0);
  const metricStyles = (parent) =>
    parent.locator(".results :is(dt, dd)").evaluateAll((elements) =>
      elements.map((element) => {
        const { color, fontSize, fontWeight, textAlign } =
          getComputedStyle(element);
        return { color, fontSize, fontWeight, textAlign };
      }),
    );
  const archiveStyles = await metricStyles(event);
  await results(page)
    .nth(0)
    .locator('[data-metric="rank"] dd')
    .evaluate((value) => {
      value.textContent = "2";
    });
  await results(page)
    .nth(1)
    .locator('[data-metric="rank"] dd')
    .evaluate((value) => {
      value.textContent = "1,000";
    });
  await results(page)
    .nth(0)
    .locator('[data-metric="points"] dd')
    .evaluate((value) => {
      value.textContent = "100";
    });
  await results(page)
    .nth(1)
    .locator('[data-metric="points"] dd')
    .evaluate((value) => {
      value.textContent = "10,000";
    });
  // Exercise wider glyph metrics than the local system font may use.
  const wideDigits = await page.addStyleTag({
    content: ".results dd { font-family: monospace; letter-spacing: 1.3px; }",
  });
  const wrappedValues = await results(page)
    .locator("dd")
    .evaluateAll((values) =>
      values.flatMap((value) => {
        const range = document.createRange();
        range.selectNodeContents(value);
        return range.getClientRects().length > 1 ? [value.textContent] : [];
      }),
    );
  expect(wrappedValues).toEqual([]);
  await wideDigits.evaluate((style) => style.remove());
  for (const metric of ["writeups", "rank", "points"]) {
    const leftEdges = await results(page)
      .locator(`[data-metric="${metric}"] dd`)
      .evaluateAll((values) =>
        values.map((value) => {
          const range = document.createRange();
          range.selectNodeContents(value);
          return range.getBoundingClientRect().left;
        }),
      );
    expect(new Set(leftEdges).size).toBe(1);
  }
  const podiumPath = "/competitions/navarra-cyber-talent-25-4/";
  const podiumRow = page.locator(`a[href="${podiumPath}"]`);
  const podium = podiumRow.locator("[data-podium] dd");
  await expect(podium).toHaveText("2");
  const podiumStyles = await metricStyles(podiumRow);
  expect(podiumStyles[3].color).not.toBe(archiveStyles[3].color);
  await event.hover();
  const background = await event.evaluate(
    (row) => getComputedStyle(row).backgroundColor,
  );
  expect(background).not.toBe("rgba(0, 0, 0, 0)");
  await event.click();
  await expect(results(page).locator("dt")).toHaveText(labels);
  await expect(results(page).locator("dd")).toHaveText(values);
  expect(await metricStyles(page)).toEqual(archiveStyles);
  await expect(page.locator(".challenge-group").last()).toHaveCSS(
    "border-block-end-width",
    "0px",
  );
  const rowGaps = await page.locator(".challenge-group").evaluateAll((groups) =>
    groups.flatMap((group) => {
      const bounds = group.getBoundingClientRect();
      const first = group.querySelector(".challenge-row");
      const last = group.querySelector("li:last-child .challenge-row");
      return [
        first.getBoundingClientRect().top - bounds.top - group.clientTop,
        bounds.bottom - last.getBoundingClientRect().bottom,
      ];
    }),
  );
  expect(rowGaps.every((gap) => Math.abs(gap) < 1)).toBe(true);
  const challenge = page.getByRole("link", { name: "Cancelled", exact: true });
  await challenge.hover();
  await expect(challenge).toHaveCSS("background-color", background);
  await page.goto(podiumPath);
  await expect(page.locator(".results [data-podium] dd")).toHaveText("2");
  expect(await metricStyles(page)).toEqual(podiumStyles);
  await expect(page.locator(".archive-intro p")).toHaveText([
    "A Jeopardy-style CTF for young cybersecurity talent, organized by the Navarra Cybersecurity Center during the first Navarra Cybersecurity Week. The event brings together educators, businesses, and public institutions to promote cybersecurity awareness.",
  ]);
  await expect(page.locator(".archive-byline time")).toHaveText([
    "Oct 23, 2025",
  ]);
  await expect(
    page.getByText("The event aims to promote the culture of cybersecurity", {
      exact: false,
    }),
  ).toHaveCount(0);
});

test("writeups get a heading when their Markdown starts without one", async ({
  page,
}) => {
  await page.goto("/competitions/lakectf-25-26-quals/guess-flag/");
  await expect(page.locator(".writeup-content > h2:first-child")).toHaveText(
    "Writeup",
  );

  await page.goto("/competitions/infobahn-ctf-2025/risky-chain/");
  await expect(page.locator(".writeup-content > h2:first-child")).toHaveText(
    "Recon",
  );
});

test("writeup media stays within the reading column below the full-width assets", async ({
  page,
}) => {
  await page.goto("/competitions/infobahn-ctf-2025/risky-chain/");
  const content = page.locator(".writeup-content");
  const readingWidth = (await content.boundingBox()).width;
  expect(
    (await page.locator(".writeup-assets").boundingBox()).width,
  ).toBeGreaterThan(readingWidth);
  const attachment = page.locator(".writeup-assets a[download]").first();
  await expect(
    attachment.locator(".writeup-asset-action + .writeup-asset-copy"),
  ).toBeVisible();
  await expect(attachment).toHaveCSS("text-decoration-line", "none");
  await expect(attachment.locator(".writeup-asset-name")).toHaveCSS(
    "text-decoration-line",
    "underline",
  );
  const mediaWidths = await content
    .locator("img, pre")
    .evaluateAll((elements) =>
      elements.map((element) => element.getBoundingClientRect().width),
    );
  expect(mediaWidths.length).toBeGreaterThan(1);
  expect(Math.max(...mediaWidths)).toBeLessThanOrEqual(readingWidth);
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
    const header = table.getByRole("columnheader").first();
    await expect(header).toHaveCSS("text-align", "left");
    await expect(header).toHaveCSS("padding-inline-end", "12px");
    await expect(header).toHaveCSS("border-right-style", "solid");
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
