import { expect, test } from "@playwright/test";

test("invalid input is explained beside the field and clears stale output", async ({
  page,
}) => {
  const cases = [
    [
      "number",
      "Base 10 (Decimal)",
      "65",
      "65x",
      /digits 0–9/,
      "Base 16 (Hexadecimal)",
      "41",
    ],
    ["base", "Base64", "QQ==", "@@@", /Base64 characters/, "Plaintext", "A"],
    [
      "url",
      "URL Encoded",
      "hello%20world",
      "hello%2",
      /valid percent escapes/,
      "Plaintext",
      "hello world",
    ],
    [
      "morse",
      "Morse Code",
      "...",
      "......",
      /Unknown Morse sequence/,
      "Plaintext",
      "S",
    ],
    [
      "timestamp",
      "Unix (seconds)",
      "0",
      "0junk",
      /whole number/,
      "ISO 8601",
      "1970-01-01T00:00:00.000Z",
    ],
  ];
  for (const [
    tool,
    label,
    valid,
    invalid,
    message,
    outputLabel,
    converted,
  ] of cases) {
    await page.goto(`/utilities/${tool}/`);
    const panel = page.getByRole("region");
    const field = panel.getByLabel(label, { exact: true });
    const output = panel.getByLabel(outputLabel, { exact: true });
    await field.fill(valid);
    await expect(output).toHaveValue(converted);
    await field.fill(invalid);
    await expect(field).toHaveValue(invalid);
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(field).toHaveAccessibleDescription(message);
    await expect(output).toHaveValue("");
    await field.fill(valid);
    await expect(field).not.toHaveAttribute("aria-invalid", "true");
    await expect(output).toHaveValue(converted);
  }
});

test("base conversions match reference vectors and preserve binary bytes", async ({
  page,
}) => {
  await page.goto("/utilities/base/");
  const field = (name) =>
    page
      .getByRole("region", { name: "Base" })
      .getByLabel(name, { exact: true });
  await field("Plaintext").fill("AB");
  await expect(field("Base45")).toHaveValue("BB8");
  await expect(field("Base85 (ASCII85)")).toHaveValue("5sb");
  await field("Base45").fill("QED8WEX0");
  await expect(field("Plaintext")).toHaveValue("ietf!");
  await field("Plaintext").fill("hello world");
  await expect(field("Base92")).toHaveValue("Fc_$aOTdKnsM*k");
  await field("Base92").fill("Fc_$aOTdKnsM*k");
  await expect(field("Plaintext")).toHaveValue("hello world");
  await field("Base85 (ASCII85)").fill("<~5sb~>");
  await expect(field("Plaintext")).toHaveValue("AB");
  await field("Base64").fill("AP8=");
  await expect(field("Plaintext")).toHaveValue("");
  await expect(field("Base58")).toHaveValue("15Q");
  await expect(
    page.getByText("Binary bytes. Copy an encoded form.", { exact: false }),
  ).toBeVisible();
});

test("ROT shift changes recompute output, including a shift of zero", async ({
  page,
}) => {
  await page.goto("/utilities/rot/");
  const plaintext = page
    .getByRole("region", { name: "ROT" })
    .getByLabel("Plaintext", { exact: true });
  const shift = page.getByLabel("Rotation shift", { exact: true });
  const output = page.getByLabel("ROTN", { exact: true });
  await plaintext.fill("abc");
  await expect(output).toHaveValue("nop");
  await shift.fill("0");
  await expect(output).toHaveValue("abc");
  await shift.fill("27");
  await expect(shift).toHaveAccessibleDescription(/whole-number shift/);
  await expect(output).toHaveValue("");
  await shift.fill("1");
  await expect(output).toHaveValue("bcd");
  await output.fill("abc");
  await expect(plaintext).toHaveValue("zab");
  await shift.fill("2");
  await expect(plaintext).toHaveValue("zab");
  await expect(output).toHaveValue("bcd");

  await plaintext.fill("日本語 🔎");
  const rot = page.getByLabel("ROT8000", { exact: true });
  const encoded = await rot.inputValue();
  expect(encoded).not.toBe("日本語 🔎");
  await plaintext.fill("");
  await rot.fill(encoded);
  await expect(plaintext).toHaveValue("日本語 🔎");
});

test("XOR retains non-UTF-8 bytes when the key changes and rejects incomplete hex", async ({
  page,
}) => {
  await page.goto("/utilities/xor/");
  const input = page.getByLabel("Input (HEX)", { exact: true });
  const key = page.getByLabel("Key (HEX)", { exact: true });
  const result = page.getByLabel("Output (HEX)", { exact: true });
  await input.fill("ff");
  await key.fill("00");
  await expect(result).toHaveValue("ff");
  await key.fill("01");
  await expect(result).toHaveValue("fe");
  await input.fill("f");
  await expect(input).toHaveAccessibleDescription(/complete hexadecimal bytes/);
  await expect(result).toHaveValue("");
  await input.fill("ff");
  await expect(result).toHaveValue("fe");
});

test("timestamps preserve nanoseconds and validate calendar dates", async ({
  page,
}) => {
  await page.goto("/utilities/timestamp/");
  const nanos = page.getByLabel("Unix (nanoseconds)", { exact: true });
  const iso = page.getByLabel("ISO 8601", { exact: true });
  await nanos.fill("-1");
  await expect(iso).toHaveValue("1969-12-31T23:59:59.999999999Z");
  await iso.fill("2026-01-01T01:00:00.123456789+01:00");
  await expect(nanos).toHaveValue("1767225600123456789");
  await iso.fill("2026-02-30");
  await expect(iso).toHaveAccessibleDescription(/valid calendar date/);
  await expect(nanos).toHaveValue("");
  await iso.fill("2026-01-01");
  await expect(
    page.getByLabel("Windows FILETIME", { exact: true }),
  ).toHaveValue("134116992000000000");
});

test("JWT decodes UTF-8 JSON and explains malformed segments", async ({
  page,
}) => {
  await page.goto("/utilities/jwt/");
  const input = page.getByLabel("JWT Token", { exact: true });
  await input.fill(
    `eyJhbGciOiJub25lIn0.${Buffer.from('{"message":"España 🔎"}').toString("base64url")}.`,
  );
  await expect(page.locator("#jwt-payload")).toHaveValue(/España 🔎/);
  await input.fill("eyJhbGciOiJub25lIn0.nope.");
  await expect(input).toHaveAccessibleDescription(/payload must contain/);
  await expect(page.locator("#jwt-header")).toHaveValue("");
  await expect(page.locator("#jwt-payload")).toHaveValue("");
});

test("examples, copy, and clear work at mobile width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => {
    Object.defineProperty(navigator.clipboard, "writeText", {
      value: async (value) => {
        if (window.blockClipboard) throw new Error("Clipboard blocked");
        window.copiedValue = value;
      },
    });
  });
  await page.goto("/utilities/number/");
  await page.getByRole("button", { name: "Try example" }).click();
  const ascii = page.getByLabel("ASCII Text", { exact: true });
  await expect(ascii).toHaveValue(/^flag\{.+\}$/);
  const expectedHex = Buffer.from(await ascii.inputValue())
    .toString("hex")
    .toUpperCase();
  await expect(
    page.getByLabel("Base 16 (Hexadecimal)", { exact: true }),
  ).toHaveValue(expectedHex);
  const copy = page.getByRole("button", { name: "Copy Base 16 (Hexadecimal)" });
  await copy.click();
  expect(await page.evaluate(() => window.copiedValue)).toBe(expectedHex);
  await expect(copy).toHaveText("Copied");
  await expect(page.getByRole("status")).toHaveText(
    "Base 16 (Hexadecimal) copied.",
  );
  await page.evaluate(() => {
    window.blockClipboard = true;
  });
  await copy.click();
  await expect(copy).toHaveText("Selected");
  await expect(page.getByRole("status")).toHaveText(
    /selected for manual copying/,
  );
  const hex = page.getByRole("textbox", {
    name: "Base 16 (Hexadecimal)",
    exact: true,
  });
  expect(
    await hex.evaluate((field) =>
      field.value.slice(field.selectionStart, field.selectionEnd),
    ),
  ).toBe(expectedHex);
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(copy).toBeDisabled();
  await expect(
    page.getByLabel("Base 16 (Hexadecimal)", { exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
});

for (const width of [390, 1440]) {
  test(`validation keeps the workbench layout stable at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.goto("/utilities/url/");
    const field = page.getByRole("textbox", {
      name: "URL Encoded",
      exact: true,
    });
    const layout = () =>
      page
        .locator(".utility-panel:visible .form-control, .site-footer")
        .evaluateAll((nodes) =>
          nodes.map((node) => {
            const rect = node.getBoundingClientRect();
            return [rect.x, rect.y + window.scrollY, rect.width, rect.height];
          }),
        );
    await field.fill("flag%7Bhello%7D");
    await page.evaluate(() => document.fonts.ready);
    const before = await layout();
    if (width < 656) {
      const [plaintext, encoded] = await page
        .locator(".utility-panel:visible .input-group")
        .all();
      const firstField = await plaintext.getByRole("textbox").boundingBox();
      const nextLabel = await encoded.locator(".field-label").boundingBox();
      expect(nextLabel.y - (firstField.y + firstField.height)).toBeLessThan(48);
    }
    await field.fill("%zz");
    await expect(field).toHaveAccessibleDescription(/valid percent escapes/);
    const message = page.locator("#url-encoded-message");
    await expect(message).toHaveCSS("color", "rgb(246, 169, 157)");
    const messageFits = await page
      .locator("#url-encoded-message")
      .evaluate((error) => error.scrollHeight <= error.clientHeight);
    expect(messageFits).toBe(true);
    expect(await layout()).toEqual(before);
    await field.fill("");
    expect(await layout()).toEqual(before);
  });
}

test("editing any JWT segment rebuilds the token and preserves other drafts", async ({
  page,
}) => {
  await page.goto("/utilities/jwt/");
  const textbox = (name) => page.getByRole("textbox", { name, exact: true });
  const token = textbox("JWT Token");
  const header = textbox("Header");
  const payload = textbox("Payload");
  const signature = textbox("Signature");

  await page.getByRole("button", { name: "Try example" }).click();
  await expect(payload).toHaveValue(/"flag": "flag\{[^}]+\}"/);
  const headerText = '{"typ":"JWT","alg":"HS256"}';
  const payloadText = '{"flag":"flag{edición}","number":12345678901234567890}';
  const encoded = (text) => Buffer.from(text).toString("base64url");
  await header.fill(headerText);
  await payload.fill(payloadText);
  await signature.fill("AQID");
  const expectedToken = `${encoded(headerText)}.${encoded(payloadText)}.AQID`;
  await expect(token).toHaveValue(expectedToken);
  await payload.fill('{"incomplete"');
  await expect(payload).toHaveAccessibleDescription(/valid JSON object/);
  await expect(token).toHaveValue("");
  await expect(header).toHaveValue(headerText);
  await expect(signature).toHaveValue("AQID");
  await payload.fill(payloadText);
  await expect(token).toHaveValue(expectedToken);
  await signature.fill("+");
  await expect(signature).toHaveAccessibleDescription(/Base64URL characters/);
  await expect(token).toHaveValue("");
  await signature.fill("");
  await expect(token).toHaveValue(
    `${encoded(headerText)}.${encoded(payloadText)}.`,
  );

  await page.getByRole("button", { name: "Clear" }).click();
  await token.fill(expectedToken);
  await expect(payload).toHaveValue(payloadText);
});

test("Morse example uses supported punctuation and matching field heights", async ({
  page,
}) => {
  await page.goto("/utilities/morse/");
  await page.getByRole("button", { name: "Try example" }).click();
  const plaintext = page.getByRole("textbox", {
    name: "Plaintext",
    exact: true,
  });
  const encoded = page.getByRole("textbox", {
    name: "Morse Code",
    exact: true,
  });
  await expect(plaintext).toHaveValue(/^flag\(.+\)$/);
  await expect(plaintext).not.toHaveAttribute("aria-invalid", "true");
  await expect(encoded).toHaveValue(/^[.\-/ ]+$/);
  const [left, right] = await Promise.all([
    plaintext.boundingBox(),
    encoded.boundingBox(),
  ]);
  expect(left.height).toBe(right.height);
});

test("flag examples cycle through the whole pool before repeating", async ({
  page,
}) => {
  await page.goto("/utilities/url/");
  const example = page.getByRole("button", { name: "Try example" });
  await expect(example).toBeEnabled();
  const flags = await example.evaluate((button) => {
    const plaintext = document.querySelector("#url-plaintext");
    return Array.from({ length: 65 }, () => {
      button.click();
      return plaintext.value;
    });
  });
  expect(flags.every((flag) => /^flag\{[a-z0-9_]+\}$/.test(flag))).toBe(true);
  expect(new Set(flags.slice(0, 64)).size).toBe(64);
  expect(flags[64]).not.toBe(flags[63]);
});
