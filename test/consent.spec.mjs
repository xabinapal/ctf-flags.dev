import { expect, test } from "@playwright/test";

async function observeAnalytics(page) {
  let requests = 0;
  await page.context().route(/^https:\/\//, (route) => route.abort());
  await page.route(
    /^https:\/\/www\.googletagmanager\.com\/gtag\/js\?/,
    (route) => {
      requests++;
      return route.fulfill({ contentType: "text/javascript", body: "" });
    },
  );
  return () => requests;
}

test("analytics starts after acceptance and the choice survives a reload", async ({
  page,
}) => {
  const requests = await observeAnalytics(page);
  const accept = page.getByRole("button", { name: "Accept", exact: true });
  await page.goto("/");
  await expect(accept).toBeVisible();
  expect(requests()).toBe(0);

  await accept.click();
  await expect(accept).toBeHidden();
  await expect.poll(requests).toBe(1);
  await page.reload();
  await expect(accept).toBeHidden();
  await expect.poll(requests).toBe(2);
});

test("declining keeps analytics off for the session", async ({ page }) => {
  const requests = await observeAnalytics(page);
  const decline = page.getByRole("button", { name: "Decline", exact: true });
  await page.goto("/");
  await decline.click();
  await expect(decline).toBeHidden();
  await page.reload();
  await expect(decline).toBeHidden();
  expect(requests()).toBe(0);
});

test("both choices work when local and session storage are blocked", async ({
  page,
}) => {
  const requests = await observeAnalytics(page);
  await page.addInitScript(() => {
    for (const name of ["localStorage", "sessionStorage"]) {
      Object.defineProperty(window, name, {
        get() {
          throw new DOMException("Storage blocked", "SecurityError");
        },
      });
    }
  });

  await page.goto("/");
  const decline = page.getByRole("button", { name: "Decline", exact: true });
  const accept = page.getByRole("button", { name: "Accept", exact: true });
  await expect(decline).toBeVisible();
  expect(requests()).toBe(0);
  await decline.click();
  await expect(decline).toBeHidden();
  expect(requests()).toBe(0);

  await page.reload();
  await expect(accept).toBeVisible();
  expect(requests()).toBe(0);
  await accept.click();
  await expect(accept).toBeHidden();
  await expect.poll(requests).toBe(1);

  await page.reload();
  await expect(accept).toBeVisible();
  expect(requests()).toBe(1);
});
