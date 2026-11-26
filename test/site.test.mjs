import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { parse } from "parse5";

const origin = "https://ctf-flags.dev";
const dist = resolve("dist");
const utilities = [
  "number",
  "base",
  "url",
  "rot",
  "xor",
  "morse",
  "timestamp",
  "jwt",
];

async function filesUnder(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const groups = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? filesUnder(path) : [path];
    }),
  );
  return groups.flat();
}

function walk(node) {
  return [node, ...(node.childNodes ?? []).flatMap(walk)];
}

function attr(node, name) {
  return node?.attrs?.find((attribute) => attribute.name === name)?.value;
}

function relativePath(base, path) {
  return relative(base, path).split(sep).join("/");
}

const distFiles = filesUnder(dist);

const publicPages = (async () => {
  const files = await distFiles;
  const pages = files.filter((file) => {
    const path = relativePath(dist, file);
    return (
      !path.startsWith("assets/") &&
      !path.startsWith("partials/") &&
      (path.endsWith("/index.html") ||
        path === "index.html" ||
        path === "404.html")
    );
  });
  return new Map(
    await Promise.all(
      pages.map(async (file) => {
        const path = `/${relativePath(dist, file).replace(/index\.html$/, "")}`;
        const nodes = walk(parse(await readFile(file, "utf8")));
        return [
          path,
          {
            ids: new Set(nodes.map((node) => attr(node, "id")).filter(Boolean)),
            nodes,
          },
        ];
      }),
    ),
  );
})();

test("static pages match the archive source paths and use their production canonical URLs", async () => {
  const routes = ["/", "/404.html", "/resources/", "/utilities/"];
  for (const file of await filesUnder("src/content/resources")) {
    if (file.endsWith(".yaml"))
      routes.push(
        `/resources/${relativePath("src/content/resources", file).slice(0, -5)}/`,
      );
  }
  routes.push(...utilities.map((id) => `/utilities/${id}/`));
  for (const folder of ["_competitions", "_writeups"]) {
    for (const file of await filesUnder(folder)) {
      if (file.endsWith(".md"))
        routes.push(
          `/competitions/${relativePath(folder, file).slice(0, -3)}/`,
        );
    }
  }
  const pages = await publicPages;
  assert.deepEqual([...pages.keys()].sort(), routes.sort());
  for (const [path, { nodes }] of pages) {
    const canonical = nodes.find(
      (node) => node.tagName === "link" && attr(node, "rel") === "canonical",
    );
    assert.equal(attr(canonical, "href"), new URL(path, origin).href, path);
  }
});

test("every page has complete Open Graph and X preview metadata", async () => {
  const imagePath = "/caption.png";
  const image = await readFile(join(dist, imagePath));
  const width = image.readUInt32BE(16);
  const height = image.readUInt32BE(20);
  assert.deepEqual([width, height], [1200, 630]);

  for (const [path, { nodes }] of await publicPages) {
    const metadata = (attribute, key) => {
      const tags = nodes.filter(
        (node) => node.tagName === "meta" && attr(node, attribute) === key,
      );
      assert.equal(tags.length, 1, `${path} ${key}`);
      const value = attr(tags[0], "content");
      assert.ok(value?.trim(), `${path} ${key}`);
      return value;
    };
    const og = (key) => metadata("property", `og:${key}`);
    const card = (key) => metadata("name", `twitter:${key}`);
    const pageUrl = new URL(path, origin).href;
    const imageUrl = new URL(imagePath, origin).href;

    assert.equal(og("url"), pageUrl);
    assert.equal(og("description"), metadata("name", "description"));
    assert.ok(["website", "article"].includes(og("type")));
    assert.equal(og("site_name"), "ctf-flags.dev");
    assert.equal(og("locale"), "en_US");
    assert.equal(og("image"), imageUrl);
    assert.equal(og("image:type"), "image/png");
    assert.equal(og("image:width"), String(width));
    assert.equal(og("image:height"), String(height));
    assert.equal(card("card"), "summary_large_image");
    for (const key of ["url", "title", "description", "image", "image:alt"])
      assert.equal(card(key), og(key), `${path} ${key}`);

    if (path === "/404.html")
      assert.equal(metadata("name", "robots"), "noindex,follow");
  }
});

test("site icons match their declared sizes", async () => {
  const manifest = JSON.parse(
    await readFile(join(dist, "site.webmanifest"), "utf8"),
  );
  const pngIcons = [
    ...manifest.icons,
    { src: "/favicon-96.png", sizes: "96x96" },
    { src: "/favicon-512.png", sizes: "512x512" },
    { src: "/icon-180.png", sizes: "180x180" },
  ];
  for (const { src, sizes } of pngIcons) {
    const icon = await readFile(join(dist, src));
    assert.equal(
      `${icon.readUInt32BE(16)}x${icon.readUInt32BE(20)}`,
      sizes,
      src,
    );
  }

  const svg = await readFile(join(dist, "favicon.svg"), "utf8");
  assert.match(svg, /<svg\b/);
  const home = (await publicPages).get("/");
  assert.ok(
    home.nodes.some(
      (node) =>
        node.tagName === "link" &&
        attr(node, "rel") === "icon" &&
        attr(node, "type") === "image/svg+xml" &&
        attr(node, "sizes") === "any" &&
        attr(node, "href") === "/favicon.svg",
    ),
  );

  const favicon = await readFile(join(dist, "favicon.ico"));
  assert.equal(favicon.readUInt16LE(0), 0);
  assert.equal(favicon.readUInt16LE(2), 1);
  assert.equal(favicon.readUInt16LE(4), 3);
  let offset = 54;
  for (const [index, size] of [16, 32, 48].entries()) {
    const entry = 6 + index * 16;
    assert.deepEqual(
      [...favicon.subarray(entry, entry + 4)],
      [size, size, 0, 0],
    );
    assert.equal(favicon.readUInt16LE(entry + 4), 1);
    assert.equal(favicon.readUInt16LE(entry + 6), 32);
    assert.equal(favicon.readUInt32LE(entry + 12), offset);
    assert.equal(
      favicon.subarray(offset, offset + 8).toString("hex"),
      "89504e470d0a1a0a",
    );
    assert.equal(favicon.readUInt32BE(offset + 16), size);
    assert.equal(favicon.readUInt32BE(offset + 20), size);
    offset += favicon.readUInt32LE(entry + 8);
  }
  assert.equal(offset, favicon.length);
});

test("published links, media and heading fragments resolve within the static artifact", async () => {
  const pages = await publicPages;
  const filePaths = new Set(
    (await distFiles).map((file) => `/${relativePath(dist, file)}`),
  );

  for (const [path, { nodes }] of pages) {
    for (const node of nodes) {
      for (const attribute of ["href", "src", "poster"]) {
        const target = attr(node, attribute);
        if (!target) continue;
        const url = new URL(target, new URL(path, origin));
        if (url.origin !== origin) continue;
        const pathname = decodeURIComponent(url.pathname);
        const page = pages.get(pathname) ?? pages.get(`${pathname}/`);
        if (page) {
          if (url.hash)
            assert.ok(
              page.ids.has(decodeURIComponent(url.hash.slice(1))),
              `${path} -> ${target}`,
            );
        } else {
          assert.ok(filePaths.has(pathname), `${path} -> ${target}`);
        }
      }
    }
  }
});

test("sitemap contains every public canonical page except the 404", async () => {
  const xml = await readFile(join(dist, "sitemap.xml"), "utf8");
  const entries = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(
    ([, url]) => url,
  );
  const canonical = [...(await publicPages).keys()]
    .filter((path) => path !== "/404.html")
    .map((path) => new URL(path, origin).href);
  assert.deepEqual(entries.sort(), canonical.sort());
  const dates = [...xml.matchAll(/<lastmod>([^<]+)<\/lastmod>/g)];
  for (const [, date] of dates) {
    assert.ok(Number.isFinite(Date.parse(date)), date);
  }
  if (process.env.GITHUB_ACTIONS === "true") {
    assert.equal(
      dates.length,
      canonical.length,
      "The Pages build has full Git history",
    );
  }
});

test("utility paths render all tabs with the requested tab selected", async () => {
  const pages = await publicPages;
  for (const path of [
    "/utilities/",
    ...utilities.map((id) => `/utilities/${id}/`),
  ]) {
    const { nodes } = pages.get(path);
    const buttons = nodes.filter((node) => attr(node, "data-utility"));
    assert.deepEqual(
      buttons.map((button) => attr(button, "data-utility")),
      utilities,
    );
    const selected = buttons.filter(
      (button) => attr(button, "aria-pressed") === "true",
    );
    assert.deepEqual(
      selected.map((button) => attr(button, "data-path")),
      [path === "/utilities/" ? "/utilities/number/" : path],
    );

    for (const button of buttons) {
      const panel = nodes.find(
        (node) => attr(node, "id") === attr(button, "aria-controls"),
      );
      assert.ok(panel, attr(button, "data-utility"));
      assert.equal(attr(panel, "aria-labelledby"), attr(button, "id"));
      assert.equal(attr(panel, "hidden") === undefined, button === selected[0]);
    }
  }
});

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

test("the output contains the same attachments and bytes as the public source tree", async () => {
  const sourceDir = resolve("public/assets/files");
  const outputDir = join(dist, "assets/files");
  const [sourceFiles, outputFiles] = await Promise.all([
    filesUnder(sourceDir),
    filesUnder(outputDir),
  ]);
  const relativeFiles = sourceFiles.map((file) =>
    relativePath(sourceDir, file),
  );
  assert.deepEqual(
    relativeFiles.sort(),
    outputFiles.map((file) => relativePath(outputDir, file)).sort(),
  );

  for (const file of relativeFiles) {
    const [source, output] = await Promise.all([
      sha256(join(sourceDir, file)),
      sha256(join(outputDir, file)),
    ]);
    assert.equal(output, source, file);
  }
});
