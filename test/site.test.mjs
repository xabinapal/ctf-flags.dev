import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { parse } from "parse5";

const origin = "https://ctf-flags.dev";
const dist = resolve("dist");

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

test("each utility selector controls a server-rendered panel", async () => {
  const { nodes } = (await publicPages).get("/utilities/");
  const buttons = nodes.filter((node) => attr(node, "data-utility"));
  assert.equal(buttons.length, 8);
  assert.equal(
    buttons.filter((button) => attr(button, "aria-pressed") === "true").length,
    1,
  );

  for (const button of buttons) {
    const panel = nodes.find(
      (node) => attr(node, "id") === attr(button, "aria-controls"),
    );
    assert.ok(panel, attr(button, "data-utility"));
    assert.equal(attr(panel, "aria-labelledby"), attr(button, "id"));
    assert.equal(
      attr(panel, "hidden") === undefined,
      attr(button, "aria-pressed") === "true",
    );
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
