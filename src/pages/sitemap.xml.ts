import type { APIRoute } from "astro";
import { root } from "astro:config/server";
import { getCollection } from "astro:content";
import { archivePath, loadArchive } from "../lib/archives";
import { readGitLastModified } from "../lib/git-last-modified";

export const GET: APIRoute = async ({ site }) => {
  const [archive, resources] = await Promise.all([
    loadArchive(),
    getCollection("resources"),
  ]);
  const { competitions, competitionsByKey, writeups, writeupsByCompetition } =
    archive;

  // Legacy paths retain dates across the source-file moves from Jekyll.
  const entries = [
    {
      path: "/",
      sources: [
        "src/pages/index.astro",
        "index.md",
        "_competitions/",
        "_writeups/",
      ],
    },
    {
      path: "/resources/",
      sources: [
        "src/pages/resources.astro",
        "src/scripts/resource-filters.ts",
        "resources.md",
        "_resources/",
        "src/content/resources/",
        ...resources.map((entry) => entry.filePath),
      ],
    },
    {
      path: "/utilities/",
      sources: [
        "src/pages/utilities.astro",
        "src/components/utilities/",
        "src/scripts/utilities/",
        "utilities.md",
        "assets/js/utilities/",
        "partials/utilities/",
      ],
    },
    ...competitions.map((entry) => ({
      path: archivePath(entry),
      sources: [
        "src/pages/competitions/[competition]/index.astro",
        entry.filePath,
        `_writeups/${entry.data.key}/`,
        ...(writeupsByCompetition.get(entry.data.key) ?? []).map(
          (writeup) => writeup.filePath,
        ),
      ],
    })),
    ...writeups.map((entry) => ({
      path: archivePath(entry),
      sources: [
        "src/pages/competitions/[competition]/[writeup].astro",
        entry.filePath,
        competitionsByKey.get(entry.data.competition)?.filePath,
      ],
    })),
  ];
  const lastModified = readGitLastModified(
    root,
    entries.flatMap(({ sources }) =>
      sources.filter((source) => source !== undefined),
    ),
  );

  const urls = entries.map(({ path, sources }) => {
    const date = sources
      .map((source) => source && lastModified.get(source))
      .filter(Boolean)
      .sort()
      .at(-1);
    const location = new URL(path, site);
    return `<url><loc>${location.href}</loc>${date ? `<lastmod>${date}</lastmod>` : ""}</url>`;
  });

  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>\n`,
    { headers: { "Content-Type": "application/xml; charset=utf-8" } },
  );
};
