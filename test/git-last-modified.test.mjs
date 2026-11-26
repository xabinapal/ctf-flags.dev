import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { readGitLastModified } from "../src/lib/git-last-modified.ts";

test("Git dates follow edits and deletions from outside the project root", async (t) => {
  const cwd = await mkdtemp(join(tmpdir(), "sitemap-history-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const root = pathToFileURL(cwd + sep);
  const fixtureEnv = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
  );

  const git = (args, env = fixtureEnv) =>
    execFileSync(
      "git",
      [
        "-c",
        "user.name=Sitemap fixture",
        "-c",
        "user.email=fixture@site.test",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.hooksPath=/dev/null",
        ...args,
      ],
      { cwd, env, stdio: "pipe" },
    );
  function commit(date) {
    git(["add", "--all"]);
    git(["commit", "-qm", "Sitemap fixture"], {
      ...fixtureEnv,
      GIT_AUTHOR_DATE: date,
      GIT_COMMITTER_DATE: date,
    });
  }

  git(["init", "-q", "--template="]);
  const resources = "src/content/resources/";
  const resource = `${resources}example.yaml`;
  const template = "src/pages/[category].astro";
  await mkdir(join(cwd, resources), { recursive: true });
  await mkdir(join(cwd, "src/pages"), { recursive: true });
  await writeFile(join(cwd, resource), "name: example\n");
  await writeFile(join(cwd, template), "<p>Example</p>\n");
  const initial = "2026-11-01T12:00:00+00:00";
  const edit = "2026-11-02T12:00:00+00:00";
  const deletion = "2026-11-03T12:00:00+00:00";
  commit(initial);

  await writeFile(join(cwd, resource), "name: edited example\n");
  commit(edit);
  const sources = [resource, resources, template];
  assert.deepEqual(
    readGitLastModified(root, sources),
    new Map([
      [resource, edit],
      [resources, edit],
      [template, initial],
    ]),
  );

  await rm(join(cwd, resource));
  commit(deletion);
  assert.equal(readGitLastModified(root, [resources]).get(resources), deletion);
});
