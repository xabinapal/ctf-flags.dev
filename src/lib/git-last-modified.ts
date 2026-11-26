import { spawnSync } from "node:child_process";

export function readGitLastModified(root: URL, sourcePaths: string[]) {
  const remaining = new Set(sourcePaths);
  const dates = new Map<string, string>();
  if (remaining.size === 0) return dates;

  const { status, stdout } = spawnSync(
    "git",
    [
      "--literal-pathspecs",
      "log",
      "--format=commit:%aI",
      "--name-only",
      "--no-renames",
      "--",
      ...remaining,
    ],
    { cwd: root, encoding: "utf8" },
  );
  if (status !== 0 || !stdout) return dates;

  let date = "";
  for (const line of stdout.split(/\r?\n/)) {
    if (line.startsWith("commit:")) {
      date = new Date(line.slice("commit:".length))
        .toISOString()
        .replace(".000Z", "+00:00");
    } else if (line && date) {
      if (remaining.delete(line)) dates.set(line, date);

      // Deleted files still contribute to pages that list a directory's contents.
      for (
        let slash = line.indexOf("/");
        slash !== -1;
        slash = line.indexOf("/", slash + 1)
      ) {
        const directory = line.slice(0, slash + 1);
        if (remaining.delete(directory)) dates.set(directory, date);
      }

      if (remaining.size === 0) break;
    }
  }
  return dates;
}
