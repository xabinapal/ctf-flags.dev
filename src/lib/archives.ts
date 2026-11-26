import { type CollectionEntry, getCollection } from "astro:content";

export type Competition = CollectionEntry<"competitions">;
export type Writeup = CollectionEntry<"writeups">;

export function archivePath(entry: Competition | Writeup) {
  return `/competitions/${entry.id}/`;
}

function compareText(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export async function loadArchive() {
  const [competitions, writeups] = await Promise.all([
    getCollection("competitions"),
    getCollection("writeups"),
  ]);
  const competitionsByKey = new Map<string, Competition>();
  const writeupsByCompetition = new Map<string, Writeup[]>();
  for (const competition of competitions) {
    const key = competition.data.key;
    if (competitionsByKey.has(key)) {
      throw new Error(`Duplicate competition key "${key}"`);
    }
    competitionsByKey.set(key, competition);
    writeupsByCompetition.set(key, []);
  }
  for (const writeup of writeups) {
    const group = writeupsByCompetition.get(writeup.data.competition);
    if (!group) {
      throw new Error(
        `Writeup "${writeup.id}" refers to unknown competition "${writeup.data.competition}"`,
      );
    }
    group.push(writeup);
  }

  competitions.sort(
    (left, right) =>
      compareText(right.data.start_date, left.data.start_date) ||
      compareText(right.data.end_date, left.data.end_date) ||
      compareText(
        left.data.title.toLowerCase(),
        right.data.title.toLowerCase(),
      ) ||
      compareText(left.id, right.id),
  );
  return { competitions, competitionsByKey, writeups, writeupsByCompetition };
}

export function writeupCategory(data: Writeup["data"]) {
  return data.challenge_type?.trim().toLowerCase();
}

export function groupWriteups(writeups: Writeup[]) {
  const groups = new Map<string, Writeup[]>();
  for (const entry of writeups) {
    const category = writeupCategory(entry.data) || "uncategorized";
    const group = groups.get(category) ?? [];
    group.push(entry);
    groups.set(category, group);
  }
  return [...groups]
    .sort(([left], [right]) => compareText(left, right))
    .map(([category, entries]) => ({
      category,
      entries: entries.sort(
        (left, right) =>
          compareText(left.data.title, right.data.title) ||
          compareText(left.id, right.id),
      ),
    }));
}

const dateFormat = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  timeZone: "UTC",
});

export function formatDate(date: string) {
  return dateFormat.format(new Date(date));
}

export interface Attribution {
  label: string;
  names?: string[];
}

function namesWithoutPrefix(value: string | string[] | undefined) {
  const names =
    typeof value === "string" ? value.split(/\s+(?=@)/u) : (value ?? []);
  return names
    .map((name) => name.trim().replace(/^@+\s*/u, ""))
    .filter(Boolean);
}

export function attribution(data: Writeup["data"]): Attribution[] {
  const parts: Attribution[] = [];
  const difficulty = data.difficulty;
  const authors = namesWithoutPrefix(data.author);
  const writers = namesWithoutPrefix(data.writeup_author);
  if (difficulty) parts.push({ label: difficulty });
  if (authors.length) parts.push({ label: "by", names: authors });
  if (writers.length) parts.push({ label: "writeup by", names: writers });
  return parts;
}
