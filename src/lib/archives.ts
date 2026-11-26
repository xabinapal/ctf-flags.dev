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

export function groupWriteups(writeups: Writeup[]) {
  const groups = new Map<string, Writeup[]>();
  for (const entry of writeups) {
    const category = entry.data.challenge_type?.trim() || "uncategorized";
    const group = groups.get(category) ?? [];
    group.push(entry);
    groups.set(category, group);
  }
  return [...groups]
    .sort(([left], [right]) => compareText(left, right))
    .map(([category, entries]) => ({
      category: category.toLowerCase(),
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

export function attribution(data: Writeup["data"]) {
  return [
    data.difficulty,
    data.author && `By ${data.author}`,
    data.writeup_author && `Writeup by ${data.writeup_author}`,
  ].filter((item): item is string => Boolean(item?.trim()));
}
