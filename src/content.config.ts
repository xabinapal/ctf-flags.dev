import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "astro/zod";

const slug = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const date = z.preprocess(
  (value) => (value instanceof Date ? value.toISOString().slice(0, 10) : value),
  z.iso.date(),
);

const competitions = defineCollection({
  loader: glob({
    base: "./_competitions",
    pattern: "*.md",
    generateId: ({ entry }) => slug.parse(entry.replace(/\.md$/, "")),
  }),
  schema: z.object({
    key: slug,
    title: z.string(),
    start_date: date,
    end_date: date,
    ctftime_url: z.url().optional(),
    summary: z.string().optional(),
    ranking: z.union([z.string(), z.number()]).optional(),
    points: z.union([z.string(), z.number()]).optional(),
  }),
});

const writeups = defineCollection({
  loader: glob({
    base: "./_writeups",
    pattern: "*/*.md",
    generateId: ({ entry }) =>
      entry
        .replace(/\.md$/, "")
        .split("/")
        .map((part) => slug.parse(part))
        .join("/"),
  }),
  schema: z.object({
    title: z.string(),
    competition: slug,
    summary: z.string().optional(),
    challenge_type: z.string().optional(),
    difficulty: z.string().optional(),
    author: z.string().optional(),
    writeup_author: z.string().optional(),
    image_width: z.literal("narrow").optional(),
    connections: z
      .array(
        z.object({
          url: z.string(),
          description: z.string().optional(),
        }),
      )
      .optional(),
    attachments: z
      .array(
        z.object({
          title: z.string(),
          url: z.string().nullish(),
          description: z.string().optional(),
        }),
      )
      .optional(),
  }),
});

const resources = defineCollection({
  loader: glob({
    base: "./src/content/resources",
    pattern: "*.yaml",
    generateId: ({ entry }) => slug.parse(entry.replace(/\.yaml$/, "")),
  }),
  schema: z.object({
    resources: z.array(
      z.object({
        name: z.string(),
        description: z.string(),
        url: z.url(),
      }),
    ),
  }),
});

export const collections = { competitions, writeups, resources };
