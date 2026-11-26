import { unified } from "@astrojs/markdown-remark";
import { defineConfig } from "astro/config";
import { scrollableMarkdownTables } from "./src/lib/markdown-tables.mjs";

export default defineConfig({
  site: "https://ctf-flags.dev",
  output: "static",
  trailingSlash: "ignore",
  devToolbar: { enabled: false },
  markdown: {
    processor: unified({ rehypePlugins: [scrollableMarkdownTables] }),
    shikiConfig: { theme: "css-variables" },
  },
});
