# ctf-flags.dev

A static Astro site for browsing Capture The Flag writeups, finding resources, and using browser-based utilities. The site is published at [ctf-flags.dev](https://ctf-flags.dev/).

## Develop locally

Install the Node.js and npm versions pinned in `mise.toml`. GitHub Pages uses the same pins.

```sh
mise install
mise exec -- npm ci
mise exec -- npm run dev
```

Open <http://localhost:4321>. To check a production build locally, run the same checks as the Pages workflow and start Astro preview.

```sh
mise exec -- npm run lint
mise exec -- npm run check
mise exec -- npm run build
mise exec -- npm test
mise exec -- npm exec -- playwright install --only-shell chromium
mise exec -- npm run test:browser
mise exec -- npm run preview
```

`npm test` validates the existing build in `dist/`. `npm run test:browser` starts Astro preview and checks the built site in Chromium using Playwright Test. Run `npm run format` to format supported application files. Markdown articles and their downloads are excluded from the formatter.

Astro builds `src/styles/site.css` into `/assets/css/style.css`. Pages link to a versioned stylesheet URL and preload the self-hosted Asul and Inconsolata fonts.

Export square PNGs at 16, 32, 48, 96, 180, 192, and 512 px as `favicon_new_ctf_<size>.png`. Run `node scripts/generate-brand-assets.mjs <export-directory>` to install the original PNGs and package the ICO. Export social preview artwork separately as a 1200 × 630 PNG at `public/caption.png`.

## Publish a competition or writeup

1. Create `_competitions/<key>.md` with `key`, `title`, `start_date`, and `end_date`. Use ISO calendar dates such as `2026-11-21`. The optional fields are `ranking`, `points`, and `ctftime_url`. Write the competition description in the Markdown body. The homepage uses that same description for its excerpt. The filename determines the competition URL.
2. Create `_writeups/<key>/<slug>.md`. Keep existing filenames stable because paths below `_writeups/` determine public permalinks. Use the competition's `key` as the `competition` value.

   ```markdown
   ---
   title: "Challenge name"
   competition: sample-2026
   challenge_type: Misc
   summary: "Short challenge description."
   writeup_author: "handle"
   ---

   ## Notes

   Write the article in Markdown.
   ```

   Set optional `difficulty` to one of `beginner`, `easy`, `medium`, `hard`, or `insane`.

   Write author names without `@` in `author` and `writeup_author`. Use a YAML list when a role has several authors.

3. Put attachments and media in `public/assets/files/<key>/<slug>/`. Refer to downloads in the writeup's `attachments` list using fields `title`, `url`, and optionally `description`. Use the root-relative URL `/assets/files/<key>/<slug>/<filename>`.
4. Preview the page, inspect its attachments, and run the checks above before opening a pull request.

The build generates `/competitions/<key>/` and `/competitions/<key>/<slug>/` from the Markdown filenames. Archive cards use `competition` to associate a writeup with its competition. Resource categories are Astro content entries under `src/content/resources/`. Each YAML filename supplies the category key, and its `resources` list contains the entries.

## Deployment

Pull requests and manual runs on other refs run the build and checks in their own concurrency groups. A push to `main` or a manual run targeting `main` builds and deploys `dist/` through the GitHub Pages environment. Keep the Pages source set to GitHub Actions and the custom domain set to `ctf-flags.dev`. URLs and assets assume deployment at the domain root. The workflow checks out full Git history for sitemap modification dates. The dates use the last recorded changes to each page’s content sources.

After deployment, check the homepage, a known competition and writeup permalink, an attachment, the resources and utilities, `/sitemap.xml`, and a missing URL. If the cutover needs to be reversed, revert the migration on `main` to trigger the previous build and deploy workflow.
