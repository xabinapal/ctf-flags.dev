# CTF Signals

A modern, terminal-inspired GitHub Pages blog for collecting Capture The Flag writeups. The site is powered by
[Jekyll](https://jekyllrb.com/) and renders Markdown posts with a neon console aesthetic that stays
readable on large and small screens.

![Screenshot of the homepage](docs/screenshot-home.png)

## Structure

- `index.md` &mdash; homepage that lists competitions with available writeups.
- `_competitions/` &mdash; one Markdown file per competition with metadata, schedule, and overview.
- `_posts/` &mdash; Markdown posts following the `YYYY-MM-DD-title.md` naming convention.
- `_layouts/` &mdash; HTML templates for pages and posts.
- `assets/css/style.css` &mdash; custom styling for the modern terminal look.
- `_config.yml` &mdash; Jekyll configuration and metadata.
- `.github/workflows/pages.yml` &mdash; GitHub Actions workflow that builds and deploys the site to Pages.

## Creating a new writeup

1. Add or update the competition entry in `_competitions/`:

   ```markdown
   ---
   key: signalfest-2024          # short identifier used by posts
   name: SignalFest 2024         # human friendly name
   start_date: 2024-04-26        # ISO date so ordering works
   end_date: 2024-04-28
   location: Remote
   summary: Optional short blurb that appears on the homepage.
   ---

   Longer Markdown description, highlights, or preparation notes.
   ```

2. Create a Markdown file in `_posts/` with front matter linking it to the competition via the `competition`
   key:

   ```markdown
   ---
   layout: post
   title: "Challenge name"
   summary: Quick one-liner description.
   competition: signalfest-2024
   category: reverse engineering
   ---

   ## Heading
   Your writeup here in Markdown.
   ```

3. (Optional) Attach challenge files by placing them under `assets/files/<competition>/<slug>/` and listing
   them in the post front matter:

   ```yaml
   attachments:
     - title: Challenge artifacts
       url: /assets/files/signalfest-2024/echo-capture/echo-capture-artifacts.txt
       description: Packet capture and helper scripts.
   ```

   Each attachment renders as a download card near the end of the post. The `url` can point to any static file
   tracked in the repository or uploaded alongside the post.

4. Commit and push to `main`. GitHub Pages will build the site automatically. The rendered post will appear at
   `https://your-github-username.github.io/ctf-writeups/`.

## Local preview

### Using Docker (recommended)

Run the site inside a pre-built Jekyll container that installs the GitHub Pages gem bundle on startup:

```bash
docker compose up
```

The first run installs the bundle before launching the server. Once the build is ready, visit
<http://localhost:4000> for the rendered site and <http://localhost:35729> for live-reload events. Changes to
Markdown, layouts, or styles automatically trigger a rebuild.

Bundler caches the gems inside the container. It may still create or update a `Gemfile.lock` file in the
repository; commit it to pin versions or discard it after you finish previewing.

Stop the server with <kbd>Ctrl+C</kbd> and remove the container with `docker compose down` if needed.

### Using a local Ruby toolchain

If you prefer running Jekyll directly on your machine, install Ruby (>= 3.0), Bundler, and the dependencies in
the `Gemfile`:

```bash
bundle install
bundle exec jekyll serve
```

Then open <http://localhost:4000> in your browser to preview the site.

## Screenshot

To capture the screenshot reference, build the site locally and use your preferred tool or take it directly
from the GitHub Pages deployment.
