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

3. Commit and push to `main`. GitHub Pages will build the site automatically. The rendered post will appear at
   `https://your-github-username.github.io/ctf-writeups/`.

## Local preview

GitHub Pages can build directly from your commits, but for a local preview you can install Ruby, Bundler, and
Jekyll:

```bash
gem install bundler jekyll
bundle exec jekyll serve
```

Then open <http://localhost:4000> in your browser to preview the site.

## Screenshot

To capture the screenshot reference, build the site locally and use your preferred tool or take it directly
from the GitHub Pages deployment.
