---
layout: default
summary: CTF writeups, challenge solutions, and cybersecurity insights from a solo enthusiast. Explore practical walkthroughs and tips for infosec challenges.
---
<section class="hero">
  <h1>flag{w3lc0m3}</h1>
  <p class="summary">
    This is one of those strange corners of the Internet where people break things to have fun. A playground full of cursed binaries, glitchy websites, and riddles that make you question your sanity. Here you will find writeups of all this chaos.
  </p>
</section>

<section >
  <h2>CTF Competitions</h2>
  {%- assign competitions = site.competitions | sort_competitions -%}
  {%- if competitions and competitions.size > 0 -%}
  <ul class="list competition-grid">
    {%- for competition in competitions -%}
    <li class="list-item">
      <a href="{{ competition.url | relative_url }}" class="card-link">
        <div class="card no-padding">
          <div class="card-content">
            <h3 class="card-title">{{ competition.title }}</h3>
            <div class="meta">
              <span>{{ competition.start_date | date: "%b %d, %Y" }} &mdash; {{ competition.end_date | date: "%b %d, %Y" }}</span>
            </div>
            {%- assign competition_writeups = site.writeups | where: 'competition', competition.key -%}
            <p class="summary">
              {{- competition.summary | markdownify | strip_block_html | truncate_words: 160 | strip_newlines | strip -}}
            </p>
            {%- if competition.ranking or competition.points -%}
            <div class="results">
              {%- if competition.ranking -%}
              <span class="chip-squared">🏆 Rank: {{ competition.ranking }}</span>
              {%- endif -%}
              {%- if competition.points -%}
              <span class="chip-squared">📊 Points: {{ competition.points }}</span>
              {%- endif -%}
            </div>
            {%- endif -%}
            {%- assign writeup_count = competition_writeups | size -%}
            <p class="card-count">
              {%- if writeup_count == 0 -%}
              No writeups yet
              {%- elsif writeup_count == 1 -%}
              1 writeup
              {%- else -%}
              {{ writeup_count }} writeups
              {%- endif -%}
            </p>
          </div>
        </div>
      </a>
    </li>
    {%- endfor -%}
  </ul>
  {%- else -%}
  <p class="empty-state">No competitions logged yet. Publish a writeup to get started.</p>
  {%- endif -%}
</section>
