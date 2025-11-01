---
layout: default
---
<section class="hero">
  <h1>flag{w3lc0m3}</h1>
  <p>
    This is one of those strange corners of the Internet where people break things to have fun. A playground full of cursed binaries, glitchy websites, and riddles that make you question your sanity. Here you will find writeups of all this chaos.
  </p>
</section>

<section class="listing">
  <h2>CTF Competitions</h2>
  {%- assign competitions = site.competitions | sort: 'start_date' | reverse -%}
  {%- if competitions and competitions.size > 0 -%}
  <ul class="competition-grid">
    {%- for competition in competitions -%}
    <li class="competition-card">
      {%- assign competition_key = competition.key | default: competition.slug -%}
      <a class="competition-card-link" href="{{ competition.url | relative_url }}">
        <h3 class="competition-card-title">{{ competition.name | default: competition.title }}</h3>
        <div class="competition-card-meta">
          <span>{{ competition.start_date | date: "%b %d, %Y" }} &mdash; {{ competition.end_date | date: "%b %d, %Y" }}</span>
        </div>
        {%- assign competition_writeups = site.writeups | where: 'competition', competition_key -%}
        <p class="competition-card-summary">
          {{ competition.summary | default: competition.excerpt | strip_html | truncate: 140 }}
        </p>
        {%- assign writeup_count = competition_writeups | size -%}
        <p class="competition-card-count">
          {%- if writeup_count == 0 -%}
          No writeups yet
          {%- elsif writeup_count == 1 -%}
          1 writeup
          {%- else -%}
          {{ writeup_count }} writeups
          {%- endif -%}
        </p>
      </a>
    </li>
    {%- endfor -%}
  </ul>
  {%- else -%}
  <p class="empty-state">No competitions logged yet. Publish a writeup to get started.</p>
  {%- endif -%}
</section>
