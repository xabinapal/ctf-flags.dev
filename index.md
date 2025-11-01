---
layout: default
title: Signal Log
---
<section class="hero">
  <h1>Trace the Exploit.</h1>
  <p>
    Drop into the logbook for past CTF operations grouped by competition. Pick an event to see every
    payload dissection, exploit walk-through, and signal capture we documented during the run.
  </p>
</section>

<section class="listing">
  <h2>Competitions</h2>
  {%- assign competitions = site.competitions | sort: 'start_date' | reverse -%}
  {%- if competitions and competitions.size > 0 -%}
  <ul class="competition-grid">
    {%- for competition in competitions -%}
    <li class="competition-card">
      {%- assign competition_key = competition.key | default: competition.slug -%}
      <a class="competition-card-link" href="{{ competition.url | relative_url }}">
        <div class="competition-card-meta">
          <span>{{ competition.start_date | date: "%b %d, %Y" }} &mdash; {{ competition.end_date | date: "%b %d, %Y" }}</span>
          {%- if competition.location -%}
          <span>{{ competition.location }}</span>
          {%- endif -%}
        </div>
        <h3 class="competition-card-title">{{ competition.name | default: competition.title }}</h3>
        {%- assign competition_posts = site.posts | where: 'competition', competition_key -%}
        <p class="competition-card-summary">
          {{ competition.summary | default: competition.excerpt | strip_html | truncate: 140 }}
        </p>
        {%- assign post_count = competition_posts | size -%}
        <p class="competition-card-count">
          {%- if post_count == 0 -%}
          No writeups yet
          {%- elsif post_count == 1 -%}
          1 writeup
          {%- else -%}
          {{ post_count }} writeups
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
