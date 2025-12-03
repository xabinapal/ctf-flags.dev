---
layout: default
title: Resources
summary: A curated collection of essential resources for CTF competitions, covering a range of categories such as cryptography, forensics, exploitation, and more.
permalink: /resources/
---

{%- assign categories = 'crypto,forensics,misc,mobile,osint,pwn,rev,stego,web' | split: ',' | sort_natural -%}

<section class="hero">
  <h1>flag{r3s0urc3s}</h1>
  <p class="summary">
    A curated collection of essential resources for CTF competitions, covering a range of categories such as cryptography, forensics, exploitation, and more.
  </p>
</section>

<section class="section">
  <div class="controls">
    <div class="search-container">
      <input 
        type="text" 
        id="resource-search" 
        class="search-input" 
        placeholder="Search resources by name or description..."
        aria-label="Search resources"
      />
    </div>
    <div class="filters">
      <button class="chip-rounded active" data-category="all">All</button>
      {%- for category in categories -%}
      <button class="chip-rounded" data-category="{{ category }}">{{ category }}</button>
      {%- endfor -%}
    </div>
  </div>

  <div id="resources-container">
    {%- for category in categories -%}
    {%- assign resources = site.data.resources[category] | sort_natural -%}
    {%- if resources and resources.size > 0 -%}
    <div class="category" data-category="{{ category }}">
      <h2 class="category-title">{{ category }}</h2>
      <ul class="list resource-list">
        {%- for resource in resources -%}
        <li class="list-item" data-name="{{ resource.name | downcase }}" data-description="{{ resource.description | downcase }}" data-category="{{ category }}">
          <a href="{{ resource.url }}" target="_blank" rel="noopener noreferrer" class="card-link">
            <div class="card">
              <div class="resource-header">
                <h3 class="card-title resource-title">{{ resource.name }}</h3>
                <div class="resource-icon">
                  <svg width="16" height="16" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M11 3L17 9M17 9H12M17 9V4M16 18H4C2.89543 18 2 17.1046 2 16V4C2 2.89543 2.89543 2 4 2H9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </div>
              </div>
              <div class="resource-content">
                <span class="resource-url">{{ resource.url }}</span>
                <p class="resource-description">{{ resource.description }}</p>
              </div>
            </div>
          </a>
        </li>
        {%- endfor -%}
      </ul>
    </div>
    {%- endif -%}
    {%- endfor -%}
  </div>

  <div id="no-results" class="empty-state" style="display: none;">
    <p>No resources found matching your search criteria.</p>
  </div>
</section>

<script src="{{ '/assets/js/resources/main.js' | relative_url }}"></script>

