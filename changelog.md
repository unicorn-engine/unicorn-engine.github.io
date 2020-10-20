---
layout: default
title: Version history
permalink: /changelog/
---

## Version history
{% for post in site.tags.changelog %}
---
<article>
<a href="{{ post.url }}">
<h3>Version {{ post.title }}</h3>
</a>
<div class="date">
{{ post.date | date: "%B %e, %Y" }}
</div>

{{ post.content }}
</article>
{% endfor %}

