---
layout: page
title: Download
permalink: /download/
---

{% for post in site.tags.changelog limit:1 %}

The current version is **{{ post.title }}**, which was released on <time datetime="{{ post.date | date: "%Y-%m-%d" }}"> {{ post.date | date: "%B %e, %Y" }}</time>.

See the [version history](/changelog/) for a list of changes.

---

### Git repository <img src="/images/octocat.jpg" height="32" width="32">

The latest version of the source code can be retrieved at our [Git repository](https://github.com/unicorn-engine/unicorn).

Grab the latest dev build artifacts from [Github Action](https://github.com/unicorn-engine/unicorn/actions/workflows/build-uc2.yml) by picking any latest successful run and navigate to artifacts.

---

### Source archive <img src="/images/tgz.png" height="28" width="28"> <img src="/images/zip.png" height="32" width="32">

<a class="download" href="https://github.com/unicorn-engine/unicorn/archive/{{ post.title }}.zip" title="Download source (ZIP)">.ZIP</a>

This package contains:

- The complete source code for the Unicorn framework.
- Bindings for Python, Java, Go, & .NET.
- A collection of sample programs.

This is the recommended version for all platforms.

<a class="download" href="https://github.com/unicorn-engine/unicorn/archive/{{ post.title }}.tar.gz" title="Download source (TGZ)">.TGZ</a>

---

### Community bindings <img src="/images/binder.png" height="24" width="24">

Besides Haskell, Ruby, Python, Java, Go, Rust, Visual Basic, Pascal, .NET & MSVC supported in the main code, some bindings for other languages are created and maintained by the community.

- [UnicornEngine](https://metacpan.org/pod/UnicornEngine): Perl binding (by Vikas Naresh Kumar)
- [Unicorn-Net](https://github.com/FICTURE7/unicorn-net): .NET binding/wrapper, written in C# (by FICTURE7)
- [Unicorn-Clj](https://github.com/williballenthin/reversing-clj/tree/master/unicorn-clj): Clojure binding (by Willi Ballenthin)
- [Unicorn.CR](https://github.com/Becojo/unicorn.cr): Crystal binding (by Benoit Côté-Jodoin)
- [Deimos/unicorn](https://github.com/D-Programming-Deimos/unicorn): D binding (by Vladimir Panteleev)
- [Unicorn-Lua](https://github.com/dargueta/unicorn-lua): Lua binding (by Diego Argueta)
- [pharo-unicorn](https://github.com/guillep/pharo-unicorn): Pharo binding (by Guille Polito)
- [Unicorn.js](https://github.com/AlexAltea/unicorn.js): JavaScript binding (by Alexandro Sanchez)

---

### Windows - Core engine <img src="/images/windows.png" height="28" width="28">

<a class="download" href="https://github.com/unicorn-engine/unicorn/releases/download/{{ post.title }}/unicorn-{{ post.title }}-win32.zip" title="Download Win32 Binaries (ZIP)">Win-32</a>

NOTE: This is necessary for all bindings (except Python) & also for C programming.

This package contains:

- README & license file.
- The Unicorn header files (\*.h) for C programming.
- 32-bit/64-bit DLLs for Microsoft Windows 32-bit/64-bit.
- A sample file (sample_x86.exe)

<a class="download" href="https://github.com/unicorn-engine/unicorn/releases/download/{{ post.title }}/unicorn-{{ post.title }}-win64.zip" title="Download Win64 Binaries (ZIP)">Win-64</a>

---

### Python module for Windows/MacOS/Linux - Binaries <img src="/images/python.png" height="28" width="28"> <img src="/images/windows.png" height="28" width="28"> <img src="/images/osx.png" height="28" width="28"> <img src="/images/linux.png" height="28" width="28"> 

With `pip` or `pip3`, you can use the same command to install Python module for either Windows, MacOS or Linux.

{% highlight bash %}
pip install unicorn
{% endhighlight %}

To upgrade from older version of Unicorn, do:

{% highlight bash %}
pip install unicorn --upgrade
{% endhighlight %}

Remember to stick "sudo" in front for root privilege if needed.

Special notes for Apple Silicon users:

You will need `cmake` to build the wheel locally due to a lack of affordable runners.

{% highlight bash %}
brew install cmake pkg-config
pip install unicorn --upgrade
{% endhighlight %}

---

### Brew package for MacOS - Binaries <img src="/images/homebrew.png" height="28" width="28"> <img src="/images/osx.png" height="28" width="28">

Install Brew package of Unicorn on MacOS with:

{% highlight bash %}
brew install unicorn
{% endhighlight %}

To upgrade from older version of Unicorn, do:

{% highlight bash %}
brew update
brew upgrade unicorn
{% endhighlight %}

---

{% endfor %}
