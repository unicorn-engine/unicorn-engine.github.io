---
layout: page
title: Documentation
permalink: /docs/
---

Find details on the design \& implementation of Unicorn in this [BlackHat USA 2015 slides](/BHUSA2015-unicorn.pdf).

---

## Compile & install Unicorn

There are several methods to compile and install Unicorn.

### 1. From source code

Find the source in [Download](/download) section and follow [the instructions](https://github.com/unicorn-engine/unicorn/blob/master/docs/COMPILE.md) to build and install the core of Unicorn.

### 2. From repositories <img src="/images/osx.png" height="24" width="24"> <img src="/images/freebsd.png" height="24" width="24"> <img src="/images/openbsd.png" height="24" width="24"> <img src="/images/netbsd.png" height="24" width="24">

This section explains how to install Unicorn on \*nix platforms from some software repositories.

#### 2.1 Mac OSX - core engine <img src="/images/osx.png" height="24" width="24"> 

**Homebrew** users can install the core of Unicorn with:

{% highlight bash %}
  $ brew install unicorn
{% endhighlight %}

  Note that Homebrew installs libraries into its own directory, so you need to tell applications where to find them, for example with:

{% highlight bash %}
  $ export DYLD_LIBRARY_PATH=/usr/local/opt/unicorn/lib/:$DYLD_LIBRARY_PATH
{% endhighlight %}

#### 2.2 Pkgsrc - core engine <img src="/images/freebsd.png" height="24" width="24"> <img src="/images/openbsd.png" height="24" width="24"> <img src="/images/netbsd.png" height="24" width="24">

Unicorn has been packaged for [pkgsrc](http://pkgsrc.se/emulators/unicorn), thus available for NetBSD, FreeBSD, Bitrig and OpenBSD.

Installation from binary pre-built packages with:

{% highlight bash %}
  $ pkgin install unicorn
{% endhighlight %}

Installation from sources with:

{% highlight bash %}
  $ cd /usr/pkgsrc/emulators/unicorn && make install
{% endhighlight %}

### 3. Python binding <img src="/images/python.png" height="24" width="24"> 

The easiest way to install Python binding is via *pip*, where packages for all the Operating Systems, including Windows, are provided.
Simply run the below command from prompt (you need sudo on Linux, MacOS for root access).

{% highlight bash %}
pip install unicorn
{% endhighlight %}

If you want to install from source, note that Python binding depends on *the core*, so make sure to *install the core before* you can use this binding.

On \*nix platforms, do:
{% highlight bash %}
$ cd bindings/python
$ sudo make install
{% endhighlight %}

On Windows, do:
{% highlight bash %}
cd bindings/python
python setup.py install
{% endhighlight %}

For Windows, after above steps, you need to copy all the *DLL files* from the *Windows core engine* in the [Download](/download) section into directory *C:\location_to_python\Lib\site-packages\unicorn\*.

---

### 4. Precompiled binaries <img src="/images/windows.png" height="24" width="24"> <img src="img/python.png" height="24" width="24"> <img src="/images/jar.png" height="24" width="24">

At the moment precompiled binaries for *Windows* & *Java* are available in our [Download](/download) section.

- **Windows** <img src="/images/windows.png" height="24" width="24">

  If you only want to write your tool in Python, all you need is the *Python installer*, which includes full Unicorn module. The Windows core engine is *not necessary* because it is *already embedded inside* the Python module.

  For all the bindings, firstly you still need to install the *Windows core engine*, which includes the static/dynamic libraries and also the headers (\*.h) for C programming.

- **Java** <img src="/images/jar.png" height="24" width="24">

  Java binding is available in JAR package.

---

## Programming

After installation, find in tutorials below how to write your tools based on Unicorn using your favorite programming languages.

- [Quick tutorial on programming with Unicorn - with C & Python](tutorial.html).

---

## Miscellaneous

- [Unicorn: next generation CPU emulator framework](/BHUSA2015-unicorn.pdf): Blackhat USA 2015 slides (PDF).

- [Beyond QEMU](/docs/beyond_qemu.html): A quick technical comparison of Unicorn and QEMU.

- [Micro-Unicorn-Engine-API-Documentation in Chinese](): This API Documentation details some Unicorn's data types, APIs, and related code implementations (currently available in Chinese only).
