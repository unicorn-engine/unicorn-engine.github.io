---
layout: default
title: Unicorn & QEMU
---

### Unicorn & QEMU

Unicorn engine is based [QEMU](http://www.qemu.org), a great open source software emulator. Find more about the techinical details of Unicorn in our [Blackhat USA 2015 slides](/BHUSA2015-unicorn.pdf).

A notable difference between Unicorn and QEMU is that we only focus on emulating CPU operations, but do not handle other parts of computer machine like QEMU. Internally, Unicorn reuses the CPU emulation component of QEMU as its core (with quite a lot of changes to adapt to our design). Therefore, *our engine is able to emulate all the instructions that QEMU can*, but beyond that we can do more & do better in many aspects.

The section below highlights the areas where Unicorn shines.

- **Framework**: QEMU is a set of emulators, but not a framework. Therefore, you cannot build your own tools on top of QEMU, while this is the main purpose of Unicorn.

- **Flexible**: QEMU cannot emulate a chunk of raw binary code without any context: it requires either a proper executable binary (for example, a file in ELF format), or a whole system image with a full OS inside. Meanwhile, Unicorn just focuses on CPU operations, and can emulate raw code without context (see [this tutorial](/docs/tutorial.html)).

- **Instrumentation**: QEMU does not support dynamic instrumentation, but with Unicorn you can register customized handlers for various kind of events from CPU execution to memory access. This feature gives tool programmers all the power they need to monitor and analyze the code under emulation.

- **Thread-safe**: QEMU cannot handle more than one CPU at the same time. In contrast, Unicorn is designed and implemented as a framework so that one program can emulate multiple code of different kinds of CPU in a moment.

- **Bindings**: QEMU does not have binding itself. But as a framework, Unicorn supports multiple bindings on top of the core written in C. This makes it easy to be adopted by developers. A rich list of efficient bindings - 4 languages have been supported in version 0.9 -  lowers the barrier for every programmer.

- **Lightweight**: Unicorn is much more lightweight than QEMU because we stripped all the subsystems that do not involve in CPU emulation. As a result, Unicorn is less than 10 times smaller in size and also in memory consumption.

- **Safety**: QEMU has a bad track of security record with a lot of vulnerabilities that can be exploited to break out of the guest. Its history says that all of these bugs are from subsystems such as devices, BIOS, firmware etc, but none of them comes from CPU emulator component. Therefore, in principle Unicorn is much more secure because it has way smaller attack surface.

<br>
With all that said, QEMU is an awesome project, which Unicorn was born from. However, Unicorn is not just QEMU, but offering a lot more because it has been designed & implemented especially for CPU emulation.
