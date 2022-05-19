---
layout: default
title: Programming with C & Python languages
---

## Tutorial for Unicorn

This short tutorial shows how the Unicorn API works and how easy it is to emulate binary code. There are more APIs than those used here, but these are all we need to get started.

### 1. Tutorial for C language

The following sample code presents how to emulate 32-bit code of X86 in C language.

{% highlight c linenos %}
#include <unicorn/unicorn.h>

// code to be emulated
#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx

// memory address where emulation starts
#define ADDRESS 0x1000000

int main(int argc, char **argv, char **envp)
{
  uc_engine *uc;
  uc_err err;
  int r_ecx = 0x1234;     // ECX register
  int r_edx = 0x7890;     // EDX register

  printf("Emulate i386 code\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return -1;
  }

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);

  // emulate code in infinite time & unlimited instructions
  err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n",
      err, uc_strerror(err));
  }

  // now print out some registers
  printf("Emulation done. Below is the CPU context\n");

  uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
  uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
  printf(">>> ECX = 0x%x\n", r_ecx);
  printf(">>> EDX = 0x%x\n", r_edx);

  uc_close(uc);

  return 0;
}
{% endhighlight %}

To compile this file, we need a *Makefile* like below.

{% highlight bash %}
LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn

all: test
%: %.c
    $(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
{% endhighlight %}

Readers can get this sample code in this [tarball file](/samples/test1.tgz). Compile and run it as follows (demonstrated on Mac OS X).

{% highlight bash %}
$ make
cc  test1.c -L/usr/local/Cellar/glib/2.44.1/lib -L/usr/local/opt/gettext/lib -lglib-2.0 -lintl  -lpthread -lm -lunicorn -o test1

$ ./test1
Emulate i386 code
Emulation done. Below is the CPU context
>>> ECX = 0x1235
>>> EDX = 0x788f
{% endhighlight %}

The C sample is intuitive, but just in case, readers can find below the explanation for each line of *test1.c*.

* Line 1: Include header file **unicorn.h** before we do anything.

* Line 4: Raw binary code we want to emulate. The code in this sample is in hex mode, and represents two X86 instructions "*INC ecx*" and "*DEC edx*".

* Line 7: Virtual address in which we will emulate the code above.

* Line 11: Declare a pointer to a handle of the type **uc_engine**. This handle will be used at every API of Unicorn.

* Line 12: Declare a variable with data type **uc_err** for possible error returned from Unicor API.

* Line 13 ~ 14: Declare 2 variables of *int* type (4 bytes) for two X86 registers *ECX* and *EDX*. It is important to use the right data types for registers, so the variable size is big enough to contain the registers. For this reason, type **uint64_t** is recommended for 64-bit registers.

* Line 19 ~ 24: Initialize Unicorn with function **uc_open**. This API accepts 3 arguments: the hardware architecture, hardware mode and pointer to Unicorn handle. In this sample, we want to emulate 32-bit code for X86 architecture. In return, we have the handle updated in variable *uc*. This API can fail in extreme cases, so our sample verifies the returned result against the error code *UC*ERR*OK*.

* Line 26: Map 2MB of memory for this emulation with function **uc_mem_map** at the virtual address declared on line *11*. All the CPU operations during this process should only access to this memory. This memory is mapped with all permissions READ, WRITE and EXECUTE (represented by combined permission **UC_PROT_ALL**).

* Line 29: Write code to be emulated into the memory we just mapped above. Function **uc_mem_write** takes 4 arguments: the handle, address to write to, the code to be written to memory and its size.

* Line 35 ~ 36: Set values of *ECX* and *EDX* registers with function **uc_reg_write**.

* Line 39: Start the emulation with function **uc_emu_start**. This API takes 5 arguments: the handle, address of the emulated code, address where emulation stops (which is right after the last byte of *X86_CODE32*), the time to be emulated, and number of instructions to be emulated. In this case, we want to run in infinite time and unlimited number of instructions, so the last two arguments are set to 0.

* Line 48 ~ 51: Print out values of registers *ECX* and *EDX*. We read the value of registers with function **uc_reg_read**.

* Line 53: Finish emulation with a call to function **uc_close**.

* * *

### 2. Tutorial for Python language

The following code presents the same example as above, but in Python, to emulate 32-bit code of X86.

{% highlight python linenos %}
from unicorn import *
from unicorn.x86_const import *

# code to be emulated
X86_CODE32 = b"\x41\x4a" # INC ecx; DEC edx

# memory address where emulation starts
ADDRESS = 0x1000000

print("Emulate i386 code")
try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.reg_write(UC_X86_REG_EDX, 0x7890)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    print(">>> ECX = 0x%x" %r_ecx)
    print(">>> EDX = 0x%x" %r_edx)

except UcError as e:
    print("ERROR: %s" % e)
{% endhighlight %}

Readers can get this sample code [here](/samples/test1.py). Run it with Python as follows.

{% highlight bash %}
$ python test1.py

Emulate i386 code
Emulation done. Below is the CPU context
>>> ECX = 0x1235
>>> EDX = 0x788f
{% endhighlight %}

The Python sample is intuitive, but just in case, readers can find below the explanation for each line of *test1.py*.


* Line 2 ~ 3: Import **unicorn** module before using Unicorn. This sample also uses some X86 register constants, so **unicorn.x86_const** is also needed.

* Line 6: Raw binary code we want to emulate. The code in this sample is in hex mode, and represents two X86 instructions "*INC ecx*" and "*DEC edx*".

* Line 9: Virtual address in which we will emulate the code above.

* Line 14: Initialize Unicorn with class **Uc**. This class accepts 2 arguments: the hardware architecture and hardware mode. In this sample, we want to emulate 32-bit code for X86 architecture. In return, we have a variable of this class in *mu*.

* Line 17: Map 2MB of memory for this emulation with method **mem_map** at the address declared in line *9*. All the CPU operations during this process should only access to this memory. This memory is mapped with default permissions READ, WRITE and EXECUTE.

* Line 20: Write code to be emulated into the memory we just mapped above. Method **mem_write** takes 2 arguments: the address to write to and the code to be written to memory.

* Line 23 ~ 24: Set values of *ECX* and *EDX* registers with method **reg_write**.

* Line 27: Start the emulation with method **emu_start**. This API takes 4 arguments: address of the emulated code, address where emulation stops (which is right after the last byte of *X86_CODE32*), the time to be emulated, and number of instructions to be emulated. If we ignore the last two arguments like in this example, Unicorn will emulate the code in infinite time and unlimited number of instructions.

* Line 32 ~ 35: Print out values of registers *ECX* and *EDX*. We read the value of registers with function **reg_read**.

* * *

### 3. More examples

This tutorial does not explain all the API of Unicorn yet.

* For more advanced C examples, see the code under directory [samples](https://github.com/unicorn-engine/unicorn/tree/master/samples).

* For more advanced samples in Python, see the code under directory [bindings/python](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python).

Have fun! If you do use Unicorn for something cool, let us know so we can [link to your products](/showcase).
