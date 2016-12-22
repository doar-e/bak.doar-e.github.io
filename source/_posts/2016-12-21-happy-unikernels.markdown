---
layout: post
title: "happy unikernels"
date: 2016-12-21 18:59
comments: true
categories: [unikernel, rumpkernel, exploitation]
author: yrp
published: true
toc: true
---
# Intro

Below is a collection of notes regarding unikernels. I had originally prepared this stuff to submit to EkoParty’s CFP, but ended up not wanting to devote time to stabilizing PHP7’s heap structures and I lost interest in the rest of the project before it was complete. However, there are still some cool takeaways I figured I could write down. Maybe they’ll come in handy? If so, please let let me know.

Unikernels are a continuation of turning everything into a container or VM. Basically, as many VMs currently just run one userland application, the idea is that we can simplify our entire software stack by removing the userland/kernelland barrier and essentially compiling our usermode process into the kernel. This is, in the implementation I looked at, done with a NetBSD kernel and a variety of either [native or lightly-patched POSIX applications](https://github.com/rumpkernel/rumprun-packages)  (bonus: there is significant lag time between upstream fixes and rump package fixes, just like every other containerized solution).

While I don’t necessarily think that conceptually unikernels are a good idea (attack surface reduction vs mitigation removal), I do think people will start more widely deploying them shortly and I was curious what memory corruption exploitation would look like inside of them, and more generally what your payload options are like.

All of the following is based off of two unikernel programs, nginx and php5 and only makes use of public vulnerabilities. I am happy to provide all referenced code (in varying states of incompleteness), on request.

<div class='entry-content-toc'></div>

<!--more-->

# Basic ‘Hello World’ Example

To get a basic understanding of a unikernel, we’ll walk through a simple ‘Hello World’ example. First, you’ll need to clone and build (`./build-rr.sh`) the [rumprun](https://github.com/rumpkernel/rumprun) toolchain. This will set you up with the various utilities you'll need.

## Compiling and ‘Baking’

In a rumpkernel application, we have a standard POSIX environment, minus anything involving multiple processes. Standard memory, file system, and networking calls all work as expected. The only differences lie in the multi-process related calls such as `fork()`, `signal()`, `pthread_create()`, etc. The scope of these differences can be found in the [The Design and Implementation of the Anykernel and Rump Kernels [pdf]](http://www.fixup.fi/misc/rumpkernel-book/rumpkernel-bookv2-20160802.pdf).

From a super basic, standard ‘hello world’ program:

```c
#include <stdio.h>

void main(void)
{
   printf("Hello\n");
}
```

After building `rumprun` we should have a new compiler, `x86_64-rumprun-netbsd-gcc`. This is a cross compiler targeting the rumpkernel platform. We can compile as normal `x86_64-rumprun-netbsd-gcc hello.c -o hello-rump` and in fact the output is an ELF: `hello-rump: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped`. However, as we obviously cannot directly boot an ELF we must manipulate the executable ('baking' in rumpkernel terms).

Rump kernels provide a `rumprun-bake` shell script. This script takes an ELF from compiling with the rumprun toolchain and converts it into a bootable image which we can then give to qemu or xen. Continuing in our example: `rumprun-bake hw_generic hello.bin hello-rump`, where the `hw_generic` just indicates we are targeting qemu.

## Booting and Debugging

At this point assuming you have qemu installed, booting your new image should be as easy as `rumprun qemu -g "-curses" -i hello.bin`. If everything went according to plan, you should see something like:

![hello](http://i.imgur.com/Or38ajp.png)

Because this is just qemu at this point, if you need to debug you can easily attach via qemu’s system debugger. Additionally, a nice side effect of this toolchain is very easy debugging — you can essentially debug most of your problems on the native architecture, then just switch compilers to build a bootable image. Also, because the boot time is so much faster, debugging and fixing problems is vastly sped up.

If you have further questions, or would like more detail, the [Rumpkernel Wiki](https://github.com/rumpkernel/wiki) has some very good documents explaining the various components and options.

# Peek/Poke Tool

Initially to develop some familiarity with the code, I wrote a simple peek/poke primitive process. The VM would boot and expose a tcp socket that would allow clients read or write arbitrary memory, as well as wrappers around `malloc()` and `free()` to play with the heap state. Most of the knowledge here is derived from this test code, poking at it with a debugger, and reading the rump kernel source.

## Memory Protections

One of the benefits of unikernels is you can prune components you might not need. For example, if your unikernel application does not touch the filesystem, that code can be removed from your resulting VM. One interesting consequence of this involves only running one process — because there is only one process running on the VM, there is no need for a virtual memory system to separate address spaces by process.

Right now this means that all memory is read-write-execute. I'm not sure if it's possible to configure the MMU in a hypervisor to enforce memory proections without enabling virtual memory, as most of the virtual memory code I've looked at has been related to process separation with page tables, etc. In any case, currently it’s pretty trivial to introduce new code into the system and there shouldn’t be much need to resort to ROP. 

# nginx

Nginx was the first target I looked at; I figured I could dig up the stack smash from 2013 (CVE-2013-2028) and use that as a baseline exploit to see what was possible. This ultimately failed, but exposed some interesting things along the way.

## Reason Why This Doesn’t Work

CVE-2013-2028 is a stack buffer overflow in the nginx handler for chunked requests. I thought this would be a good test as the user controls much of the data on the stack, however, various attempts to trigger the overflow failed. Running the VM in a debugger you could see the bug was not triggered despite the size value being large enough. In fact, the syscall returned an error.

It turns out however that NetBSD has code to prevent against this inside the kernel:

```c
do_sys_recvmsg_so(struct lwp *l, int s, struct socket *so, struct msghdr *mp,
      struct mbuf **from, struct mbuf **control, register_t *retsize) {
// …
        if (tiov->iov_len > SSIZE_MAX || auio.uio_resid > SSIZE_MAX) {
            error = EINVAL;
            goto out;
        }
// …
```

iov_len is our `recv()` size parameter, so this bug is dead in the water. As an aside, this also made me wonder how Linux applications would respond if you passed a size greater than LONG_MAX into `recv()` and it succeeded…

## Something Interesting

Traditionally when exploiting this bug one has to worry about stack cookies. Nginx has a worker pool of processes forked from the main process. In the event of a crash, a new process will be forked from the parent, meaning that the stack cookie will remain constant across subsequent connections. This allows you to break it down into four, 1 byte brute forces as opposed to one 4 byte, meaning it can be done in a maximum of 1024 connections. However, inside the unikernel, there is only one process — if a process crashes the entire VM must be restarted, and because the only process is the kernel, the stack cookie should (in theory) be regenerated. Looking at the disassembled nginx code, you can see the stack cookie checks in all off the relevant functions.

In practice, the point is moot because the stack cookies are always zero. The compiler creates and checks the cookies, it just never populates `fs:0x28` (the location of the cookie value), so it’s always a constant value and assuming you can write null bytes, this should pose no problem.

# ASLR

I was curious if unikernels would implement some form of ASLR, as during the build process they get compiled to an ELF (which is quite nice for analysis!) which might make position independent code easier to deal with. They don’t: all images are loaded at `0x100000`. There is however "natures ASLR" as these images aren’t distributed in binary form. Thus, as everyone must compile their own images, these will vary slightly depending on compiler version, software version, etc. However, even this constraint gets made easier. If you look at the format of the loaded images, they look something like this:

```
0x100000: <unikernel init code>
…
0x110410: <application code starts>
```

This means across any unikernel application you’ll have approximately 0x10000 bytes of fixed value, fixed location executable memory. If you find an exploitable bug it should be possible to construct a payload entirely from the code in this section. This payload could be used to leak the application code, install persistence, whatever.

# PHP

Once nginx was off the table, I needed another application that had a rumpkernel package and a history of exploitable bugs. The PHP interpreter fits the bill. I ended up using Sean Heelan's PHP bug [#70068](https://bugs.php.net/bug.php?id=70068), because of the provided trigger in the bug description, and detailed description explaining the bug. Rather than try to poorly recap Sean's work, I'd encourage you to just read the inital report if you're curious about the bug.

In retrospect, I took a poor exploitation path for this bug. Because the heap slabs have no ASLR, you can fairly confidently predict mapped addresses inside the PHP interpreter. Furthermore, by controlling the size of the payload, you can determine which bucket it will fall into and pick a lesser used bucket for more stability. This allows you to be lazy, and hard code payload addresses, leading to easy exploitation. This works very well -- I was basically able to take Sean's trigger, slap some addresses and a payload into it, and get code exec out of it. However, the downsides to this approach quickly became apparent. When trying to return from my payload and leave the interpreter in a sane state (as in, running) I realized that I would need to actually understand the PHP heap to repair it. I started this process by examining the rump heap (see below), but got bored when I ended up in the PHP heap.

# Persistence

This was the portion I wanted to finish for EkoParty, and it didn’t get done. In theory, as all memory is read-write-execute, it should be pretty trivial to just patch `recv()` or something to inspect the data received, and if matching some constant execute the rest of the packet. This is strictly in memory, anything touching disk will be application specific.

Assuming your payload is stable, you should be able to install an in-memory backdoor which will persist for the runtime of that session (and be deleted on poweroff). While in many configurations there is no writable persistent storage which will survive reboots this is not true for all unikernels (e.g. mysql). In those cases it might be possible to persist across power cycles, but this will be application specific.

One final, and hopefully obvious note: one of the largest differences in exploitation of unikernels is the lack of multiple processes. Exploits frequently use the existence of multiple processes to avoid cleaning up application state after a payload is run. In a unikernel, your payload must repair application state or crash the VM. In this way it is much more similar to a kernel exploit.

# Heap Notes

The unikernel heap is quite nice from an exploitation perspective. It's a slab-style allocator with in-line metadata on every block. Specifically, the metadata contains the ‘bucket’ the allocation belongs to (and thus the freelist the block should be released to). This means a relative overwrite plus `free()`ing into a smaller bucket should allow for fairly fine grained control of contents. Additionally the heap is LIFO, allowing for standard heap massaging.

Also, while kinda untested, I believe rumpkernel applications are compiled without `QUEUEDEBUG` defined. This is relevant as the sanity checks on `unlink` operations ("safe unlink") require this to be defined. This means that in some cases, if freelists themselves can be overflown then removed you can get a write-what-where. However, I think this is fairly unlikely in practice, and with the lack of memory protections elsewhere, I'd be surprised if it would currently be useful.

You can find most of the relevant heap source [here](https://github.com/rumpkernel/rumprun/blob/master/lib/libbmk_core/memalloc.c)

# Symbol Resolution

Rumpkernels helpfully include an entire syscall table under the `mysys` symbol. When rumpkernel images get loaded, the ELF header gets stripped, but the rest of the memory is loaded contigiously:

```
gef➤  info file
Symbols from "/home/x/rumprun-packages/php5/bin/php.bin".
Remote serial target in gdb-specific protocol:
Debugging a target over a serial line.
        While running this, GDB does not access memory from...
Local exec file:
        `/home/x/rumprun-packages/php5/bin/php.bin', file type elf64-x86-64.
        Entry point: 0x104000
        0x0000000000100000 - 0x0000000000101020 is .bootstrap
        0x0000000000102000 - 0x00000000008df31c is .text
        0x00000000008df31c - 0x00000000008df321 is .init
        0x00000000008df340 - 0x0000000000bba9f0 is .rodata
        0x0000000000bba9f0 - 0x0000000000cfbcd0 is .eh_frame
        0x0000000000cfbcd0 - 0x0000000000cfbd28 is link_set_sysctl_funcs
        0x0000000000cfbd28 - 0x0000000000cfbd50 is link_set_bufq_strats
        0x0000000000cfbd50 - 0x0000000000cfbde0 is link_set_modules
        0x0000000000cfbde0 - 0x0000000000cfbf18 is link_set_rump_components
        0x0000000000cfbf18 - 0x0000000000cfbf60 is link_set_domains
        0x0000000000cfbf60 - 0x0000000000cfbf88 is link_set_evcnts
        0x0000000000cfbf88 - 0x0000000000cfbf90 is link_set_dkwedge_methods
        0x0000000000cfbf90 - 0x0000000000cfbfd0 is link_set_prop_linkpools
        0x0000000000cfbfd0 - 0x0000000000cfbfe0 is .initfini
        0x0000000000cfc000 - 0x0000000000d426cc is .data
        0x0000000000d426d0 - 0x0000000000d426d8 is .got
        0x0000000000d426d8 - 0x0000000000d426f0 is .got.plt
        0x0000000000d426f0 - 0x0000000000d42710 is .tbss
        0x0000000000d42700 - 0x0000000000e57320 is .bss
```

This means you should be able to just run simple linear scan, looking for the `mysys` table. A basic heuristic should be fine, 8 byte syscall number, 8 byte address. In the PHP5 interpreter, this table has 67 entries, giving it a big, fat footprint:

```
gef➤  x/6g mysys
0xaeea60 <mysys>:       0x0000000000000003      0x000000000080b790 -- <sys_read>
0xaeea70 <mysys+16>:    0x0000000000000004      0x000000000080b9d0 -- <sys_write>
0xaeea80 <mysys+32>:    0x0000000000000006      0x000000000080c8e0 -- <sys_close>
...
```

There is probably a chain of pointers in the initial constant 0x10410 bytes you could also follow, but this approach should work fine.

# Hypervisor fuzzing

After playing with these for a while, I had another idea: rather than using unikernels to host userland services, I think there is a really cool opportunity to write a hypervisor fuzzer in a unikernel. Consider:
You have all the benefits of a POSIX userland only you’re in ring0. You don’t need to export your data to userland to get easy and familiar IO functions.
Unikernels boot really, really fast. As in under 1 second. This should allow for pretty quick state clearing.

This is definitely an area of interesting future work I’d like to come back to.

# Final Suggestions

If you develop unikernels:

- Populate the randomness for stack cookies.
- Load at a random location for some semblance of ASLR.
- Is there a way you can enforce memory permissions? Some form of NX would go a long way.
- If you can’t, some control flow integrity stuff might be a good idea? Haven’t really thought this through or tried it.
- Take as many lessons from grsec as possible.

If you’re exploiting unikernels:

- Have fun.

If you’re exploiting hypervisors:

- Unikernels might provide a cool platform to easily play in ring0.

## Thanks
For feedback, bugs used, or editing
[@seanhn](https://twitter.com/seanhn), [@hugospns](https://twitter.com/hugospns), [@0vercl0k](https://twitter.com/0vercl0k), [@darkarnium](https://twitter.com/darkarnium), other quite helpful anonymous types.