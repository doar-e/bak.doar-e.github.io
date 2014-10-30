---
layout: post
title: "Having a look at the Windows' User/Kernel exceptions dispatcher"
date: 2013-10-12 14:03
comments: true
categories: [coding, hooking, windows internals]
author: Axel "0vercl0k" Souchet
published: true
toc: true
---
# Introduction
The purpose of this little post is to create a piece of code able to monitor exceptions raised in a process (a bit like [gynvael](http://gynvael.coldwind.pl/)'s [ExcpHook](http://gynvael.coldwind.pl/?id=148) but in userland), and to generate a report with information related to the exception. The other purpose is to have a look at the internals of course.

```text
--Exception detected--
ExceptionRecord: 0x0028fa2c Context: 0x0028fa7c
Image Path: D:\Codes\The Sentinel\tests\divzero.exe
Command Line: ..\tests\divzero.exe divzero.exe
PID: 0x00000aac
Exception Code: 0xc0000094 (EXCEPTION_INT_DIVIDE_BY_ZERO)
Exception Address: 0x00401359
EAX: 0x0000000a EDX: 0x00000000 ECX: 0x00000001 EBX: 0x7ffde000
ESI: 0x00000000 EDI: 0x00000000 ESP: 0x0028fee0 EBP: 0x0028ff18
EIP: 0x00401359
EFLAGS: 0x00010246

Stack:
0x767bc265 0x54f3620f 0xfffffffe 0x767a0f5a 
0x767ffc59 0x004018b0 0x0028ff90 0x00000000

Disassembly:
00401359 (04) f77c241c                 IDIV DWORD [ESP+0x1c]
0040135d (04) 89442404                 MOV [ESP+0x4], EAX
00401361 (07) c7042424304000           MOV DWORD [ESP], 0x403024
00401368 (05) e833080000               CALL 0x401ba0
0040136d (05) b800000000               MOV EAX, 0x0
```

That's why I divided this post in two big parts:

 * the first one will talk about Windows internals background required to understand how things work under the hood,
 * the last one will talk about [*Detours*](http://research.microsoft.com/en-us/projects/detours/) and how to hook *ntdll!KiUserExceptionDispatcher* toward our purpose. Basically, the library gives programmers a set of APIs to easily hook procedures. It also has a clean and readable documentation, so you should use it! It is usually used for that kind of things:
   * Hot-patching bugs (no need to reboot),
   * Tracing API calls ([API Monitor](http://www.rohitab.com/apimonitor) like),
   * Monitoring (a bit like our example),
   * Pseudo-sandboxing (prevent API calls),
   * etc.

<div class='entry-content-toc'></div>

<!--more-->

# Lights on *ntdll!KiUserExceptionDispatcher*
The purpose of this part is to be sure to understand how exceptions are given back to userland in order to be handled (or not) by the [SEH](http://msdn.microsoft.com/en-us/library/windows/desktop/ms680657(v=vs.85).aspx)/[UEF](http://msdn.microsoft.com/en-us/library/windows/desktop/ms681401(v=vs.85).aspx) mechanisms ; though I'm going to focus on Windows 7 x86 because that's the OS I run in my VM. The other objective of this part is to give you the big picture, I mean we are not going into too many details, just enough to write a working exception sentinel PoC later.


## nt!KiTrap*
When your userland application does something wrong an exception is raised by your CPU: let's say you are trying to do a division by zero (*nt!KiTrap00* will handle that case), or you are trying to fetch a memory page that doesn't exist (*nt!KiTrap0E*).

```text
kd> !idt -a

Dumping IDT: 80b95400

00:   8464d200 nt!KiTrap00
01:   8464d390 nt!KiTrap01
02:   Task Selector = 0x0058
03:   8464d800 nt!KiTrap03
04:   8464d988 nt!KiTrap04
05:   8464dae8 nt!KiTrap05
06:   8464dc5c nt!KiTrap06
07:   8464e258 nt!KiTrap07
08:   Task Selector = 0x0050
09:   8464e6b8 nt!KiTrap09
0a:   8464e7dc nt!KiTrap0A
0b:   8464e91c nt!KiTrap0B
0c:   8464eb7c nt!KiTrap0C
0d:   8464ee6c nt!KiTrap0D
0e:   8464f51c nt!KiTrap0E
0f:   8464f8d0 nt!KiTrap0F
10:   8464f9f4 nt!KiTrap10
11:   8464fb34 nt!KiTrap11
[...]
```
I'm sure you already know that but in x86 Intel processors there is a table called the [IDT](http://wiki.osdev.org/Interrupt_Descriptor_Table) that stores the different routines that will handle the exceptions. The virtual address of that table is stored in a special x86 register called *IDTR*, and that register is accessible only by using the instructions *sidt* (Stores Interrupt Descriptor Table register) and *lidt* (Loads Interrupt Descriptor Table register).

Basically there are two important things in an IDT entry: the address of the [ISR](https://en.wikipedia.org/wiki/Interrupt_handler), and the segment selector (remember it's a simple index in the [GDT](http://wiki.osdev.org/GDT_Tutorial)) the CPU should use.

```text
kd> !pcr
KPCR for Processor 0 at 84732c00:
    [...]
                    IDT: 80b95400
                    GDT: 80b95000

kd> dt nt!_KIDTENTRY 80b95400
   +0x000 Offset           : 0xd200
   +0x002 Selector         : 8
   +0x004 Access           : 0x8e00
   +0x006 ExtendedOffset   : 0x8464

kd> ln (0x8464 << 10) + (0xd200)
Exact matches:
    nt!KiTrap00 (<no parameter info>)

kd> !@display_gdt 80b95000

#################################
# Global Descriptor Table (GDT) #
#################################

Processor 00
Base : 80B95000    Limit : 03FF

Off.  Sel.  Type    Sel.:Base  Limit   Present  DPL  AVL  Informations
----  ----  ------  ---------  ------- -------  ---  ---  ------------
[...]
0008  0008  Code32  00000000  FFFFFFFF  YES     0    0    Execute/Read, accessed  (Ring 0)CS=0008
[...]
```

The entry just above tells us that for the processor 0, if a *division-by-zero* exception is raised the kernel mode routine nt!KiTrap00 will be called with a flat-model code32 ring0 segment (cf GDT dump).

Once the CPU is in *nt!KiTrap00*'s code it basically does a lot of things, same thing for all the other *nt!KiTrap* routines, but somehow they (more or less) end up in the kernel mode exceptions dispatcher: *nt!KiDispatchException* (remember [gynvael](http://gynvael.coldwind.pl/)'s tool ? He was hooking that method!) once they created the *nt!_KTRAP_FRAME* structure associated with the fault. 

{% img center /images/ntdll.KiUserExceptionDispatcher/butterfly.png nt!KiExceptionDispatch graph from ReactOS %}

Now, you may already have asked yourself how the kernel reaches back to the userland in order to process the exception via the SEH mechanism for example ?

That's kind of simple actually. The trick used by the Windows kernel is to check where the exception took place: if it's from user mode, the kernel mode exceptions dispatcher sets the field *eip* of the trap frame structure (passed in argument) to the symbol *nt!KeUserExceptionDispatcher*. Then, *nt!KeEloiHelper* will use that same trap frame to resume the execution (in our case on *nt!KeUserExceptionDispatcher*).

But guess what ? That symbol holds the address of *ntdll!KiUserExceptionDispatcher*, so it makes total sense!
```text
kd> dps nt!KeUserExceptionDispatcher L1
847a49a0  77476448 ntdll!KiUserExceptionDispatcher
```

If like me you like illustrations, I've made a WinDbg session where I am going to show what we just talked about. First, let's trigger our *division-by-zero* exception:

```text
kd> bp nt!KiTrap00
kd> g
Breakpoint 0 hit
nt!KiTrap00:
8464c200 6a00            push    0
kd> k
ChildEBP RetAddr  
8ec9bd98 01141269 nt!KiTrap00
8ec9bd9c 00000000 divzero+0x1269
kd> u divzero+0x1269 l1
divzero+0x1269:
01141269 f7f0            div     eax,eax
```

Now let's go a bit further in the ISR, and more precisely when the *nt!_KTRAP_FRAME* is built:

```text
kd> bp nt!KiTrap00+0x36
kd> g
Breakpoint 1 hit
nt!KiTrap00+0x36:
8464c236 8bec            mov     ebp,esp
kd> dt nt!_KTRAP_FRAME @esp
   +0x000 DbgEbp           : 0x1141267
   +0x004 DbgEip           : 0x1141267
   +0x008 DbgArgMark       : 0
   +0x00c DbgArgPointer    : 0
   +0x010 TempSegCs        : 0
   +0x012 Logging          : 0 ''
   +0x013 Reserved         : 0 ''
   +0x014 TempEsp          : 0
   +0x018 Dr0              : 0
   +0x01c Dr1              : 0
   +0x020 Dr2              : 0
   +0x024 Dr3              : 0x23
   +0x028 Dr6              : 0x23
   +0x02c Dr7              : 0x1141267
   +0x030 SegGs            : 0
   +0x034 SegEs            : 0x23
   +0x038 SegDs            : 0x23
   +0x03c Edx              : 0x1141267
   +0x040 Ecx              : 0
   +0x044 Eax              : 0
   +0x048 PreviousPreviousMode : 0
   +0x04c ExceptionList    : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x050 SegFs            : 0x270030
   +0x054 Edi              : 0
   +0x058 Esi              : 0
   +0x05c Ebx              : 0x7ffd3000
   +0x060 Ebp              : 0x27fd58
   +0x064 ErrCode          : 0
   +0x068 Eip              : 0x1141269
   +0x06c SegCs            : 0x1b
   +0x070 EFlags           : 0x10246
   +0x074 HardwareEsp      : 0x27fd50
   +0x078 HardwareSegSs    : 0x23
   +0x07c V86Es            : 0
   +0x080 V86Ds            : 0
   +0x084 V86Fs            : 0
   +0x088 V86Gs            : 0
kd> .trap @esp
ErrCode = 00000000
eax=00000000 ebx=7ffd3000 ecx=00000000 edx=01141267 esi=00000000 edi=00000000
eip=01141269 esp=0027fd50 ebp=0027fd58 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
divzero+0x1269:
001b:01141269 f7f0            div     eax,eax
kd> .trap
Resetting default scope
```

The idea now is to track the modification of the *nt!_KTRAP_FRAME.Eip* field as we discussed earlier (BTW, don't try to put directly a breakpoint on *nt!KiDispatchException* with VMware, it just blows my guest virtual machine) via a hardware-breakpoint:

```text
kd> ba w4 esp+68
kd> g
Breakpoint 2 hit
nt!KiDispatchException+0x3d6:
846c559e c745fcfeffffff  mov     dword ptr [ebp-4],0FFFFFFFEh
kd> dt nt!_KTRAP_FRAME Eip @esi
   +0x068 Eip : 0x77b36448
kd> ln 0x77b36448
Exact matches:
    ntdll!KiUserExceptionDispatcher (<no parameter info>)
```

OK, so here we can clearly see the trap frame has been modified (keep in mind WinDbg gives you the control *after* the actual writing). That basically means that when the kernel will resume the execution via *nt!KiExceptionExit* (or *nt!Kei386EoiHelper*, two symbols for one same address) the CPU will directly execute the user mode exceptions dispatcher.

Great, I think we have now enough understanding to move on the second part of the article.

# Serial Detourer
In this part we are going to talk about Detours, what looks like the API and how you can use it to build a userland exceptions sentinel without too many lines of codes. Here is the list of the features we want:

 * To hook *ntdll!KiUserExceptionDispatcher*: we will use Detours for that,
 * To generate a tiny readable exception report: for the disassembly part we will use [Distorm](http://www.ragestorm.net/distorm/) (yet another easy cool library to use),
 * To focus x86 architecture: because unfortunately the express version doesn't work for x86_64.

Detours is going to modify the first bytes of the API you want to hook in order to redirect its execution in your piece of code: it's called an *inline-hook*.

{% img center /images/ntdll.KiUserExceptionDispatcher/detours.png %}

Detours can work in two modes:

 * A first mode where you don't touch to the binary you're going to hook, you will need a DLL module you will inject into your binary's memory. Then, Detours will modify in-memory the code of the APIs you will hook. That's what we are going to use.
 * A second mode where you modify the binary file itself, more precisely the [IAT](http://sandsprite.com/CodeStuff/Understanding_imports.html). In that mode, you won't need to have a DLL injecter. If you are interested in details about those tricks they described them in the *Detours.chm* file in the installation directory, read it!

So our sentinel will be divided in two main parts:

 * A program that will start the target binary and inject our DLL module (that's where all the important things are),
 * The sentinel DLL module that will hook the userland exceptions dispatcher and write the exception report.

The first one is really easy to implement using [DetourCreateProcessWithDll](https://github.com/0vercl0k/stuffz/blob/master/The%20Sentinel/ProcessSpawner/main.cpp#L66): it's going to create the process and inject the DLL we want.

```text
Usage: ./ProcessSpawner <full path dll> <path executable> <excutable name> [args..]
```

To successfully hook a function you have to know its address of course, and you have to implement the hook function. Then, you have to call *DetourTransactionBegin*, *DetourUpdateThread*, *DetourTransactionCommit* and you're done, wonderful isn't it ?

The only tricky thing, in our case, is that we want to hook *ntdll!KiUserExceptionDispatcher*, and that function has its own custom calling convention. Fortunately for us, in the *samples* directory of Detours you can find how you are supposed to deal with that specific case:

```c KiUserExceptionDispatcher hook
VOID __declspec(naked) NTAPI KiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
    /* Taken from the Excep's detours sample */
    __asm
    {
        xor     eax, eax                ; // Create fake return address on stack.
        push    eax                     ; // (Generally, we are called by the kernel.)

        push    ebp                     ; // Prolog
        mov     ebp, esp                ;
        sub     esp, __LOCAL_SIZE       ;
    }

    EnterCriticalSection(&critical_section);
    log_exception(ExceptionRecord, Context);
    LeaveCriticalSection(&critical_section);

    __asm
    {
        mov     ebx, ExceptionRecord    ;
        mov     ecx, Context            ;
        push    ecx                     ;
        push    ebx                     ;
        mov     eax, [TrueKiUserExceptionDispatcher];
        jmp     eax                     ;
        //
        // The above code should never return.
        //
        int     3                       ; // Break!
        mov     esp, ebp                ; // Epilog
        pop     ebp                     ;
        ret                             ;
    }
}
```

Here is what looks *ntdll!KiUserExceptionDispatcher* like in memory after the hook:

{% img center /images/ntdll.KiUserExceptionDispatcher/hook.png %}

Disassembling some instructions pointed by the *CONTEXT.Eip* field is also really straightforward to do with *distorm_decode*:

```c Use distorm3 to disassemble some codes
if(IsBadReadPtr((const void*)Context->Eip, SIZE_BIGGEST_X86_INSTR * MAX_INSTRUCTIONS) == 0)
{
  _DecodeResult res;
  _OffsetType offset = Context->Eip;
  _DecodedInst decodedInstructions[MAX_INSTRUCTIONS] = {0};
  unsigned int decodedInstructionsCount = 0;

  res = distorm_decode(
      offset,
      (const unsigned char*)Context->Eip,
      MAX_INSTRUCTIONS * SIZE_BIGGEST_X86_INSTR,
      Decode32Bits,
      decodedInstructions,
      MAX_INSTRUCTIONS,
      &decodedInstructionsCount
  );

  if(res == DECRES_SUCCESS || res == DECRES_MEMORYERR)
  {
    fprintf(f, "\nDisassembly:\n");
    for(unsigned int i = 0; i < decodedInstructionsCount; ++i)
    {
      fprintf(
        f,
        "%.8I64x (%.2d) %-24s %s%s%s\n",
        decodedInstructions[i].offset,
        decodedInstructions[i].size,
        (char*)decodedInstructions[i].instructionHex.p,
        (char*)decodedInstructions[i].mnemonic.p,
        decodedInstructions[i].operands.length != 0 ? " " : "",
        (char*)decodedInstructions[i].operands.p
      );
    }
  }
}
```

So the prototype works pretty great like that.

```text
D:\Codes\The Sentinel\Release>ProcessSpawner.exe "D:\Codes\The Sentinel\Release\ExceptionMonitorDll.dll" ..\tests\divzero.exe divzero.exe
D:\Codes\The Sentinel\Release>ls -l D:\Crashs\divzero.exe
total 4
-rw-rw-rw-  1 0vercl0k 0 863 2013-10-16 22:58 exceptionaddress_401359pid_2732tick_258597468timestamp_1381957116.txt
```

But once I've encountered a behavior that I didn't plan on: there was like a stack-corruption in a stack-frame protected by the */GS* cookie. If the cookie has been, somehow, rewritten the program calls *___report_gs_failure* (sometimes the implementation is directly inlined, thus you can find the definition of the function in your binary) in order to kill the program because the stack-frame is broken. Long story short, I was also hooking *kernel32!UnhandleExceptionFilter* to not miss that kind of exceptions, but I noticed while writing this post that it doesn't work anymore. We are going to see why in the next part.

# The untold story: Win8 and *nt!KiFastFailDispatch*
## Introduction
When I was writing this little post I did also some tests on my personal machine: a Windows 8 host. But the test for the */GS* thing we just talked about wasn't working at all as I said. So I started my investigation by looking at the code of *__report_gsfailure* (generated with a VS2012) and I saw this:

```c __report_gsfailure
void __usercall __report_gsfailure(unsigned int a1<ebx>, unsigned int a2<edi>, unsigned int a3<esi>, char a4)
{
  unsigned int v4; // eax@1
  unsigned int v5; // edx@1
  unsigned int v6; // ecx@1
  unsigned int v11; // [sp-4h] [bp-328h]@1
  unsigned int v12; // [sp+324h] [bp+0h]@0
  void *v13; // [sp+328h] [bp+4h]@3

  v4 = IsProcessorFeaturePresent(0x17u);
  // [...]
  if ( v4 )
  {
    v6 = 2;
    __asm { int     29h             ; DOS 2+ internal - FAST PUTCHAR }
  }
  [...]
  __raise_securityfailure(&GS_ExceptionPointers);
}
```

The first thing I asked myself was about that weird *int 29h*. Next thing I did was to download a fresh Windows 8 VM [here](http://www.modern.ie/fr-fr/virtualization-tools#downloads) and attached a kernel debugger in order to check the IDT entry 0x29:

```text
kd> vertarget
Windows 8 Kernel Version 9200 MP (2 procs) Free x86 compatible
Built by: 9200.16424.x86fre.win8_gdr.120926-1855
Machine Name:
Kernel base = 0x8145c000 PsLoadedModuleList = 0x81647e68
Debug session time: Thu Oct 17 11:30:18.772 2013 (UTC + 2:00)
System Uptime: 0 days 0:02:55.784
kd> !idt 29

Dumping IDT: 809da400

29: 8158795c nt!KiRaiseSecurityCheckFailure
```

As opposed I was used to see on my Win7 machine:

```text
kd> vertarget
Windows 7 Kernel Version 7600 MP (1 procs) Free x86 compatible
Product: WinNt, suite: TerminalServer SingleUserTS
Built by: 7600.16385.x86fre.win7_rtm.090713-1255
Machine Name:
Kernel base = 0x84646000 PsLoadedModuleList = 0x8478e810
Debug session time: Thu Oct 17 14:25:40.969 2013 (UTC + 2:00)
System Uptime: 0 days 0:00:55.203
kd> !idt 29

Dumping IDT: 80b95400

29: 00000000
```

I've opened my favorite IDE and I wrote a bit of code to test if there was a different behavior between Win7 and Win8 regarding this exception handling:

```c gs.c
#include <stdio.h>
#include <windows.h>

int main()
{
  __try
  {
    __asm int 0x29
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    printf("SEH catched the exception!\n");
  }
  return 0;
}
```

On Win7 I'm able to catch the exception via a SEH handler: it means the Windows kernel calls the user mode exception dispatcher for further processing by the user exception handlers (as we saw at the beginning of the post). But on Win8, at my surprise, I don't get the message ; the process is killed directly after displaying the usual message box "a program has stopped". Definitely weird.

## What happens on Win7
When the interruption 0x29 is triggered by my code, the CPU is going to check if there is an IDT entry for that interruption, and if there isn't it's going to raise a #GP (*nt!KiTrap0d*) that will end up in *nt!KiDispatchException*.

And as previously, the function is going to check where the fault happened and because it happened in userland it will modify the trap frame structure to reach *ntdll!KiUserExceptionDispatcher*. That's why we can catch it in our *__except* scope.

```text
kd> r
eax=0000000d ebx=86236d40 ecx=862b48f0 edx=0050e600 esi=00000000 edi=0029b39f
eip=848652dd esp=9637fd34 ebp=9637fd34 iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000246
nt!KiTrap0D+0x471:
848652dd e80ddeffff      call    nt!CommonDispatchException+0x123 (848630ef)
kd> k 2
ChildEBP RetAddr  
9637fd34 0029b39f nt!KiTrap0D+0x471
0016fc1c 0029be4c gs+0x2b39f
kd> u gs+0x2b39f l1
gs+0x2b39f:
0029b39f cd29            int     29h
```

## What happens on Win8
This time the kernel has defined an ISR for the interruption 0x29: *nt!KiRaiseSecurityCheckFailure*. This function is going to call *nt!KiFastFailDispatch*, and this one is going to call *nt!KiDispatchException*:

{% img center /images/ntdll.KiUserExceptionDispatcher/kifastfaildispatch.png %}

BUT the exception is going to be processed as a **second-chance** exception because of the way *nt!KiFastFailDispatch* calls the kernel mode exception dispatcher. And if we look at the source of *nt!KiDispatchException* in ReactOS we can see that this exception won't have the chance to reach back the userland as in Win7 :)):

```c KiDispatchException from ReactOS
VOID
NTAPI
KiDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
                    IN PKEXCEPTION_FRAME ExceptionFrame,
                    IN PKTRAP_FRAME TrapFrame,
                    IN KPROCESSOR_MODE PreviousMode,
                    IN BOOLEAN FirstChance)
{
    CONTEXT Context;
    EXCEPTION_RECORD LocalExceptRecord;

// [...]
    /* Handle kernel-mode first, it's simpler */
    if (PreviousMode == KernelMode)
    {
// [...]
    }
    else
    {
        /* User mode exception, was it first-chance? */
        if (FirstChance)
        {
// [...]
// that's in this branch the kernel reaches back to the user mode exception dispatcher
// but if FirstChance=0, we won't have that chance

          /* Set EIP to the User-mode Dispatcher */
          TrapFrame->Eip = (ULONG)KeUserExceptionDispatcher;

          /* Dispatch exception to user-mode */
          _SEH2_YIELD(return);
        }

        /* Try second chance */
        if (DbgkForwardException(ExceptionRecord, TRUE, TRUE))
        {
            /* Handled, get out */
            return;
        }
        else if (DbgkForwardException(ExceptionRecord, FALSE, TRUE))
        {
            /* Handled, get out */
            return;
        }
// [...]
    return;
}
```

To convince yourself you can even modify the *FirstChance* argument passed to *nt!KiDispatchException* from *nt!KiFastFailDispatch*. You will see the SEH handler is called like in Win7:

{% img center /images/ntdll.KiUserExceptionDispatcher/win8.png %}

Cool, we have now our answer to the weird behavior! I guess if you want to monitor */GS* exception you are going to find another trick :)).

# Conclusion
I hope you enjoyed this little trip in the Windows' exception world both in user and kernel mode. You will find the seems-to-be-working PoC on my github account here: [The sentinel](https://github.com/0vercl0k/stuffz/tree/master/The%20Sentinel). By the way, you are highly encouraged to improve it, or to modify it in order to suit your use-case!

If you liked the subject of the post, I've made a list of really cool/interesting links you should check out:

 * [New Security Assertions in Windows 8](http://www.alex-ionescu.com/?p=69) - [@aionescu](https://twitter.com/aionescu) endless source of inspiration
 * [Exploiting the Otherwise Unexploitable on Windows](http://www.uninformed.org/?v=4&a=5&t=txt) - Yet another awesome article by [Skywing](http://www.nynaeve.net/) and [skape](http://uninformed.org/)
 * [A catalog of NTDLL kernel mode to user mode callbacks, part 2: KiUserExceptionDispatcher](http://www.nynaeve.net/?p=201)
 * [Windows Exceptions, Part II: Exception Dispatching](http://dralu.com/?p=167)
 * [EasyHook](https://easyhook.codeplex.com/) - "EasyHook starts where Microsoft Detours ends."

High five to my friend [@Ivanlef0u](https://twitter.com/Ivanlef0u) for helping me to troubleshoot the weird behavior, and [@__x86](https://twitter.com/__x86) for the review!
