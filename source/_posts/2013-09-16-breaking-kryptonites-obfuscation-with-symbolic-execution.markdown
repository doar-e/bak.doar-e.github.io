---
layout: post
title: "Breaking Kryptonite's obfuscation: a static analysis approach relying on symbolic execution"
date: 2013-09-16 11:47
comments: true
categories: [reverse-engineering]
author: Axel "0vercl0k" Souchet
published: true
toc: true
---
# Introduction
*Kryptonite* was a proof-of-concept I built to obfuscate codes at the LLVM intermediate representation level. The idea was to use semantic-preserving transformations in order to not break the original program. One of the main idea was for example to build a home-made 32 bits adder to replace the *add* LLVM instruction. Instead of having a single asm instruction generated at the end of the pipeline, you will end up with a ton of assembly codes doing only an addition. If you never read my article, and you are interested in it here it is: [Obfuscation of steel: meet my Kryptonite](http://0vercl0k.tuxfamily.org/bl0g/?p=260).

{% img center /images/breaking_kryptonite_s_obfuscation_with_symbolic_execution/home-made-adder.png %}


In this post I wanted to show you how we can manage to break that obfuscation with symbolic execution. We are going to write a really tiny symbolic execution engine with IDAPy, and we will use Z3Py to simplify all our equations. Note that a friend of mine [@elvanderb](https://twitter.com/elvanderb) used a similar approach (more generic though) to simplify some parts of the [crackme](http://download.tuxfamily.org/overclokblog/Obfuscation%20of%20steel%3a%20meet%20my%20Kryptonite/binaries/) ; but he didn't wanted to publish it, so here is my blog post about it!

<div class='entry-content-toc'></div>

<!--more-->

# The target
In this blogpost we are first going to work on the LLVM code emitted by [llvm-cpp-frontend-home-made-32bits-adder.cpp](https://github.com/0vercl0k/stuffz/blob/master/llvm-funz/llvm-cpp-frontend-home-made-32bits-adder.cpp). Long story short, the code uses the LLVM frontend API to emit a home made 32 bits adder in the [LLVM intermediate language](http://llvm.org/docs/LangRef.html). You can then feed the output directly to clang to generate a real executable binary for your platform, I chose to work only on the x86 platform here. I've also uploaded the binary here: [adder](https://github.com/0vercl0k/stuffz/blob/master/llvm-funz/adder).

So if you open the generated binary in IDA, you will see an interminable routine that only does an addition. At first glance, it really is kind of scary:

* every instructions seems to be important, there is no junk codes
* it seems that only binary operations are used: addition, left shift, right shift, xor, etc.
* it's also a two thousands instructions routine

The idea in this post is to write a very basic symbolic execution engine in order to see what kind of result will hold the EAX register at the end of the routine. Hopefully, we will obtain something highly simplified and more readable that this bunch of assembly codes!

# The symbolic execution engine approach
But in fact that piece of code makes it **really** easy for us to write a symbolic execution engine. Here are the main reasons:

* there is no branches, no loops, perfect.
* the instruction aren't playing with the [EFLAGS](https://en.wikipedia.org/wiki/FLAGS_register) register.
* the instruction only used 32 bits registers (not 16 bits, or 8 bits).
* the number of unique instruction is really small: *mov*, *shr*, *shl*, *xor*, *and*, *xor*, *add*.
* the instructions used are easy to emulate.

Understand that here, we are really in a specific case, the engine wouldn't be that easy to implement to cover the most used x86 instructions ; but we are lucky, we won't need that!

The engine is in fact a pseudo-emulator that propagates the different actions done by the asm instructions. Here is how our engine works:

1. Each time a symbolic variable is found, you instantiate a Z3 BitVector and you keep it somewhere. A symbolic variable is basically a variable that the attacker can control. For example, in our case, we will have two symbolic variables: the two arguments passed to the function. We will see later an easy heuristic to find "automatically" the symbolic variables in our case.
2. When you have an instruction, you emulate it and you update the CPU state of the engine. If it involves an equation, you update your set of equations.
3. You do that until the end of the routine.

Of course, when the engine has been successfully executed, you may want to ask it some questions like "what does hold the EAX register at the end of the routine?". You want to have exactly all the operations needed to compute EAX. In our case, we hope to obtain "*symbolic_variable1* + *symbolic_variable2*".

Here is a little example to sum up what we just said:
```nasm
mov eax, [arg1]  ; at this moment we have our first symbolic variable
                 ; we push it in our equations list
mov edx, [arg2]  ; same thing here

shr eax, 2   ; EAX=sym1 >> 2
add eax, 1   ; EAX=(sym1 >> 2) + 1
shl eax, 3   ; EAX=((sym1 >> 2) + 1) << 1
and eax, 2   ; EAX=(((sym1 >> 2) + 1) << 1) & 2
inc edx      ; EDX=sym2 + 1
xor edx, eax ; EDX=(sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2)
mov eax, edx ; EAX=(sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2)
```

So at the end, you can ask the engine to give you the final state of EAX for example and it should give you something like:
```text
EAX=(sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2)
```

With that equation you are free to use Z3Py to either simplify it or to try to find how you can have a specific value in EAX controlling only the symbolic variables:

```text
In [1]: from z3 import *
In [2]: sym1 = BitVec('sym1', 32)
In [3]: sym2 = BitVec('sym2', 32)

In [4]: simplify((sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2))
Out[4]: 1 + sym2 ^ Concat(0, 1 + Extract(0, 0, sym1 >> 2), 0)

In [5]: solve((sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2) == 0xdeadbeef)
[sym1 = 0, sym2 = 3735928556]

In [6]: solve((sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2) == 0xdeadbeef, sym1 !=  0)
[sym1 = 1073741824, sym2 = 3735928556]

In [7]: sym1 = 1073741824
In [8]: sym2 = 3735928556

In [9]: hex((sym2 + 1) ^ ((((sym1 >> 2) + 1) << 1) & 2) & 0xffffffff)
Out[9]: '0xdeadbeefL'
```

As you can imagine, that kind of tool is very valuable/handy when you do reverse-engineering tasks or bug-hunting. Unfortunately, our PoC won't be enough accurate/generic/complete to be used in "normal" cases, but never mind.

# Let's code
To implement our little PoC we will use only [IDAPython](https://code.google.com/p/idapython/) and [Z3Py](http://rise4fun.com/z3py/).
## The disassembler
The first thing we have to do is to use IDA's API in order to have some inspection information about assembly instructions. The idea is just to have the mnemonic, the source and the destination operands easily ; here is the class I've designed toward that purpose:

```python Disassembler class
class Disassembler(object):
    '''A simple class to decode easily instruction in IDA'''
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.eip = start

    def _decode_instr(self):
        '''Returns mnemonic, dst, src'''
        mnem = GetMnem(self.eip)
        x = []
        for i in range(2):
            ty = GetOpType(self.eip, i)
            # cst
            if 5 <= ty <= 7:
                x.append(GetOperandValue(self.eip, i))
            else:
                x.append(GetOpnd(self.eip, i))

        return [mnem] + x

    def get_next_instruction(self):
        '''This is a convenient generator, you can iterator through
        each instructions easily'''
        while self.eip != self.end:
            yield self._decode_instr()
            self.eip += ItemSize(self.eip)
```

## The symbolic execution engine
There are several important parts in our engine:

1. the part which "emulates" the assembly instruction.
2. the part which stores the different equations used through the routine. It is a simple Python dictionary: the key is a unique identifier, and the value is the equation
3. the CPU state. We also use a dictionary for that purpose: the key will be the register names, and the value will be what the register holds at that specific moment. Note we will only store the unique identifier of the equation. In fact, our design is really similar to Jonathan's one in "[Binary analysis: Concolic execution with Pin and z3](http://shell-storm.org/blog/Binary-analysis-Concolic-execution-with-Pin-and-z3/)", so please refer you to his cool pictures if it's not really clear :P.
4. the memory state ; in that dictionary we store memory references. Remember, if we find a non-initialized access to a memory area we instantiate a symbolic variable. That is our heuristic to find the symbolic variables automatically.

Here is the PoC code:

```python SymbolicExecutionEngine class
def prove(f):
    '''Taken from http://rise4fun.com/Z3Py/tutorialcontent/guide#h26'''
    s = Solver()
    s.add(Not(f))
    if s.check() == unsat:
        return True
    return False

class SymbolicExecutionEngine(object):
    '''The symbolic execution engine is the class that will
    handle the symbolic execution. It will keep a track of the 
    different equations encountered, and the CPU context at each point of the program.

    The symbolic variables have to be found by the user (or using data-taing). This is not
    the purpose of this class.

    We are lucky, we only need to handle those operations & encodings:
        . mov:
            . mov reg32, reg32
            . mov reg32, [mem]
            . mov [mem], reg32
        . shr:
            . shr reg32, cst
        . shl:
            . shl reg32, cst
        . and:
            . and reg32, cst
            . and reg32, reg32
        . xor:
            . xor reg32, cst
        . or:
            . or reg32, reg32
        . add:
            . add reg32, reg32

    We also don't care about:
        . EFLAGS
        . branches
        . smaller registers (16/8 bits)
    Long story short: it's perfect ; that environment makes really easy to play with symbolic execution.'''
    def __init__(self, start, end):
        # This is the CPU context at each time
        # The value of the registers are index in the equations dictionnary
        self.ctx = {
            'eax' : None,
            'ebx' : None,
            'ecx' : None,
            'edx' : None,
            'esi' : None,
            'edi' : None,
            'ebp' : None,
            'esp' : None,
            'eip' : None
        }

        # The address where the symbolic execution will start
        self.start = start

        # The address where the symbolic execution will stop
        self.end = end

        # Our disassembler
        self.disass = Disassembler(start, end)

        # This is the memory that can be used by the instructions to save temporary values/results
        self.mem = {}

        # Each equation must have a unique id
        self.idx = 0

        # The symbolic variables will be stored there
        self.sym_variables = []

        # Each equation will be stored here
        self.equations = {}

    def _check_if_reg32(self, r):
        '''XXX: make a decorator?'''
        return r.lower() in self.ctx

    def _push_equation(self, e):
        self.equations[self.idx] = e
        self.idx += 1
        return (self.idx - 1)

    def set_reg_with_equation(self, r, e):
        if self._check_if_reg32(r) == False:
            return

        self.ctx[r] = self._push_equation(e)

    def get_reg_equation(self, r):
        if self._check_if_reg32(r) == False:
            return

        return self.equations[self.ctx[r]]

    def run(self):
        '''Run from start address to end address the engine'''
        for mnemonic, dst, src in self.disass.get_next_instruction():
            if mnemonic == 'mov':
                # mov reg32, reg32
                if src in self.ctx and dst in self.ctx:
                    self.ctx[dst] = self.ctx[src]
                # mov reg32, [mem]
                elif (src.find('var_') != -1 or src.find('arg') != -1) and dst in self.ctx:
                    if src not in self.mem:
                        # A non-initialized location is trying to be read, we got a symbolic variable!
                        sym = BitVec('arg%d' % len(self.sym_variables), 32)
                        self.sym_variables.append(sym)
                        print 'Trying to read a non-initialized area, we got a new symbolic variable: %s' % sym
                        self.mem[src] = self._push_equation(sym)
                    
                    self.ctx[dst] = self.mem[src]
                # mov [mem], reg32
                elif dst.find('var_') != -1 and src in self.ctx:
                    if dst not in self.mem:
                        self.mem[dst] = None

                    self.mem[dst] = self.ctx[src]
                else:
                    raise Exception('This encoding of "mov" is not handled.')
            elif mnemonic == 'shr':
                # shr reg32, cst
                if dst in self.ctx and type(src) == int:
                    self.set_reg_with_equation(dst, LShR(self.get_reg_equation(dst), src))
                else:
                    raise Exception('This encoding of "shr" is not handled.')
            elif mnemonic == 'shl':
                # shl reg32, cst
                if dst in self.ctx and type(src) == int:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) << src)
                else:
                    raise Exception('This encoding of "shl" is not handled.')
            elif mnemonic == 'and':
                x = None
                # and reg32, cst
                if type(src) == int:
                    x = src
                # and reg32, reg32
                elif src in self.ctx:
                    x = self.get_reg_equation(src)
                else:
                    raise Exception('This encoding of "and" is not handled.')

                self.set_reg_with_equation(dst, self.get_reg_equation(dst) & x)
            elif mnemonic == 'xor':
                # xor reg32, cst
                if dst in self.ctx and type(src) == int:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) ^ src)
                else:
                    raise Exception('This encoding of "xor" is not handled.')
            elif mnemonic == 'or':
                # or reg32, reg32
                if dst in self.ctx and src in self.ctx:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) | self.get_reg_equation(src))
                else:
                    raise Exception('This encoding of "or" is not handled.')
            elif mnemonic == 'add':
                # add reg32, reg32
                if dst in self.ctx and src in self.ctx:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) + self.get_reg_equation(src))
                else:
                    raise Exception('This encoding of "add" is not handled.')
            else:
                print mnemonic, dst, src
                raise Exception('This instruction is not handled.')

    def get_reg_equation_simplified(self, reg):
        eq = self.get_reg_equation(reg)
        eq = simplify(eq)
        return eq
```

## Testing
OK, we just have to instantiate the engine giving him the start/end address of the routine and to ask him to give us the final equation holded in EAX.

```python main
def main():
    '''Here we will try to attack the semantic-preserving obfuscations
    I talked about in "Obfuscation of steel: meet my Kryptonite." : http://0vercl0k.tuxfamily.org/bl0g/?p=260.

    The idea is to defeat those obfuscations using a tiny symbolic execution engine.'''
    sym = SymbolicExecutionEngine(0x804845A, 0x0804A17C)
    print 'Launching the engine..'
    sym.run()
    print 'Done, retrieving the equation in EAX, and simplifying..'
    eax = sym.get_reg_equation_simplified('eax')
    print 'EAX=%r' % eax
    return 1

if __name__ == '__main__':
    main()
```

And here is what I saw:

```text
Launching the engine..
Trying to read a non-initialized area, we got a new symbolic variable: arg0
Trying to read a non-initialized area, we got a new symbolic variable: arg1
Done, retrieving the equation in EAX, and simplifying..
EAX=(~(Concat(2147483647, Extract(0, 0, arg1)) |
   Concat(2147483647, ~Extract(0, 0, arg0)) |
   4294967294) |
 ~(Concat(2147483647, ~Extract(0, 0, arg1)) |
   Concat(2147483647, Extract(0, 0, arg0)) |
   4294967294)) +
Concat(~(Concat(1073741823, Extract(1, 1, arg1)) |
         Concat(1073741823, ~Extract(1, 1, arg0)) |
         Concat(1073741823,
                ~(~Extract(0, 0, arg1) |
                  ~Extract(0, 0, arg0)))) |
       ~(Concat(1073741823, ~Extract(1, 1, arg1)) |
         Concat(1073741823, Extract(1, 1, arg0)) |
         Concat(1073741823,
                ~(~Extract(0, 0, arg1) |
                  ~Extract(0, 0, arg0)))) |
       ~(Concat(1073741823, Extract(1, 1, arg1)) |
         Concat(1073741823, Extract(1, 1, arg0)) |
         Concat(1073741823, ~Extract(0, 0, arg1)) |
         Concat(1073741823, ~Extract(0, 0, arg0)) |
         2147483646) |
       ~(Concat(1073741823, ~Extract(1, 1, arg1)) |
         Concat(1073741823, ~Extract(1, 1, arg0)) |
         Concat(1073741823, ~Extract(0, 0, arg1)) |
         Concat(1073741823, ~Extract(0, 0, arg0)) |
         2147483646),
       0) +
...
```

There was two possible explanations for this problem:

* my code is wrong, and it generates equations not simplify-able.
* my code is right, and Z3Py's simplify method has a hard time to simplify it.

 To know what was the right answer, I used Z3Py's prove function in order to know if the equation was equivalent to a simple addition:

```python main
 def main():
    '''Here we will try to attack the semantic-preserving obfuscations
    I talked about in "Obfuscation of steel: meet my Kryptonite." : http://0vercl0k.tuxfamily.org/bl0g/?p=260.

    The idea is to defeat those obfuscations using a tiny symbolic execution engine.'''
    sym = SymbolicExecutionEngine(0x804845A, 0x0804A17C)
    print 'Launching the engine..'
    sym.run()
    print 'Done, retrieving the equation in EAX, and simplifying..'
    eax = sym.get_reg_equation_simplified('eax')
    print prove(eax == Sum(sym.sym_variables))
    return 1

if __name__ == '__main__':
    main()
```

Fortunately for us, it printed *True* ; so our code is correct. But it also means, the simplify function, as is at least, isn't able to simplify that bunch of equations involving bit-vector arithmetics. I still haven't found a clean way to make Z3Py simplify my big equation, so if someone knows how I can do that please contact me. I've also exported the complete equation, and uploaded it [here](/downloads/code/breaking_kryptonite_s_obfuscation_with_symbolic_execution/eq.txt) ; you are free to give it a try like this.

The ugly trick I came up with is just to use Z3Py's prove function, to try to prove that the equation is in fact an addition and if this is the case it returns the simplified equation. Again, if someone manages to simplify the previous equation without that type of trick I'm really interested!

```python nasty trick
    def _simplify_additions(self, eq):
        '''The idea in this function is to help Z3 to simplify our big bitvec-arithmetic
        expression. It's simple, in eq we have a big expression with two symbolic variables (arg0 & arg1)
        and a lot of bitvec arithmetic. Somehow, the simplify function is not clever enough to reduce the
        equation.

        The idea here is to use the prove function in order to see if we can simplify an equation by an addition of the
        symbolic variables.'''
        # The two expressions are equivalent ; we got a simplification!
        if prove(Sum(self.sym_variables) == eq):
            return Sum(self.sym_variables)

        return eq

    def get_reg_equation_simplified(self, reg):
        eq = self.get_reg_equation(reg)
        eq = simplify(self._simplify_additions(eq))
        return eq
```

And now if you relaunch the script you will get:

```text
Launching the engine..
Trying to read a non-initialized area, we got a new symbolic variable: arg0
Trying to read a non-initialized area, we got a new symbolic variable: arg1
Done, retrieving the equation in EAX, and simplifying..
EAX=arg0 + arg1
```

We just successfully simplified two thousands of assembly into a simple addition, wonderful!

# Symbolic execution VS Kryptonite
OK, now we have a working engine able to break a small program (~two thousands instructions), let's see if we can do the same with a kryptonized-binary. Let's take a simple addition like in the previous parts:

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int add(unsigned int a, unsigned int b)
{
    return a + b;
}

int main(int argc, char* argv[])
{
    if(argc != 3)
        return 0;

    printf("Result: %u\n", add(atoll(argv[1]), atoll(argv[2])));
    return 1;
}
```

Now, time for a kryptonization:

```bash
$ wget https://raw.github.com/0vercl0k/stuffz/master/llvm-funz/kryptonite/llvm-functionpass-kryptonite-obfuscater.cpp
$ clang++ llvm-functionpass-kryptonite-obfuscater.cpp `llvm-config --cxxflags --ldflags --libs core` -shared -o llvm-functionpass-kryptonite-obfuscater.so
$ clang -S -emit-llvm add.c -o add.ll
$ opt -S -load ~/dev/llvm-functionpass-kryptonite-obfuscater.so -kryptonite -heavy-add-obfu add.ll -o add.opti.ll && mv add.opti.ll add.ll
$ opt -S -load ~/dev/llvm-functionpass-kryptonite-obfuscater.so -kryptonite -heavy-add-obfu add.ll -o add.opti.ll && mv add.opti.ll add.ll
$ llc -O0 -filetype=obj -march=x86 add.ll -o add.o
$ clang -static add.o -o kryptonite-add
$ strip --strip-all ./kryptonite-add
```

At this moment we end up with that binary: [kryptonite-add](https://github.com/0vercl0k/stuffz/blob/master/llvm-funz/kryptonite-add). The target routine for our study starts at 0x804823C and ends at 0x08072284 ; roughly more than 40 thousands assembly instructions and kind of big right?

Here is our final IDAPython script after some minor adjustments (added one or two more instructions):

```python tiny_symbolic_execution_engine_z3.py https://github.com/0vercl0k/stuffz/blob/master/llvm-funz/tiny_symbolic_execution_engine_z3.py
class EquationId(object):
    def __init__(self, id_):
        self.id = id_

    def __repr__(self):
        return 'EID:%d' % self.id

class Disassembler(object):
    '''A simple class to decode easily instruction in IDA'''
    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.eip = start

    def _decode_instr(self):
        '''Returns mnemonic, dst, src'''
        mnem = GetMnem(self.eip)
        x = []
        for i in range(2):
            ty = GetOpType(self.eip, i)
            # cst
            if 5 <= ty <= 7:
                x.append(GetOperandValue(self.eip, i))
            else:
                x.append(GetOpnd(self.eip, i))

        return [mnem] + x

    def get_next_instruction(self):
        '''This is a convenient generator, you can iterator through
        each instructions easily'''
        while self.eip != self.end:
            yield self._decode_instr()
            self.eip += ItemSize(self.eip)

class SymbolicExecutionEngine(object):
    '''The symbolic execution engine is the class that will
    handle the symbolic execution. It will keep a track of the 
    different equations encountered, and the CPU context at each point of the program.

    The symbolic variables have to be found by the user (or using data-taing). This is not
    the purpose of this class.

    We are lucky, we only need to handle those operations & encodings:
        . mov:
            . mov reg32, reg32
            . mov reg32, [mem]
            . mov [mem], reg32
            . mov reg32, cst
        . shr:
            . shr reg32, cst
        . shl:
            . shl reg32, cst
        . and:
            . and reg32, cst
            . and reg32, reg32
        . xor:
            . xor reg32, cst
        . or:
            . or reg32, reg32
        . add:
            . add reg32, reg32
            . add reg32, cst

    We also don't care about:
        . EFLAGS
        . branches
        . smaller registers (16/8 bits)
    Long story short: it's perfect ; that environment makes really easy to play with symbolic execution.'''
    def __init__(self, start, end):
        # This is the CPU context at each time
        # The value of the registers are index in the equations dictionnary
        self.ctx = {
            'eax' : None,
            'ebx' : None,
            'ecx' : None,
            'edx' : None,
            'esi' : None,
            'edi' : None,
            'ebp' : None,
            'esp' : None,
            'eip' : None
        }

        # The address where the symbolic execution will start
        self.start = start

        # The address where the symbolic execution will stop
        self.end = end

        # Our disassembler
        self.disass = Disassembler(start, end)

        # This is the memory that can be used by the instructions to save temporary values/results
        self.mem = {}

        # Each equation must have a unique id
        self.idx = 0

        # The symbolic variables will be stored there
        self.sym_variables = []

        # Each equation will be stored here
        self.equations = {}

        # Number of instructions emulated
        self.ninstrs = 0

    def _check_if_reg32(self, r):
        '''XXX: make a decorator?'''
        return r.lower() in self.ctx

    def _push_equation(self, e):
        idx = EquationId(self.idx)
        self.equations[idx] = e
        self.idx += 1
        return idx

    def set_reg_with_equation(self, r, e):
        if self._check_if_reg32(r) == False:
            return

        self.ctx[r] = self._push_equation(e)

    def get_reg_equation(self, r):
        if self._check_if_reg32(r) == False:
            return

        if isinstance(self.ctx[r], EquationId):
            return self.equations[self.ctx[r]]
        else:
            return self.ctx[r]

    def run(self):
        '''Run from start address to end address the engine'''
        for mnemonic, dst, src in self.disass.get_next_instruction():
            if (self.ninstrs % 5000) == 0 and self.ninstrs > 0:
                print '%d instructions, %d equations so far...' % (self.ninstrs, len(self.equations))

            if mnemonic == 'mov':
                # mov reg32, imm32
                if dst in self.ctx and isinstance(src, (int, long)):
                    self.ctx[dst] = src
                # mov reg32, reg32
                elif src in self.ctx and dst in self.ctx:
                    self.ctx[dst] = self.ctx[src]
                # mov reg32, [mem]
                elif (src.find('var_') != -1 or src.find('arg') != -1) and dst in self.ctx:
                    if src not in self.mem:
                        # A non-initialized location is trying to be read, we got a symbolic variable!
                        sym = BitVec('arg%d' % len(self.sym_variables), 32)
                        self.sym_variables.append(sym)
                        print 'Trying to read a non-initialized area, we got a new symbolic variable: %s' % sym
                        self.mem[src] = self._push_equation(sym)
                    
                    self.ctx[dst] = self.mem[src]
                # mov [mem], reg32
                elif dst.find('var_') != -1 and src in self.ctx:
                    self.mem[dst] = self.ctx[src]
                else:
                    raise Exception('This encoding of "mov" is not handled.')
            elif mnemonic == 'shr':
                # shr reg32, cst
                if dst in self.ctx and isinstance(src, (int, long)):
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) >> src)
                else:
                    raise Exception('This encoding of "shr" is not handled.')
            elif mnemonic == 'shl':
                # shl reg32, cst
                if dst in self.ctx and isinstance(src, (int, long)):
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) << src)
                else:
                    raise Exception('This encoding of "shl" is not handled.')
            elif mnemonic == 'and':
                # and reg32, cst
                if isinstance(src, (int, long)):
                    x = src
                # and reg32, reg32
                elif src in self.ctx:
                    x = self.get_reg_equation(src)
                else:
                    raise Exception('This encoding of "and" is not handled.')

                self.set_reg_with_equation(dst, self.get_reg_equation(dst) & x)
            elif mnemonic == 'xor':
                # xor reg32, cst
                if dst in self.ctx and isinstance(src, (int, long)):
                    if self.ctx[dst] not in self.equations:
                        self.ctx[dst] ^= src
                    else:
                        self.set_reg_with_equation(dst, self.get_reg_equation(dst) ^ src)
                else:
                    raise Exception('This encoding of "xor" is not handled.')
            elif mnemonic == 'or':
                # or reg32, reg32
                if dst in self.ctx and src in self.ctx:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) | self.get_reg_equation(src))
                else:
                    raise Exception('This encoding of "or" is not handled.')
            elif mnemonic == 'add':
                # add reg32, reg32
                if dst in self.ctx and src in self.ctx:
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) + self.get_reg_equation(src))
                # add reg32, cst
                elif dst in self.ctx and isinstance(src, (int, long)):
                    self.set_reg_with_equation(dst, self.get_reg_equation(dst) + src)
                else:
                    raise Exception('This encoding of "add" is not handled.')
            else:
                print mnemonic, dst, src
                raise Exception('This instruction is not handled.')

            self.ninstrs += 1

    def _simplify_additions(self, eq):
        '''The idea in this function is to help Z3 to simplify our big bitvec-arithmetic
        expression. It's simple, in eq we have a big expression with two symbolic variables (arg0 & arg1)
        and a lot of bitvec arithmetic. Somehow, the simplify function is not clever enough to reduce the
        equation.

        The idea here is to use the prove function in order to see if we can simplify an equation by an addition of the
        symbolic variables.'''
        # The two expressions are equivalent ; we got a simplification!
        if prove_(Sum(self.sym_variables) == eq):
            return Sum(self.sym_variables)

        return eq

    def get_reg_equation_simplified(self, reg):
        eq = self.get_reg_equation(reg)
        eq = simplify(self._simplify_additions(eq))
        return eq


def main():
    '''Here we will try to attack the semantic-preserving obfuscations
    I talked about in "Obfuscation of steel: meet my Kryptonite." : http://0vercl0k.tuxfamily.org/bl0g/?p=260.

    The idea is to defeat those obfuscations using a tiny symbolic execution engine.'''
    # sym = SymbolicExecutionEngine(0x804845A, 0x0804A17C) # for simple adder
    sym = SymbolicExecutionEngine(0x804823C, 0x08072284) # adder kryptonized
    print 'Launching the engine..'
    sym.run()
    print 'Done. %d equations built, %d assembly lines emulated, %d virtual memory cells used' % (len(sym.equations), sym.ninstrs, len(sym.mem))
    print 'CPU state at the end:'
    print sym.ctx
    print 'Retrieving and simplifying the EAX register..'
    eax = sym.get_reg_equation_simplified('eax')
    print 'EAX=%r' % eax
    return 1

if __name__ == '__main__':
    main()
```

And here is the final output:

```text
Launching the engine..
Trying to read a non-initialized area, we got a new symbolic variable: arg0
Trying to read a non-initialized area, we got a new symbolic variable: arg1
5000 instructions, 2263 equations so far...
10000 instructions, 4832 equations so far...
15000 instructions, 7228 equations so far...
20000 instructions, 9766 equations so far...
25000 instructions, 12212 equations so far...
30000 instructions, 14762 equations so far...
35000 instructions, 17255 equations so far...
40000 instructions, 19801 equations so far...
Done. 19857 equations built, 40130 assembly lines emulated, 5970 virtual memory cells used
CPU state at the end:
{'eax': EID:19856, 'ebp': None, 'eip': None, 'esp': None, 'edx': EID:19825, 'edi': EID:19796, 'ebx': EID:19797, 'esi': EID:19823, 'ecx': EID:19856}
Retrieving and simplifying the EAX register..
EAX=arg0 + arg1
```

# Conclusion
I hope you did enjoy this little introduction to symbolic execution, and how it can be very valuable to remove some semantic-preserving obfuscations. We also have seen that this PoC is not really elaborate: it doesn't handle loops or any branches, doesn't care about EFLAGS, etc ; but it was enough to break our two examples. I hope you also enjoyed the examples used to showcase our tiny symbolic execution engine.

If you want to go further with symbolic execution, here is a list of nice articles:

* [Anatomy of a Symbolic Emulator, Part 1: Trace Generation](http://seanhn.wordpress.com/2012/03/23/anatomy-of-a-symbolic-emulator-part-1-trace-generation/)
* [Anatomy of a Symbolic Emulator, Part 2: Introducing Symbolic Data](http://seanhn.wordpress.com/2012/03/23/anatomy-of-a-symbolic-emulator-part-2-introducing-symbolic-data/)
* [Anatomy of a Symbolic Emulator, Part 3: Processing Symbolic Data & Generating New Inputs](http://seanhn.wordpress.com/2012/03/23/anatomy-of-a-symbolic-emulator-part-3-processing-symbolic-data-generating-new-inputs/)
* [Test Generation Using Symbolic Execution](http://research.microsoft.com/en-us/um/people/pg/public_psfiles/fsttcs2012.pdf)
* [The KLEE Symbolic Virtual Machine](http://ccadar.github.io/klee/)
* [Concolic execution - Taint analysis with Valgrind and constraints path solver with Z3](http://shell-storm.org/blog/Concolic-execution-taint-analysis-with-valgrind-and-constraints-path-solver-with-z3/)
* [A Bibliography of Papers on Symbolic Execution Technique and its Applications](https://sites.google.com/site/symexbib/)

PS: By the way, for those who like weird machines, I've managed to code a MOV/JMP turing machine based on [mov is Turing-complete](http://www.cl.cam.ac.uk/~sd601/papers/mov.pdf) here: [fun_with_mov_turing_completeness.cpp](https://github.com/0vercl0k/stuffz/blob/master/fun_with_mov_turing_completeness.cpp)!