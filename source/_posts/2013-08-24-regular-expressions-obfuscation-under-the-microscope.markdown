---
layout: post
title: "Regular expressions obfuscation under the microscope"
date: 2013-08-24 12:35
comments: true
categories: [reverse-engineering, obfuscation]
author: Axel "0vercl0k" Souchet
published: false
---
# Introduction #
Some months ago I came across a strange couple of functions that was kind of playing with a [finite-state automaton](http://en.wikipedia.org/wiki/Finite-state_machine) to validate an input. At first glance, I didn't really notice it was processing a regex, that's exactly why I spent quite some time to understand those routines. Maybe you are thinking something like "Hmm but the regex string representation should be in the binary shoudn't it?", but it wasn't. The purpose of this post is to focus on those kind of "compiled" regex, like when the author transform somehow the regex in a FSM directly usable in its program (for the sake of efficiency I guess). And to extract that handy string representation, you have to study the automata.

In this short post, we are going to see how a regular expression looks like in assembly/C. I hope you will enjoy the read, and you will either now be able to recognize a regular expression compiled in your future reverse-engineering tasks or to obfuscate heavily/evily your regex!

<!--more-->

# Bring out the FSM
## Manually
Before studying how works well-known regex libraries, let's see how we can implement a simple regex in C. It's always easier to reverse-engineer something you have, at least once in your life, implemented. Even if the actual implementation is slightly different from the one you did.
Let's say we want to have an automata that matches "Hi-[0-9]{4}". Now, if from that string representation we extract an FSM, we can have that one:

{% img center /images/regular_expressions_obfuscation_under_the_microscope/FSM_example.png %}

Here is this automata implemented in C:

{% include_code regular_expressions_obfuscation_under_the_microscope/fsm_example.c %}

If we try to execute the program:
{% codeblock %}
> fsm_example.exe garbage-Hi-1337-garbage
Good boy.

> fsm_example.exe garbage-Hi-1337
Good boy.

> fsm_example.exe Hi-1337-garbage
Good boy.

> fsm_example.exe Hi-dudies
Bad boy.
{% endcodeblock %}

The purpose of that trivial example was just to show you how a regex string representation can be compiled into something harder to analyze but also more efficient (it doesn't need a compilation step, that's the reason why you may encounter that kind of thing). Even if the code seems trivial at the first sight, when you look at it at the assembly level, it takes a bit of time to figure out it's a simple "Hi-[0-9]{4}" regex.

{% img center /images/regular_expressions_obfuscation_under_the_microscope/cfg.png %}

In that kind of analysis, it's really important to find the "state" variable that allows the program to pass through the differents nodes of the FSM. Then, you have also to figure out how you can reach a node, and all the nodes reachable from a specific one. To make it short, at the end of your analysis you really want to have a clean FSM automata like the one we did earlier. And once you have it, you want to eliminate unreachable nodes, and to minimize it in order to remove some potential automaton obfuscation.

{% include_code regular_expressions_obfuscation_under_the_microscope/fsm_example.c %}


## Automatically
What if our regex was totally more complex ? It would be a hell to implement manually the FSM. That's why I wanted to find some ways usable if you want to generate your own FSM from a regex string manipulation.
### With re2c
[re2c](http://re2c.org/manual.html) is a cool and simple tool that allows you to describe your regex in a C comment, then it will generate you the code of the scanner. As an example, here is the source code to generate the scanner for the previous regex:

{% include_code regular_expressions_obfuscation_under_the_microscope/fsm_re2c_example.c %}

Once you feed that source to re2c, it gives you that scanner that is ready to be compiled:

{% include_code regular_expressions_obfuscation_under_the_microscope/fsm_re2c_generated_non_optimized.c %}

Cool isn't it ? But in fact, if you try to compile and Hexrays it (even with optimizations disabled) you will be completely disappointed: it gets simplified like *really*.

{% img center /images/regular_expressions_obfuscation_under_the_microscope/hexrays.png %}

### By hand
That's why I tried to generate myself the C code of the scanner. The first thing I wanted to find was a ["regular-expression string" to FSM Python library](http://osteele.com/software/python/fsa/reCompiler.html): a regex compiler. Then, once you have your FSM, you are completely free to obfuscate the automaton. You are also free to generate the C code you want.
Here is the ugly-buggy-PoC code I did to generate the scanner for the regex used previously:

{% include_code regular_expressions_obfuscation_under_the_microscope/generate_c_fsm.py %}

Now, if you open it in IDA the CFG will look like this:

{% img center /images/regular_expressions_obfuscation_under_the_microscope/hell_yeah.png %}

Not that fun to reverse-engineer I guess. If you want to look at the complete source, here it is: [fsm_generated_by_hand_example.c](/downloads/code/regular_expressions_obfuscation_under_the_microscope/fsm_generated_by_hand_example.c).

## Thoughts to be more evil: one input to bind all the regex in the darkness
Keep in mind, the previous examples are really trivial to analyze, even if we had to do it at the assembly level without Hexrays (by the way Hexrays does a really nice job to simplify the assembly code, cool for us!). Of course you can imagine to obfuscate the automaton with useless states, etc.

But one interesting idea to bother the reverse-engineer is to use several regex as input filters. If you extract the first FSM, you will see there is too many possible valid inputs ; so you use another regex as a filter, to reduce the valid inputs set. And you do that until you have only one valid input: your serial. You also want to do that with complex regex, because you are evil.

Then, the reverse-engineer has to analyze all the different regex, because if you focus on a unique regex, you will have too many valid inputs and only one gives you the good boy (the intersection of all the valid inputs of the different regex). The only public thing I've seen that does similar things was in a CTF task write-up written by [Michal Kowalczyk](https://plus.google.com/111956453297829313313): read [it](http://blog.dragonsector.pl/2013/07/sigint-ctf-2013-task-fenster-400-pts.html), it's awesome.

Messing with automata is good for you.