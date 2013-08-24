---
layout: post
title: "Compiled regular expressions under the microscope"
date: 2013-08-24 12:35
comments: true
categories: [reverse-engineering, obfuscation]
author: Axel "0vercl0k" Souchet
published: false
---
# Introduction #
Some months ago I came across a strange couple of functions that was kind of playing with a [finite-state automaton](http://en.wikipedia.org/wiki/Finite-state_machine) to validate an input. At first glance, I didn't really notice it was a finite-state machine, that's exactly why I spent quite some time to understand those routines. Maybe you are thinking something like "Hmm but the regex string representation should be in the binary shoudn't it?", but it wasn't. The purpose of this post is to focus on those kind of "compiled" regex, like when the author transform somehow the regex in a FSM directly usable in its program (for the sake of efficiency I guess). And to extract that handy string representation, you have to study the automata.

In this short post, we are going to see how a regular expression looks like in assembly/C. I hope you will enjoy the read, and you will either now be able to recognize a regular expression compiled in your future reverse-engineering tasks or to obfuscate heavily/evily your regex!

<!--more-->

# Bring out the FSM
## Manually
Before studying how works well-known regex libraries, let's see how we can implement a simple regex in C. It's always easier to reverse-engineer something you have, at least once in your life, implemented. Even if the actual implementation is slightly different from the one you did.
Let's say we want to have an automata that matches "Hi-[0-9]{4}". Now, if from that string representation we extract an FSM, we can have that one:

{% img center /images/compiled_regular_expressions_under_the_microscope/FSM_example.png %}

Here is this automata implemented in C:

{% include_code compiled_regular_expressions_under_the_microscope/fsm_example.c %}

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

{% img center /images/compiled_regular_expressions_under_the_microscope/cfg.png %}

In that kind of analysis, it's really important to find the "state" variable that allows the program to pass through the differents nodes of the FSM. Then, you have also to figure out how you can reach a node, and all the nodes reachable from a specific one. To make it short, at the end of your analysis you really want to have a clean FSM automata like the one we did earlier.

## Automatically with re2c

## One input to bind all the regex in the darkness
Keep in mind, the previous examples are really trivial to analyze, even if we had to do it at the assembly level without Hexrays (by the way Hexrays does a really nice job to simplify the assembly code, cool for us!). Of course you can imagine to obfuscate the automaton with useless states, etc.

But one interesting idea to bother the reverse-engineer is to use several regex as input filters. If you extract the first FSM, you will see there is too many possible valid inputs ; so you use another regex as a filter, to reduce the valid inputs set. And you do that until you have only one valid input: your serial. You also want to do that with complex regex, because you are evil.

Then, the reverse-engineer has to analyze all the different regex, because if you focus on a unique regex, you will have too many valid inputs and only one gives you the good boy (the intersection of all the valid inputs of the different regex). The only public thing I've seen that does similar things was in a CTF task write-up written by [Michal Kowalczyk](https://plus.google.com/111956453297829313313): read [it](http://blog.dragonsector.pl/2013/07/sigint-ctf-2013-task-fenster-400-pts.html), it's awesome.