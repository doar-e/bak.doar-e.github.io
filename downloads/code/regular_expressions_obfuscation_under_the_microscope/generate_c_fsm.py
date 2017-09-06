import reCompiler
import random

c = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'

fsm = reCompiler.compileRE('Hi-[0-9][0-9][0-9][0-9]', minimize = 1)
states = fsm.states
transitions = fsm.transitions

useless_states = [random.randint(0, 0xffffffff) for _ in range(random.randint(50, 100))]
states += useless_states

# We don't want to have dead nodes, so let's create transition
deadnodes = set(useless_states)
while len(deadnodes) != 0:
    s, d, t = random.choice(states), random.choice(states), random.choice(c)
    transitions += [(s, d, t)]
    deadnodes -= set([s])

# To obfuscate we can use random state number
dic_states = dict(
    (i, random.randint(0, 0xffffffff)) for i in states
)

random.shuffle(states)
assert(len(dic_states.values()) == len(set(dic_states.values())))

print 'unsigned char checkinput(char *p){\nunsigned int state = %d;\nwhile(*p)\n{\nswitch(state)\n{' % dic_states[fsm.initialState]

for i in states:
    if i in fsm.finalStates:
        continue

    print 'case %d:\n{' % dic_states[i]
    
    is_first = True
    for src, dst, t in transitions:
        if src != i:
            continue

        if is_first == False:
            print 'else',
        else:
            is_first = False

        r = str(t)
        if r.startswith('\\') == False or len(r) == 1:
            print "if(*p == %s)" % repr(r)
        elif r == '\\d':
            print "if(*p >= '0' && *p <= '9')"
        else:
            raise Exception('Not implemented!')

        print '{'

        if dst in fsm.finalStates:
            print 'return 1;'
        else:
            print 'state = %d; ++p;' % dic_states[dst]

        print '}' 

    # Kind of hack to not anchor the regex (not handled by the RE->FSM)
    if i == fsm.initialState:
        print 'else ++p;'
    else:
        print 'else return 0;'
    print 'break;\n}' 

print '}\n}\nreturn 0;\n}'



