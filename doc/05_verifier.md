# Verifier

## Introduction

All eBPF programs have to pass verification in the kernel on load; failure 
prevents the programs from running. This chapter discusses some coding 
approaches that can satisfy the verifier.

## Basic verifier activities

The verifier simulates execution of the eBPF program to ensure that it is safe, 
and also that it exits within a reasonable number of instructions. It does this 
by tracking register values and exercising an amount of execution paths. 
Different versions of the verifier do this differently, so programs need to be 
tested on many kernels to confirm they will work.

The tracking of register values effectively tracks variable values, as 
variables are stored temporarily in registers. The aim is to check if array 
indices are within the array bounds, and also to check if loops will terminate 
in all cases. It does this by recording the upper and lower bounds that a value 
can take, and modifying them according to branches and logical operations on 
the value.

## Restricting variables to array bounds

Variables representing array indices can be limited to array sizes by checking 
them prior to using them as indices. For example:

```
if (i >= 32)
    return;
v = a[i];
```

The problem with this construction is that the compiler may optimise the code 
in such a way that the variable i gets stored on the stack between being 
checked and being used. If this happens then (in some versions of the verifier) 
the upper and lower bounds of variable i will be reset when it is retrieved 
from the stack; this will result in the array access appearing unbounded, and a 
claimed illegal memory access.

An alternative construction that appears less likely to suffer from this 
problem (and also easier to fix) is the following:

```
v = a[i & (32 - 1)]
```

Because the array is sized to a power of 2 (32 == 2^5), then one less than the 
size of the array has a binary representation that masks the available indices; 
e.g. 32 - 1 = 31 = 0b011111. Any value of i will be reduced to a value between 
0 and 31 before it is used to access the array. This approach requires arrays 
to be sized as powers of 2, which can waste some memory if the natural array 
upper bound is not a power of 2 (which isn't that often in practice).

This construction is much less likely to fall foul of the issue described above 
because the compiler is less likely to optimise the code in a way that moves 
the logical 'and' instruction sufficiently earlier, that the temporary value 
gets stored on the stack before it gets used. It does still happen occasionally 
however.

When it does happen, my solution is something like the following:

```
t = i;
asm volatile("%[t] &= 31\n"
             :[t]"+&r"(t)
             );
v = a[t];
```

The volatile keyword indicates that this code should not be moved due to 
optimisation, causing it to happen immediately prior to the array access, where 
the variable t should still be in a register (and not stored on the stack). The 
same approach can be used where the compiler has optimised out the bounding due 
to considering it unnecessary.

## Loop bounds

In situations where loops are not unrolled (>= v5.2) the verifier exercises 
various iterations of the loops for different loop termination conditions. 
Sometimes complicated loop conditions trick the verifier into exploring many 
more iterations of a loop than necessary, resulting in the 1,000,000 
instructions processed condition and rejection of the program.

To avoid this issue, make all loops with really simple conditions, such as:

```
for (i=0; i<16; i++)
```

The verifier can tell from this that the maximum number of iterations is 16 and 
will only explore that many iterations. Additional 'break' clauses can be added 
inside the loop if early (or other) termination is required.

## Debugging

Problems with passing verification are difficult to debug. Usually the verifier 
dumps a log of the instructions processed, followed by a single error message. 
Sometimes these messages are easily interpreted - it might state that array 
access is out of bounds or that a parameter to a function is the wrong type - 
and some are much more difficult.

If the error is that it exceeded the maximum number of processed instructions, 
then that means a loop bound is probably to blame. It could be that there are 
too many iterations (maybe halve the iteration count and see if it passes), or 
it could be that the loop conditions are too complex for the verifier (simplify 
things to make it obvious that it must exit).

Otherwise, it is likely a fault caused either by missing protections on 
variables, failure to initialise memory that is being accessed, or due to using 
the wrong type of memory for a helper API call. In these situations, the 
verifier will make it clear the instruction number that it failed on.

You can dump the assembler code for the program with:

```
llvm-objdump -source <FILE>
```

The assembler code uses a small number of registers from r0 to r11 to hold 
values. Parameters to a helper function are r1 to r5, and they return their 
result in r0. Helper functions are called by number, e.g. 'call 1' would call 
helper function 1, which is bpf\_map\_lookup\_elem(). A mapping between helper 
functions and numbers can be generated from bpf\_helper\_defs.h (see [libbpf 
code](https://github.com/libbpf/libbpf/tree/master/src)) as follows:

```
cat bpf_helper_defs.h | grep -e '^static' | sed -e 's/^[^(]*(\*\([^)]*\)).*)\([^();]*\);$/\2 \1/'
```

By following the API calls and/or any literal values used in the program (e.g. 
some have 4095 as PATH\_MAX - 1) it is possible to match up the offending 
instruction in the assembler with a C statement. It should then be possible to:

* comment out the offending C statement, recompile and show that it passes 
verification; if not, repeat exercise - there might be more than one issue, or 
you might have got the wrong C statement;
* rewrite the C statement in a manner such that it passes verification; or
* insert inline assembler to replace the C statement with your assembler 
intention.


