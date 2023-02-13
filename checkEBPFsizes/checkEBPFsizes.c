/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// checkEBPFsizes.c
//
// Checks the eBPF program lengths against a user-supplied max number
// of instructions.
//
//====================================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/mman.h>
#include <linux/limits.h>
#include <errno.h>
#include <ctype.h>
#include <libsysinternalsEBPF.h>

int main(int argc, char *argv[])
{
    int maxInsns = 0;
    unsigned int numProgs = 0;
    bool fail = false;
    ebpfProgramSizes* progs = NULL;


    if (argc < 3) {
        printf("Usage: %s <eBPF object> <max instructions>\n", argv[0]);
        return 1;
    }

    maxInsns = atoi(argv[2]);
    if (maxInsns <= 0) {
        printf("%s: maximum instructions must be greater than 0\n", argv[0]);
        return 1;
    }

    numProgs = getEbpfProgramSizes(argv[1], &progs);
    if(numProgs>0)
    {
        for(int i=0; i<numProgs; i++)
        {
            if (progs[i].size > maxInsns)
            {
                printf("  Error: %s is greater than max instructions: %d > %d\n", progs[i].name, (int)progs[i].size, maxInsns);
                fail = true;
            }
        }

        free(progs);
    }

    printf("\n");

    if (fail)
        return 2;

    return 0;
}



