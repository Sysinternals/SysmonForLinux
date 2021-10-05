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
#include <errno.h>
#include <ctype.h>


int main(int argc, char *argv[])
{
    int fd = 0;
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    int maxInsns = 0;
    int numInsns = 0;
    char *secName = NULL;
    bool fail = false;

    if (argc < 3) {
        printf("Usage: %s <eBPF object> <max instructions>\n", argv[0]);
        return 1;
    }

    if ((fd = open(argv[1], O_RDONLY)) <= 0) {
        printf("%s: cannot open file %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }

    maxInsns = atoi(argv[2]);
    if (maxInsns <= 0) {
        printf("%s: maximum instructions must be greater than 0\n", argv[0]);
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("%s: WARNING Elf Library is out of date!\n", argv[0]);
    }

    //
    // init elf pointer
    //
    elf = elf_begin(fd, ELF_C_READ, NULL);
    gelf_getehdr(elf, &ehdr);

    printf("\neBPF Program Sizes: (max %d)\n\n", maxInsns);

    //
    // find sections
    //
    while((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_PROGBITS && shdr.sh_size > 0) {
            secName = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
            if (secName != NULL && secName[0] != 0x00 && secName[0] != '.' &&
                    strcmp(secName, "maps") != 0 && strcmp(secName, "license") != 0) {

                numInsns = shdr.sh_size / sizeof(uint64_t);

                printf("%s: %d\n", secName, numInsns);

                if (numInsns > maxInsns) {
                    printf("  Error: %s is greater than max instructions: %d > %d\n", secName, numInsns, maxInsns);
                    fail = true;
                }
            }
        }
    }

    printf("\n");

    if (fail)
        return 2;

    return 0;
}



