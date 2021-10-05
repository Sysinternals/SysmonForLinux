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
// hexdump.c
//
// Outputs binary data as hex for debugging
//
//====================================================================

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>

//--------------------------------------------------------------------
//
// hexdump
//
// Dump n bytes of the provided buffer as hex unsigned chars to stdout
//
//--------------------------------------------------------------------
void hexdump(const unsigned char *x, size_t n)
{
    if (x == NULL) {
        fprintf(stderr, "hexdump invalid params\n");
        return;
    }

    printf("\n");
    for (size_t i=0; i<n; i++) {
        if (i % 16 == 0) {
            printf("%08lx  ", i);
        }
        printf("0x%02x ", x[i]);
        if (i % 16 == 7) {
            printf(" ");
        }
        if (i % 16 == 15) {
            for (size_t j=i-15; j<=i; j++) {
                if (isprint(x[j])) {
                    printf("%c", x[j]);
                } else {
                    printf(".");
                }
                if (j % 16 == 7) {
                    printf(" ");
                }
            }
            printf("\n");
        }
    }
    printf("\n");
}


