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
// linuxWideChar.h
//
// Functions exported by linuxWideChar.c
//
//====================================================================

#include "linuxTypes.h"

//
// In linuxWideChar.cpp
//
#ifdef __cplusplus
extern "C" {
#endif

size_t UTF8toUTF16( PWCHAR dst, CONST CHAR* src, size_t len);
size_t UTF16toUTF8( PCHAR dst, CONST WCHAR* src, size_t len);
int WideStrcmp( _In_ PCWCHAR s1, _In_ PCWCHAR s2 );
int WideStrncmp( _In_ PCWCHAR s1, _In_ PCWCHAR s2, _In_ int n );
int WideStrcasecmp( _In_ PCWCHAR s1, _In_ PCWCHAR s2 );
int WideStrncasecmp( _In_ PCWCHAR s1, _In_ PCWCHAR s2, _In_ int n );
size_t WideStrlen( _In_ PCWCHAR s );
PCWCHAR WideStrchr( _In_ PCWCHAR s, _In_ CONST WCHAR c );
PWCHAR WideStrrchr( _In_ PWCHAR s, _In_ CONST WCHAR c );
PWCHAR WideStrstr( _In_ PWCHAR h, _In_ PCWCHAR n);
size_t WideStrspn( _In_ PCWCHAR s, _In_ PCWCHAR acc );
WCHAR WideToupper( WCHAR c );
WCHAR WideTolower( WCHAR c );

#ifdef __cplusplus
}
#endif

