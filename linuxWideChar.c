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
// linuxWideChar.c
//
// 16-bit character routines for linux
//
//====================================================================

#include "stdafx.h"

//--------------------------------------------------------------------
//
// UTF8toUTF16
//
// Convert null-terminated UTF8 string to null-terminated UTF16 string
//
// len is the size of the target buffer (WCHARs, not bytes)
// If len==0, then nothing is written, but the value returned is equal
// to the size of the buffer required.
//
// Returns the number of wchars writtern, including the null.
// Returns 0 on error.
//
//--------------------------------------------------------------------
size_t UTF8toUTF16(
    PWCHAR dst,
    CONST CHAR* src,
    size_t len
    )
{
    size_t i = 0;
    uint32_t unicode;
    bool writeDst = true;

    if (src == NULL) {
        return 0;
    }

    if (len == 0) {
        // only calculate the length, so set len to max value
        len = 0xFFFFFFFF;
        writeDst = false;
    } else if (dst == NULL) {
        return 0;
    }

    while (i<len - 1 && *src != 0) {
        if (*src & 0x80) { // multibyte
            if ((src[0] & 0xE0) == 0xC0 && (src[1] & 0xC0) == 0x80) { // 2 bytes
                unicode = (src[1] & 0x3F) | ((uint32_t)(src[0] & 0x1F) << 6);
                src += 2;
            } else if ((src[0] & 0xF0) == 0xE0 && (src[1] & 0xC0) == 0x80
                    && (src[2] & 0xC0) == 0x80) { // 3 bytes
                unicode = (src[2] & 0x3F) | ((uint32_t)(src[1] & 0x3F) << 6) |
                        ((uint32_t)(src[0] & 0x0F) << 12);
                src += 3;
            } else if ((src[0] & 0xF8) == 0xF0 && (src[1] & 0xC0) == 0x80
                    && (src[2] & 0xC0) == 0x80 && (src[3] & 0xC0) == 0x80) { // 4 bytes
                unicode = (src[3] & 0x3F) | ((uint32_t)(src[2] & 0x3F) << 6) |
                        ((uint32_t)(src[1] & 0x3F) << 12) |
                        ((uint32_t)(src[0] & 0x07) << 18);
                src += 4;
            } else {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
        } else {
            unicode = *src;
            src++;
        }

        if (unicode > 0xFFFF) {
            if (i == len - 2) {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
            if (writeDst) {
                *dst = (WCHAR)(0xD800 | (((unicode - 0x10000) & 0xFFC00) >> 10));
                dst++;
                *dst = (WCHAR)(0xDC00 | ((unicode - 0x10000) & 0x3FF));
                dst++;
            }
            i += 2;
        } else {
            if (writeDst) {
                *dst = (WCHAR)unicode;
                dst++;
            }
            i++;
        }
    }
    if (writeDst) {
        *dst = 0;
    }
    return i+1;
}

//--------------------------------------------------------------------
//
// UTF16toUTF8
//
// Convert null-terminated UTF16 string to null-terminated UTF8 string
//
// len is the size of the target buffer (bytes)
// If len==0, then nothing is written, but the value returned is equal
// to the size of the buffer required.
//
// Returns the number of wchars writtern, including the null.
// Returns 0 on error.
//
//--------------------------------------------------------------------
size_t UTF16toUTF8(
    PCHAR dst,
    CONST WCHAR* src,
    size_t len
    )
{
    size_t i = 0;
    uint32_t unicode;
    bool writeDst = true;

    if (src == NULL) {
        return 0;
    }

    if (len == 0) {
        // only calculate the length, so set len to max value
        len = 0xFFFFFFFF;
        writeDst = false;
    } else if (dst == NULL) {
        return 0;
    }

    while (i<len - 1 && *src != 0) {
        if ((*src & 0xFC00) == 0xD800) { // multiword
            if ((src[1] & 0xFC00) == 0xDC00) { // check second word
                unicode = ((src[1] & 0x3FF) | ((uint32_t)(src[0] & 0x3FF) << 10)) + 0x10000;
                src += 2;
            } else {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
        } else {
            unicode = *src;
            src++;
        }

        if (unicode > 0xFFFF) { // 4 bytes
            if (i < len - 4) {
                if (writeDst) {
                    dst[0] = (UCHAR)(0xF0 | ((unicode & 0x001C0000) >> 18));
                    dst[1] = (UCHAR)(0x80 | ((unicode & 0x0003F000) >> 12));
                    dst[2] = (UCHAR)(0x80 | ((unicode & 0x00000FC0) >>  6));
                    dst[3] = (UCHAR)(0x80 |  (unicode & 0x0000003F));
                    dst += 4;
                }
                i += 4;
            } else {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
        } else if (unicode > 0x7FF) { // 3 bytes
            if (i < len - 3) {
                if (writeDst) {
                    dst[0] = (UCHAR)(0xE0 | ((unicode & 0xF000) >> 12));
                    dst[1] = (UCHAR)(0x80 | ((unicode & 0x0FC0) >>  6));
                    dst[2] = (UCHAR)(0x80 |  (unicode & 0x003F));
                    dst += 3;
                }
                i += 3;
            } else {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
        } else if (unicode > 0x7F) { // 2 bytes
            if (i < len - 2) {
                if (writeDst) {
                    dst[0] = (UCHAR)(0xC0 | ((unicode & 0x7C0) >> 6));
                    dst[1] = (UCHAR)(0x80 |  (unicode & 0x03F));
                    dst += 2;
                }
                i += 2;
            } else {
                if (writeDst) {
                    *dst = 0;
                }
                return 0;
            }
        } else {
            if (writeDst) {
                *dst = (UCHAR)unicode;
                dst++;
            }
            i++;
        }
    }
    if (writeDst) {
        *dst = 0;
    }
    return i+1;
}

//--------------------------------------------------------------------
//
// WideStrcmp
//
// Wide version of strcmp.
//
//--------------------------------------------------------------------
int WideStrcmp(
    _In_ PCWCHAR s1,
    _In_ PCWCHAR s2
    )
{
    if (s1 == NULL || s2 == NULL) {
        fprintf(stderr, "WideStrcmp invalid params\n");
        return 1;
    }

    while (*s1 != 0 || *s2 != 0) {
        if (*s1 < *s2) {
            return -1;
        } else if (*s1 > *s2) {
            return 1;
        }
        s1++;
        s2++;
    }
    return 0;
}

//--------------------------------------------------------------------
//
// WideStrncmp
//
// Wide version of strncmp.
//
//--------------------------------------------------------------------
int WideStrncmp(
    _In_ PCWCHAR s1,
    _In_ PCWCHAR s2,
    _In_ int n
    )
{
    if (s1 == NULL || s2 == NULL) {
        fprintf(stderr, "WideStrncmp invalid params\n");
        return 1;
    }

    while ((*s1 != 0 || *s2 != 0) && n>0) {
        if (*s1 < *s2) {
            return -1;
        } else if (*s1 > *s2) {
            return 1;
        }
        s1++;
        s2++;
        n--;
    }
    return 0;
}

//--------------------------------------------------------------------
//
// WideStrcasecmp
//
// Wide version of strcasecmp.
//
//--------------------------------------------------------------------
int WideStrcasecmp(
    _In_ PCWCHAR s1,
    _In_ PCWCHAR s2
    )
{
    if (s1 == NULL || s2 == NULL) {
        fprintf(stderr, "WideStrcasecmp invalid params\n");
        return 1;
    }

    WCHAR c1, c2;
    while (*s1 != 0 || *s2 != 0) {
        c1 = WideToupper(*s1);
        c2 = WideToupper(*s2);
        if (c1 < c2) {
            return -1;
        } else if (c1 > c2) {
            return 1;
        }
        s1++;
        s2++;
    }
    return 0;
}

//--------------------------------------------------------------------
//
// WideStrncasecmp
//
// Wide version of strncasecmp.
//
//--------------------------------------------------------------------
int WideStrncasecmp(
    _In_ PCWCHAR s1,
    _In_ PCWCHAR s2,
    _In_ int n
    )
{
    if (s1 == NULL || s2 == NULL) {
        fprintf(stderr, "WideStrncasecmp invalid params\n");
        return 1;
    }

    WCHAR c1, c2;
    while ((*s1 != 0 || *s2 != 0) && n>0) {
        c1 = WideToupper(*s1);
        c2 = WideToupper(*s2);
        if (c1 < c2) {
            return -1;
        } else if (c1 > c2) {
            return 1;
        }
        s1++;
        s2++;
        n--;
    }
    return 0;
}

//--------------------------------------------------------------------
//
// WideStrlen
//
// Wide version of strlen.
//
//--------------------------------------------------------------------
size_t WideStrlen(
    _In_ PCWCHAR s
    )
{
    if (s == NULL) {
        fprintf(stderr, "WideStrlen invalid params\n");
        return 0;
    }

    size_t n = 0;

    while (*s != 0) {
        s++;
        n++;
    }

    return n;
}

//--------------------------------------------------------------------
//
// WideStrchr
//
// Wide version of strchr.
//
//--------------------------------------------------------------------
PCWCHAR WideStrchr(
    _In_ PCWCHAR      s,
    _In_ CONST WCHAR  c
    )
{
    if (s == NULL) {
        fprintf(stderr, "WideStrchr invalid params\n");
        return NULL;
    }

    while (*s != 0) {
        if (*s == c) {
            return s;
        }
        s++;
    }
    if (c == 0) {
        return s;
    }

    return NULL;
}

//--------------------------------------------------------------------
//
// WideStrrchr
//
// Wide version of strrchr.
//
//--------------------------------------------------------------------
PWCHAR WideStrrchr(
    _In_ PWCHAR       s,
    _In_ CONST WCHAR  c
    )
{
    if (s == NULL) {
        fprintf(stderr, "WideStrrchr invalid params\n");
        return NULL;
    }

    PWCHAR t = s + WideStrlen(s);
    while (t != s) {
        if (*t == c) {
            return t;
        }
        t--;
    }
    if (*t == c) {
        return t;
    }

    return NULL;
}

//--------------------------------------------------------------------
//
// WideStrstr
//
// Wide version of strstr.
//
//--------------------------------------------------------------------
PWCHAR WideStrstr(
    _In_ PWCHAR     h,
    _In_ PCWCHAR    n
    )
{
    if (h == NULL || n == NULL) {
        fprintf(stderr, "WideStrstr invalid params\n");
        return NULL;
    }

    unsigned int hLen = WideStrlen(h);
    unsigned int nLen = WideStrlen(n);

    if (hLen == 0 || nLen == 0) {
        return NULL;
    }

    while (hLen >= nLen && WideStrncmp(h, n, nLen) != 0) {
        h++;
        hLen--;
    }
    if (hLen < nLen) {
        return NULL;
    } else {
        return h;
    }
}

//--------------------------------------------------------------------
//
// WideStrspn
//
// Wide version of strspn.
//
//--------------------------------------------------------------------
size_t WideStrspn(
    _In_ PCWCHAR s,
    _In_ PCWCHAR acc
    )
{
    if (s == NULL || acc == NULL) {
        fprintf(stderr, "WideStrspn invalid params\n");
        return 0;
    }

    size_t n = 0;
    unsigned int accLen = WideStrlen(acc);

    if (accLen == 0) {
        return 0;
    }
    while (*s != 0 && WideStrchr(acc, *s) != NULL) {
        s++;
        n++;
    }

    return n;
}

//--------------------------------------------------------------------
//
// WideToupper
//
// Wide version of toupper.
//
//--------------------------------------------------------------------
WCHAR WideToupper(
    WCHAR c
    )
{
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 'A';
    }
    return c;
}

//--------------------------------------------------------------------
//
// WideTolower
//
// Wide version of tolower.
//
//--------------------------------------------------------------------
WCHAR WideTolower(
    WCHAR c
    )
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 'a';
    }
    return c;
}


