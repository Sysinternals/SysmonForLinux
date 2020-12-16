/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef _PARSEXML_H
#define _PARSEXML_H

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 *To compile this file using gcc you can type
 *gcc `xml2-config --cflags --libs` -o OUTPUT INPUT.c
 */

typedef enum {
    Image,
    CommandLine,
    CurrentDirectory,
    User,
    LogonId,
    ParentImage,
    ParentCommandLine,
    IntegrityLevel,
    MaxRuleType
} RuleType;

typedef enum {
    MatchIs,
    MatchIsAny,
    MatchIsNot,
    MatchContains,
    MatchContainsAny,
    MatchContainsAll,
    MatchExcludes,
    MatchExcludesAny,
    MatchExcludesAll,
    MatchBeginWith,
    MatchEndWith,
    MatchLessThan,
    MatchMoreThan,
    MatchImage
} MatchType;

typedef enum {
    CombineOr,
    CombineAnd,
    CombineNone
} CombineType;

typedef enum {
    OnMatchInclude,
    OnMatchExclude
} OnMatch;

typedef struct RuleT {
    RuleType     ruleType;
    MatchType    matchType;
    xmlChar      *value;
    xmlChar      *name;
    struct RuleT *next;
} Rule, *RulePtr;

typedef struct RuleGroupT {
    RulePtr           rulesHead;
    RulePtr           rulesTail;
    xmlChar           *name;
    CombineType       combine;
    OnMatch           onMatch;
    struct RuleGroupT *next;
} RuleGroup, *RuleGroupPtr;


void loadConfig(char *filename);
char *getField(event_s *e, RuleType r);
bool fieldMatch(char *f, xmlChar *s, MatchType m);

#endif
