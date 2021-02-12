/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "ebpf_loader/ebpf_telemetry_loader.h"
#include "sysmon_defs.h"
#include "parsexml.h"

/*
 *To compile this file using gcc you can type
 *gcc `xml2-config --cflags --libs` -o OUTPUT INPUT.c
 */


extern char *hashAlgorithms;
extern RuleGroupPtr ruleGroupsHead;
extern RuleGroupPtr ruleGroupsTail;

extern RuleGroupPtr procCreateInclude;
extern RuleGroupPtr procCreateExclude;

char *getField(event_s *e, RuleType r)
{
    switch (r) {
        case Image:
            return e->exe;
        case CommandLine:
            return e->execve.cmdline;
        case CurrentDirectory:
            return e->pwd;
        case ParentImage:
            return e->p_exe;
        default:
            return NULL;
    }
}

// check if a contains b
bool contains(char *a, char *b)
{
    if (strstr(a, b))
        return true;
    else
        return false;
}

// compare if a starts with b
bool starts_with(char *a, char *b)
{
    if (!strncmp(a, b, strlen(b)))
        return true;
    else
        return false;
}

// compare if a ends with b
bool ends_with(char *a, char *b)
{
    if (!strcmp(a + strlen(a) - strlen(b), b))
        return true;
    else
        return false;
}


bool fieldMatch(char *f, xmlChar *s, MatchType m)
{
    xmlChar *t = NULL;
    xmlChar *d = NULL;
    bool res = false;

    if (!f)
        return false;

    d = (xmlChar *)malloc(strlen(s)+1);
    memcpy(d, s, strlen(s)+1);

    switch (m) {
        case MatchIs:
            if (!strcmp(f, s))
                res = true;
            else
                res = false;
            break;
        case MatchIsAny:
            while (t = strtok(d, ";")) {
                if (!strcmp(f, t))
                    res = true;
            }
            break;
        case MatchIsNot:
            if (strcmp(f, s))
                res = true;
            else
                res = false;
            break;
        case MatchContains:
            res = contains(f, s);
            break;
        case MatchContainsAny:
            while (t = strtok(d, ";")) {
                if (contains(f, t))
                    res = true;
            }
            break;
        case MatchContainsAll:
            res = true;
            while (t = strtok(d, ";")) {
                if (!contains(f, t))
                    res = false;
            }
            break;
        case MatchExcludes:
            if (!contains(f, s))
                res = true;
            else
                res = false;
            break;
        case MatchExcludesAny:
            while (t = strtok(d, ";")) {
                if (!contains(f, t))
                    res = true;
            }
            break;
        case MatchExcludesAll:
            res = true;
            while (t = strtok(d, ";")) {
                if (contains(f, t))
                    res = false;
            }
            break;
        case MatchBeginWith:
            res = starts_with(f, s);
            break;
        case MatchEndWith:
            res = ends_with(f, s);
            break;
        case MatchLessThan:
            break;
        case MatchMoreThan:
            break;
        case MatchImage:
            t = strrchr(f, '\\');
            if (t) {
                if (!strcmp(t+1, s))
                    res = true;
                else
                    res = false;
            } else {
                if (!strcmp(f, s))
                    res = true;
                else
                    res = false;
            }
            break;
    }
    free(d);
    return res;
}


void parseRules(xmlDoc *doc, xmlNode *node, xmlChar *name, RuleGroupPtr ruleGroup)
{
    xmlNode *cur = NULL;
    RulePtr rule = NULL;
    xmlChar *ruleName = NULL;
    xmlChar *condition = NULL;
    RuleType ruleType = Image;
    MatchType matchType = MatchIs;
    unsigned int fieldCounts[MaxRuleType];

    memset(fieldCounts, 0, sizeof(fieldCounts));

    for (cur = node; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!strcmp(cur->name, "Image")) {
                ruleType = Image;
                fieldCounts[Image]++;
            } else if (!strcmp(cur->name, "CommandLine")) {
                ruleType = CommandLine;
                fieldCounts[CommandLine]++;
            } else if (!strcmp(cur->name, "CurrentDirectory")) {
                ruleType = CurrentDirectory;
                fieldCounts[CurrentDirectory]++;
            } else if (!strcmp(cur->name, "User")) {
                ruleType = User;
                fieldCounts[User]++;
            } else if (!strcmp(cur->name, "LogonId")) {
                ruleType = LogonId;
                fieldCounts[LogonId]++;
            } else if (!strcmp(cur->name, "ParentImage")) {
                ruleType = ParentImage;
                fieldCounts[ParentImage]++;
            } else if (!strcmp(cur->name, "ParentCommandLine")) {
                ruleType = ParentCommandLine;
                fieldCounts[ParentCommandLine]++;
            } else if (!strcmp(cur->name, "IntegrityLevel")) {
                ruleType = IntegrityLevel;
                fieldCounts[IntegrityLevel]++;
            } else {
                printf("Invalid rule type found: '%s'\n", cur->name);
                exit(1);
            }

            ruleName = xmlGetProp(cur, "name");
            if (!ruleName || ruleName[0] == 0)
                ruleName = name;

            condition = xmlGetProp(cur, "condition");
            if (!condition || condition[0] == 0) {
                printf("Rule without condition found\n");
                exit(1);
            }
            if (!strcmp(condition, "is")) {
                matchType = MatchIs;
            } else if (!strcasecmp(condition, "is any")) {
                matchType = MatchIsAny;
            } else if (!strcasecmp(condition, "is not")) {
                matchType = MatchIsNot;
            } else if (!strcasecmp(condition, "contains")) {
                matchType = MatchContains;
            } else if (!strcasecmp(condition, "contains any")) {
                matchType = MatchContainsAny;
            } else if (!strcasecmp(condition, "contains all")) {
                matchType = MatchContainsAll;
            } else if (!strcasecmp(condition, "excludes")) {
                matchType = MatchExcludes;
            } else if (!strcasecmp(condition, "excludes any")) {
                matchType = MatchExcludesAny;
            } else if (!strcasecmp(condition, "excludes all")) {
                matchType = MatchExcludesAll;
            } else if (!strcasecmp(condition, "begin with")) {
                matchType = MatchBeginWith;
            } else if (!strcasecmp(condition, "end with")) {
                matchType = MatchEndWith;
            } else if (!strcasecmp(condition, "less than")) {
                matchType = MatchLessThan;
            } else if (!strcasecmp(condition, "more than")) {
                matchType = MatchMoreThan;
            } else if (!strcasecmp(condition, "image")) {
                matchType = MatchImage;
            } else {
                printf("Rule with invalid condition found: '%s'\n", condition);
                exit(1);
            }

            rule = (RulePtr)malloc(sizeof(Rule));
            assert(rule);

            rule->ruleType = ruleType;
            rule->matchType = matchType;
            rule->value = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
            rule->name = ruleName;
            rule->next = NULL;

            if (ruleGroup->rulesHead == NULL) {
                ruleGroup->rulesHead = rule;
                ruleGroup->rulesTail = rule;
            } else {
                ruleGroup->rulesTail->next = rule;
                ruleGroup->rulesTail = rule;
            }
        }
    }
    if (ruleGroup->combine == CombineNone) {
        ruleGroup->combine = CombineAnd;
        for (unsigned int i=0; i<MaxRuleType; i++) {
            if (fieldCounts[i] > 1)
                ruleGroup->combine = CombineOr;
        }
    }
}

void parseRuleGroups(xmlDoc *doc, xmlNode *node, CombineType combine, xmlChar *name)
{
    xmlNode *cur = NULL;
    RuleGroupPtr ruleGroup = NULL;
    xmlChar *groupRelation = NULL;
    xmlChar *groupName = NULL;
    xmlChar *match = NULL;
    CombineType groupCombine = CombineNone;

    for (cur = node; cur; cur = cur->next) {
        groupCombine = CombineNone;
        if (cur->type == XML_ELEMENT_NODE) {
            groupName = xmlGetProp(cur, "name");
            if (!groupName || groupName[0] == 0)
                groupName = name;

            if (!strcmp(cur->name, "RuleGroup")) {
                groupRelation = xmlGetProp(cur, "groupRelation");
                if (groupRelation) {
                    if (!strcmp(groupRelation, "and")) {
                        groupCombine = CombineAnd;
                    } else if (!strcmp(groupRelation, "or")) {
                        groupCombine = CombineOr;
                    }
                }
                if (groupCombine == CombineNone)
                    groupCombine = combine;
                parseRuleGroups(doc, cur->children, groupCombine, groupName);

            } else if (!strcmp(cur->name, "ProcessCreate")) {
                ruleGroup = (RuleGroupPtr) malloc(sizeof(RuleGroup));
                assert(ruleGroup);
                ruleGroup->rulesHead = NULL;
                ruleGroup->rulesTail = NULL;
                ruleGroup->name = groupName;
                ruleGroup->next = NULL;
                ruleGroup->combine = combine;
                match = xmlGetProp(cur, "onmatch");
                if (!match) {
                    printf("Rule without an onmatch condition\n");
                    exit(1);
                }
                if (!strcmp(match, "include")) {
                    ruleGroup->onMatch = OnMatchInclude;
                    if (procCreateInclude) {
                        printf("More than 1 ProcessCreate include rule found\n");
                        exit(1);
                    }
                    procCreateInclude = ruleGroup;
                } else if (!strcmp(match, "exclude")) {
                    ruleGroup->onMatch = OnMatchExclude;
                    if (procCreateExclude) {
                        printf("More than 1 ProcessCreate exclude rule found\n");
                        exit(1);
                    }
                    procCreateExclude = ruleGroup;
                } else {
                    printf("Rule with an invalid onmatch condition: '%s'\n", match);
                    exit(1);
                }

                if (ruleGroupsHead == NULL) {
                    ruleGroupsHead = ruleGroup;
                    ruleGroupsTail = ruleGroup;
                } else {
                    ruleGroupsTail->next = ruleGroup;
                    ruleGroupsTail = ruleGroup;
                }

                parseRules(doc, cur->children, groupName, ruleGroup);
            } else {
                printf("Invalid element: '%s'\n", cur->name);
                exit(1);
            }
        }
    }
}
                   

void parseSysmonTopLevel(xmlDoc *doc, xmlNode *node)
{
    xmlNode *cur = NULL;

    for (cur = node; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!strcmp(cur->name, "HashAlgorithms")) {
                hashAlgorithms = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
                printf("Hash Algorithms = '%s'\n", hashAlgorithms);
            } else if (!strcmp(cur->name, "EventFiltering")) {
                parseRuleGroups(doc, cur->children, CombineNone, NULL);
            }
        }
    }
}


void printTree()
{
    RuleGroupPtr ruleGroup = NULL;
    RulePtr rule = NULL;

    for (ruleGroup = ruleGroupsHead; ruleGroup; ruleGroup = ruleGroup->next) {
        printf("RuleGroup name='%s'", ruleGroup->name);
        switch (ruleGroup->combine) {
            case CombineOr:
                printf(" combine=or");
                break;
            case CombineAnd:
                printf(" combine=and");
                break;
            case CombineNone:
                printf(" combine=none");
                break;
            default:
                printf(" UNKNOWN combine\n");
                exit(1);
        }
        switch (ruleGroup->onMatch) {
            case OnMatchInclude:
                printf(" onmatch=include\n");
                break;
            case OnMatchExclude:
                printf(" onmatch=exclude\n");
                break;
            default:
                printf(" UNKNOWN onmatch\n");
                exit(1);
        }

        for (rule = ruleGroup->rulesHead; rule; rule = rule->next) {
            printf("    Rule name='%s'", rule->name);
            switch (rule->ruleType) {
                case Image:
                    printf(" Image");
                    break;
                case CommandLine:
                    printf(" CommandLine");
                    break;
                case CurrentDirectory:
                    printf(" CurrentDirectory");
                    break;
                case User:
                    printf(" User");
                    break;
                case LogonId:
                    printf(" LogonId");
                    break;
                case ParentImage:
                    printf(" ParentImage");
                    break;
                case ParentCommandLine:
                    printf(" ParentCommandLine");
                    break;
                case IntegrityLevel:
                    printf(" IntegrityLevel");
                    break;
                default:
                    printf(" UNKNOWN rule type\n");
                    exit(1);
            }

            switch (rule->matchType) {
                case MatchIs:
                    printf(" is");
                    break;
                case MatchIsAny:
                    printf(" is any");
                    break;
                case MatchIsNot:
                    printf(" is not");
                    break;
                case MatchContains:
                    printf(" contains");
                    break;
                case MatchContainsAny:
                    printf(" contains any");
                    break;
                case MatchContainsAll:
                    printf(" contains all");
                    break;
                case MatchExcludes:
                    printf(" excludes");
                    break;
                case MatchExcludesAny:
                    printf(" excludes any");
                    break;
                case MatchExcludesAll:
                    printf(" excludes all");
                    break;
                case MatchBeginWith:
                    printf(" begin with");
                    break;
                case MatchEndWith:
                    printf(" end with");
                    break;
                case MatchLessThan:
                    printf(" less than");
                    break;
                case MatchMoreThan:
                    printf(" more than");
                    break;
                case MatchImage:
                    printf(" image");
                    break;
                default:
                    printf(" UNKNOWN match type\n");
                    exit(1);
            }

            printf(" '%s'\n", rule->value);
        }
    }
}


void loadConfig(char *filename)
{
    xmlDoc *doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *sysmonNode = NULL;

    LIBXML_TEST_VERSION

    doc = xmlReadFile(filename, NULL, 0);

    if (doc == NULL) {
        printf("error: could not load config '%s'\n", filename);
        exit(1);
    }

    xpathCtx = xmlXPathNewContext(doc);
    if (!xpathCtx) {
        printf("error: could not create xpath context\n");
        exit(1);
    }

    xpathObj = xmlXPathEvalExpression("//Sysmon[1]", xpathCtx);
    if (!xpathObj || !xpathObj->nodesetval || xpathObj->nodesetval->nodeNr < 1) {
        printf("error: could not find Sysmon node\n");
        exit(1);
    }

    if (doc->encoding) {
        printf("encoding: '%s'\n", doc->encoding);
    } else {
        printf("no encoding\n");
    }

    sysmonNode = xpathObj->nodesetval->nodeTab[0];
    printf("Schema version '%s'\n", xmlGetProp(sysmonNode, "schemaversion"));
    parseSysmonTopLevel(doc, sysmonNode->children);

//    printTree();

//    xmlFreeDoc(doc);

//    xmlCleanupParser();

}

