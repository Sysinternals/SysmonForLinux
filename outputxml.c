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
// outputxml.c
//
// Event output formatting for Syslog
//
//====================================================================

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <assert.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define SYSMON_EVENT_C
#include "linuxTypes.h"
#include "sysmonevents.h"
#include "linuxHelpers.h"
#include "sysmon_defs.h"

#define XML_ENCODING "ISO-8859-1"

extern uint64_t *eventIdAddr;

//--------------------------------------------------------------------
//
// FormatSyslogString
//
// Format an event into an XML string.
//
//--------------------------------------------------------------------
VOID FormatSyslogString(
    PCHAR                           EventStr,
    size_t                          EventMax,
    CONST PSYSMON_EVENT_TYPE_FMT    EventType,
    CONST EVENT_DATA_DESCRIPTOR*    Fields,
    unsigned int                    FieldCount
    )
{
    if (EventStr != NULL) {
        *EventStr = 0x00;
    }

    if (EventStr == NULL || EventType == NULL || Fields == NULL) {
        fprintf(stderr, "FormatSyslogString invalid params\n");
        return;
    }

    xmlTextWriterPtr writer;
    xmlBufferPtr buf;

    uint64_t eventId = 0;

    unsigned int index = 0;
    const char *field = NULL;
    PCTSTR *fieldNames = NULL;
    char providerGuid[40];
    LARGE_INTEGER curTime;
    char systemTime[32];
    char hostname[HOST_NAME_MAX + 1];

    if (eventIdAddr != NULL && eventIdAddr != MAP_FAILED) {
        eventId = (*eventIdAddr)++;
        msync(eventIdAddr, sizeof(eventId), MS_ASYNC);
    } else {
        eventId = 0;
    }

    assert(StringFromGUID2(SYSMON_PROVIDER, providerGuid, sizeof(providerGuid)) != 0);
    
    GetSystemTimeAsLargeInteger(&curTime);
    LargeIntegerToSystemTimeString(systemTime, 32, &curTime);

    if (gethostname(hostname, HOST_NAME_MAX + 1) < 0) {
        hostname[0] = 0x00;
    }

    buf = xmlBufferCreate();
    assert(buf);

    writer = xmlNewTextWriterMemory(buf, 0);
    assert(writer);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Event") >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"System") >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Provider") >= 0);
    assert(xmlTextWriterWriteAttribute(writer, (const xmlChar*)"Name", (const xmlChar*)"Linux-Sysmon") >= 0);
    assert(xmlTextWriterWriteAttribute(writer, (const xmlChar*)"Guid", (const xmlChar*)providerGuid) >= 0);
    assert(xmlTextWriterEndElement(writer) >= 0);

    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"EventID", "%d",
            EventType->EventDescriptor->Id) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"Version", "%d",
            EventType->EventDescriptor->Version) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"Level", "%d",
            EventType->EventDescriptor->Level) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"Task", "%d",
            EventType->EventDescriptor->Task) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"Opcode", "%d",
            EventType->EventDescriptor->Opcode) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"Keywords", "0x%lx",
            EventType->EventDescriptor->Keyword) >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"TimeCreated") >= 0);
    assert(xmlTextWriterWriteAttribute(writer, (const xmlChar*)"SystemTime", (const xmlChar*)systemTime) >= 0);
    assert(xmlTextWriterEndElement(writer) >= 0);

    assert(xmlTextWriterWriteFormatElement(writer, (const xmlChar*)"EventRecordID", "%lu", eventId) >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Correlation") >= 0);
    assert(xmlTextWriterEndElement(writer) >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Execution") >= 0);
    assert(xmlTextWriterWriteFormatAttribute(writer, (const xmlChar*)"ProcessID", "%d", getpid()) >= 0);
    assert(xmlTextWriterWriteFormatAttribute(writer, (const xmlChar*)"ThreadID", "%d", GetTid()) >= 0);
    assert(xmlTextWriterEndElement(writer) >= 0);

    assert(xmlTextWriterWriteElement(writer, (const xmlChar*)"Channel", (const xmlChar*)"Linux-Sysmon/Operational") >= 0);
    assert(xmlTextWriterWriteElement(writer, (const xmlChar*)"Computer", (const xmlChar*)hostname) >= 0);

    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Security") >= 0);
    assert(xmlTextWriterWriteFormatAttribute(writer, (const xmlChar*)"UserId", "%d", geteuid()) >= 0);
    assert(xmlTextWriterEndElement(writer) >= 0);

    assert(xmlTextWriterEndElement(writer) >= 0); // end of System
    assert(xmlTextWriterStartElement(writer, (const xmlChar*)"EventData") >= 0);

    fieldNames = (PCTSTR *)EventType->FieldNames;
    for( index = 0; index < FieldCount; index++ ) {

        field = (const char *)Fields[index].Ptr;
        assert(xmlTextWriterStartElement(writer, (const xmlChar*)"Data") >= 0);
        assert(xmlTextWriterWriteAttribute(writer, (const xmlChar*)"Name", (const xmlChar*)fieldNames[index]) >= 0);
        assert(xmlTextWriterWriteFormatString(writer, "%s",
                field != NULL ? field : "") >= 0);
        assert(xmlTextWriterEndElement(writer) >= 0);
    }
    assert(xmlTextWriterEndElement(writer) >= 0); // end of EventData
    assert(xmlTextWriterEndElement(writer) >= 0); // end of Event
    xmlFreeTextWriter(writer);
    snprintf(EventStr, EventMax, "%s", buf->content);
    xmlBufferFree(buf);
}


