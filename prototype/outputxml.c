#include <stdio.h>
#include <string.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "sysmon_defs.h"
#include <assert.h>
#include <syslog.h>

#define XML_ENCODING "ISO-8859-1"

void outputXml(event_s *event)
{
    int rc;
    xmlTextWriterPtr writer;
    xmlBufferPtr buf;
    xmlChar *tmp;
    FILE *fp;

    buf = xmlBufferCreate();
    assert(buf);

    writer = xmlNewTextWriterMemory(buf, 0);
    assert(writer);

    assert(xmlTextWriterStartDocument(writer, NULL, XML_ENCODING, NULL) >= 0);

    assert(xmlTextWriterStartElement(writer, "SYSMON_CREATE_PROCESS") >= 0);
    assert(xmlTextWriterWriteAttribute(writer, "version", "5") >= 0);

    assert(xmlTextWriterWriteFormatElement(writer, "RuleName", "%s", "*") >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "UtcTime", "%s", event->utcTime) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ProcessGuid", "%s", event->processGuid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ProcessId", "%d", event->pid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "Image", "%s", event->exe) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "CommandLine", "%s", event->execve.cmdline) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "CurrentDirectory", "%s", event->pwd) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "User", "%s", event->username) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "LogonGuid", "%s", event->loginGuid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "LogonId", "%d", event->auid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ProcessUserId", "%d", event->uid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ParentProcessGuid", "%s", event->p_processGuid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ParentProcessId", "%d", event->ppid) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ParentImage", "%s", event->p_exe) >= 0);
    assert(xmlTextWriterWriteFormatElement(writer, "ParentCommandLine", "%s", event->p_execve.cmdline) >= 0);

    assert(xmlTextWriterEndElement(writer) >= 0);
    assert(xmlTextWriterEndDocument(writer) >= 0);

    xmlFreeTextWriter(writer);

    syslog(LOG_USER | LOG_INFO, "%s", buf->content);

    xmlBufferFree(buf);
}


