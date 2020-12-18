/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <sys/utsname.h>
#include "sysmon_config.h"
#include "ebpf_loader/ebpf_telemetry_loader.h"
#include "sysmon_defs.h"
#include <assert.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utmpx.h>
#include "parsexml.h"
#include "outputxml.h"

//Notes:
//https://github.com/vmware/p4c-xdp/issues/58
//https://github.com/libbpf/libbpf/commit/9007494e6c3641e82a3e8176b6e0b0fb0e77f683
//https://elinux.org/images/d/dc/Kernel-Analysis-Using-eBPF-Daniel-Thompson-Linaro.pdf
//https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
//https://blogs.oracle.com/linux/notes-on-bpf-3
//https://elixir.free-electrons.com/linux/latest/source/samples/bpf/bpf_load.c#L339
//https://stackoverflow.com/questions/57628432/ebpf-maps-for-one-element-map-type-and-kernel-user-space-communication

unsigned long total_events = 0;
unsigned long bad_events = 0;
unsigned int num_lost_notifications = 0;
unsigned long num_lost_events = 0;
unsigned long num_fail = 0;
unsigned long num_parsev = 0;
struct utsname uname_data;

uint32_t machineId = 0;

bool o_syslog = false;
bool quiet = false;
bool superquiet = false;
bool xmloutput = true;

char *hashAlgorithms = NULL;
RuleGroupPtr ruleGroupsHead = NULL;
RuleGroupPtr ruleGroupsTail = NULL;

RuleGroupPtr procCreateInclude = NULL;
RuleGroupPtr procCreateExclude = NULL;

#define EVENT_BUFFER_SIZE (49 * 1024)
#define EVENT_BUF1_SIZE (16 * 1024)
#define EVENT_BUF2_SIZE (33 * 1024)

/*
void combine_paths(char *dest, event_path_s *path, char *pwd, bool resolvepath)
{
    char temp[PATH_MAX * 2];
    char abs_path[PATH_MAX];

    if (path->dfd_path[0] == ABSOLUTE_PATH)
        snprintf(temp, PATH_MAX * 2, "%s", path->pathname);
    else if (path->dfd_path[0] == CWD_REL_PATH)
        snprintf(temp, PATH_MAX * 2, "%s/%s", pwd, path->pathname);
    else if (path->dfd_path[0] == RELATIVE_PATH)
        snprintf(temp, PATH_MAX * 2, "Relative to CWD /%s", path->pathname);
    else if (path->dfd_path[0] == UNKNOWN_PATH)
        snprintf(temp, PATH_MAX * 2, "Unknown %s", path->pathname);
    else
        snprintf(temp, PATH_MAX * 2, "%s/%s", path->dfd_path, path->pathname);

    // don't resolve real path for symbolic links
    if (!resolvepath || !realpath(temp, dest))
        snprintf(dest, PATH_MAX, "%s", temp);
}
*/

/*
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

bool filter_path(char *p)
{
    if (starts_with(p, "/bin/") ||
        starts_with(p, "/boot/") ||
        starts_with(p, "/etc/") ||
        starts_with(p, "/lib/") ||
        starts_with(p, "/lib64/") ||
        starts_with(p, "/opt/") ||
        starts_with(p, "/sbin/") ||
        starts_with(p, "/snap/") ||
        starts_with(p, "/usr/bin/") ||
        starts_with(p, "/usr/lib/") ||
        starts_with(p, "/usr/local/bin/") ||
        starts_with(p, "/usr/local/etc/") ||
        starts_with(p, "/usr/local/lib/") ||
        starts_with(p, "/usr/local/sbin/") ||
        starts_with(p, "/usr/local/share/") ||
        starts_with(p, "/usr/sbin/") ||
        starts_with(p, "/usr/share/"))
        return false;

    if (contains(p, "authorized_keys"))
        return false;

    if (starts_with(p, "/dev/sd"))
        return false;

    return true;
}
*/

void copy_cmdline(char *c, event_execve_s *e)
{
    unsigned int i = 0;
    if (e->cmdline_size > 1) {
        for (i=0; i < e->cmdline_size - 1; i++) {
            if (e->cmdline[i] == 0)
                c[i] = ' ';
            else
                c[i] = e->cmdline[i];
        }
        c[e->cmdline_size - 1] = 0;
    } else {
        c[0] = 0;
    }
}

void fix_cmdline(event_execve_s *e)
{
    unsigned int i = 0;
    if (e->cmdline_size > 1) {
        for (i=0; i < e->cmdline_size - 1; i++) {
            if (e->cmdline[i] == 0)
                e->cmdline[i] = ' ';
        }
        e->cmdline[e->cmdline_size - 1] = 0;
    } else {
        e->cmdline[0] = 0;
    }
}

bool checkRuleGroupMatch(RuleGroupPtr ruleGroup, event_s *event)
{
    bool match = false;
    bool filterRes = false;
    RulePtr rule = NULL;
    char *field = NULL;

    if (ruleGroup->combine == CombineAnd)
        match = true;
    else
        match = false;
    for (rule = ruleGroup->rulesHead; rule; rule = rule->next) {
        field = getField(event, rule->ruleType);
        filterRes = fieldMatch(field, rule->value, rule->matchType);
        if (ruleGroup->combine == CombineAnd)
            match &= filterRes;
        else
            match |= filterRes;
    }
    return match;
}

void read_parent_cmdline(event_s *e)
{
    int fd;
    char p_cmdline[64];
    ssize_t num_read;

    snprintf(p_cmdline, sizeof(p_cmdline), "/proc/%d/cmdline", e->ppid);

    fd = open(p_cmdline, O_RDONLY);
    if (fd <= 0)
        return;

    num_read = read(fd, e->p_execve.cmdline, sizeof(e->p_execve.cmdline));
    e->p_execve.cmdline_size = num_read;
    e->p_execve.cmdline[num_read] = 0;

    close(fd);

    fix_cmdline(&e->p_execve);
}

void makeGuid(char *d, uint32_t timestamp, uint64_t id)
{
    unsigned char guid[16];

    *(uint32_t *)guid = machineId;
    *(uint32_t *)(guid + 4) = timestamp;
    *(uint64_t *)(guid + 8) = id;

    sprintf(d, "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
        *(uint32_t *)guid,
        *(uint16_t *)(guid + 4),
        *(uint16_t *)(guid + 6),
        *(unsigned char *)(guid +  8),
        *(unsigned char *)(guid +  9),
        *(unsigned char *)(guid + 10),
        *(unsigned char *)(guid + 11),
        *(unsigned char *)(guid + 12),
        *(unsigned char *)(guid + 13),
        *(unsigned char *)(guid + 14),
        *(unsigned char *)(guid + 15));
}

int32_t getLoginTime(char *tty, char *username)
{
    struct utmpx *r;
    struct utmpx s;
    int32_t t = 0;

    strcpy(s.ut_line, tty);

    setutxent();

    while ((r = getutxline(&s)) != (struct utmpx *)NULL) {
        if (!strcmp(r->ut_user, username)) {
            t = r->ut_tv.tv_sec;
        }
    }

    endutxent();

    return t;
}

uint32_t uptime()
{
    int fd;
    char u[128];
    int num_read;
    uint32_t t = 0;

    fd = open("/proc/uptime", O_RDONLY);

    if (fd > 0) {
        num_read = read(fd, u, 128);
        if (num_read > 0) {
            t = atoi(u);
        }
        close(fd);
    }

    return t;
}

void fix_tty(char *t)
{
    char p[TTYSIZE];

    if (!strncmp(t, "pts", 3)) {
        if (t[3] != '/') {
            strcpy(p, t+3);
            t[3] = '/';
            strcpy(t+4, p);
        }
    }
}


static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    char e_buf[EVENT_BUFFER_SIZE];
    char cmdline[CMDLINE_MAX_LEN];
    char p_cmdline[CMDLINE_MAX_LEN];
    char buf1[EVENT_BUF1_SIZE];
    char buf2[EVENT_BUF2_SIZE];
    bool filter = false;
    event_s event;
    struct timeval now;
    struct passwd *user;
    uint32_t loginTime = 0;

    gettimeofday(&now, NULL);
    struct tm *t = gmtime(&now.tv_sec);

    memcpy(&event, data, sizeof(event));

    strftime(event.utcTime, sizeof(event.utcTime), "%m/%d/%Y %I:%M:%S", t);
    sprintf(event.utcTime + 19, ".%03ld", now.tv_usec / 1000);
    strftime(event.utcTime + 23, sizeof(event.utcTime - 23), " %p", t);

    total_events++;
    if ( (size > sizeof(event_s)) && // make sure we have enough data
         (event.code_bytes_start == CODE_BYTES) && // garbage check...
         (event.code_bytes_end == CODE_BYTES) && // garbage check...
         (event.version    == VERSION) )     // version check...
    {   
        if (!quiet && event.status & STATUS_VALUE) {
            printf("PARSEV!     ");
            num_parsev++;
        }
        if (!quiet && event.status & ~STATUS_VALUE) {
            printf("FAIL!       ");
            num_fail++;
        }

        buf2[0] = 0x00;
        filter = false;

        switch(event.syscall_id)
        {    
/*
            case __NR_open:
            case __NR_truncate:
            case __NR_rmdir:
            case __NR_creat:
            case __NR_unlink:
            case __NR_chmod:
            case __NR_chown:
            case __NR_lchown:
            case __NR_mknod:
            case __NR_ftruncate:
            case __NR_fchmod:
            case __NR_fchown:
            case __NR_openat:
            case __NR_mknodat:
            case __NR_fchownat:
            case __NR_unlinkat:
            case __NR_fchmodat:
            {
                char abs_path[PATH_MAX];

                combine_paths(abs_path, &event->fileop.path1, event->pwd, true);
                if (filter_path(abs_path))
                    filter = true;
                else
                    snprintf(buf2, EVENT_BUF2_SIZE, " path=\"%s\"", abs_path);
                break;
            }

            case __NR_rename:
            case __NR_link:
            case __NR_symlink:
            case __NR_renameat:
            case __NR_renameat2:
            case __NR_linkat:
            case __NR_symlinkat:
            {
                bool resolvepath = true;
                char abs_path1[PATH_MAX];
                char abs_path2[PATH_MAX];

                // don't resolve paths for symlinks
                if (event->syscall_id == __NR_symlink || event->syscall_id == __NR_symlinkat)
                    resolvepath = false;

                combine_paths(abs_path1, &event->fileop.path1, event->pwd, true);
                combine_paths(abs_path2, &event->fileop.path2, event->pwd, resolvepath);
                if (filter_path(abs_path1) && filter_path(abs_path2))
                    filter = true;
                else
                    snprintf(buf2, EVENT_BUF2_SIZE, " path1=\"%s\" path2=\"%s\"", abs_path1, abs_path2);
                break;
            }
*/

            case __NR_execve:
            case __NR_execveat:
            {
                // cmdline is a series of null terminated strings
                // concat them all with spaces in place

                fix_cmdline(&event.execve);

                read_parent_cmdline(&event);

                user = getpwuid(event.auid);
                if (user) {
                    snprintf(event.username, sizeof(event.username), "%s", user->pw_name);
                    fix_tty(event.tty);
                    loginTime = getLoginTime(event.tty, event.username);
                    makeGuid(event.loginGuid, loginTime, *(uint64_t *)&user->pw_uid);
                } else {
                    event.username[0] = 0;
                    makeGuid(event.loginGuid, uptime(), 0);
                }

                makeGuid(event.processGuid, now.tv_sec, (uint64_t)event.task);
                makeGuid(event.p_processGuid, now.tv_sec, (uint64_t)event.p_task);


                filter = false;
                if (procCreateExclude && procCreateExclude->rulesHead) {
                    filter = checkRuleGroupMatch(procCreateExclude, &event);
                }
                if (!filter) {
                    if (procCreateInclude && procCreateInclude->rulesHead) {
                        filter = !checkRuleGroupMatch(procCreateInclude, &event);
                    }
                }
            
                if (!filter) {
                    snprintf(e_buf, EVENT_BUFFER_SIZE, "RuleName=\"*\", UtcTime=\"%s\", ProcessGuid=\"%s\", ProcessId=%u, Image=\"%s\", CommandLine=\"%s\", CurrentDirectory=\"%s\", User=\"%s\", LogonGuid=\"{%s}\", LogonId=%d, ProcessUserId=%d, ParentProcessGuid=\"%s\", ParentProcessId=%u, ParentImage=\"%s\", ParentCommandLine=\"%s\"\n",
                        event.utcTime, event.processGuid, event.pid, event.exe, event.execve.cmdline, event.pwd, event.username, event.loginGuid, event.auid, event.uid, event.p_processGuid, event.ppid, event.p_exe, event.p_execve.cmdline);
                }

                break;
            }

/*
            case __NR_accept:
            case __NR_accept4:
            case __NR_connect: 
            {
                char addr[INET6_ADDRSTRLEN] = {0};
                
                if (event->socket.addr.sin_family == AF_INET) {
                    inet_ntop(AF_INET, &event->socket.addr.sin_addr, addr, INET_ADDRSTRLEN);
                    snprintf(buf2, EVENT_BUF2_SIZE, " addr=%s:%hu", addr, ntohs(event->socket.addr.sin_port));
                } else if (event->socket.addr6.sin6_family == AF_INET6) {
                    inet_ntop(AF_INET6, &event->socket.addr6.sin6_addr, addr, INET6_ADDRSTRLEN);
                    snprintf(buf2, EVENT_BUF2_SIZE, " addr=[%s]:%hu", addr, ntohs(event->socket.addr6.sin6_port));
                }
                break;                
            }
*/
        }
        if (!quiet && !filter)
            printf("%s\n", e_buf);
        if (o_syslog && !filter) {
            if (xmloutput)
                outputXml(&event);
            else
                syslog(LOG_USER | LOG_INFO, "%s", e_buf);
        }
    } else {
        bad_events++;
        if (!quiet)
            printf("bad data arrived - start: 0x%016lx end: 0x%016lx\n", event.code_bytes_start, event.code_bytes_end);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    if (!quiet)
        fprintf(stdout, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
    num_lost_notifications++;
    num_lost_events += lost_cnt;
    //assert(0);
}

void intHandler(int code) {
    
    if (!quiet)
        printf("\nStopping....\n");
    ebpf_telemetry_close_all();

    if (!superquiet) {
        printf("total events: %ld, bad events: %ld, ratio = %f\n", total_events, bad_events, (double)bad_events / total_events);
        printf("lost events: %ld, in %d notifications\n", num_lost_events, num_lost_notifications);
        printf("parse errors: %ld, value parse errors: %ld\n", num_fail, num_parsev);
    }   

    if (o_syslog)
        closelog();

    exit(0);
}

void setMachineId()
{
    int fd;
    char raw[64];
    int numread;

    machineId = 0;

    fd = open("/etc/machine-id", O_RDONLY);
    if (fd > 0) {
        numread = read(fd, raw, 64);
        if (numread > 8) {
            raw[8] = 0;
            machineId = strtoul(raw, NULL, 16);
        }
        close(fd);
    }
    if (!machineId) {
        machineId = gethostid();
    }
}

int main(int argc, char *argv[])
{
    int c;
    char *filename = NULL;
    bool out_xml = false;
    bool out_raw = false;

    o_syslog = true;
    quiet = true;
    superquiet = true;

    setMachineId();

    while ((c = getopt (argc, argv, "i:RX")) != -1) {
        switch(c) {
            case 'i':
                filename = optarg;
                break;
            case 'R':
                out_raw = true;
                break;
            case 'X':
                out_xml = true;
                break;
            default:
                printf("Usage: %s [-i configFile] [-R] [-X]\n\n    -R indicates RAW output\n    -X indicates XML output\n\n", argv[0]);
                exit(1);
        }
    }

    if (!superquiet)
        printf("Sysmon v%d.%d\n\n", Sysmon_VERSION_MAJOR, Sysmon_VERSION_MINOR);

    if (out_raw && out_xml) {
        printf("Select raw output OR XML output\n");
        exit(1);
    }

    if (out_raw) {
        xmloutput = false;
    } else {
        xmloutput = true;
    }

    if (!filename) {
        printf("You must specify a configuration file (-h for help)\n");
        exit(1);
    }

    if (!quiet && sizeof(event_s) > MAX_EVENT_SIZE) {
        printf("sizeof(event_s) == %ld > %d!\n", sizeof(event_s), MAX_EVENT_SIZE);
        exit(1);
    }

    if (uname(&uname_data) != 0) {
        printf("Failed to get uname\n");
        exit(1);
    }
    
    if (o_syslog)
        openlog("sysmon", LOG_NOWAIT, LOG_USER);
    signal(SIGINT, intHandler);



    loadConfig(filename);

    if (!procCreateInclude && !procCreateExclude) {
        printf("No ProcessCreate rules loaded\n");
        exit(1);
    }

    if (!quiet)
        printf("Running...\n");

    ebpf_telemetry_start("../syscalls.rules", print_bpf_output, handle_lost_events);

    return 0;
}

