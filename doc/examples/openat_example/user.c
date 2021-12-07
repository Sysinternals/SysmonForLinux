/*
    eBPF openat example

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#include <unistd.h>
#include <asm/unistd.h>
#include <stdlib.h>
#include <libbpf.h>
#include <sys/resource.h>
#include <bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/utsname.h>
#include <types.h>
#include <signal.h>
#include "event_defs.h"


#define MAP_PAGE_SIZE 1024

static int    event_map_fd          = 0;
static struct bpf_object  *bpf_obj  = NULL;

static struct bpf_program *bpf_syscall_openat[2] = {NULL, NULL};
static struct bpf_program *bpf_raw_syscalls[2] = {NULL, NULL};
static struct bpf_program *bpf_raw_syscalls_raw[2] = {NULL, NULL};

static struct bpf_link    *bpf_syscall_openat_link[2] = {NULL, NULL};
static struct bpf_link    *bpf_raw_syscalls_link[2] = {NULL, NULL};
static struct bpf_link    *bpf_raw_syscalls_raw_link[2] = {NULL, NULL};

unsigned int total_events = 0;
unsigned int bad_events = 0;

static void bpf_close_all(){
    
    if (bpf_syscall_openat_link[0] != NULL)
        bpf_link__destroy(bpf_syscall_openat_link[0]);
    if (bpf_syscall_openat_link[1] != NULL)
        bpf_link__destroy(bpf_syscall_openat_link[1]);
    if (bpf_raw_syscalls_link[0] != NULL)
        bpf_link__destroy(bpf_raw_syscalls_link[0]);
    if (bpf_raw_syscalls_link[1] != NULL)
        bpf_link__destroy(bpf_raw_syscalls_link[1]);
    if (bpf_raw_syscalls_raw_link[0] != NULL)
        bpf_link__destroy(bpf_raw_syscalls_raw_link[0]);
    if (bpf_raw_syscalls_raw_link[1] != NULL)
        bpf_link__destroy(bpf_raw_syscalls_raw_link[1]);

    bpf_object__close(bpf_obj);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    total_events ++;
    event_s *event = (event_s *)data;
    if (size > 8) // make sure we have enough data
    {   
        printf("PID:%u FILE:'%s' FLAGS:0x%lx MODE:0x%lx\n", event->pid, event->filename, event->flags, event->mode);
    } else {
        bad_events++;
        printf("bad data arrived: expected size=%ld, actual size=%d\n", sizeof(event_s), size);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void intHandler(int code) {
    
    printf("\nStopping....\n");
    bpf_close_all();
    printf("total events: %d, bad events: %d (%f)\n", total_events, bad_events, (double)bad_events / total_events);
   
    exit(0);
}

void usage(char *progname)
{
    printf("%s <1|2>\n", progname);
    printf("  1 = tracepoint syscalls/sys_enter_openat\n");
    printf("  2 = tracepoint raw_syscalls/sys_enter\n");
    printf("  3 = raw tracepoint raw_syscalls/sys_enter\n");
    printf("\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int type = 0;

    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filename[256] = "kern.o";

    printf("eBPF openat example\n");

    if (argc < 2) {
        usage(argv[0]);
    }

    type = atoi(argv[1]);
    if (type < 1 || type > 3) {
        usage(argv[0]);
    }

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open(filename);
    if (libbpf_get_error(bpf_obj)) {
        printf("ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_syscall_openat[0] = bpf_object__find_program_by_title(bpf_obj,"tracepoint/syscalls/sys_enter_openat");
    if (bpf_syscall_openat[0]) 
    {
        bpf_program__set_type(bpf_syscall_openat[0], BPF_PROG_TYPE_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_syscall_openat[1] = bpf_object__find_program_by_title(bpf_obj,"tracepoint/syscalls/sys_exit_openat");
    if (bpf_syscall_openat[1]) 
    {
        bpf_program__set_type(bpf_syscall_openat[1], BPF_PROG_TYPE_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_raw_syscalls[0] = bpf_object__find_program_by_title(bpf_obj,"tracepoint/raw_syscalls/sys_enter");
    if (bpf_raw_syscalls[0]) 
    {
        bpf_program__set_type(bpf_raw_syscalls[0], BPF_PROG_TYPE_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_raw_syscalls[1] = bpf_object__find_program_by_title(bpf_obj,"tracepoint/raw_syscalls/sys_exit");
    if (bpf_raw_syscalls[1]) 
    {
        bpf_program__set_type(bpf_raw_syscalls[1], BPF_PROG_TYPE_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_raw_syscalls_raw[0] = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/raw_syscalls/sys_enter");
    if (bpf_raw_syscalls_raw[0]) 
    {
        bpf_program__set_type(bpf_raw_syscalls_raw[0], BPF_PROG_TYPE_RAW_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_raw_syscalls_raw[1] = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/raw_syscalls/sys_exit");
    if (bpf_raw_syscalls_raw[1]) 
    {
        bpf_program__set_type(bpf_raw_syscalls_raw[1], BPF_PROG_TYPE_RAW_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
        return 1;
    }

    if (bpf_object__load(bpf_obj)) {
        printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "event_map");
    if ( 0 >= event_map_fd){
        printf("ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    switch(type) {
        case 1:
            bpf_syscall_openat_link[0] = bpf_program__attach_tracepoint(bpf_syscall_openat[0], "syscalls", "sys_enter_openat");
                
            if (libbpf_get_error(bpf_syscall_openat_link[0])) 
                return 2;

            bpf_syscall_openat_link[1] = bpf_program__attach_tracepoint(bpf_syscall_openat[1], "syscalls", "sys_exit_openat");
                
            if (libbpf_get_error(bpf_syscall_openat_link[1])) 
                return 2;

            break;

        case 2:
            bpf_raw_syscalls_link[0] = bpf_program__attach_tracepoint(bpf_raw_syscalls[0], "raw_syscalls", "sys_enter");
                
            if (libbpf_get_error(bpf_raw_syscalls_link[0])) 
                return 2;

            bpf_raw_syscalls_link[1] = bpf_program__attach_tracepoint(bpf_raw_syscalls[1], "raw_syscalls", "sys_exit");
                
            if (libbpf_get_error(bpf_raw_syscalls_link[1])) 
                return 2;

            break;

        case 3:
            bpf_raw_syscalls_raw_link[0] = bpf_program__attach_raw_tracepoint(bpf_raw_syscalls_raw[0], "sys_enter");
                
            if (libbpf_get_error(bpf_raw_syscalls_raw_link[0])) 
                return 2;

            bpf_raw_syscalls_raw_link[1] = bpf_program__attach_raw_tracepoint(bpf_raw_syscalls_raw[1], "sys_exit");
                
            if (libbpf_get_error(bpf_raw_syscalls_raw_link[1])) 
                return 2;

            break;

        default:
            break;
    }

    // from Kernel 5.7.1 ex: trace_output_user.c 
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb;
    int ret;

    pb_opts.sample_cb = print_bpf_output;
    pb_opts.lost_cb = handle_lost_events;
    pb_opts.ctx     = NULL;
    pb = perf_buffer__new(event_map_fd, MAP_PAGE_SIZE, &pb_opts); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        printf("ERROR: failed to setup perf_buffer: %d\n", ret);
        return 1;
    }

    signal(SIGINT, intHandler);

    printf("Running...\n");

    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 ) {
        // go forever
    }

    bpf_close_all();

    return 0;
}

