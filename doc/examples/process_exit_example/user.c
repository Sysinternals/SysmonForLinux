/*
    eBPF process_exit example

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
#include <stdbool.h>
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

static struct bpf_program *bpf_sched_exit = NULL;
static struct bpf_program *bpf_sched_exit_raw = NULL;

static struct bpf_link    *bpf_sched_exit_link = NULL;
static struct bpf_link    *bpf_sched_exit_raw_link = NULL;

unsigned int total_events = 0;
unsigned int bad_events = 0;

static void bpf_close_all(){
    
    if (bpf_sched_exit_link != NULL)
        bpf_link__destroy(bpf_sched_exit_link);
    if (bpf_sched_exit_raw_link != NULL)
        bpf_link__destroy(bpf_sched_exit_raw_link);

    bpf_object__close(bpf_obj);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    total_events ++;
    event_s *event = (event_s *)data;
    if (size > 8) // make sure we have enough data
    {   
        switch (event->type) {
            case 1:  printf("TRACEPOINT     SCHED/SCHED_PROCESS_EXIT "); break;
            case 2:  printf("RAW TRACEPOINT SCHED/SCHED_PROCESS_EXIT "); break;
            default: printf("UNKNOWN                                 "); break;
        }
        printf("PID:%u EXE:'%s'\n", event->pid, event->exe);
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

struct bpf_program *find_tracepoint_prog(struct bpf_object *obj, char *tp, bool raw)
{
    struct bpf_program *prog = NULL;

    prog = bpf_object__find_program_by_title(obj, tp);
    if (prog)
    {
        if (raw) {
            bpf_program__set_type(prog, BPF_PROG_TYPE_RAW_TRACEPOINT);
        } else {
            bpf_program__set_type(prog, BPF_PROG_TYPE_TRACEPOINT);
        }
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
    }
    return prog;
}

struct bpf_link *link_prog(struct bpf_program *prog, char *class, char *tp, bool raw)
{
    struct bpf_link *link = NULL;

    if (raw) {
        link = bpf_program__attach_raw_tracepoint(prog, tp);
    } else {
        link = bpf_program__attach_tracepoint(prog, class, tp);
    }
    if (libbpf_get_error(link))
        return NULL;

    return link;
}

int main(int argc, char *argv[])
{
    printf("eBPF process_exit example\n");
    
    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filename[256] = "kern.o";

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open(filename);
    if (libbpf_get_error(bpf_obj)) {
        printf("ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_sched_exit = find_tracepoint_prog(bpf_obj, "tracepoint/sched/sched_process_exit", false);
    if (bpf_sched_exit == NULL) 
        return 1;

    bpf_sched_exit_raw = find_tracepoint_prog(bpf_obj, "raw_tracepoint/sched/sched_process_exit", true);
    if (bpf_sched_exit_raw == NULL) 
        return 1;

    if (bpf_object__load(bpf_obj)) {
        printf("ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "event_map");
    if ( 0 >= event_map_fd){
        printf("ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    bpf_sched_exit_link = link_prog(bpf_sched_exit, "sched", "sched_process_exit", false);
    if (bpf_sched_exit_link == NULL)
        return 2;

    bpf_sched_exit_raw_link = link_prog(bpf_sched_exit_raw, NULL, "sched_process_exit", true);
    if (bpf_sched_exit_raw_link == NULL)
        return 2;

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

