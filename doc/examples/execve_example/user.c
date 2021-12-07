/*
    eBPF execve example

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

static struct bpf_program *bpf_syscall_execve[2] = {NULL, NULL};
static struct bpf_program *bpf_sched_exec = NULL;
static struct bpf_program *bpf_sched_fork = NULL;
static struct bpf_program *bpf_task_new = NULL;

static struct bpf_link    *bpf_syscall_execve_link[2] = {NULL, NULL};
static struct bpf_link    *bpf_sched_exec_link = NULL;
static struct bpf_link    *bpf_sched_fork_link = NULL;
static struct bpf_link    *bpf_task_new_link = NULL;

unsigned int total_events = 0;
unsigned int bad_events = 0;

static void bpf_close_all(){
    
    if (bpf_syscall_execve_link[0] != NULL)
        bpf_link__destroy(bpf_syscall_execve_link[0]);
    if (bpf_syscall_execve_link[1] != NULL)
        bpf_link__destroy(bpf_syscall_execve_link[1]);
    if (bpf_sched_exec_link != NULL)
        bpf_link__destroy(bpf_sched_exec_link);
    if (bpf_sched_fork_link != NULL)
        bpf_link__destroy(bpf_sched_fork_link);
    if (bpf_task_new_link != NULL)
        bpf_link__destroy(bpf_task_new_link);

    bpf_object__close(bpf_obj);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    total_events ++;
    event_s *event = (event_s *)data;
    if (size > 8) // make sure we have enough data
    {   
        switch (event->type) {
            case 1:  printf("SYSCALLS/SYS_ENTER_EXECVE "); break;
            case 2:  printf("SCHED/SCHED_PROCESS_EXEC  "); break;
            case 3:  printf("SCHED/SCHED_PROCESS_FORK  "); break;
            case 4:  printf("TASK/TASK_NEWTASK         "); break;
            default: printf("UNKNOWN                   "); break;
        }
        printf("PID:%u PPID:%u EXE:'%s'\n", event->pid, event->ppid, event->exe);
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

struct bpf_program *find_tracepoint_prog(struct bpf_object *obj, char *tp)
{
    struct bpf_program *prog = NULL;

    prog = bpf_object__find_program_by_title(obj, tp);
    if (prog)
    {
        bpf_program__set_type(prog, BPF_PROG_TYPE_TRACEPOINT);
    } else {
        printf("ERROR: failed to find program: '%s'\n", strerror(errno));
    }
    return prog;
}

struct bpf_link *link_prog(struct bpf_program *prog, char *class, char *tp)
{
    struct bpf_link *link = NULL;

    link = bpf_program__attach_tracepoint(prog, class, tp);
    if (libbpf_get_error(link))
        return NULL;

    return link;
}

int main(int argc, char *argv[])
{
    printf("eBPF execve example\n");
    
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

    bpf_syscall_execve[0] = find_tracepoint_prog(bpf_obj, "tracepoint/syscalls/sys_enter_execve");
    if (bpf_syscall_execve[0] == NULL)
        return 1;

    bpf_syscall_execve[1] = find_tracepoint_prog(bpf_obj, "tracepoint/syscalls/sys_exit_execve");
    if (bpf_syscall_execve[1] == NULL)
        return 1;

    bpf_sched_exec = find_tracepoint_prog(bpf_obj, "tracepoint/sched/sched_process_exec");
    if (bpf_sched_exec == NULL) 
        return 1;

    bpf_sched_fork = find_tracepoint_prog(bpf_obj, "tracepoint/sched/sched_process_fork");
    if (bpf_sched_fork == NULL) 
        return 1;

    bpf_task_new = find_tracepoint_prog(bpf_obj, "tracepoint/task/new_task");
    if (bpf_task_new == NULL) 
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

    bpf_syscall_execve_link[0] = link_prog(bpf_syscall_execve[0], "syscalls", "sys_enter_execve");
    if (bpf_syscall_execve_link[0] == NULL)
        return 2;

    bpf_syscall_execve_link[1] = link_prog(bpf_syscall_execve[1], "syscalls", "sys_exit_execve");
    if (bpf_syscall_execve_link[1] == NULL)
        return 2;

    bpf_sched_exec_link = link_prog(bpf_sched_exec, "sched", "sched_process_exec");
    if (bpf_sched_exec_link == NULL)
        return 2;

    bpf_sched_fork_link = link_prog(bpf_sched_fork, "sched", "sched_process_fork");
    if (bpf_sched_fork_link == NULL)
        return 2;

    bpf_task_new_link = link_prog(bpf_task_new, "task", "task_newtask");
    if (bpf_task_new_link == NULL)
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

