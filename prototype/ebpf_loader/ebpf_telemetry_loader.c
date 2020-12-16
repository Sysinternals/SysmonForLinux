/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/


#include "ebpf_telemetry_loader.h"
#include "../sysmon_defs.h"

//Notes:
//https://github.com/vmware/p4c-xdp/issues/58
//https://github.com/libbpf/libbpf/commit/9007494e6c3641e82a3e8176b6e0b0fb0e77f683
//https://elinux.org/images/d/dc/Kernel-Analysis-Using-eBPF-Daniel-Thompson-Linaro.pdf
//https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
//https://blogs.oracle.com/linux/notes-on-bpf-3
//https://elixir.free-electrons.com/linux/latest/source/samples/bpf/bpf_load.c#L339
//https://stackoverflow.com/questions/57628432/ebpf-maps-for-one-element-map-type-and-kernel-user-space-communication

#define MAP_PAGE_SIZE (16 * 1024)
#define DEBUGFS "/sys/kernel/debug/tracing/"

#define KERN_TRACEPOINT_OBJ "ebpf_loader/ebpf_telemetry_kern_tp.o"
#define KERN_RAW_TRACEPOINT_SUB4096_OBJ "ebpf_loader/ebpf_telemetry_kern_raw_tp_sub4096.o"
#define KERN_RAW_TRACEPOINT_NOLOOPS_OBJ "ebpf_loader/ebpf_telemetry_kern_raw_tp_noloops.o"
#define KERN_RAW_TRACEPOINT_OBJ "ebpf_loader/ebpf_telemetry_kern_raw_tp.o"

#ifndef STOPLOOP
    #define STOPLOOP 0
#endif

static unsigned int isTesting       = STOPLOOP;

static int    event_map_fd          = 0;
static int    config_map_fd         = 0;
static int    sysconf_map_fd        = 0;
static struct utsname     uname_s   = { 0 };
static struct bpf_object  *bpf_obj  = NULL;

static struct bpf_program *bpf_sys_enter_tp[7];
static struct bpf_program *bpf_sys_enter = NULL;
static struct bpf_program *bpf_sys_exit  = NULL;

static struct bpf_link    *bpf_sys_enter_tp_link[SYSCALL_MAX+1];
static struct bpf_link    *bpf_sys_exit_tp_link[SYSCALL_MAX+1];
static struct bpf_link    *bpf_sys_enter_link = NULL;
static struct bpf_link    *bpf_sys_exit_link  = NULL;

typedef enum bpf_type { NOBPF, BPF_TP, BPF_RAW_TP_SUB4096, BPF_RAW_TP_NOLOOPS, BPF_RAW_TP } bpf_type;

static bpf_type support_version = NOBPF;

void ebpf_telemetry_close_all(){
    
    if ( support_version == BPF_TP ) {
        for (int i=0; i<=SYSCALL_MAX; i++) {
            if (bpf_sys_enter_tp_link[i])
                bpf_link__destroy(bpf_sys_enter_tp_link[i]);
            if (bpf_sys_exit_tp_link[i])
                bpf_link__destroy(bpf_sys_exit_tp_link[i]);
        }
    } else {
        bpf_link__destroy(bpf_sys_enter_link);
        bpf_link__destroy(bpf_sys_exit_link);
    }

    bpf_object__close(bpf_obj);
}

unsigned int *find_config_item(config_s *c, char *param)
{
    if (!strcmp(param, "parent"))
        return c->parent;
    else if (!strcmp(param, "pid"))
        return c->pid;
    else if (!strcmp(param, "ppid"))
        return c->ppid;
    else if (!strcmp(param, "auid"))
        return c->auid;
    else if (!strcmp(param, "ses"))
        return c->ses;
    else if (!strcmp(param, "cred"))
        return c->cred;
    else if (!strcmp(param, "cred_uid"))
        return c->cred_uid;
    else if (!strcmp(param, "cred_gid"))
        return c->cred_gid;
    else if (!strcmp(param, "cred_euid"))
        return c->cred_euid;
    else if (!strcmp(param, "cred_suid"))
        return c->cred_suid;
    else if (!strcmp(param, "cred_fsuid"))
        return c->cred_fsuid;
    else if (!strcmp(param, "cred_egid"))
        return c->cred_egid;
    else if (!strcmp(param, "cred_sgid"))
        return c->cred_sgid;
    else if (!strcmp(param, "cred_fsgid"))
        return c->cred_fsgid;
    else if (!strcmp(param, "tty"))
        return c->tty;
    else if (!strcmp(param, "comm"))
        return c->comm;
    else if (!strcmp(param, "exe_path"))
        return c->exe_path;
    else if (!strcmp(param, "mm_arg_start"))
        return c->mm_arg_start;
    else if (!strcmp(param, "mm_arg_end"))
        return c->mm_arg_end;
    else if (!strcmp(param, "pwd_path"))
        return c->pwd_path;
    else if (!strcmp(param, "path_vfsmount"))
        return c->path_vfsmount;
    else if (!strcmp(param, "path_dentry"))
        return c->path_dentry;
    else if (!strcmp(param, "dentry_parent"))
        return c->dentry_parent;
    else if (!strcmp(param, "dentry_name"))
        return c->dentry_name;
    else if (!strcmp(param, "dentry_inode"))
        return c->dentry_inode;
    else if (!strcmp(param, "inode_mode"))
        return c->inode_mode;
    else if (!strcmp(param, "inode_ouid"))
        return c->inode_ouid;
    else if (!strcmp(param, "inode_ogid"))
        return c->inode_ogid;
    else if (!strcmp(param, "mount_mnt"))
        return c->mount_mnt;
    else if (!strcmp(param, "mount_parent"))
        return c->mount_parent;
    else if (!strcmp(param, "mount_mountpoint"))
        return c->mount_mountpoint;
    else if (!strcmp(param, "max_fds"))
        return c->max_fds;
    else if (!strcmp(param, "fd_table"))
        return c->fd_table;
    else if (!strcmp(param, "fd_path"))
        return c->fd_path;
    else return NULL;
}

bool insert_config_offsets(unsigned int *item, char *value)
{
    char *offset = NULL;
    unsigned int i;
    char *inner_strtok = NULL;

    offset = strtok_r(value, " ,", &inner_strtok);
    if (!offset) {
        item[0] = -1;
        return false;
    }

    i = 0;

    while (offset && i < (NUM_REDIRECTS - 1)) {
        item[i] = atoi(offset);
        offset = strtok_r(NULL, " ,", &inner_strtok);
        i++;
    }
    item[i] = DEREF_END;

    return true;
}


bool populate_config_offsets(config_s *c)
{
    FILE *config;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    char *param = NULL;
    char *value = NULL;
    char *whitespace = NULL;
    unsigned int *item = NULL;
    char *outer_strtok = NULL;

    config = fopen(CONFIG_FILE, "r");
    if (!config)
        return false;

    while ((read_len = getline(&line, &len, config)) >= 0) {
        if (read_len > 0 && line[0] == '#')
            continue;
        whitespace = line;
        while (*whitespace == ' ')
            whitespace++;
        param = strtok_r(whitespace, " =", &outer_strtok);
        if (!param)
            continue;
        value = strtok_r(NULL, "\n", &outer_strtok);
        if (!value)
            continue;
        whitespace = value;
        while (*whitespace == ' ' || *whitespace == '=')
            whitespace++;
        value = whitespace;

        item = find_config_item(c, param);

        if (item)
            insert_config_offsets(item, value);
    }

    free(line);
    fclose(config);

    return true;
}

char get_op(char *arg)
{
    switch (*arg) {
        case '=':
            return COMP_EQ;
            break;
        case '<':
            return COMP_LT;
            break;
        case '>':
            return COMP_GT;
            break;
        case '&':
            return COMP_AND;
            break;
        case '|':
            return COMP_OR;
            break;
        default:
            return COMP_ERROR;
    }
}

bool get_next_arg(char **arg, char **strtok_ctx)
{
    if (**arg == 0x00) {
        *arg = strtok_r(NULL, " \n", strtok_ctx);
        if (!*arg) {
            return false;
        }
    }
    return true;
}

int comp_syscalls(const void *v1, const void *v2)
{
    syscall_names_s *s1 = (syscall_names_s *)v1;
    syscall_names_s *s2 = (syscall_names_s *)v2;
    return strcmp(s1->name, s2->name);
}

bool populate_syscall_conf(char *filename, config_s *config, int sysconf_map_fd, syscall_names_s *syscall_names)
{
    unsigned int index;
    FILE *sysconf;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    char *syscall = NULL;
    char *arg = NULL;
    char *whitespace = NULL;
    unsigned int syscall_num;
    unsigned int arg_len;
    char *strtok_ctx = NULL;
    bool error = false;
    bool eol = false;
    sysconf_s sc;
    char *orig = NULL;
    syscall_names_s key;
    syscall_names_s *name_index;

    memset(config->active, 0, sizeof(config->active));

    sysconf = fopen(filename, "r");
    if (!sysconf) {
        fprintf(stderr, "Cannot open syscall conf file, '%s'\n", filename);
        return false;
    }
    while ((read_len = getline(&line, &len, sysconf)) >= 0) {
        if (read_len > 0 && line[0] == '#')
            continue;
        whitespace = line;
        while (*whitespace == ' ')
            whitespace++;
        syscall = strtok_r(whitespace, " \n", &strtok_ctx);
        if (!syscall)
            continue;
        if (syscall[0] >= '0' && syscall[0] <= '9')
            syscall_num = atoi(syscall);
        else {
            snprintf(key.name, sizeof(key.name), "%s", syscall);
            name_index = bsearch(&key, syscall_names, SYSCALL_MAX+1, sizeof(syscall_names_s), comp_syscalls);
            if (!name_index) {
                fprintf(stderr, "Cannot find syscall: %s\n", syscall);
                continue;
            }
            syscall_num = name_index->nr;
        }

        if (syscall_num > SYSCALL_MAX)
            continue;

        orig = (char *)malloc(read_len + 1);
        if (!orig) {
            fprintf(stderr, "Cannot malloc when reading syscall config\n");
            exit(1);
        }
        memcpy(orig, line, read_len + 1);
        error = false;
        eol = false;
        while (!error && !eol) {
            sc.is_signed = 0;
            arg = strtok_r(NULL, " \n", &strtok_ctx);
            if (!arg) {
                config->active[syscall_num] |= ACTIVE_SYSCALL;
                eol = true;
                continue;
            }
            switch (arg[0]) {
                case 'P':
                case 'p':
                    config->active[syscall_num] |= ACTIVE_NOFAIL;
                    break;
                case 'V':
                case 'v':
                    config->active[syscall_num] |= ACTIVE_PARSEV;
                    break;
                case 'a':
                case 'A':
                    arg_len = strlen(arg);
                    if (arg_len <= 1 || arg[1] < '0' || arg[1] > '5') {
                        error = true;
                        continue;
                    }
                    sc.arg = arg[1] - '0';
                    arg += 2;
                    if (error = !get_next_arg(&arg, &strtok_ctx))
                        continue;
                    if (error = !(sc.op = get_op(arg)))
                        continue;
                    arg++;
                    if (error = !get_next_arg(&arg, &strtok_ctx))
                        continue;
                    if (*arg == 's' || *arg == 'S') {
                        sc.is_signed = 1;
                        arg++;
                    }
                    if (error = !get_next_arg(&arg, &strtok_ctx))
                        continue;
                    sc.value = strtoul(arg, NULL, 0);
                    index = (syscall_num << 16) | (config->active[syscall_num] & ACTIVE_MASK);
                    if (bpf_map_update_elem(sysconf_map_fd, &index, &sc, BPF_ANY)) {
                        fprintf(stderr, "ERROR: failed to set syscall config: '%s'\n", strerror(errno));
                        return false;
                    }
                    config->active[syscall_num]++;
                    break;
                default:
                    error = true;
                    continue;
            }
        }
        if (error) {
            fprintf(stderr, "Error in syscall config:\n'%s'\n", orig);
            break;
        }
        free(orig);
    }
    free(line);
    fclose(sysconf);
    return !error;
}

bool generate_syscall_table(syscall_names_s *num2name, syscall_names_s *name2num)
{
    FILE *input;
    char *line = NULL;
    size_t len = 0;
    ssize_t read_len;
    char *syscall = NULL;
    int syscall_num;
    char *name = NULL;
    char *args = NULL;
    int num_args;
    char *whitespace = NULL;
    char *strtok_ctx = NULL;

    input = fopen(SYSCALL_FILE, "r");
    if (!input)
        return false;

    while ((read_len = getline(&line, &len, input)) >= 0) {
        if (read_len > 0 && line[0] == '#')
            continue;
        syscall = strtok_r(line, "=", &strtok_ctx);
        if (!syscall)
            continue;
        whitespace = strtok_r(NULL, ",", &strtok_ctx);
        if (!whitespace)
            continue;
        while (*whitespace == ' ')
            whitespace++;
        name = whitespace;
        whitespace = name + strlen(name) - 1;
        while (*whitespace == ' ') {
            *whitespace = 0x00;
            whitespace--;
        }
        args = strtok_r(NULL, "\n", &strtok_ctx);
        if (!args)
            continue;

        syscall_num = atoi(syscall);
        num_args = atoi(args);
        if (syscall < 0 || num_args < 0)
            continue;
        snprintf(num2name[syscall_num].name, SYSCALL_NAME_LEN, "%s", name);
        num2name[syscall_num].num_args = num_args;
        snprintf(name2num[syscall_num].name, SYSCALL_NAME_LEN, "%s", name);
        name2num[syscall_num].nr = syscall_num;
        name2num[syscall_num].num_args = num_args;
    }

    qsort(name2num, SYSCALL_MAX+1, sizeof(syscall_names_s), comp_syscalls);

    free(line);
    fclose(input);
    return true;
}

int ebpf_telemetry_start(char *sysconf_filename, void (*event_cb)(void *ctx, int cpu, void *data, __u32 size), void (*events_lost_cb)(void *ctx, int cpu, __u64 lost_cnt))
{
    unsigned int major = 0, minor = 0;
    syscall_names_s syscall_num_to_name[SYSCALL_MAX+1];
    syscall_names_s syscall_name_to_num[SYSCALL_MAX+1];
    memset(syscall_num_to_name, 0, sizeof(syscall_num_to_name));
    memset(syscall_name_to_num, 0, sizeof(syscall_name_to_num));

    if (!generate_syscall_table(syscall_num_to_name, syscall_name_to_num)) {
        fprintf(stderr, "Couldn't build syscall table\n");
        return 1;
    }

    if ( uname(&uname_s) ){
        fprintf(stderr, "Couldn't find uname, '%s'\n", strerror(errno));
        return 1;
    }

    if ( 2 == sscanf(uname_s.release, "%u.%u", &major, &minor)){
        fprintf(stderr, "Found Kernel version: %u.%u\n", major, minor);
    }
    else{
        fprintf(stderr, "Couldn't find version\n");
        return 1;
    }    

    // <  4.15, no ebpf support due to no direct r/w access to maps
    // 4.15 - 4.16 - tracepoints
    // 4.17 - 5.1  - raw tracepoints, <4096 instructions, no loops
    // 5.2         - raw tracepoints, <1M instructions, no loops
    // >= 5.3      - raw tracepoints, <1M instructions, loops

    if ((major < 4) || (major == 4 && minor < 15)) {
        support_version = NOBPF;
        fprintf(stderr, "Kernel Version %u.%u not supported\n", major, minor);
        return 1;    
    } else if (major == 4 && minor <= 16) {
        support_version = BPF_TP;
        fprintf(stderr, "Using Tracepoints, sub 4096 instructions, no loops\n");
    } else if ((major == 4) || (major == 5 && minor <= 1)) {
        support_version = BPF_RAW_TP_SUB4096;
        fprintf(stderr, "Using Raw Tracepoints, sub 4096 instructions, no loops\n");
    } else if (major == 5 && minor == 2) {
        support_version = BPF_RAW_TP_NOLOOPS;
        fprintf(stderr, "Using Raw Tracepoints, sub 1M instructions, no loops\n");
    } else {
        support_version = BPF_RAW_TP;
        fprintf(stderr, "Using Raw Tracepoints, sub 1M instructions, with loops\n");
    }

    struct rlimit lim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    char filename[256];

    switch (support_version) {
        case BPF_TP:
            strncpy(filename, KERN_TRACEPOINT_OBJ, sizeof(filename));
            break;
        case BPF_RAW_TP_SUB4096:
            strncpy(filename, KERN_RAW_TRACEPOINT_SUB4096_OBJ, sizeof(filename));
            break;
        case BPF_RAW_TP_NOLOOPS:
            strncpy(filename, KERN_RAW_TRACEPOINT_NOLOOPS_OBJ, sizeof(filename));
            break;
        case BPF_RAW_TP:
            strncpy(filename, KERN_RAW_TRACEPOINT_OBJ, sizeof(filename));
            break;
    }

    fprintf(stderr, "Using EBPF object: %s\n", filename);

    setrlimit(RLIMIT_MEMLOCK, &lim);

    bpf_obj = bpf_object__open(filename);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "ERROR: failed to open prog: '%s'\n", strerror(errno));
        return 1;
    }

    switch (support_version) {
        case BPF_TP: {
            char program_name[] = "tracepoint/syscalls/sys_enter0";
            unsigned int program_name_len = strlen(program_name);
            for (char n=0; n<7; n++) {
                program_name[program_name_len - 1] = '0' + n;
                if ((bpf_sys_enter_tp[n] = bpf_object__find_program_by_title(bpf_obj, program_name)) == NULL) {
                    fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", program_name, strerror(errno));
                    break;
                }
                bpf_program__set_type(bpf_sys_enter_tp[n], BPF_PROG_TYPE_TRACEPOINT);
            }
            if ((bpf_sys_exit = bpf_object__find_program_by_title(bpf_obj,"tracepoint/syscalls/sys_exit")) == NULL) {
                fprintf(stderr, "ERROR: failed to find program: '%s' '%s'\n", program_name, strerror(errno));
            }
            bpf_program__set_type(bpf_sys_exit, BPF_PROG_TYPE_TRACEPOINT);
            break;
        }
        case BPF_RAW_TP_SUB4096:
        case BPF_RAW_TP_NOLOOPS:
        case BPF_RAW_TP:
            if (((bpf_sys_enter = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_enter")) != NULL)  &&
                    ((bpf_sys_exit  = bpf_object__find_program_by_title(bpf_obj,"raw_tracepoint/sys_exit")) != NULL)) {
                bpf_program__set_type(bpf_sys_enter, BPF_PROG_TYPE_RAW_TRACEPOINT);
                bpf_program__set_type(bpf_sys_exit, BPF_PROG_TYPE_RAW_TRACEPOINT);
            } else {
                fprintf(stderr, "ERROR: failed to find program: '%s'\n", strerror(errno));
                return 1;
            }
            break;
    }

    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "ERROR: failed to load prog: '%s'\n", strerror(errno));
        return 1;
    }

    event_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "event_map");
    if (event_map_fd <= 0) {
        fprintf(stderr, "ERROR: failed to load event_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    config_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "config_map");
    if (config_map_fd <= 0) {
        fprintf(stderr, "ERROR: failed to load config_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    sysconf_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "sysconf_map");
    if (sysconf_map_fd <= 0) {
        fprintf(stderr, "ERROR: failed to load sysconf_map_fd: '%s'\n", strerror(errno));
        return 1;
    }

    // populate config
    unsigned int config_entry = 0;
    config_s config;
    config.userland_pid = getpid();
    populate_config_offsets(&config);
    if (!populate_syscall_conf(sysconf_filename, &config, sysconf_map_fd, syscall_name_to_num))
        exit(1);

    if (bpf_map_update_elem(config_map_fd, &config_entry, &config, BPF_ANY)) {
        fprintf(stderr, "ERROR: failed to set config: '%s'\n", strerror(errno));
        return 1;
    }

    if ( support_version == BPF_TP ){

        for (unsigned int i=0; i<=SYSCALL_MAX; i++) {
            int j;
            memset(bpf_sys_enter_tp_link, 0, sizeof(bpf_sys_enter_tp_link));
            if (config.active[i] & ACTIVE_SYSCALL) {
                char tracepoint[SYSCALL_NAME_LEN * 2];
                snprintf(tracepoint, SYSCALL_NAME_LEN * 2, "sys_enter_%s", syscall_num_to_name[i].name);
                j = syscall_num_to_name[i].num_args;
                bpf_sys_enter_tp_link[i] = bpf_program__attach_tracepoint(bpf_sys_enter_tp[j], "syscalls", tracepoint);
                if (libbpf_get_error(bpf_sys_enter_tp_link[i]))
                    return 2;
                snprintf(tracepoint, SYSCALL_NAME_LEN * 2, "sys_exit_%s", syscall_num_to_name[i].name);
                bpf_sys_exit_tp_link[i] = bpf_program__attach_tracepoint(bpf_sys_exit, "syscalls", tracepoint);
                if (libbpf_get_error(bpf_sys_exit_tp_link[i]))
                    return 2;
            }
        }
    }
    else{
         
        bpf_sys_enter_link = bpf_program__attach_raw_tracepoint(bpf_sys_enter, "sys_enter");
        bpf_sys_exit_link = bpf_program__attach_raw_tracepoint(bpf_sys_exit, "sys_exit");
        
        if ( (libbpf_get_error(bpf_sys_enter_link)) || 
             (libbpf_get_error(bpf_sys_exit_link))  )
        return 2;
    }

    // from Kernel 5.7.1 ex: trace_output_user.c 
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb;
    int ret;

    pb_opts.sample_cb = event_cb;
    pb_opts.lost_cb = events_lost_cb;
    pb_opts.ctx     = NULL;
    pb = perf_buffer__new(event_map_fd, MAP_PAGE_SIZE, &pb_opts); // param 2 is page_cnt == number of pages to mmap.
    ret = libbpf_get_error(pb);
    if (ret) {
        fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", ret);
        return 1;
    }

    fprintf(stderr, "Running...\n");

    int i = 0;
    while ((ret = perf_buffer__poll(pb, 1000)) >= 0 ) {
        if (isTesting){
            if (i++ > STOPLOOP) break;
        }
    }

    ebpf_telemetry_close_all();

    return 0;
}

