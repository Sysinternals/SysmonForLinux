/*
    SysmonForLinux

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


#ifndef KERN_HELPERS_H
#define KERN_HELPERS_H

#include "ebpf_kern_common.h"

// Our own inline helper functions

// return pointer to struct member
__attribute__((always_inline))
static inline void *deref_member(void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    void *result = ref;
    unsigned int breakindex = 0;
    bool breakloop = false; // problems with clang loop unrolling led to this...

    if (!refs || refs[0] == DEREF_END)
        return NULL;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<NUM_REDIRECTS - 1; i++) {
        if (!breakloop) {
            if (refs[i+1] == DEREF_END) {
                breakindex = i;
                breakloop = true;
            } else {
                if (bpf_probe_read(&result, sizeof(result), ref + refs[i]) != READ_OKAY)
                    return NULL;
                ref = result;
                if (!ref)
                    return NULL;
            }
        }
    }

    return result + refs[breakindex & (NUM_REDIRECTS - 1)];
}

// return value pointed to by struct member
__attribute__((always_inline))
static inline uint64_t deref_ptr(void *base, unsigned int *refs)
{
    uint64_t result = 0;
    void *ref;

    ref = deref_member(base, refs);

    if (bpf_probe_read(&result, sizeof(result), ref) != READ_OKAY)
        return 0;

    return result;
}

// extract string from struct
__attribute__((always_inline))
static inline bool deref_string_into(char *dest, unsigned int size, void *base, unsigned int *refs)
{
    unsigned int i;
    void *ref = base;
    uint64_t result = 0;

    ref = deref_member(base, refs);

    if (ref && bpf_probe_read_str(dest, size, ref) > 0)
        return true;
    else {
        *dest = 0x00;
        return false;
    }
}

// extract filepath from dentry
__attribute__((always_inline))
static inline bool deref_filepath_into(char *dest, void *base, unsigned int *refs, config_s *config)
{
    int dlen, dlen2;
    char *dname = NULL;
    char *temp = NULL;
    unsigned int i;
    unsigned int size = 0;
    uint32_t map_id = bpf_get_smp_processor_id();
    void *path = NULL;
    void *dentry = NULL;
    void *newdentry = NULL;
    void *vfsmount = NULL;
    void *mnt = NULL;

    // nullify string in case of error
    dest[0] = 0x00;

    path = deref_member(base, refs);
    if (!path)
        return false;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->path_dentry[0]) != READ_OKAY)
        return false;

    if (!dentry)
        return false;

    // get a pointer to the vfsmount
    if (bpf_probe_read(&vfsmount, sizeof(vfsmount), path + config->path_vfsmount[0]) != READ_OKAY)
        return false;

    // retrieve temporary filepath storage
    temp = bpf_map_lookup_elem(&temppath_array, &map_id);
    if (!temp)
        return false;

#ifdef NOLOOPS
    #pragma unroll
#endif
    for (i=0; i<FILEPATH_NUMDIRS; i++) {
        if (bpf_probe_read(&dname, sizeof(dname), dentry + config->dentry_name[0]) != READ_OKAY)
            return false;
        if (!dname)
            return false;
        // store this dentry name in start of second half of our temporary storage
        dlen = bpf_probe_read_str(&temp[PATH_MAX], PATH_MAX, dname);
        // get parent dentry
        bpf_probe_read(&newdentry, sizeof(newdentry), dentry + config->dentry_parent[0]);
        // copy the temporary copy to the first half of our temporary storage, building it backwards from the middle of it
        dlen2 = bpf_probe_read_str(&temp[(PATH_MAX - size - dlen) & (PATH_MAX - 1)], dlen & (PATH_MAX - 1), &temp[PATH_MAX]);
        // check if current dentry name is valid
        if (dlen2 <= 0 || dlen <= 0 || dlen >= PATH_MAX || size + dlen > PATH_MAX)
            return false;
        if (size > 0)
            // overwrite the null char with a slash
            temp[(PATH_MAX - size - 1) & (PATH_MAX - 1)] = '/';
        size = (size + dlen2) & (PATH_MAX - 1);  // by restricting size to PATH_MAX we help the verifier keep the complexity
                                                // low enough so that it can analyse the loop without hitting the 1M ceiling
        // check if this is the root of the filesystem
        if (!newdentry || dentry == newdentry) {
            // check if we're on a mounted partition
            // find mount struct from vfsmount
            mnt = vfsmount - config->mount_mnt[0];
            void *parent = (void *)deref_ptr(mnt, config->mount_parent);
            // check if we're at the real root
            if (parent == mnt)
                break;
            // move to mount point
            vfsmount = parent + config->mount_mnt[0];
            newdentry = (void *)deref_ptr(mnt, config->mount_mountpoint);
            // another check for real root
            if (dentry == newdentry)
                break;
            size = (size - dlen2) & (PATH_MAX - 1);  // ditto above message about restricting size to PATH_MAX
        }

        // go up one directory
        dentry = newdentry;
    }

    // copy the path from the temporary location to the destination
    if (size == 2)
        // path is simply "/"
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[(PATH_MAX - size) & (PATH_MAX -1)]);
    else if (size > 2)
        // otherwise don't copy the extra slash
        dlen = bpf_probe_read_str(dest, PATH_MAX, &temp[(PATH_MAX - (size - 1)) & (PATH_MAX -1)]);
    if (dlen <= 0)
        return false;

    return true;
}

// copy commandline from task
__attribute__((always_inline))
static inline bool copy_commandline(event_execve_s *e, void *task, config_s *config)
{
    // read the more reliable cmdline from task_struct->mm->arg_start
    uint64_t arg_start = deref_ptr(task, config->mm_arg_start);
    uint64_t arg_end = deref_ptr(task, config->mm_arg_end);

    if (arg_start >= arg_end)
        return false;
    int arg_len = arg_end - arg_start;
    if (arg_len > (CMDLINE_MAX_LEN - 1))
        arg_len = CMDLINE_MAX_LEN - 1;

    arg_len = arg_len & (CMDLINE_MAX_LEN - 1);

    if (bpf_probe_read(&e->cmdline, arg_len, (void *)arg_start) != READ_OKAY)
        return false;

    // add nul terminator just in case
    e->cmdline[CMDLINE_MAX_LEN - 1] = 0x00;
    e->cmdline[arg_len] = 0x00;
    e->cmdline_size = arg_len;
    return true;
}

// extract pathname from a file descriptor
__attribute__((always_inline))
static inline bool fd_to_path(char *fd_path, int fd, void *task, config_s *config)
{
    int byte_count;

    // check if fd is valid
    int max_fds = deref_ptr(task, config->max_fds);
    if (fd < 0 || fd > MAX_FDS || max_fds <= 0 || fd > max_fds) {
        return false;
    }

    // resolve the fd to the fd_path
    void **fd_table = (void **)deref_ptr(task, config->fd_table);
    if (!fd_table) {
        return false;
    }

    void *file = NULL;
    if (bpf_probe_read(&file, sizeof(file), &fd_table[fd & MAX_FDS]) != READ_OKAY || !file) {
        return false;
    } else {
        return deref_filepath_into(fd_path, file, config->fd_path, config);
    }
}

// wrapper for fd_to_path()
__attribute__((always_inline))
static inline bool resolve_fd_path(event_path_s *fd_path, int fd, void *task, config_s *config)
{
    fd_path->pathname[0] = 0x00;
    fd_path->dfd_path[0] = ABSOLUTE_PATH;
    fd_path->dfd_path[1] = 0x00;

    if (fd > 0)
        return fd_to_path(fd_path->pathname, fd, task, config);

    return false;
}

// extract pathname and dfd pathname
__attribute__((always_inline))
static inline bool resolve_dfd_path(event_path_s *dfd_path, int dfd, char *pathname, void *task, config_s *config)
{
    int byte_count;

    if (pathname) {
        if ((byte_count = bpf_probe_read_str(dfd_path->pathname,
                sizeof(dfd_path->pathname), (void *)pathname)) < 0) {
            BPF_PRINTK("ERROR, reading pathname (0x%lx), returned %ld\n", pathname, byte_count);
            return false;
        } 
    }

    dfd_path->dfd_path[0] = RELATIVE_PATH;
    dfd_path->dfd_path[1] = 0x00;
    // find the dfd path and store in event
    if (dfd_path->pathname[0] == '/') {
        // absolute path
        dfd_path->dfd_path[0] = ABSOLUTE_PATH;
        return true;
    }
    if (dfd == AT_FDCWD) {
        // relative to current working directory
        dfd_path->dfd_path[0] = CWD_REL_PATH;
        return true;
    }

#ifndef SUB4096
    if (!fd_to_path(dfd_path->dfd_path, dfd, task, config)) {
        dfd_path->dfd_path[0] = UNKNOWN_PATH;
        BPF_PRINTK("resolve_dfd_path: fd_to_path() failed\n");
        return false;
    }
#endif

    return true;
}

// set the initial values for the event arguments
__attribute__((always_inline))
static inline void init_args(args_s *event_args, unsigned long syscall_id)
{
    memset(event_args, 0, sizeof(args_s));
    event_args->syscall_id = syscall_id;
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (unsigned int i=0; i<ARG_ARRAY_SIZE; i++) {
        event_args->a[i] = 0;
    }
}

// check if this is an event to process
__attribute__((always_inline))
static inline bool sys_enter_check_and_init(args_s *event_args, uint32_t syscall, uint64_t pid_tid, uint32_t cpu_id)
{
    uint32_t config_id = 0;
    config_s *config;
    uint32_t userland_pid = 0;
    char syscall_flags = 0;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return false;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return false;

    // initialise the args
    init_args(event_args, syscall);

    return true;
}

// retrieve and process per-syscall filters
__attribute__((always_inline))
static inline bool check_event_filters(unsigned long *a, uint32_t syscall)
{
    sysconf_s *sysconf = NULL;
    uint32_t sysconf_index = 0;
    uint32_t index = 0;

    return true;

    // check if there are any filters first
    sysconf_index = syscall << 16;
    sysconf = bpf_map_lookup_elem(&sysconf_map, &sysconf_index);
    if (!sysconf)
        return true;
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (index = 0; index < SYSCALL_MAX_FILTERS; index++) {
        sysconf_index = (syscall << 16) | index;
        sysconf = bpf_map_lookup_elem(&sysconf_map, &sysconf_index);
        if (!sysconf)
            return false;
        switch(sysconf->op) {
            case COMP_EQ:
                if (a[sysconf->arg & ARG_MASK] == sysconf->value)
                    return true;
                break;
            case COMP_LT:
                if (sysconf->is_signed) {
                    if ((long)a[sysconf->arg & ARG_MASK] < (long)sysconf->value)
                        return true;
                } else {
                    if (a[sysconf->arg & ARG_MASK] < sysconf->value)
                        return true;
                }
                break;
            case COMP_GT:
                if (sysconf->is_signed) {
                    if ((long)a[sysconf->arg & ARG_MASK] > (long)sysconf->value)
                        return true;
                } else {
                    if (a[sysconf->arg & ARG_MASK] > sysconf->value)
                        return true;
                }
                break;
            case COMP_AND:
                if ((a[sysconf->arg & ARG_MASK] & sysconf->value) == sysconf->value)
                    return true;
                break;
            case COMP_OR:
                if (a[sysconf->arg & ARG_MASK] & sysconf->value)
                    return true;
                break;
        }
    }
    return false;
}

// complete and store event
__attribute__((always_inline))
static inline void sys_enter_complete_and_store(args_s *event_args, uint32_t syscall, uint64_t pid_tid)
{
    args_s args;
    memset(&args, 0, sizeof(args_s));
    // check syscall conditions
    if (check_event_filters(event_args->a, syscall)) {
        // store args in the hash
#ifdef NOLOOPS
        #pragma unroll
#endif
        for (int i=0; i<NUM_ARGS; i++) {
            args.a[i] = event_args->a[i];
        }
        args.syscall_id = event_args->syscall_id;
        long ret = 0;
        if ((ret = bpf_map_update_elem(&args_hash, &pid_tid, &args, BPF_ANY)) != UPDATE_OKAY) {
            BPF_PRINTK("ERROR, HASHMAP: failed to update args map, %ld\n", ret);
        }
    }
}

// set the initial values for an event
__attribute__((always_inline))
static inline void init_event(event_s *event, args_s *event_args, unsigned int pid)
{
    event->code_bytes_start = CODE_BYTES;
    event->code_bytes_end   = CODE_BYTES;
    event->version          = VERSION;
    event->syscall_id       = event_args->syscall_id;
    event->status           = 0;
    event->pid              = pid;
#ifdef NOLOOPS
    #pragma unroll
#endif
    for (int i=0; i<NUM_ARGS; i++) {
        event->a[i] = event_args->a[i];
    }
}

// extract details of the process' executable
__attribute__((always_inline))
static inline bool set_event_exe_info(event_s *event, void *task, config_s *config)
{
    void *path = NULL;
    void *dentry = NULL;
    void *inode = NULL;

    path = deref_member(task, config->exe_path);
    if (!path)
        return false;
    if (bpf_probe_read(&dentry, sizeof(dentry), path + config->path_dentry[0]) != READ_OKAY)
        return false;
    inode = (void *)deref_ptr(dentry, config->dentry_inode);
    if (!inode)
        return false;
    event->exe_mode = (uint16_t)deref_ptr(inode, config->inode_mode);
    event->exe_ouid = (uint32_t)deref_ptr(inode, config->inode_ouid);
    event->exe_ogid = (uint32_t)deref_ptr(inode, config->inode_ogid);
    return true;
}

// fill in details on syscall exit
__attribute__((always_inline))
static inline bool set_event_exit_info(event_s *event, void *task, void *p_task, config_s *config)
{
    void *cred = NULL;
    char notty[] = NOTTY_STRING;

    // timestamp
    event->bootns = bpf_ktime_get_ns();

    // get the ppid
    event->ppid = (uint32_t)deref_ptr(p_task, config->pid);

    // get the session
    event->auid = (uint32_t)deref_ptr(task, config->auid);
//    event->ses = (uint32_t)deref_ptr(task, config->ses);

/*
    if (!deref_string_into(event->tty, sizeof(event->tty), task, config->tty)){
        bpf_probe_read_str(event->tty, sizeof(event->tty), notty);
    }
*/

    // get the creds
    cred = (void *)deref_ptr(task, config->cred);
    if (cred) {
        event->uid = (uint32_t)deref_ptr(cred, config->cred_uid);
//        event->gid = (uint32_t)deref_ptr(cred, config->cred_gid);
        event->euid = (uint32_t)deref_ptr(cred, config->cred_euid);
        event->suid = (uint32_t)deref_ptr(cred, config->cred_suid);
//        event->fsuid = (uint32_t)deref_ptr(cred, config->cred_fsuid);
//        event->egid = (uint32_t)deref_ptr(cred, config->cred_egid);
//        event->sgid = (uint32_t)deref_ptr(cred, config->cred_sgid);
//        event->fsgid = (uint32_t)deref_ptr(cred, config->cred_fsgid);
    } else {
        BPF_PRINTK("ERROR, failed to deref creds\n");
        event->status |= STATUS_CRED;

        event->uid = -1;
//        event->gid = -1;
        event->euid = -1;
        event->suid = -1;
//        event->fsuid = -1;
//        event->egid = -1;
//        event->sgid = -1;
//        event->fsgid = -1;
    }

    // get the comm, etc
/*
    if (!deref_string_into(event->comm, sizeof(event->comm), task, config->comm))
        event->status |= STATUS_COMM;
*/
//#ifndef SUB4096
    if (!deref_filepath_into(event->exe, task, config->exe_path, config))
        event->status |= STATUS_EXE;
    if (!deref_filepath_into(event->p_exe, p_task, config->exe_path, config))
        event->status |= STATUS_EXE;
//#endif
    if (!deref_filepath_into(event->pwd, task, config->pwd_path, config))
        event->status |= STATUS_PWD;
/*
    if (!set_event_exe_info(event, task, config))
        event->status |= STATUS_EXEINFO;
*/

    if (!event->status)
        return false;
    else
        return true;
}

// extract details from the arguments
__attribute__((always_inline))
static inline void set_event_arg_info(event_s *event, void *task, void *p_task, config_s *config, uint32_t cpu_id)
{
    switch(event->syscall_id)
    {
/*
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        case __NR_connect: 
        {
            if (bpf_probe_read(&event->socket.addr.sin_family, sizeof(event->socket.addr.sin_family), (void *)event->a[1]) != READ_OKAY) {
                BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket sa_family from a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
                break;
            }
            if (event->socket.addr.sin_family == AF_INET) {
                if (bpf_probe_read(&event->socket.addr, sizeof(event->socket.addr), (void *)event->a[1]) != READ_OKAY) {
                    BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                    event->status |= STATUS_VALUE;
                }
            } else if (event->socket.addr6.sin6_family == AF_INET6) {
                if (bpf_probe_read(&event->socket.addr6, sizeof(event->socket.addr6), (void *)event->a[1]) != READ_OKAY) {
                    BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket6 info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                    event->status |= STATUS_VALUE;
                }
            }
            break;
        }

        // int accept(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen);
        // int accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);
        case __NR_accept:
        case __NR_accept4:
        {
            event->socket.addr.sin_family = AF_UNSPEC;
            if (event->a[1] != 0) {
                if (bpf_probe_read(&event->socket.addr.sin_family, sizeof(event->socket.addr.sin_family), (void *)event->a[1]) != READ_OKAY) {
                    BPF_PRINTK("ERROR, CONNECT(%lu): failed to get socket sa_family from a1 0x%lx\n", event->syscall_id, event->a[1]);
                    event->status |= STATUS_VALUE;
                    break;
                }
                if (event->socket.addr.sin_family == AF_INET) {
                    if (bpf_probe_read(&event->socket.addr, sizeof(event->socket.addr), (void *)event->a[1]) != READ_OKAY) {
                        BPF_PRINTK("ERROR, ACCEPT(%lu) failed to retrieve addr info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                        event->status |= STATUS_VALUE;
                    }
                } else if (event->socket.addr6.sin6_family == AF_INET6) {
                    if (bpf_probe_read(&event->socket.addr6, sizeof(event->socket.addr6), (void *)event->a[1]) != READ_OKAY) {
                        BPF_PRINTK("ERROR, ACCEPT(%lu) failed to retrieve addr info from a1 0x%lx\n", event->syscall_id, event->a[1]);
                        event->status |= STATUS_VALUE;
                    }
                }
            }
            break;
        }

        // int open(const char *pathname, int flags, mode_t mode);
        case __NR_open:
        // int truncate(const char *pathname, long length);
        case __NR_truncate:
        // int rmdir(const char *pathname);
        case __NR_rmdir:
        // int creat(const char *pathname, int mode);
        case __NR_creat:
        // int unlink(const char *pathname);
        case __NR_unlink:
        // int chmod(const char *pathname, mode_t mode);
        case __NR_chmod:
        // int chown(const char *pathname, uid_t user, gid_t group);
        case __NR_chown:
        // int lchown(const char *pathname, uid_t user, gid_t group);
        case __NR_lchown:
        // int mknod(const char *pathname, umode_t mode, unsigned dev);
        case __NR_mknod:
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int rename(const char *oldname, const char *newname);
        case __NR_rename:
        // int link(const char *oldname, const char *newname);
        case __NR_link:
        // int symlink(const char *oldname, const char *newname);
        case __NR_symlink:
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            if (!resolve_dfd_path(&event->fileop.path2, AT_FDCWD, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int ftruncate(unsigned int fd, unsigned long length);
        case __NR_ftruncate:
        // int fchmod(unsigned int fd, mode_t mode);
        case __NR_fchmod:
        // int fchown(unsigned int fd, uid_t user, gid_t group);
        case __NR_fchown:
        {
#ifndef SUB4096
            if (!resolve_fd_path(&event->fileop.path1, event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_fd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
#endif
            break;
        }

        // int openat(int dirfd, const char *pathname, int flags);
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        case __NR_openat:
        // int mknodat(int dfd, const char *pathname, int mode, unsigned dev);
        case __NR_mknodat:
        // int fchownat(int dfd, const char *pathname, uid_t user, gid_t group, int flag);
        case __NR_fchownat:
        // int unlinkat(int dfd, const char *pathname, int flag);
        case __NR_unlinkat:
        // int fchmodat(int dfd, const char *pathname, mode_t mode);
        case __NR_fchmodat:
        {
            int dfd = event->a[0];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            break;
        }

        // int renameat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        case __NR_renameat:
        // int renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
        case __NR_renameat2:
        // int linkat(int olddfd, const char *oldname, int newdfd, const char *newname, int flags);
        case __NR_linkat:
        {
            int dfd = event->a[0];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[1], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a1 0x%lx\n", event->syscall_id, event->a[1]);
                event->status |= STATUS_VALUE;
            }
            dfd = event->a[2];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[3], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a3 0x%lx\n", event->syscall_id, event->a[3]);
                event->status |= STATUS_VALUE;
                }
            break;
        }

        // int symlinkat(const char *oldname, int newdfd, const char *newname);
        case __NR_symlinkat:
        {
            if (!resolve_dfd_path(&event->fileop.path1, AT_FDCWD, (void *)event->a[0], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a0 0x%lx\n", event->syscall_id, event->a[0]);
                event->status |= STATUS_VALUE;
            }
            int dfd = event->a[1];
            if (dfd <= 0)
                dfd = AT_FDCWD;
            if (!resolve_dfd_path(&event->fileop.path1, dfd, (void *)event->a[2], task, config)) {
                BPF_PRINTK("ERROR, syscall %d, resolve_dfd_path() failed on a2 0x%lx\n", event->syscall_id, event->a[2]);
                event->status |= STATUS_VALUE;
            }
            break;
        }
*/

        // int execve(const char *filename, char *const argv[], char *const envp[]);
        case __NR_execve: 
        // int execveat(int dfd, const char *filename, char *const argv[], char *const envp[]);
        case __NR_execveat: 
        {
            event->execve.cmdline[0] = 0x00;
            event->execve.cmdline_size = 0;
            if (event->return_code == 0) {
                if (!copy_commandline(&event->execve, task, config)) {
                    BPF_PRINTK("ERROR, execve(%d), failed to copy cmdline\n", event->syscall_id);
                    event->status |= STATUS_VALUE;
                }
            }
/*
            event->p_execve.cmdline[0] = 0x00;
            event->p_execve.cmdline_size = 0;
            if (event->return_code == 0) {
                if (!copy_commandline(&event->p_execve, p_task, config)) {
                    BPF_PRINTK("ERROR, execve(%d), failed to copy parent cmdline\n", event->syscall_id);
                    event->status |= STATUS_VALUE;
                }
            }
*/
            break;
        }
    }
}

// check and send
__attribute__((always_inline))
static inline void check_and_send_event(void *ctx, event_s *event, config_s *config)
{
    bool send_event = true;

    if (!event->status)
        send_event = true;
    else {
        if ((event->status & STATUS_VALUE) &&
            (config->active[event->syscall_id & (SYSCALL_ARRAY_SIZE - 1)] & ACTIVE_PARSEV))
            send_event = false;
        if ((event->status & ~STATUS_VALUE) &&
            (config->active[event->syscall_id & (SYSCALL_ARRAY_SIZE - 1)] & ACTIVE_NOFAIL))
            send_event = false;
    }

    if (send_event) {
        bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(event_s));
    } else {
        BPF_PRINTK("ERROR, Unable to finish event... dropping\n");
    }
}
 
#endif
