/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#ifndef SYSMON_DEFS_H
#define SYSMON_DEFS_H

#include <linux/limits.h>

#define VERSION 1
#define CODE_BYTES 0xdeadbeef

#define CONFIG_FILE "../sysmon_offsets.conf"
#define SYSCALL_FILE "../syscalls.conf"

// return values
#define READ_OKAY 0
#define UPDATE_OKAY 0

#define CMDLINE_MAX_LEN 16384 // must be power of 2
#define TTYSIZE 64
#define NOTTY_STRING "(none)"
#define COMMSIZE 16
#define MAX_FDS 65535
#define MAX_EVENT_SIZE (65536 - 8)

// tunable parameters for building paths through iteration.
// for SUB4096 it's about instruction count <4096
// for NOLOOPS it's about instruction count <32768(ish - due to signed 16bit jumps)
// for others it's about verification complexity <1M instructions
// 
// when adding code, change these to keep within these limits
#ifdef SUB4096
#define FILEPATH_NUMDIRS 6
#else
#ifdef NOLOOPS
#define FILEPATH_NUMDIRS 15
#else
#define FILEPATH_NUMDIRS 95
#endif
#endif

#define ABSOLUTE_PATH 'A'
#define RELATIVE_PATH 'R'
#define CWD_REL_PATH 'C'
#define UNKNOWN_PATH 'U'

#define NUM_REDIRECTS 4
#define DEREF_END -1


#define SYSCALL_MAX 335
#define SYSCALL_NAME_LEN 64
#define SYSCALL_ARRAY_SIZE 512
#define SYSCALL_MAX_FILTERS 8
#define COMP_ERROR 0
#define COMP_EQ    1
#define COMP_LT    2
#define COMP_GT    3
#define COMP_AND   4
#define COMP_OR    5

#define NUM_ARGS 6
#define ARG_ARRAY_SIZE 8
#define ARG_MASK 7

#define ACTIVE_MASK 0x1f
#define ACTIVE_SYSCALL 0x20
#define ACTIVE_NOFAIL  0x40
#define ACTIVE_PARSEV  0x80

#define STATUS_VALUE   0x0001
#define STATUS_RC      0x0002
#define STATUS_CRED    0x0004
#define STATUS_COMM    0x0008
#define STATUS_EXE     0x0010
#define STATUS_PWD     0x0020
#define STATUS_EXEINFO 0x0040
#define STATUS_NOTASK  0x0080
#define STATUS_NOARGS  0x0100


// file operations
typedef struct e_path {
    union {
        struct {
            char  pathname[PATH_MAX];
            char  dfd_path[PATH_MAX];
        };
        struct {
            int   dfd;
            void  *pathname_ptr;
        };
    };
} event_path_s;

// file op: open/at, truncate, rename/at/2, rmdir, creat, link/at, unlink/at, symlink/at, chmod, fchmodat, chown, lchown, fchownat, mknod/at
typedef struct e_fileop {
    event_path_s  path1;
    event_path_s  path2;
} event_fileop_s;

// __NR_execve
typedef struct e_execve {
    unsigned int  cmdline_size;
    char          cmdline[CMDLINE_MAX_LEN];
} event_execve_s;

// __NR_connect: 
typedef struct e_socket {
    union {
        struct sockaddr_in addr;
        struct sockaddr_in6 addr6;
    };
} event_socket_s;

// Event arguments structure
typedef struct a_rec {
    unsigned long      syscall_id;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
} args_s;

// Event structure
typedef struct e_rec {
    unsigned long int  code_bytes_start; //Always 0xdeadbeef = 3735928559
    unsigned int       version;
    unsigned long      bootns; // time since boot in nanoseconds, not including time when suspended
    unsigned int       status;
    unsigned long      syscall_id;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
    unsigned int       pid;
    long int           return_code;
    unsigned int       ppid;
    unsigned int       ses;
    char               tty[TTYSIZE];
    char               comm[COMMSIZE];
    char               exe[PATH_MAX];
    char               p_exe[PATH_MAX];
    unsigned short     exe_mode;
    unsigned int       exe_ouid;
    unsigned int       exe_ogid;
    char               pwd[PATH_MAX];
    unsigned int       auid;
    unsigned int       uid;
    unsigned int       gid;
    unsigned int       euid;
    unsigned int       suid;
    unsigned int       fsuid;
    unsigned int       egid;
    unsigned int       sgid;
    unsigned int       fsgid;
    event_execve_s     execve;
/*
    union {
        event_fileop_s fileop;
        event_execve_s execve;
        event_socket_s socket;
    };
*/
    unsigned long int  code_bytes_end; //Always 0xdeadbeef = 3735928559
} event_s;

// configuration
typedef struct conf {
    unsigned int       userland_pid;
    unsigned char      active[SYSCALL_ARRAY_SIZE]; // b0-b4 count of filters
                                                   // for this syscall;
                                    // b5 = syscall should generate events;
                                    // b6 = no failures; b7 = parse value ok
    unsigned int       timesec[NUM_REDIRECTS];
    unsigned int       timensec[NUM_REDIRECTS];
    unsigned int       serial[NUM_REDIRECTS];
    unsigned int       arch[NUM_REDIRECTS];
    unsigned int       arg0[NUM_REDIRECTS];
    unsigned int       arg1[NUM_REDIRECTS];
    unsigned int       arg2[NUM_REDIRECTS];
    unsigned int       arg3[NUM_REDIRECTS];
    unsigned int       parent[NUM_REDIRECTS];
    unsigned int       pid[NUM_REDIRECTS];
    unsigned int       ppid[NUM_REDIRECTS];
    unsigned int       auid[NUM_REDIRECTS];
    unsigned int       cred[NUM_REDIRECTS];
    unsigned int       cred_uid[NUM_REDIRECTS];
    unsigned int       cred_gid[NUM_REDIRECTS];
    unsigned int       cred_euid[NUM_REDIRECTS];
    unsigned int       cred_suid[NUM_REDIRECTS];
    unsigned int       cred_fsuid[NUM_REDIRECTS];
    unsigned int       cred_egid[NUM_REDIRECTS];
    unsigned int       cred_sgid[NUM_REDIRECTS];
    unsigned int       cred_fsgid[NUM_REDIRECTS];
    unsigned int       ses[NUM_REDIRECTS];
    unsigned int       tty[NUM_REDIRECTS];
    unsigned int       comm[NUM_REDIRECTS];
    unsigned int       exe_path[NUM_REDIRECTS];
    unsigned int       mm_arg_start[NUM_REDIRECTS];
    unsigned int       mm_arg_end[NUM_REDIRECTS];
    unsigned int       pwd_path[NUM_REDIRECTS];
    unsigned int       path_vfsmount[NUM_REDIRECTS];
    unsigned int       path_dentry[NUM_REDIRECTS];
    unsigned int       dentry_parent[NUM_REDIRECTS];
    unsigned int       dentry_name[NUM_REDIRECTS];
    unsigned int       dentry_inode[NUM_REDIRECTS];
    unsigned int       inode_mode[NUM_REDIRECTS];
    unsigned int       inode_ouid[NUM_REDIRECTS];
    unsigned int       inode_ogid[NUM_REDIRECTS];
    unsigned int       mount_mnt[NUM_REDIRECTS];
    unsigned int       mount_parent[NUM_REDIRECTS];
    unsigned int       mount_mountpoint[NUM_REDIRECTS];
    unsigned int       max_fds[NUM_REDIRECTS];
    unsigned int       fd_table[NUM_REDIRECTS];
    unsigned int       fd_path[NUM_REDIRECTS];
} config_s;

// syscall configuration
// arg specifies which of the 6 syscall arguments to match on
// op represents the comparison operator from:
//     COMP_EQ, COMP_LT, COMP_GT, COMP_AND (bitwise AND), COMP_OR (bitwise OR)
//     - these are all ORed so any matches means event is generated
// is_signed represents whether the operation should be a signed one
// value is the value to compare with
typedef struct sysconf {
    unsigned char      arg;
    unsigned char      op;
    unsigned char      is_signed;
    unsigned long      value;
} sysconf_s;

typedef struct syscall_names {
    char name[SYSCALL_NAME_LEN];
    unsigned int nr;
    unsigned int num_args;
} syscall_names_s;


#endif
