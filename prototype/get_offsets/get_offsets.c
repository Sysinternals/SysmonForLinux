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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include "mount.h"
//#include "/usr/src/linux/fs/mount.h"
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin Sheldrake");
MODULE_DESCRIPTION("Acquires and prints offsets into structs to dmesg");
MODULE_VERSION("0.01");

static int __init get_offsets_init(void) {
    struct task_struct *ts;
    struct cred *c;
    struct signal_struct *ss;
    struct tty_struct *ttys;
    struct mm_struct *mm;
    struct file *f;
    struct fs_struct *fs;
    struct path *p;
    struct dentry *d;
    struct inode *i;
    struct mount *m;
    struct files_struct *files;
    struct fdtable *fdtable;

    ts = current;
    while (ts->pid != 1) {
     ts = ts->parent;
    }

    printk(KERN_INFO "get_offsets loaded\n");
    printk(KERN_INFO "\n\n");

    printk(KERN_INFO "# ebpf_telemetry.conf\n");
    printk(KERN_INFO "#\n");
    printk(KERN_INFO "# This file contains the dereference offsets from the start of the kernel task_struct\n");
    printk(KERN_INFO "# struct task_struct: include/linux/sched.h\n");
    printk(KERN_INFO "# struct cred: include/linux/cred.h\n");
    printk(KERN_INFO "# struct signal_struct: include/linux/sched/signal.h\n");
    printk(KERN_INFO "# struct tty_struct: include/linux/tty.h\n");
    printk(KERN_INFO "# ppid = task_struct->real_parent->tgid (tgid is userland pid)\n");
    printk(KERN_INFO "ppid = %lu, %lu\n", (void *)&ts->real_parent - (void *)ts, (void *)&ts->tgid - (void *)ts);
    printk(KERN_INFO "# auid = task_struct->loginuid\n");
    printk(KERN_INFO "auid = %lu\n", (void *)&ts->loginuid - (void *)ts);
    printk(KERN_INFO "# ses = task_struct->sessionid\n");
    printk(KERN_INFO "ses = %lu\n", (void *)&ts->sessionid - (void *)ts);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# cred = task_struct->cred\n");
    printk(KERN_INFO "cred = %lu\n", (void *)&ts->cred - (void *)ts);
    c = (struct cred *)ts->cred;
    printk(KERN_INFO "cred_uid = %lu\n", (void *)&c->uid - (void *)c);
    printk(KERN_INFO "cred_gid = %lu\n", (void *)&c->gid - (void *)c);
    printk(KERN_INFO "cred_euid = %lu\n", (void *)&c->euid - (void *)c);
    printk(KERN_INFO "cred_suid = %lu\n", (void *)&c->suid - (void *)c);
    printk(KERN_INFO "cred_fsuid = %lu\n", (void *)&c->fsuid - (void *)c);
    printk(KERN_INFO "cred_egid = %lu\n", (void *)&c->egid - (void *)c);
    printk(KERN_INFO "cred_sgid = %lu\n", (void *)&c->sgid - (void *)c);
    printk(KERN_INFO "cred_fsgid = %lu\n", (void *)&c->fsgid - (void *)c);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# tty = task_struct->signal->tty->name\n");
    ss = ts->signal;
    ttys = ss->tty;
    printk(KERN_INFO "tty = %lu, %lu, %lu\n", (void *)&ts->signal - (void *)ts, (void *)&(ss->tty) - (void *)ss, (void *)&(ttys->name) - (void *)ttys);
    printk(KERN_INFO "# comm = task_struct->comm\n");
    printk(KERN_INFO "comm = %lu\n", (void *)&ts->comm - (void *)ts);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# exe_path = task_struct->mm->exe_file->f_path\n");
    mm = ts->mm;
    f = mm->exe_file;
    printk(KERN_INFO "exe_path = %lu, %lu, %lu\n", (void *)&ts->mm - (void *)ts, (void *)&mm->exe_file - (void *)mm, (void *)&f->f_path - (void *)f);
    printk(KERN_INFO "# mm_arg_start = task_struct->mm->arg_start\n");
    printk(KERN_INFO "mm_arg_start = %lu, %lu\n", (void *)&ts->mm - (void *)ts, (void *)&mm->arg_start - (void *)mm);
    printk(KERN_INFO "# mm_arg_end = task_struct->mm->arg_end\n");
    printk(KERN_INFO "mm_arg_end = %lu, %lu\n", (void *)&ts->mm - (void *)ts, (void *)&mm->arg_end - (void *)mm);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# pwd_path = task_struct->fs->pwd\n");
    fs = ts->fs;
    printk(KERN_INFO "pwd_path = %lu, %lu\n", (void *)&ts->fs - (void *)ts, (void *)&fs->pwd - (void *)fs);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# path_vfsmount = path.vfsmount\n");
    p = &fs->pwd;
    printk(KERN_INFO "path_vfsmount = %lu\n", (void *)&p->mnt - (void *)p);
    printk(KERN_INFO "# path_dentry = path.dentry\n");
    printk(KERN_INFO "path_dentry = %lu\n", (void *)&p->dentry - (void *)p);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# dentry_parent = dentry->d_parent\n");
    d = p->dentry;
    printk(KERN_INFO "dentry_parent = %lu\n", (void *)&d->d_parent - (void *)d);
    printk(KERN_INFO "# dentry_name = dentry->name (part of embedded d_name)\n");
    printk(KERN_INFO "dentry_name = %lu\n", (void *)&d->d_name.name - (void *)d);
    printk(KERN_INFO "# dentry_inode = dentry->d_inode\n");
    printk(KERN_INFO "dentry_inode = %lu\n", (void *)&d->d_inode - (void *)d);
    printk(KERN_INFO "# inode_mode = inode->i_mode\n");
    i = d->d_inode;
    printk(KERN_INFO "inode_mode = %lu\n", (void *)&i->i_mode - (void *)i);
    printk(KERN_INFO "# inode_ouid = inode->i_uid\n");
    printk(KERN_INFO "inode_ouid = %lu\n", (void *)&i->i_uid - (void *)i);
    printk(KERN_INFO "# inode_ogid = inode->i_gid\n");
    printk(KERN_INFO "inode_ogid = %lu\n", (void *)&i->i_gid - (void *)i);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# mount_mnt = mount->mnt\n");
    m = container_of(p->mnt, struct mount, mnt);
    printk(KERN_INFO "mount_mnt = %lu\n", (void *)&m->mnt - (void *)m);
    printk(KERN_INFO "# mount_parent = mount->mnt_parent\n");
    printk(KERN_INFO "mount_parent = %lu\n", (void *)&m->mnt_parent - (void *)m);
    printk(KERN_INFO "# mount_mountpoint = mount->mnt_mountpoint\n");
    printk(KERN_INFO "mount_mountpoint = %lu\n", (void *)&m->mnt_mountpoint - (void *)m);
    printk(KERN_INFO "\n");
    printk(KERN_INFO "# max_fds = task_struct->files->fdt->max_fds\n");
    files = ts->files;
    fdtable = files->fdt;
    printk(KERN_INFO "max_fds = %lu, %lu, %lu\n", (void *)&ts->files - (void *)ts, (void *)&files->fdt - (void *)files, (void *)&fdtable->max_fds - (void *)fdtable);
    printk(KERN_INFO "# fd_table = task_struct->files->fdt->fd\n");
    printk(KERN_INFO "fd_table = %lu, %lu, %lu\n", (void *)&ts->files - (void *)ts, (void *)&files->fdt - (void *)files, (void *)&fdtable->fd - (void *)fdtable);
    printk(KERN_INFO "# fd_path = file.f_path\n");
    printk(KERN_INFO "fd_path = %lu\n", (void *)&f->f_path - (void *)f);
    printk(KERN_INFO "\n\n");
    return 0;
}

static void __exit get_offsets_exit(void) {
    printk(KERN_INFO "get_offsets unloaded\n");
}

module_init(get_offsets_init);
module_exit(get_offsets_exit);

