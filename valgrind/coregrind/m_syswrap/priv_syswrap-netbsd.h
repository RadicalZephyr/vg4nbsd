
/*--------------------------------------------------------------------*/
/*--- Linux-specific syscalls stuff.          priv_syswrap-linux.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Nicholas Nethercote
      njn@valgrind.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __PRIV_SYSWRAP_LINUX_H
#define __PRIV_SYSWRAP_LINUX_H

/* requires #include "priv_types_n_macros.h" */

// Run a thread from beginning to end. 
extern VgSchedReturnCode VG_(thread_wrapper)(Word /*ThreadId*/ tid);
DECL_TEMPLATE(netbsdelf2, sys_set_tid_address);
DECL_TEMPLATE(netbsdelf2, sys_exit_group);
DECL_TEMPLATE(netbsdelf2, sys_mount);
DECL_TEMPLATE(netbsdelf2, sys_oldumount)
DECL_TEMPLATE(netbsdelf2, sys_umount)
DECL_TEMPLATE(netbsdelf2, sys_llseek)
DECL_TEMPLATE(netbsdelf2, sys_setfsuid16)
DECL_TEMPLATE(netbsdelf2, sys_setfsuid)
DECL_TEMPLATE(netbsdelf2, sys_setfsgid16)
DECL_TEMPLATE(netbsdelf2, sys_setfsgid)
DECL_TEMPLATE(netbsdelf2, sys_setresuid16)
DECL_TEMPLATE(netbsdelf2, sys_setresuid)
DECL_TEMPLATE(netbsdelf2, sys_getresuid16)
DECL_TEMPLATE(netbsdelf2, sys_getresuid)
DECL_TEMPLATE(netbsdelf2, sys_setresgid16)
DECL_TEMPLATE(netbsdelf2, sys_setresgid)
DECL_TEMPLATE(netbsdelf2, sys_getresgid16)
DECL_TEMPLATE(netbsdelf2, sys_getresgid)
DECL_TEMPLATE(netbsdelf2, sys_ioperm)
DECL_TEMPLATE(netbsdelf2, sys_syslog)
DECL_TEMPLATE(netbsdelf2, sys_vhangup)
DECL_TEMPLATE(netbsdelf2, sys_sysinfo)
DECL_TEMPLATE(netbsdelf2, sys_personality)
DECL_TEMPLATE(netbsdelf2, sys_sysctl)
DECL_TEMPLATE(netbsdelf2, sys_prctl)
DECL_TEMPLATE(netbsdelf2, sys_sendfile)
DECL_TEMPLATE(netbsdelf2, sys_sendfile64)
DECL_TEMPLATE(netbsdelf2, sys_futex)
DECL_TEMPLATE(netbsdelf2, sys_epoll_create)
DECL_TEMPLATE(netbsdelf2, sys_epoll_ctl)
DECL_TEMPLATE(netbsdelf2, sys_epoll_wait)
DECL_TEMPLATE(netbsdelf2, sys_gettid)
DECL_TEMPLATE(netbsdelf2, sys_tgkill)
DECL_TEMPLATE(netbsdelf2, sys_fadvise64)
DECL_TEMPLATE(netbsdelf2, sys_fadvise64_64)
DECL_TEMPLATE(netbsdelf2, sys_io_setup)
DECL_TEMPLATE(netbsdelf2, sys_io_destroy)
DECL_TEMPLATE(netbsdelf2, sys_io_getevents)
DECL_TEMPLATE(netbsdelf2, sys_io_submit)
DECL_TEMPLATE(netbsdelf2, sys_io_cancel)

#endif   // __PRIV_SYSWRAP_LINUX_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
