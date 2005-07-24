
/*--------------------------------------------------------------------*/
/*--- NetBSD-specific syscalls stuff.        priv_syswrap-netbsd.h ---*/
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

#ifndef __PRIV_SYSWRAP_NETBSD_H
#define __PRIV_SYSWRAP_NETBSD_H

/* requires #include "priv_types_n_macros.h" */

// Run a thread from beginning to end. 
extern VgSchedReturnCode VG_(thread_wrapper)(Word /*ThreadId*/ tid);
DECL_TEMPLATE(netbsdelf2, sys_set_tid_address);
DECL_TEMPLATE(netbsdelf2, sys_exit_group);
DECL_TEMPLATE(netbsdelf2, sys_mount);
DECL_TEMPLATE(netbsdelf2, sys_unmount);
DECL_TEMPLATE(netbsdelf2, sys_setfsuid16);
DECL_TEMPLATE(netbsdelf2, sys_setfsuid);
DECL_TEMPLATE(netbsdelf2, sys_setfsgid16);
DECL_TEMPLATE(netbsdelf2, sys_setfsgid);
DECL_TEMPLATE(netbsdelf2, sys_setresuid16);
DECL_TEMPLATE(netbsdelf2, sys_setresuid);
DECL_TEMPLATE(netbsdelf2, sys_getresuid16);
DECL_TEMPLATE(netbsdelf2, sys_getresuid);
DECL_TEMPLATE(netbsdelf2, sys_setresgid16);
DECL_TEMPLATE(netbsdelf2, sys_setresgid);
DECL_TEMPLATE(netbsdelf2, sys_getresgid16);
DECL_TEMPLATE(netbsdelf2, sys_getresgid);
DECL_TEMPLATE(netbsdelf2, sys_ioperm);
DECL_TEMPLATE(netbsdelf2, sys_syslog);
DECL_TEMPLATE(netbsdelf2, sys_vhangup);
DECL_TEMPLATE(netbsdelf2, sys_sysinfo);
DECL_TEMPLATE(netbsdelf2, sys_personality);
DECL_TEMPLATE(netbsdelf2, sys_sysctl);
DECL_TEMPLATE(netbsdelf2, sys_prctl);
DECL_TEMPLATE(netbsdelf2, sys_futex);
DECL_TEMPLATE(netbsdelf2, sys_epoll_create);
DECL_TEMPLATE(netbsdelf2, sys_epoll_ctl);
DECL_TEMPLATE(netbsdelf2, sys_epoll_wait);
DECL_TEMPLATE(netbsdelf2, sys_gettid);
DECL_TEMPLATE(netbsdelf2, sys_tgkill);
DECL_TEMPLATE(netbsdelf2, sys_io_setup);
DECL_TEMPLATE(netbsdelf2, sys_io_destroy);
DECL_TEMPLATE(netbsdelf2, sys_io_getevents);
DECL_TEMPLATE(netbsdelf2, sys_io_submit);
DECL_TEMPLATE(netbsdelf2, sys_io_cancel);
DECL_TEMPLATE(netbsdelf2, sys_getfsstat);
DECL_TEMPLATE(netbsdelf2, sys_chflags);
DECL_TEMPLATE(netbsdelf2, sys_fchflags);
DECL_TEMPLATE(netbsdelf2, sys_compat_stat);
DECL_TEMPLATE(netbsdelf2, sys_compat_lstat);
DECL_TEMPLATE(netbsdelf2, sys_compat_sigaction);
DECL_TEMPLATE(netbsdelf2, sys_compat_sigprocmask);
DECL_TEMPLATE(netbsdelf2, sys_compat_sigpending);
DECL_TEMPLATE(netbsdelf2, sys_compat_sigaltstack);
DECL_TEMPLATE(netbsdelf2, sys_getlogin);
DECL_TEMPLATE(netbsdelf2, sys_setlogin);
DECL_TEMPLATE(netbsdelf2, sys_revoke);
DECL_TEMPLATE(netbsdelf2, sys_compat_uname);
DECL_TEMPLATE(netbsdelf2, sys_recvmsg);
DECL_TEMPLATE(netbsdelf2, sys_sendmsg);
DECL_TEMPLATE(netbsdelf2, sys_accept);
DECL_TEMPLATE(netbsdelf2, sys_getpeername);
DECL_TEMPLATE(netbsdelf2, sys_getsockname);

#endif   // __PRIV_SYSWRAP_NETBSD_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
