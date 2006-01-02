
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

// Clone-related functions
extern Word ML_(start_thread_NORETURN) ( void* arg );
extern Addr ML_(allocstack)            ( ThreadId tid );
extern void ML_(call_on_new_stack_0_1) ( Addr stack, Addr retaddr,
			                 void (*f)(Word), Word arg1 );
extern SysRes ML_(do_fork_clone) ( ThreadId tid, UInt flags,
                                   Int* parent_tidptr, Int* child_tidptr );

extern VgSchedReturnCode ML_(thread_wrapper)(Word /*ThreadId*/ tid);
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
DECL_TEMPLATE(netbsdelf2, sys_io_setup);
DECL_TEMPLATE(netbsdelf2, sys_io_destroy);
DECL_TEMPLATE(netbsdelf2, sys_io_getevents);
DECL_TEMPLATE(netbsdelf2, sys_io_submit);
DECL_TEMPLATE(netbsdelf2, sys_io_cancel);
DECL_TEMPLATE(netbsdelf2, sys_getfsstat);
DECL_TEMPLATE(netbsdelf2, sys_chflags);
DECL_TEMPLATE(netbsdelf2, sys_fchflags);
DECL_TEMPLATE(netbsdelf2, sys_compat_stat);
DECL_TEMPLATE(netbsdelf2, sys_compat_fstat);
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
DECL_TEMPLATE(netbsdelf2, sys_compat_orecvmsg);
DECL_TEMPLATE(netbsdelf2, sys_sendmsg);
DECL_TEMPLATE(netbsdelf2, sys_compat_osendmsg);
DECL_TEMPLATE(netbsdelf2, sys_accept);
DECL_TEMPLATE(netbsdelf2, sys_socket);
DECL_TEMPLATE(netbsdelf2, sys_connect);
DECL_TEMPLATE(netbsdelf2, sys_bind);
DECL_TEMPLATE(netbsdelf2, sys_setsockopt);
DECL_TEMPLATE(netbsdelf2, sys_getsockopt);
DECL_TEMPLATE(netbsdelf2, sys_listen);
DECL_TEMPLATE(netbsdelf2, sys_compat_oaccept);
DECL_TEMPLATE(netbsdelf2, sys_compat_osend);
DECL_TEMPLATE(netbsdelf2, sys_compat_orecv);
DECL_TEMPLATE(netbsdelf2, sys_getpeername);
DECL_TEMPLATE(netbsdelf2, sys_getsockname);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogetsockname);
DECL_TEMPLATE(netbsdelf2, sys_ni_syscall);
DECL_TEMPLATE(netbsdelf2, sys_vfork);
DECL_TEMPLATE(netbsdelf2, sys_munmap);
DECL_TEMPLATE(netbsdelf2, sys_mprotect);
DECL_TEMPLATE(netbsdelf2, sys_madvise);
DECL_TEMPLATE(netbsdelf2, sys_recvfrom);
DECL_TEMPLATE(netbsdelf2, sys_socketpair);
DECL_TEMPLATE(netbsdelf2, sys_compat_orecvfrom);
DECL_TEMPLATE(netbsdelf2, sys_compat_owait);
DECL_TEMPLATE(netbsdelf2, sys_compat_oswapon);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogethostname);
DECL_TEMPLATE(netbsdelf2, sys_compat_osethostname);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogetdtablesize);
DECL_TEMPLATE(netbsdelf2, sys_compat_otruncate);
DECL_TEMPLATE(netbsdelf2, sys_compat_oftruncate);
DECL_TEMPLATE(netbsdelf2, sys_mkfifo);
DECL_TEMPLATE(netbsdelf2, sys_sendto);
DECL_TEMPLATE(netbsdelf2, sys_shutdown);
DECL_TEMPLATE(netbsdelf2, sys_adjtime);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogetpeername);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogethostid);
DECL_TEMPLATE(netbsdelf2, sys_compat_osethostid);
DECL_TEMPLATE(netbsdelf2, sys_compat_okillpg);
DECL_TEMPLATE(netbsdelf2, sys_compat_oquota);
DECL_TEMPLATE(netbsdelf2, sys_nfssvc);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogetdirentries);
DECL_TEMPLATE(netbsdelf2, sys_compat_getdirentries);
DECL_TEMPLATE(netbsdelf2, sys_getfh);
DECL_TEMPLATE(netbsdelf2, sys_compat_ogetdomainname);
DECL_TEMPLATE(netbsdelf2, sys_compat_osetdomainname);
DECL_TEMPLATE(netbsdelf2, sys_sysarch);
DECL_TEMPLATE(netbsdelf2, sys_pread);
DECL_TEMPLATE(netbsdelf2, sys_pwrite);
DECL_TEMPLATE(netbsdelf2, sys_ntp_gettime);
DECL_TEMPLATE(netbsdelf2, sys_ntp_adjtime);
DECL_TEMPLATE(netbsdelf2, sys_setegid);
DECL_TEMPLATE(netbsdelf2, sys_seteuid);
DECL_TEMPLATE(netbsdelf2, sys_lfs_bmapv);
DECL_TEMPLATE(netbsdelf2, sys_lfs_markv);
DECL_TEMPLATE(netbsdelf2, sys_lfs_segclean);
DECL_TEMPLATE(netbsdelf2, sys_lfs_segwait);
DECL_TEMPLATE(netbsdelf2, sys_pathconf);
DECL_TEMPLATE(netbsdelf2, sys_fpathconf);
DECL_TEMPLATE(netbsdelf2, sys_undelete);
DECL_TEMPLATE(netbsdelf2, sys_futimes);
DECL_TEMPLATE(netbsdelf2, sys_swapctl);
DECL_TEMPLATE(netbsdelf2, sys_preadv);
DECL_TEMPLATE(netbsdelf2, sys_pwritev);
DECL_TEMPLATE(netbsdelf2, sys_fchroot);
DECL_TEMPLATE(netbsdelf2, sys_fhopen);
DECL_TEMPLATE(netbsdelf2, sys_fhstat);
DECL_TEMPLATE(netbsdelf2, sys_fhstatfs);
DECL_TEMPLATE(netbsdelf2, sys_issetugid);
DECL_TEMPLATE(netbsdelf2, sys_kqueue);
DECL_TEMPLATE(netbsdelf2, sys_kevent);
DECL_TEMPLATE(netbsdelf2, sys_fsync_range);
DECL_TEMPLATE(netbsdelf2, sys_uuidgen);

#endif   // __PRIV_SYSWRAP_NETBSD_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
