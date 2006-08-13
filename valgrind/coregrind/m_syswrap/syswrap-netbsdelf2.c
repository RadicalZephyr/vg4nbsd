
/*--------------------------------------------------------------------*/
/*--- NetBSD-specific syscalls, etc.          syswrap-netbsdelf2.c ---*/
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

#include "pub_core_basics.h"
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"     // Needed for pub_core_aspacemgr :(
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_mallocfree.h"
#include "pub_core_tooliface.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"
#include "priv_syswrap-netbsd.h"

#include "vki_unistd.h"

// Run a thread from beginning to end and return the thread's
// scheduler-return-code.
static VgSchedReturnCode thread_wrapper(Word /*ThreadId*/ tidW)
{
   VgSchedReturnCode ret;
   ThreadId     tid = (ThreadId)tidW;
   ThreadState* tst = VG_(get_ThreadState)(tid);

   VG_(debugLog)(1, "syswrap-netbsdelf2", 
                    "thread_wrapper(tid=%lld): entry\n", 
                    (ULong)tidW);

   vg_assert(tst->status == VgTs_Init);

   /* make sure we get the CPU lock before doing anything significant */
   VG_(set_running)(tid);

   if (1)
      VG_(printf)("thread tid %d started: stack = %p\n",
		  tid, &tid);

   VG_TRACK ( post_thread_create, tst->os_state.parent, tid );

   tst->os_state.lwpid = VG_(gettid)();
   tst->os_state.threadgroup = VG_(getpid)();

   /* Thread created with all signals blocked; scheduler will set the
      appropriate mask */

   ret = VG_(scheduler)(tid);

   vg_assert(VG_(is_exiting)(tid));
   
   vg_assert(tst->status == VgTs_Runnable);
   vg_assert(VG_(is_running_thread)(tid));

   VG_(debugLog)(1, "syswrap-netbsdelf2", 
                    "thread_wrapper(tid=%lld): exit\n", 
                    (ULong)tidW);

   /* Return to caller, still holding the lock. */
   return ret;
}

static void run_a_thread_NORETURN ( Word tidW )
{
	VG_(printf)("in run a thread_noreturn\n");
   ThreadId tid = (ThreadId)tidW;
   VgSchedReturnCode src;
Int c;
   VG_(debugLog)(1, "syswrap-netbsd", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper_NORETURN) called\n",
                       (ULong)tidW);

   /* Run the thread all the way through. */
src = thread_wrapper(tid);

   VG_(debugLog)(1, "syswrap-netbsd", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper) done\n",
                       (ULong)tidW);

   c = VG_(count_living_threads)();
   vg_assert(c >= 1); /* stay sane */

   if (c == 1) {

      VG_(debugLog)(1, "syswrap-netbsd", 
                       "run_a_thread_NORETURN(tid=%lld): "
                          "last one standing\n",
                          (ULong)tidW);

      /* We are the last one standing.  Keep hold of the lock and
         carry on to show final tool results, then exit the entire system. */
      ( * VG_(address_of_m_main_shutdown_actions_NORETURN) ) (tid, src);

   } else {

      VG_(debugLog)(1, "syswrap-netbsd", 
                       "run_a_thread_NORETURN(tid=%lld): "
                          "not last one standing\n",
                          (ULong)tidW);

      /* OK, thread is dead, but others still exist.  Just exit. */
      ThreadState *tst = VG_(get_ThreadState)(tid);

      /* This releases the run lock */
      VG_(exit_thread)(tid);
      vg_assert(tst->status == VgTs_Zombie);

      /* We have to use this sequence to terminate the thread to
         prevent a subtle race.  If VG_(exit_thread)() had left the
         ThreadState as Empty, then it could have been reallocated,
         reusing the stack while we're doing these last cleanups.
         Instead, VG_(exit_thread) leaves it as Zombie to prevent
         reallocation.  We need to make sure we don't touch the stack
         between marking it Empty and exiting.  Hence the
         assembler. */
      asm volatile (
         "movl	%1, %0\n"	/* set tst->status = VgTs_Empty */
         "movl	%2, %%eax\n"    /* set %eax = __NR_exit */
         "movl	%3, %%ebx\n"    /* set %ebx = tst->os_state.exitcode */
         "int	$0x80\n"	/* exit(tst->os_state.exitcode) */
         : "=m" (tst->status)
         : "n" (VgTs_Empty), "n" (__NR_exit), "m" (tst->os_state.exitcode));

      VG_(core_panic)("Thread exit failed?\n");
   }

   /*NOTREACHED*/
   vg_assert(0);
}
Word ML_(start_thread_NORETURN) ( void* arg )
{
   ThreadState* tst = (ThreadState*)arg;
   ThreadId     tid = tst->tid;

   run_a_thread_NORETURN ( (Word)tid );
   /*NOTREACHED*/
   vg_assert(0);
}

/* Allocate a stack for this thread, if it doesn't already have one.
   They're allocated lazily, and never freed.  Returns the initial stack
   pointer value to use, or 0 if allocation failed. */
Addr ML_(allocstack)(ThreadId tid)
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   VgStack*     stack;
   Addr         initial_SP;

   /* Either the stack_base and stack_init_SP are both zero (in which
      case a stack hasn't been allocated) or they are both non-zero,
      in which case it has. */

   if (tst->os_state.valgrind_stack_base == 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP == 0);

   if (tst->os_state.valgrind_stack_base != 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP != 0);

   /* If no stack is present, allocate one. */

   if (tst->os_state.valgrind_stack_base == 0) {
      stack = VG_(am_alloc_VgStack)( &initial_SP );
      if (stack) {
         tst->os_state.valgrind_stack_base    = (Addr)stack;
         tst->os_state.valgrind_stack_init_SP = initial_SP;
      }
   }

   if (0)
      VG_(printf)( "stack for tid %d at %p; init_SP=%p\n",
                   tid, 
                   (void*)tst->os_state.valgrind_stack_base, 
                   (void*)tst->os_state.valgrind_stack_init_SP );
                  
   return tst->os_state.valgrind_stack_init_SP;
}

/* Allocate a stack for the main thread, and run it all the way to the
   end.  Although we already have a working VgStack
   (VG_(interim_stack)) it's better to allocate a new one, so that
   overflow detection works uniformly for all threads.
*/
void VG_(main_thread_wrapper_NORETURN)(ThreadId tid)
{
   Addr sp;
   VG_(debugLog)(1, "syswrap-linux", 
                    "entering VG_(main_thread_wrapper_NORETURN)\n");

   sp = ML_(allocstack)(tid);

#if defined(VGP_ppc32_linux)
   /* make a stack frame */
   sp -= 16;
   sp &= ~0xF;
   *(UWord *)sp = 0;
#endif

   /* If we can't even allocate the first thread's stack, we're hosed.
      Give up. */
   vg_assert2(sp != 0, "Cannot allocate main thread's stack.");

   /* shouldn't be any other threads around yet */
   vg_assert( VG_(count_living_threads)() == 1 );

   ML_(call_on_new_stack_0_1)( 
      (Addr)sp,               /* stack */
      0,                      /* bogus return address */
      run_a_thread_NORETURN,  /* fn to call */
      (Word)tid               /* arg to give it */
   );

   /*NOTREACHED*/
   vg_assert(0);
}


SysRes ML_(do_fork_clone) ( ThreadId tid, UInt flags,
                            Int* parent_tidptr, Int* child_tidptr )
{
	I_die_here;
}

/* ---------------------------------------------------------------------
   PRE/POST wrappers for arch-specific, NetBSD-specific syscalls
   ------------------------------------------------------------------ */

// Nb: See the comment above the generic PRE/POST wrappers in
// m_syswrap/syswrap-generic.c for notes about how they work.

// XXX: Shouldn't these be factored out or sth?  It seems silly to
// redefine them in every single arch-specific C file, and in the generic
// file as well

#define PRE(name)       DEFN_PRE_TEMPLATE(netbsdelf2, name)
#define POST(name)      DEFN_POST_TEMPLATE(netbsdelf2, name)

PRE(sys_ni_syscall)
{
   PRINT("non-existent syscall! (ni_syscall)");
   PRE_REG_READ0(long, "ni_syscall");
   SET_STATUS_Failure( VKI_ENOSYS );
}

PRE(sys_set_tid_address)
{
   PRINT("sys_set_tid_address ( %p )", ARG1);
   PRE_REG_READ1(long, "set_tid_address", int *, tidptr);
}

PRE(sys_exit_group)
{
   ThreadId     t;
   ThreadState* tst;

   PRINT("exit_group( %d )", ARG1);
   PRE_REG_READ1(void, "exit_group", int, exit_code);

   tst = VG_(get_ThreadState)(tid);

   /* A little complex; find all the threads with the same threadgroup
      as this one (including this one), and mark them to exit */
   for (t = 1; t < VG_N_THREADS; t++) {
      if ( /* not alive */
           VG_(threads)[t].status == VgTs_Empty
           ||
	   /* not our group */
           VG_(threads)[t].os_state.threadgroup != tst->os_state.threadgroup
         )
         continue;

      VG_(threads)[t].exitreason = VgSrc_ExitSyscall;
      VG_(threads)[t].os_state.exitcode = ARG1;

      if (t != tid)
	 VG_(kill_thread)(t);	/* unblock it, if blocked */
   }

   /* We have to claim the syscall already succeeded. */
   SET_STATUS_Success(0);
}

PRE(sys_mount)
{
   // Nb: depending on 'flags', the 'type' and 'data' args may be ignored.
   // We are conservative and check everything, except the memory pointed to
   // by 'data'.
   *flags |= SfMayBlock;
   PRINT( "sys_mount( %p, %p, %p, %p, %p )" ,ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "mount",
                 char *, source, char *, target, char *, type,
                 unsigned long, flags, void *, data);
   PRE_MEM_RASCIIZ( "mount(source)", ARG1);
   PRE_MEM_RASCIIZ( "mount(target)", ARG2);
   PRE_MEM_RASCIIZ( "mount(type)", ARG3);
}

PRE(sys_unmount)
{
   PRINT("sys_umount( %p )", ARG1);
   PRE_REG_READ2(long, "umount2", char *, path, int, flags);
   PRE_MEM_RASCIIZ( "umount2(path)", ARG1);
}

//zz PRE(sys_adjtimex, 0)
//zz {
//zz    struct vki_timex *tx = (struct vki_timex *)ARG1;
//zz    PRINT("sys_adjtimex ( %p )", ARG1);
//zz    PRE_REG_READ1(long, "adjtimex", struct timex *, buf);
//zz    PRE_MEM_READ( "adjtimex(timex->modes)", ARG1, sizeof(tx->modes));
//zz
#if 0 //zz  (avoiding warnings about multi-line comments)
zz #define ADJX(bit,field) 				\
zz    if (tx->modes & bit)					\
zz       PRE_MEM_READ( "adjtimex(timex->"#field")",	\
zz 		    (Addr)&tx->field, sizeof(tx->field))
#endif
//zz    ADJX(ADJ_FREQUENCY, freq);
//zz    ADJX(ADJ_MAXERROR, maxerror);
//zz    ADJX(ADJ_ESTERROR, esterror);
//zz    ADJX(ADJ_STATUS, status);
//zz    ADJX(ADJ_TIMECONST, constant);
//zz    ADJX(ADJ_TICK, tick);
//zz #undef ADJX
//zz
//zz    PRE_MEM_WRITE( "adjtimex(timex)", ARG1, sizeof(struct vki_timex));
//zz }
//zz
//zz POST(sys_adjtimex)
//zz {
//zz    POST_MEM_WRITE( ARG1, sizeof(struct vki_timex) );
//zz }

/* Copy from above, maybe? */
PRE(sys_adjtime)
{
    I_die_here;
}

POST(sys_adjtime)
{
    I_die_here;
}

PRE(sys_setfsuid16)
{
   PRINT("sys_setfsuid16 ( %d )", ARG1);
   PRE_REG_READ1(long, "setfsuid16", vki_old_uid_t, uid);
}

PRE(sys_setfsuid)
{
   PRINT("sys_setfsuid ( %d )", ARG1);
   PRE_REG_READ1(long, "setfsuid", vki_uid_t, uid);
}

PRE(sys_setfsgid16)
{
   PRINT("sys_setfsgid16 ( %d )", ARG1);
   PRE_REG_READ1(long, "setfsgid16", vki_old_gid_t, gid);
}

PRE(sys_setfsgid)
{
   PRINT("sys_setfsgid ( %d )", ARG1);
   PRE_REG_READ1(long, "setfsgid", vki_gid_t, gid);
}

PRE(sys_setresuid16)
{
   PRINT("sys_setresuid16 ( %d, %d, %d )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresuid16",
                 vki_old_uid_t, ruid, vki_old_uid_t, euid, vki_old_uid_t, suid);
}

PRE(sys_setresuid)
{
   PRINT("sys_setresuid ( %d, %d, %d )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresuid",
                 vki_uid_t, ruid, vki_uid_t, euid, vki_uid_t, suid);
}

PRE(sys_getresuid16)
{
   PRINT("sys_getresuid16 ( %p, %p, %p )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresuid16",
                 vki_old_uid_t *, ruid, vki_old_uid_t *, euid,
                 vki_old_uid_t *, suid);
   PRE_MEM_WRITE( "getresuid16(ruid)", ARG1, sizeof(vki_old_uid_t) );
   PRE_MEM_WRITE( "getresuid16(euid)", ARG2, sizeof(vki_old_uid_t) );
   PRE_MEM_WRITE( "getresuid16(suid)", ARG3, sizeof(vki_old_uid_t) );
}
POST(sys_getresuid16)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_old_uid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_old_uid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_old_uid_t) );
   }
}

PRE(sys_getresuid)
{
   PRINT("sys_getresuid ( %p, %p, %p )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresuid",
                 vki_uid_t *, ruid, vki_uid_t *, euid, vki_uid_t *, suid);
   PRE_MEM_WRITE( "getresuid(ruid)", ARG1, sizeof(vki_uid_t) );
   PRE_MEM_WRITE( "getresuid(euid)", ARG2, sizeof(vki_uid_t) );
   PRE_MEM_WRITE( "getresuid(suid)", ARG3, sizeof(vki_uid_t) );
}
POST(sys_getresuid)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_uid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_uid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_uid_t) );
   }
}

PRE(sys_setresgid16)
{
   PRINT("sys_setresgid16 ( %d, %d, %d )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresgid16",
                 vki_old_gid_t, rgid,
                 vki_old_gid_t, egid, vki_old_gid_t, sgid);
}

PRE(sys_setresgid)
{
   PRINT("sys_setresgid ( %d, %d, %d )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "setresgid",
                 vki_gid_t, rgid, vki_gid_t, egid, vki_gid_t, sgid);
}

PRE(sys_getresgid16)
{
   PRINT("sys_getresgid16 ( %p, %p, %p )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresgid16",
                 vki_old_gid_t *, rgid, vki_old_gid_t *, egid,
                 vki_old_gid_t *, sgid);
   PRE_MEM_WRITE( "getresgid16(rgid)", ARG1, sizeof(vki_old_gid_t) );
   PRE_MEM_WRITE( "getresgid16(egid)", ARG2, sizeof(vki_old_gid_t) );
   PRE_MEM_WRITE( "getresgid16(sgid)", ARG3, sizeof(vki_old_gid_t) );
}
POST(sys_getresgid16)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_old_gid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_old_gid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_old_gid_t) );
   }
}

PRE(sys_getresgid)
{
   PRINT("sys_getresgid ( %p, %p, %p )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getresgid",
                 vki_gid_t *, rgid, vki_gid_t *, egid, vki_gid_t *, sgid);
   PRE_MEM_WRITE( "getresgid(rgid)", ARG1, sizeof(vki_gid_t) );
   PRE_MEM_WRITE( "getresgid(egid)", ARG2, sizeof(vki_gid_t) );
   PRE_MEM_WRITE( "getresgid(sgid)", ARG3, sizeof(vki_gid_t) );
}

POST(sys_getresgid)
{
   vg_assert(SUCCESS);
   if (RES == 0) {
      POST_MEM_WRITE( ARG1, sizeof(vki_gid_t) );
      POST_MEM_WRITE( ARG2, sizeof(vki_gid_t) );
      POST_MEM_WRITE( ARG3, sizeof(vki_gid_t) );
   }
}

PRE(sys_ioperm)
{
   PRINT("sys_ioperm ( %d, %d, %d )", ARG1, ARG2, ARG3 );
   PRE_REG_READ3(long, "ioperm",
                 unsigned long, from, unsigned long, num, int, turn_on);
}
PRE(sys_vfork)
{ 
	I_die_here;
}
PRE(sys_mprotect){
	I_die_here;
}
PRE(sys_madvise){
	I_die_here;
}

PRE(sys_recvmsg)
{
   I_die_here;
}

POST(sys_recvmsg)
{
   I_die_here;
}

PRE(sys_compat_orecvmsg)
{
   I_die_here;
}

POST(sys_compat_orecvmsg)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_sendmsg)
{
   I_die_here;
}

PRE(sys_compat_osendmsg)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_accept)
{
   I_die_here;
}

POST(sys_accept)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_bind)
{
   I_die_here;
}

POST(sys_bind)
{
   I_die_here;
}

/* From sys_socketcall? */
PRE(sys_setsockopt)
{
   I_die_here;
}

/* From sys_socketcall? */
PRE(sys_getsockopt)
{
   I_die_here;
}

POST(sys_getsockopt)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_listen)
{
   I_die_here;
}

POST(sys_listen)
{
   I_die_here;
}


/* Maybe this can be simply a call to sys_accept instead? */
PRE(sys_compat_oaccept)
{
   I_die_here;
}

POST(sys_compat_oaccept)
{
   I_die_here;
}

/* Same here, maybe we can just call sys_send? */
PRE(sys_compat_osend)
{
   I_die_here;
}

/* ?? */
PRE(sys_compat_orecv)
{
   I_die_here;
}

POST(sys_compat_orecv)
{
   I_die_here;
}


/* From sys_socketcall */
PRE(sys_socket)
{
   I_die_here;
}

POST(sys_socket)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_connect)
{
   I_die_here;
}

POST(sys_connect)
{
   I_die_here;
}

/* From sys_socketcall */
PRE(sys_getpeername)
{
   I_die_here;
}

POST(sys_getpeername)
{
   I_die_here;
}

PRE(sys_compat_ogetpeername)
{
   I_die_here;
}

POST(sys_compat_ogetpeername)
{
   I_die_here;
}


/* From sys_socketcall */
PRE(sys_getsockname)
{
   I_die_here;
}

POST(sys_getsockname)
{
   I_die_here;
}

PRE(sys_compat_ogetsockname)
{
   I_die_here;
}

POST(sys_compat_ogetsockname)
{
   I_die_here;
}


PRE(sys_syslog)
{
   *flags |= SfMayBlock;
   PRINT("sys_syslog (%d, %p, %d)", ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "syslog", int, type, char *, bufp, int, len);
   switch (ARG1) {
   // The kernel uses magic numbers here, rather than named constants,
   // therefore so do we.
   case 2: case 3: case 4:
      PRE_MEM_WRITE( "syslog(bufp)", ARG2, ARG3);
      break;
   default:
      break;
   }
}

POST(sys_syslog)
{
   switch (ARG1) {
   case 2: case 3: case 4:
      POST_MEM_WRITE( ARG2, ARG3 );
      break;
   default:
      break;
   }
}

PRE(sys_vhangup)
{
   PRINT("sys_vhangup ( )");
   PRE_REG_READ0(long, "vhangup");
}

PRE(sys_sysinfo)
{
/*    PRINT("sys_sysinfo ( %p )",ARG1); */
/*    PRE_REG_READ1(long, "sysinfo", struct sysinfo *, info); */
/*    PRE_MEM_WRITE( "sysinfo(info)", ARG1, sizeof(struct vki_sysinfo) ); */
	I_die_here;
}

POST(sys_sysinfo)
{
 /*   POST_MEM_WRITE( ARG1, sizeof(struct vki_sysinfo) ); */
	I_die_here;
}

PRE(sys_personality)
{
   PRINT("sys_personality ( %llu )", (ULong)ARG1);
   PRE_REG_READ1(long, "personality", vki_u_long, persona);
}

PRE(sys_sysctl)
{
/*     struct __vki_sysctl_args *args; */
/*    PRINT("sys_sysctl ( %p )", ARG1 ); */
/*    args = (struct __vki_sysctl_args *)ARG1; */
/*    PRE_REG_READ1(long, "sysctl", struct __sysctl_args *, args); */
/*    PRE_MEM_WRITE( "sysctl(args)", ARG1, sizeof(struct __vki_sysctl_args) ); */
/*    if (!VG_(is_addressable)(ARG1, sizeof(struct __vki_sysctl_args), VKI_PROT_READ)) { */
/*       SET_STATUS_Failure( VKI_EFAULT ); */
/*       return; */
/*    } */

/*    PRE_MEM_READ("sysctl(name)", (Addr)args->name, args->nlen * sizeof(*args->name)); */
/*    if (args->newval != NULL) */
/*       PRE_MEM_READ("sysctl(newval)", (Addr)args->newval, args->newlen); */
/*    if (args->oldlenp != NULL) { */
/*       PRE_MEM_READ("sysctl(oldlenp)", (Addr)args->oldlenp, sizeof(*args->oldlenp)); */
/*       PRE_MEM_WRITE("sysctl(oldval)", (Addr)args->oldval, *args->oldlenp); */
/*    } */
 	PRINT("__sysctl(%p , %d , %p, %p, %p, %d)",
 	      ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);

	PRE_MEM_READ("sysctl(name)", (Addr)ARG1, ARG2 * sizeof(int));

/*	We don't know the type that it will return, therefore */
/*	if (ARG5 != NULL)
	PRE_MEM_READ("sysctl(newp)", (Addr)ARG5, ARG6);*/
/*	if (ARG3 == null)
		PRE_MEM_READ("sysctl(oldp)", (Addr)ARG3, ARG4); */
/* 	I_die_here; */
}

POST(sys_sysctl)
{
/*    struct __vki_sysctl_args *args; */
/*    args = (struct __vki_sysctl_args *)ARG1; */
/*    if (args->oldlenp != NULL) { */
/*       POST_MEM_WRITE((Addr)args->oldlenp, sizeof(*args->oldlenp)); */
/*       POST_MEM_WRITE((Addr)args->oldval, 1 + *args->oldlenp); */
/*    } */
	//I_die_here;
}

PRE(sys_prctl)
{
   *flags |= SfMayBlock;
   PRINT( "prctl ( %d, %d, %d, %d, %d )", ARG1, ARG2, ARG3, ARG4, ARG5 );
   // XXX: too simplistic, often not all args are used
   // Nb: can't use "ARG2".."ARG5" here because that's our own macro...
   PRE_REG_READ5(long, "prctl",
                 int, option, unsigned long, arg2, unsigned long, arg3,
                 unsigned long, arg4, unsigned long, arg5);
   // XXX: totally wrong... we need to look at the 'option' arg, and do
   // PRE_MEM_READs/PRE_MEM_WRITEs as necessary...
}

// Nb: this wrapper has to pad/unpad memory around the syscall itself,
// and this allows us to control exactly the code that gets run while
// the padding is in place.
PRE(sys_io_setup)
{
   PRINT("sys_io_setup ( %u, %p )", ARG1,ARG2);
   PRE_REG_READ2(long, "io_setup",
                 unsigned, nr_events, vki_aio_context_t *, ctxp);
   PRE_MEM_WRITE( "io_setup(ctxp)", ARG2, sizeof(vki_aio_context_t) );
}
POST(sys_io_setup)
{
   SizeT size;
   struct vki_aio_ring *r;
           
   size = VG_PGROUNDUP(sizeof(struct vki_aio_ring) +
                       ARG1*sizeof(struct vki_io_event));
   r = *(struct vki_aio_ring **)ARG2;
   vg_assert(ML_(valid_client_addr)((Addr)r, size, tid, "io_setup"));

   ML_(notify_aspacem_and_tool_of_mmap)( (Addr)r, size,
                                         VKI_PROT_READ | VKI_PROT_WRITE,
                                         VKI_MAP_ANONYMOUS, -1, 0 );

   POST_MEM_WRITE( ARG2, sizeof(vki_aio_context_t) );
}

// Nb: This wrapper is "Special" because we need 'size' to do the unmap
// after the syscall.  We must get 'size' from the aio_ring structure,
// before the syscall, while the aio_ring structure still exists.  (And we
// know that we must look at the aio_ring structure because Tom inspected the
// kernel and glibc sources to see what they do, yuk.)
//
// XXX This segment can be implicitly unmapped when aio
// file-descriptors are closed...
PRE(sys_io_destroy)
{
   struct vki_aio_ring *r;
   SizeT size;
      
   PRINT("sys_io_destroy ( %llu )", (ULong)ARG1);
   PRE_REG_READ1(long, "io_destroy", vki_aio_context_t, ctx);

   // If we are going to seg fault (due to a bogus ARG1) do it as late as
   // possible...
   r = (struct vki_aio_ring *)ARG1;
   size = VG_PGROUNDUP(sizeof(struct vki_aio_ring) + 
                       r->nr*sizeof(struct vki_io_event));

   SET_STATUS_from_SysRes( VG_(do_syscall1)(SYSNO, ARG1) );

   if (SUCCESS && RES == 0) { 
      Bool d = VG_(am_notify_munmap)( ARG1, size );
      VG_TRACK( die_mem_munmap, ARG1, size );
      if (d)
         VG_(discard_translations)( (Addr64)ARG1, (ULong)size, 
                                    "PRE(sys_io_destroy)" );
   }  
}  

PRE(sys_io_getevents)
{
   *flags |= SfMayBlock;
   PRINT("sys_io_getevents ( %llu, %lld, %lld, %p, %p )",
         (ULong)ARG1,(Long)ARG2,(Long)ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "io_getevents",
                 vki_aio_context_t, ctx_id, long, min_nr, long, nr,
                 struct io_event *, events,
                 struct timespec *, timeout);
   if (ARG3 > 0)
      PRE_MEM_WRITE( "io_getevents(events)",
                     ARG4, sizeof(struct vki_io_event)*ARG3 );
   if (ARG5 != 0)
      PRE_MEM_READ( "io_getevents(timeout)",
                    ARG5, sizeof(struct vki_timespec));
}
POST(sys_io_getevents)
{
   Int i;
   vg_assert(SUCCESS);
   if (RES > 0) {
      POST_MEM_WRITE( ARG4, sizeof(struct vki_io_event)*RES );
      for (i = 0; i < RES; i++) {
         const struct vki_io_event *vev = ((struct vki_io_event *)ARG4) + i;
         const struct vki_iocb *cb = (struct vki_iocb *)(Addr)vev->obj;

         switch (cb->aio_lio_opcode) {
         case VKI_IOCB_CMD_PREAD:
            if (vev->result > 0)
               POST_MEM_WRITE( cb->aio_buf, vev->result );
            break;
            
         case VKI_IOCB_CMD_PWRITE:
            break;
           
         default:
            VG_(message)(Vg_DebugMsg,
                        "Warning: unhandled io_getevents opcode: %u\n",
                        cb->aio_lio_opcode);
            break;
         }
      }
   }
}

PRE(sys_io_submit)
{
   Int i;

   PRINT("sys_io_submit ( %llu, %lld, %p )", (ULong)ARG1,(Long)ARG2,ARG3);
   PRE_REG_READ3(long, "io_submit",
                 vki_aio_context_t, ctx_id, long, nr,
                 struct iocb **, iocbpp);
   PRE_MEM_READ( "io_submit(iocbpp)", ARG3, ARG2*sizeof(struct vki_iocb *) );
   if (ARG3 != 0) {
      for (i = 0; i < ARG2; i++) {
         struct vki_iocb *cb = ((struct vki_iocb **)ARG3)[i];
         PRE_MEM_READ( "io_submit(iocb)", (Addr)cb, sizeof(struct vki_iocb) );
         switch (cb->aio_lio_opcode) {
         case VKI_IOCB_CMD_PREAD:
            PRE_MEM_WRITE( "io_submit(PREAD)", cb->aio_buf, cb->aio_nbytes );
            break;

         case VKI_IOCB_CMD_PWRITE:
            PRE_MEM_READ( "io_submit(PWRITE)", cb->aio_buf, cb->aio_nbytes );
            break;
           
         default:
            VG_(message)(Vg_DebugMsg,"Warning: unhandled io_submit opcode: %u\n",
                         cb->aio_lio_opcode);
            break;
         }
      }
   }
}

PRE(sys_io_cancel)
{
   PRINT("sys_io_cancel ( %llu, %p, %p )", (ULong)ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "io_cancel",
                 vki_aio_context_t, ctx_id, struct iocb *, iocb,
                 struct io_event *, result);
   PRE_MEM_READ( "io_cancel(iocb)", ARG2, sizeof(struct vki_iocb) );
   PRE_MEM_WRITE( "io_cancel(result)", ARG3, sizeof(struct vki_io_event) );
}

POST(sys_io_cancel)
{
   POST_MEM_WRITE( ARG3, sizeof(struct vki_io_event) );
}

PRE(sys_getfsstat)
{
   I_die_here;
}

POST(sys_getfsstat)
{
   I_die_here;
}

PRE(sys_chflags)
{
   I_die_here;
}

PRE(sys_fchflags)
{
   I_die_here;
}

PRE(sys_compat_stat)
{
   I_die_here;
}

POST(sys_compat_stat)
{
   I_die_here;
}

PRE(sys_compat_fstat)
{
   I_die_here;
}

POST(sys_compat_fstat)
{
   I_die_here;
}

PRE(sys_compat_lstat)
{
   I_die_here;
}

POST(sys_compat_lstat)
{
   I_die_here;
}

PRE(sys_compat_sigaction)
{
   I_die_here;
}

POST(sys_compat_sigaction)
{
   I_die_here;
}

PRE(sys_compat_sigprocmask)
{
   I_die_here;
}

POST(sys_compat_sigprocmask)
{
   I_die_here;
}

PRE(sys_compat_sigpending)
{
   I_die_here;
}

POST(sys_compat_sigpending)
{
   I_die_here;
}

PRE(sys_compat_sigaltstack)
{
   I_die_here;
}

POST(sys_compat_sigaltstack)
{
   I_die_here;
}

PRE(sys_getlogin)
{
   I_die_here;
}

PRE(sys_setlogin)
{
   I_die_here;
}

PRE(sys_revoke)
{
   I_die_here;
}

PRE(sys_compat_uname)
{
   I_die_here;
}

POST(sys_compat_uname)
{
   I_die_here;
}

PRE(sys_recvfrom)
{
   I_die_here;
}

POST(sys_recvfrom)
{
   I_die_here;
}

PRE(sys_compat_orecvfrom)
{
   I_die_here;
}

POST(sys_compat_orecvfrom)
{
   I_die_here;
}

PRE(sys_compat_owait)
{
   I_die_here;
}

POST(sys_compat_owait)
{
   I_die_here;
}

PRE(sys_compat_oswapon)
{
   I_die_here;
}

PRE(sys_compat_ogethostname)
{
   I_die_here;
}

POST(sys_compat_ogethostname)
{
   I_die_here;
}

PRE(sys_compat_osethostname)
{
   I_die_here;
}

PRE(sys_compat_ogetdtablesize)
{
   I_die_here;
}

PRE(sys_compat_otruncate)
{
   I_die_here;
}

PRE(sys_compat_oftruncate)
{
   I_die_here;
}

PRE(sys_mkfifo)
{
   I_die_here;
}

PRE(sys_sendto)
{
   I_die_here;
}

/* Hint: Look at sys_close */
PRE(sys_shutdown)
{
   I_die_here;
}

POST(sys_shutdown)
{
   I_die_here;
}

/* Hint: Look at sys_open */
PRE(sys_socketpair)
{
   I_die_here;
}

POST(sys_socketpair)
{
   I_die_here;
}

PRE(sys_compat_ogethostid)
{
   I_die_here;
}

POST(sys_compat_ogethostid)
{
   I_die_here;
}

PRE(sys_compat_osethostid)
{
   I_die_here;
}

PRE(sys_compat_okillpg)
{
   I_die_here;
}

// ??
PRE(sys_compat_oquota)
{
   I_die_here;
}

PRE(sys_nfssvc)
{
   I_die_here;
}

POST(sys_nfssvc)
{
   I_die_here;
}

PRE(sys_compat_ogetdirentries)
{
   I_die_here;
}

POST(sys_compat_ogetdirentries)
{
   I_die_here;
}

PRE(sys_compat_getdirentries)
{
   I_die_here;
}

POST(sys_compat_getdirentries)
{
   I_die_here;
}

PRE(sys_getfh)
{
   I_die_here;
}

POST(sys_getfh)
{
   I_die_here;
}

PRE(sys_compat_ogetdomainname)
{
   I_die_here;
}

POST(sys_compat_ogetdomainname)
{
   I_die_here;
}

PRE(sys_compat_osetdomainname)
{
   I_die_here;
}

PRE(sys_sysarch)
{
   I_die_here;
}

POST(sys_sysarch)
{
   I_die_here;
}

PRE(sys_pread)
{
   I_die_here;
}

POST(sys_pread)
{
   I_die_here;
}

PRE(sys_pwrite)
{
   I_die_here;
}

PRE(sys_ntp_gettime)
{
   I_die_here;
}

POST(sys_ntp_gettime)
{
   I_die_here;
}

PRE(sys_ntp_adjtime)
{
   I_die_here;
}

POST(sys_ntp_adjtime)
{
   I_die_here;
}

PRE(sys_setegid)
{
   I_die_here;
}

PRE(sys_seteuid)
{
   I_die_here;
}

PRE(sys_lfs_bmapv)
{
   I_die_here;
}

POST(sys_lfs_bmapv)
{
   I_die_here;
}

PRE(sys_lfs_markv)
{
   I_die_here;
}

POST(sys_lfs_markv)
{
   I_die_here;
}

PRE(sys_lfs_segclean)
{
   I_die_here;
}

POST(sys_lfs_segclean)
{
   I_die_here;
}

PRE(sys_lfs_segwait)
{
   I_die_here;
}

POST(sys_lfs_segwait)
{
   I_die_here;
}

PRE(sys_pathconf)
{
   I_die_here;
}

POST(sys_pathconf)
{
   I_die_here;
}

PRE(sys_fpathconf)
{
   I_die_here;
}

POST(sys_fpathconf)
{
   I_die_here;
}

PRE(sys_undelete)
{
   I_die_here;
}

PRE(sys_futimes)
{
   I_die_here;
}

PRE(sys_swapctl)
{
   I_die_here;
}

POST(sys_swapctl)
{
   I_die_here;
}

// Hint: See if we can reuse readv/writev from generic functions
PRE(sys_preadv)
{
   I_die_here;
}

POST(sys_preadv)
{
   I_die_here;
}

PRE(sys_pwritev)
{
   I_die_here;
}

// We can probably just copy chroot and add a descriptor check
PRE(sys_fchroot)
{
   I_die_here;
}

// We can probably just copy open here and do some funky file handle check?
// (same goes for the other fh* calls
PRE(sys_fhopen)
{
   I_die_here;
}

POST(sys_fhopen)
{
   I_die_here;
}

PRE(sys_fhstat)
{
   I_die_here;
}

POST(sys_fhstat)
{
   I_die_here;
}

PRE(sys_fhstatfs)
{
   I_die_here;
}

POST(sys_fhstatfs)
{
   I_die_here;
}

PRE(sys_issetugid)
{
   PRINT("sys_issetugid ()");
      PRE_REG_READ0(int, "issetugid");
   //I_die_here;  // Do we even need to do anything here?  I don't think so...
}


PRE(sys_kqueue)
{
   I_die_here;
}

POST(sys_kqueue)
{
   I_die_here;
}

PRE(sys_kevent)
{
   I_die_here;
}

POST(sys_kevent)
{
   I_die_here;
}

// Just look at sys_fsync
PRE(sys_fsync_range)
{
   I_die_here;
}

PRE(sys_uuidgen)
{
   I_die_here;
}

POST(sys_uuidgen)
{
   I_die_here;
}

PRE(sys_fstatvfs1)
{
  I_die_here;
}
POST(sys_fstatvfs1)
{
  I_die_here;
}
#undef PRE
#undef POST

/* -------------------------------------------------------------------- */
/* --- end                                                          --- */
/* -------------------------------------------------------------------- */
