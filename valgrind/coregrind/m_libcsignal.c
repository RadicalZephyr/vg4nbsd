
/*--------------------------------------------------------------------*/
/*--- Signal-related libc stuff.                    m_libcsignal.c ---*/
/*--------------------------------------------------------------------*/
 
/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Julian Seward 
      jseward@acm.org

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
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcsignal.h"
#include "pub_core_syscall.h"
#include "vki_unistd.h"

/* sigemptyset, sigfullset, sigaddset and sigdelset return 0 on
   success and -1 on error.  */

Int VG_(sigfillset)( vki_sigset_t* set )
{
   Int i;
   if (set == NULL)
      return -1;
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      set->sig[i] = ~(UWord)0x0;
   return 0;
}

Int VG_(sigemptyset)( vki_sigset_t* set )
{
   Int i;
   if (set == NULL)
      return -1;
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      set->sig[i] = 0x0;
   return 0;
}

Bool VG_(isemptysigset)( const vki_sigset_t* set )
{
   Int i;
   vg_assert(set != NULL);
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      if (set->sig[i] != 0x0) return False;
   return True;
}

Bool VG_(isfullsigset)( const vki_sigset_t* set )
{
   Int i;
   vg_assert(set != NULL);
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      if (set->sig[i] != ~(UWord)0x0) return False;
   return True;
}

Bool VG_(iseqsigset)( const vki_sigset_t* set1, const vki_sigset_t* set2 )
{
   Int i;
   vg_assert(set1 != NULL && set2 != NULL);
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      if (set1->sig[i] != set2->sig[i]) return False;
   return True;
}


Int VG_(sigaddset)( vki_sigset_t* set, Int signum )
{
   if (set == NULL)
      return -1;
   if (signum < 1 || signum > _VKI_NSIG)
      return -1;
   signum--;
   set->sig[signum / _VKI_NSIG_BPW] |= (1UL << (signum % _VKI_NSIG_BPW));
   return 0;
}

Int VG_(sigdelset)( vki_sigset_t* set, Int signum )
{
   if (set == NULL)
      return -1;
   if (signum < 1 || signum > _VKI_NSIG)
      return -1;
   signum--;
   set->sig[signum / _VKI_NSIG_BPW] &= ~(1UL << (signum % _VKI_NSIG_BPW));
   return 0;
}

Int VG_(sigismember) ( const vki_sigset_t* set, Int signum )
{
   if (set == NULL)
      return 0;
   if (signum < 1 || signum > _VKI_NSIG)
      return 0;
   signum--;
   if (1 & ((set->sig[signum / _VKI_NSIG_BPW]) >> (signum % _VKI_NSIG_BPW)))
      return 1;
   else
      return 0;
}


/* Add all signals in src to dst. */
void VG_(sigaddset_from_set)( vki_sigset_t* dst, vki_sigset_t* src )
{
   Int i;
   vg_assert(dst != NULL && src != NULL);
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      dst->sig[i] |= src->sig[i];
}

/* Remove all signals in src from dst. */
void VG_(sigdelset_from_set)( vki_sigset_t* dst, vki_sigset_t* src )
{
   Int i;
   vg_assert(dst != NULL && src != NULL);
   for (i = 0; i < _VKI_NSIG_WORDS; i++)
      dst->sig[i] &= ~(src->sig[i]);
}


/* The functions sigaction, sigprocmask, sigpending and sigsuspend
   return 0 on success and -1 on error.  
*/
/* #if defined (VGP_x86_netbsdelf2) */
/* asm(  */
/* 	"do_sigprocmask_inner:\n" */
/* 	"movl    8(%esp),%ecx\n"            /\*  fetch new sigset pointer *\/ */
/* 	"testl   %ecx,%ecx\n"               /\*  check new sigset pointer *\/ */
/* 	"jnz     1f\n"                      /\*  if not null, indirect *\/ */
/* 	"movl    $1,4(%esp)\n "             /\*  SIG_BLOCK *\/ */
/* 	"jmp     2f\n" */
/* 	"1:movl    (%ecx),%ecx\n"             /\*  fetch indirect  ... *\/ */
/* 	"movl    %ecx,8(%esp)\n"             /\* to new mask arg *\/ */
/* 	"2:movl $48,%eax\n" /\*  move syscall no to eax  *\/ */
/* 	"int $0x80\n" */
/* 	"jae 3f\n" */
/* 	"movl $-1,%eax\n" */
/* 	"3:\n" */
/* 	"ret\n" */
/* 	); */
/* #endif  */
Int VG_(sigprocmask)( Int how, const vki_sigset_t* set, vki_sigset_t* oldset)
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res = VG_(do_syscall4)(__NR_rt_sigprocmask, 
                                 how, (UWord)set, (UWord)oldset, 
                                 _VKI_NSIG_WORDS * sizeof(UWord));
   return res.isError ? -1 : 0;
#else
   SysRes res = VG_(do_syscall3)(__NR___sigprocmask14, how,(UWord)set,(UWord)oldset);
/*    return do_sigprocmask_inner(how,set,oldset); */
   return res.isError ? -1 : 0;
#endif
}


Int VG_(sigaction) ( Int signum, const struct vki_sigaction* act,  
                     struct vki_sigaction* oldact)
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res = VG_(do_syscall4)(__NR_rt_sigaction,
                                 signum, (UWord)act, (UWord)oldact, 
                                 _VKI_NSIG_WORDS * sizeof(UWord));
   return res.isError ? -1 : 0;
#else
SysRes res = VG_(do_syscall4)(__NR_compat_13_sigaction13,
                                 signum, (UWord)act, (UWord)oldact, 
                                 _VKI_NSIG_WORDS * sizeof(UWord));
   return res.isError ? -1 : 0;
#endif
}


Int VG_(sigaltstack)( const vki_stack_t* ss, vki_stack_t* oss )
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res = VG_(do_syscall2)(__NR_sigaltstack, (UWord)ss, (UWord)oss);
   return res.isError ? -1 : 0;
#else
   I_die_here;
#endif
}

Int VG_(sigtimedwait)( const vki_sigset_t *set, vki_siginfo_t *info, 
                       const struct vki_timespec *timeout )
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res = VG_(do_syscall4)(__NR_rt_sigtimedwait, (UWord)set, (UWord)info, 
                                 (UWord)timeout, sizeof(*set));
   return res.isError ? -1 : res.val;
#else
   I_die_here;
#endif
}
 
Int VG_(signal)(Int signum, void (*sighandler)(Int))
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res;
   Int    n;
   struct vki_sigaction sa;
   sa.ksa_handler = sighandler;
   sa.sa_flags = VKI_SA_ONSTACK | VKI_SA_RESTART;
   sa.sa_restorer = NULL;
   n = VG_(sigemptyset)( &sa.sa_mask );
   vg_assert(n == 0);
   res = VG_(do_syscall4)(__NR_rt_sigaction, signum, (UWord)&sa, (UWord)NULL,
                           _VKI_NSIG_WORDS * sizeof(UWord));
   return res.isError ? -1 : 0;
#else
   I_die_here;
#endif
}


Int VG_(kill)( Int pid, Int signo )
{
   SysRes res = VG_(do_syscall2)(__NR_kill, pid, signo);
   return res.isError ? -1 : 0;
}


Int VG_(tkill)( ThreadId tid, Int signo )
{
#  if !defined(VGP_x86_netbsdelf2)
   SysRes res = VG_(mk_SysRes_Error)(VKI_ENOSYS);

#if 0
   /* This isn't right because the client may create a process
      structure with multiple thread groups */
   res = VG_(do_syscall3)(__NR_tgkill, VG_(getpid)(), tid, signo);
#endif

   res = VG_(do_syscall2)(__NR_tkill, tid, signo);

   if (res.isError && res.val == VKI_ENOSYS)
      res = VG_(do_syscall2)(__NR_kill, tid, signo);

   return res.isError ? -1 : 0;
#else
   I_die_here;
#endif
}

Int VG_(sigpending) ( vki_sigset_t* set )
{
#  if !defined(VGP_x86_netbsdelf2)

// Nb: AMD64/Linux doesn't have __NR_sigpending;  it only provides
// __NR_rt_sigpending.  This function will have to be abstracted in some
// way to account for this.  In the meantime, the easy option is to forget
// about it for AMD64 until it's needed.
#if defined(VGA_amd64)
   I_die_here;
#else
   SysRes res = VG_(do_syscall1)(__NR_sigpending, (UWord)set);
   return res.isError ? -1 : 0;
#endif

#else
   I_die_here;
#endif
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
