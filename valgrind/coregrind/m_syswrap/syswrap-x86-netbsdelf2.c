
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.        syswrap-x86-netbsd.c ---*/
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

/* TODO/FIXME jrs 20050207: assignments to the syscall return result
   in interrupted_syscall() need to be reviewed.  They don't seem
   to assign the shadow state.
*/

#include "pub_core_basics.h"
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"     // Needed for pub_core_aspacemgr :(
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcmman.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_main.h"          // For VG_(shutdown_actions_NORETURN)()
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"      // For VG_(sigframe_destroy)()
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"    /* for decls of generic wrappers */
#include "priv_syswrap-netbsd.h"     /* for decls of netbsd-ish wrappers */
#include "priv_syswrap-main.h"

#include "vki_unistd.h"              /* for the __NR_* constants */


/* ---------------------------------------------------------------------
   Stacks, thread wrappers
   Note.  Why is this stuff here?
   ------------------------------------------------------------------ */

/* 
   Allocate a stack for this thread.

   They're allocated lazily, but never freed.
 */
#define FILL	0xdeadbeef

// Valgrind's stack size, in words.
#define STACK_SIZE_W      16384

static UWord* allocstack(ThreadId tid)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   UWord *esp;

   if (tst->os_state.valgrind_stack_base == 0) {
      void *stk = VG_(mmap)(0, STACK_SIZE_W * sizeof(UWord) + VKI_PAGE_SIZE,
			    VKI_PROT_READ|VKI_PROT_WRITE,
			    VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS,
			    SF_VALGRIND,
			    -1, 0);

      if (stk != (void *)-1) {
         VG_(mprotect)(stk, VKI_PAGE_SIZE, VKI_PROT_NONE); /* guard page */
         tst->os_state.valgrind_stack_base = ((Addr)stk) + VKI_PAGE_SIZE;
         tst->os_state.valgrind_stack_szB  = STACK_SIZE_W * sizeof(UWord);
      } else 
      return (UWord*)-1;
   }

   for (esp = (UWord*) tst->os_state.valgrind_stack_base;
        esp < (UWord*)(tst->os_state.valgrind_stack_base + 
                       tst->os_state.valgrind_stack_szB); 
        esp++)
      *esp = FILL;
   /* esp is left at top of stack */

   if (0)
      VG_(printf)("stack for tid %d at %p (%x); esp=%p\n",
		  tid, tst->os_state.valgrind_stack_base, 
                  *(UWord*)(tst->os_state.valgrind_stack_base), esp);

   return esp;
}

/* NB: this is identical the the amd64 version. */
/* Return how many bytes of this stack have not been used */
SSizeT VG_(stack_unused)(ThreadId tid)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   UWord* p;

   for (p = (UWord*)tst->os_state.valgrind_stack_base; 
	p && (p < (UWord*)(tst->os_state.valgrind_stack_base +
                           tst->os_state.valgrind_stack_szB)); 
	p++)
      if (*p != FILL)
	 break;

   if (0)
      VG_(printf)("p=%p %x tst->os_state.valgrind_stack_base=%p\n",
                  p, *p, tst->os_state.valgrind_stack_base);

   return ((Addr)p) - tst->os_state.valgrind_stack_base;
}


/* Run a thread all the way to the end, then do appropriate exit actions
   (this is the last-one-out-turn-off-the-lights bit). 
*/
static void run_a_thread_NORETURN ( Word tidW )
{
	VG_(printf)("in run a thread_noreturn\n");
   ThreadId tid = (ThreadId)tidW;

   VG_(debugLog)(1, "syswrap-x86-netbsd", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper) called\n",
                       (ULong)tidW);

   /* Run the thread all the way through. */
   VgSchedReturnCode src = ML_(thread_wrapper)(tid);  

   VG_(debugLog)(1, "syswrap-x86-netbsd", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper) done\n",
                       (ULong)tidW);

   Int c = VG_(count_living_threads)();
   vg_assert(c >= 1); /* stay sane */

   if (c == 1) {

      VG_(debugLog)(1, "syswrap-x86-netbsd", 
                       "run_a_thread_NORETURN(tid=%lld): "
                          "last one standing\n",
                          (ULong)tidW);

      /* We are the last one standing.  Keep hold of the lock and
         carry on to show final tool results, then exit the entire system. */
      VG_(shutdown_actions_NORETURN)(tid, src);

   } else {

      VG_(debugLog)(1, "syswrap-x86-netbsd", 
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


/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f.*/
__attribute__((noreturn))
void call_on_new_stack_0_1 ( Addr stack,
			     Addr retaddr,
			     void (*f)(Word),
                             Word arg1 );
//  4(%esp) == stack
//  8(%esp) == retaddr
// 12(%esp) == f
// 16(%esp) == arg1
asm(
"call_on_new_stack_0_1:\n"
"   movl %esp, %esi\n"     // remember old stack pointer
"   movl 4(%esi), %esp\n"  // set stack
"   pushl 16(%esi)\n"      // arg1 to stack
"   pushl  8(%esi)\n"      // retaddr to stack
"   pushl 12(%esi)\n"      // f to stack
"   movl $0, %eax\n"       // zero all GP regs
"   movl $0, %ebx\n"
"   movl $0, %ecx\n"
"   movl $0, %edx\n"
"   movl $0, %esi\n"
"   movl $0, %edi\n"
"   movl $0, %ebp\n"
"   ret\n"                 // jump to f
"   ud2\n"                 // should never get here
);


/*
   Allocate a stack for the main thread, and run it all the way to the
   end.  
*/
void VG_(main_thread_wrapper_NORETURN)(ThreadId tid)
{
	VG_(debugLog)(1, "syswrap-x86-netbsd", 
		      "entering VG_(main_thread_wrapper_NORETURN)\n"); 

   UWord* esp = allocstack(tid);

   /* shouldn't be any other threads around yet */
   vg_assert( VG_(count_living_threads)() == 1 );

   call_on_new_stack_0_1( 
      (Addr)esp,              /* stack */
      0,                      /*bogus return address*/
      run_a_thread_NORETURN,  /* fn to call */
      (Word)tid               /* arg to give it */
   );

   /*NOTREACHED*/
   vg_assert(0);
}


static Int start_thread_NORETURN ( void* arg )
{
   ThreadState* tst = (ThreadState*)arg;
   ThreadId     tid = tst->tid;

   run_a_thread_NORETURN ( (Word)tid );
   /*NOTREACHED*/
   vg_assert(0);
}


/* ---------------------------------------------------------------------
   clone() handling
   ------------------------------------------------------------------ */

/*
        Perform a clone system call.  clone is strange because it has
        fork()-like return-twice semantics, so it needs special
        handling here.

        Upon entry, we have:

            int (fn)(void*)     in  0+FSZ(%esp)
            void* child_stack   in  4+FSZ(%esp)
            int flags           in  8+FSZ(%esp)
            void* arg           in 12+FSZ(%esp)
            pid_t* child_tid    in 16+FSZ(%esp)
            pid_t* parent_tid   in 20+FSZ(%esp)
            void* tls_ptr       in 24+FSZ(%esp)

        System call requires:

            int    $__NR_clone  in %eax
            int    flags        in %ebx
            void*  child_stack  in %ecx
            pid_t* parent_tid   in %edx
            pid_t* child_tid    in %edi
            void*  tls_ptr      in %esi

	Returns an Int encoded in the netbsd-x86 way, not a SysRes.
 */
#define STRINGIFZ(__str) #__str
#define STRINGIFY(__str)  STRINGIFZ(__str)
#define FSZ               "4+4+4+4" /* frame size = retaddr+ebx+edi+esi */
#define __NR_CLONE        STRINGIFY(__NR_clone)
#define __NR_EXIT         STRINGIFY(__NR_exit)

extern
Int do_syscall_clone_x86_netbsd ( Int (*fn)(void *), 
                                 void* stack, 
                                 Int   flags, 
                                 void* arg,
                                 Int*  child_tid, 
                                 Int*  parent_tid, 
                                 vki_modify_ldt_t * );
asm(
"\n"
"do_syscall_clone_x86_netbsd:\n"
"        push    %ebx\n"
"        push    %edi\n"
"        push    %esi\n"

         /* set up child stack with function and arg */
"        movl     4+"FSZ"(%esp), %ecx\n"    /* syscall arg2: child stack */
"        movl    12+"FSZ"(%esp), %ebx\n"    /* fn arg */
"        movl     0+"FSZ"(%esp), %eax\n"    /* fn */
"        lea     -8(%ecx), %ecx\n"          /* make space on stack */
"        movl    %ebx, 4(%ecx)\n"           /*   fn arg */
"        movl    %eax, 0(%ecx)\n"           /*   fn */

         /* get other args to clone */
"        movl     8+"FSZ"(%esp), %ebx\n"    /* syscall arg1: flags */
"        movl    20+"FSZ"(%esp), %edx\n"    /* syscall arg3: parent tid * */
"        movl    16+"FSZ"(%esp), %edi\n"    /* syscall arg5: child tid * */
"        movl    24+"FSZ"(%esp), %esi\n"    /* syscall arg4: tls_ptr * */
"        movl    $"__NR_CLONE", %eax\n"
"        int     $0x80\n"                   /* clone() */
"        testl   %eax, %eax\n"              /* child if retval == 0 */
"        jnz     1f\n"

         /* CHILD - call thread function */
"        popl    %eax\n"
"        call    *%eax\n"                   /* call fn */

         /* exit with result */
"        movl    %eax, %ebx\n"              /* arg1: return value from fn */
"        movl    $"__NR_EXIT", %eax\n"
"        int     $0x80\n"

         /* Hm, exit returned */
"        ud2\n"

"1:\n"   /* PARENT or ERROR */
"        pop     %esi\n"
"        pop     %edi\n"
"        pop     %ebx\n"
"        ret\n"
);

#undef FSZ
#undef __NR_CLONE
#undef __NR_EXIT
#undef STRINGIFY
#undef STRINGIFZ


// forward declarations
static void setup_child ( ThreadArchState*, ThreadArchState*, Bool );
static SysRes sys_set_thread_area ( ThreadId, vki_modify_ldt_t* );

/* 
   When a client clones, we need to keep track of the new thread.  This means:
   1. allocate a ThreadId+ThreadState+stack for the the thread

   2. initialize the thread's new VCPU state

   3. create the thread using the same args as the client requested,
   but using the scheduler entrypoint for EIP, and a separate stack
   for ESP.
 */
static SysRes do_clone ( ThreadId ptid, 
                         UInt flags, Addr esp, 
                         Int* parent_tidptr, 
                         Int* child_tidptr, 
                         vki_modify_ldt_t *tlsinfo)
{
   static const Bool debug = False;

   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(ptid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   UWord*       stack;
   Segment*     seg;
   SysRes       res;
   Int          eax;
   vki_sigset_t blockall, savedmask;

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(ptid));
   vg_assert(VG_(is_valid_tid)(ctid));

   stack = allocstack(ctid);

   /* Copy register state

      Both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL esp for the new thread, then
      it actually gets a copy of the parent's esp.
   */
   /* Note: the clone call done by the Quadrics Elan3 driver specifies
      clone flags of 0xF00, and it seems to rely on the assumption
      that the child inherits a copy of the parent's GDT.  
      setup_child takes care of setting that up. */
   setup_child( &ctst->arch, &ptst->arch, True );

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   ctst->arch.vex.guest_EAX = 0;

   if (esp != 0)
      ctst->arch.vex.guest_ESP = esp;

   ctst->os_state.parent = ptid;

   /* inherit signal mask */
   ctst->sig_mask     = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* We don't really know where the client stack is, because its
      allocated by the client.  The best we can do is look at the
      memory mappings and try to derive some useful information.  We
      assume that esp starts near its highest possible value, and can
      only go down to the start of the mmaped segment. */
   seg = VG_(find_segment)((Addr)esp);
   if (seg) {
      ctst->client_stack_highest_word = (Addr)VG_PGROUNDUP(esp);
      ctst->client_stack_szB  = ctst->client_stack_highest_word - seg->addr;

      if (debug)
	 VG_(printf)("tid %d: guessed client stack range %p-%p\n",
		     ctid, seg->addr, VG_PGROUNDUP(esp));
   } else {
      VG_(message)(Vg_UserMsg, "!? New thread %d starts with ESP(%p) unmapped\n",
		   ctid, esp);
      ctst->client_stack_szB  = 0;
   }

   if (flags & VKI_CLONE_SETTLS) {
      if (debug)
	 VG_(printf)("clone child has SETTLS: tls info at %p: idx=%d "
                     "base=%p limit=%x; esp=%p fs=%x gs=%x\n",
		     tlsinfo, tlsinfo->entry_number, 
                     tlsinfo->base_addr, tlsinfo->limit,
		     ptst->arch.vex.guest_ESP,
		     ctst->arch.vex.guest_FS, ctst->arch.vex.guest_GS);
      res = sys_set_thread_area(ctid, tlsinfo);
      if (res.isError)
	 goto out;
   }

   flags &= ~VKI_CLONE_SETTLS;

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Create the new thread */
   eax = do_syscall_clone_x86_netbsd(
            start_thread_NORETURN, stack, flags, &VG_(threads)[ctid],
            child_tidptr, parent_tidptr, NULL
         );
   res = VG_(mk_SysRes_x86_netbsdelf2)( eax );

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

  out:
   if (res.isError) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
   }

   return res;
}


/* Do a clone which is really a fork() */
static SysRes do_fork_clone ( ThreadId tid, 
                              UInt flags, Addr esp, 
                              Int* parent_tidptr, 
                              Int* child_tidptr )
{
   vki_sigset_t fork_saved_mask;
   vki_sigset_t mask;
   SysRes       res;

   if (flags & (VKI_CLONE_SETTLS | VKI_CLONE_FS | VKI_CLONE_VM 
                | VKI_CLONE_FILES | VKI_CLONE_VFORK))
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* Block all signals during fork, so that we can fix things up in
      the child without being interrupted. */
   VG_(sigfillset)(&mask);
   VG_(sigprocmask)(VKI_SIG_SETMASK, &mask, &fork_saved_mask);

   /* Since this is the fork() form of clone, we don't need all that
      VG_(clone) stuff */
   res = VG_(do_syscall5)( __NR_clone, flags, 
                           (UWord)NULL, (UWord)parent_tidptr, 
                           (UWord)NULL, (UWord)child_tidptr );

   if (!res.isError && res.val == 0) {
      /* child */
      VG_(do_atfork_child)(tid);

      /* restore signal mask */
      VG_(sigprocmask)(VKI_SIG_SETMASK, &fork_saved_mask, NULL);
   } 
   else 
   if (!res.isError && res.val > 0) {
      /* parent */
      if (VG_(clo_trace_syscalls))
	  VG_(printf)("   clone(fork): process %d created child %d\n", 
                      VG_(getpid)(), res.val);

      /* restore signal mask */
      VG_(sigprocmask)(VKI_SIG_SETMASK, &fork_saved_mask, NULL);
   }

   return res;
}

/* ---------------------------------------------------------------------
   LDT/GDT simulation
   ------------------------------------------------------------------ */

/* Details of the LDT simulation
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  
   When a program runs natively, the linux kernel allows each *thread*
   in it to have its own LDT.  Almost all programs never do this --
   it's wildly unportable, after all -- and so the kernel never
   allocates the structure, which is just as well as an LDT occupies
   64k of memory (8192 entries of size 8 bytes).

   A thread may choose to modify its LDT entries, by doing the
   __NR_modify_ldt syscall.  In such a situation the kernel will then
   allocate an LDT structure for it.  Each LDT entry is basically a
   (base, limit) pair.  A virtual address in a specific segment is
   translated to a linear address by adding the segment's base value.
   In addition, the virtual address must not exceed the limit value.

   To use an LDT entry, a thread loads one of the segment registers
   (%cs, %ss, %ds, %es, %fs, %gs) with the index of the LDT entry (0
   .. 8191) it wants to use.  In fact, the required value is (index <<
   3) + 7, but that's not important right now.  Any normal instruction
   which includes an addressing mode can then be made relative to that
   LDT entry by prefixing the insn with a so-called segment-override
   prefix, a byte which indicates which of the 6 segment registers
   holds the LDT index.

   Now, a key constraint is that valgrind's address checks operate in
   terms of linear addresses.  So we have to explicitly translate
   virtual addrs into linear addrs, and that means doing a complete
   LDT simulation.

   Calls to modify_ldt are intercepted.  For each thread, we maintain
   an LDT (with the same normally-never-allocated optimisation that
   the kernel does).  This is updated as expected via calls to
   modify_ldt.

   When a thread does an amode calculation involving a segment
   override prefix, the relevant LDT entry for the thread is
   consulted.  It all works.

   There is a conceptual problem, which appears when switching back to
   native execution, either temporarily to pass syscalls to the
   kernel, or permanently, when debugging V.  Problem at such points
   is that it's pretty pointless to copy the simulated machine's
   segment registers to the real machine, because we'd also need to
   copy the simulated LDT into the real one, and that's prohibitively
   expensive.

   Fortunately it looks like no syscalls rely on the segment regs or
   LDT being correct, so we can get away with it.  Apart from that the
   simulation is pretty straightforward.  All 6 segment registers are
   tracked, although only %ds, %es, %fs and %gs are allowed as
   prefixes.  Perhaps it could be restricted even more than that -- I
   am not sure what is and isn't allowed in user-mode.
*/

/* Translate a struct modify_ldt_ldt_s to a VexGuestX86SegDescr, using
   the Linux kernel's logic (cut-n-paste of code in
   linux/kernel/ldt.c).  */

static
void translate_to_hw_format ( /* IN  */ vki_modify_ldt_t* inn,
                              /* OUT */ VexGuestX86SegDescr* out,
                                        Int oldmode )
{
   UInt entry_1, entry_2;
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   if (0)
      VG_(printf)("translate_to_hw_format: base %p, limit %d\n", 
                  inn->base_addr, inn->limit );

   /* Allow LDTs to be cleared by the user. */
   if (inn->base_addr == 0 && inn->limit == 0) {
      if (oldmode ||
          (inn->contents == 0      &&
           inn->read_exec_only == 1   &&
           inn->seg_32bit == 0      &&
           inn->limit_in_pages == 0   &&
           inn->seg_not_present == 1   &&
           inn->useable == 0 )) {
         entry_1 = 0;
         entry_2 = 0;
         goto install;
      }
   }

   entry_1 = ((inn->base_addr & 0x0000ffff) << 16) |
             (inn->limit & 0x0ffff);
   entry_2 = (inn->base_addr & 0xff000000) |
             ((inn->base_addr & 0x00ff0000) >> 16) |
             (inn->limit & 0xf0000) |
             ((inn->read_exec_only ^ 1) << 9) |
             (inn->contents << 10) |
             ((inn->seg_not_present ^ 1) << 15) |
             (inn->seg_32bit << 22) |
             (inn->limit_in_pages << 23) |
             0x7000;
   if (!oldmode)
      entry_2 |= (inn->useable << 20);

   /* Install the new entry ...  */
  install:
   out->LdtEnt.Words.word1 = entry_1;
   out->LdtEnt.Words.word2 = entry_2;
}

/* Create a zeroed-out GDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_GDT ( void )
{
   Int nbytes = VEX_GUEST_X86_GDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, nbytes, 1);
}

/* Create a zeroed-out LDT. */
static VexGuestX86SegDescr* alloc_zeroed_x86_LDT ( void )
{
   Int nbytes = VEX_GUEST_X86_LDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, nbytes, 1);
}

/* Free up an LDT or GDT allocated by the above fns. */
static void free_LDT_or_GDT ( VexGuestX86SegDescr* dt )
{
   vg_assert(dt);
   VG_(arena_free)(VG_AR_CORE, (void*)dt);
}

/* Copy contents between two existing LDTs. */
static void copy_LDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_LDT_NENT; i++)
      dst[i] = src[i];
}

/* Copy contents between two existing GDTs. */
static void copy_GDT_from_to ( VexGuestX86SegDescr* src,
                               VexGuestX86SegDescr* dst )
{
   Int i;
   vg_assert(src);
   vg_assert(dst);
   for (i = 0; i < VEX_GUEST_X86_GDT_NENT; i++)
      dst[i] = src[i];
}

/* Free this thread's DTs, if it has any. */
static void deallocate_LGDTs_for_thread ( VexGuestX86State* vex )
{
   vg_assert(sizeof(HWord) == sizeof(void*));

   if (0)
      VG_(printf)("deallocate_LGDTs_for_thread: "
                  "ldt = 0x%x, gdt = 0x%x\n", 
                  vex->guest_LDT, vex->guest_GDT );

   if (vex->guest_LDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_LDT );
      vex->guest_LDT = (HWord)NULL;
   }

   if (vex->guest_GDT != (HWord)NULL) {
      free_LDT_or_GDT( (VexGuestX86SegDescr*)vex->guest_GDT );
      vex->guest_GDT = (HWord)NULL;
   }
}


/*
 * linux/kernel/ldt.c
 *
 * Copyright (C) 1992 Krishna Balasubramanian and Linus Torvalds
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

/*
 * read_ldt() is not really atomic - this is not a problem since
 * synchronization of reads and writes done to the LDT has to be
 * assured by user-space anyway. Writes are atomic, to protect
 * the security checks done on new descriptors.
 */
static
SysRes read_ldt ( ThreadId tid, UChar* ptr, UInt bytecount )
{
   SysRes res;
   UInt   i, size;
   UChar* ldt;

   if (0)
      VG_(printf)("read_ldt: tid = %d, ptr = %p, bytecount = %d\n",
                  tid, ptr, bytecount );

   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   ldt = (Char*)(VG_(threads)[tid].arch.vex.guest_LDT);
   res = VG_(mk_SysRes_Success)( 0 );
   if (ldt == NULL)
      /* LDT not allocated, meaning all entries are null */
      goto out;

   size = VEX_GUEST_X86_LDT_NENT * sizeof(VexGuestX86SegDescr);
   if (size > bytecount)
      size = bytecount;

   res = VG_(mk_SysRes_Success)( size );
   for (i = 0; i < size; i++)
      ptr[i] = ldt[i];

  out:
   return res;
}


static
SysRes write_ldt ( ThreadId tid, void* ptr, UInt bytecount, Int oldmode )
{
   SysRes res;
   VexGuestX86SegDescr* ldt;
   vki_modify_ldt_t* ldt_info; 

   if (0)
      VG_(printf)("write_ldt: tid = %d, ptr = %p, "
                  "bytecount = %d, oldmode = %d\n",
                  tid, ptr, bytecount, oldmode );

   vg_assert(8 == sizeof(VexGuestX86SegDescr));
   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));

   ldt      = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_LDT;
   ldt_info = (vki_modify_ldt_t*)ptr;

   res = VG_(mk_SysRes_Error)( VKI_EINVAL );
   if (bytecount != sizeof(vki_modify_ldt_t))
      goto out;

   res = VG_(mk_SysRes_Error)( VKI_EINVAL );
   if (ldt_info->entry_number >= VEX_GUEST_X86_LDT_NENT)
      goto out;
   if (ldt_info->contents == 3) {
      if (oldmode)
         goto out;
      if (ldt_info->seg_not_present == 0)
         goto out;
   }

   /* If this thread doesn't have an LDT, we'd better allocate it
      now. */
   if (ldt == (HWord)NULL) {
      ldt = alloc_zeroed_x86_LDT();
      VG_(threads)[tid].arch.vex.guest_LDT = (HWord)ldt;
   }

   /* Install the new entry ...  */
   translate_to_hw_format ( ldt_info, &ldt[ldt_info->entry_number], oldmode );
   res = VG_(mk_SysRes_Success)( 0 );

  out:
   return res;
}


static SysRes sys_modify_ldt ( ThreadId tid,
                               Int func, void* ptr, UInt bytecount )
{
   SysRes ret = VG_(mk_SysRes_Error)( VKI_ENOSYS );

   switch (func) {
   case 0:
      ret = read_ldt(tid, ptr, bytecount);
      break;
   case 1:
      ret = write_ldt(tid, ptr, bytecount, 1);
      break;
   case 2:
      VG_(unimplemented)("sys_modify_ldt: func == 2");
      /* god knows what this is about */
      /* ret = read_default_ldt(ptr, bytecount); */
      /*UNREACHED*/
      break;
   case 0x11:
      ret = write_ldt(tid, ptr, bytecount, 0);
      break;
   }
   return ret;
}


static SysRes sys_set_thread_area ( ThreadId tid, vki_modify_ldt_t* info )
{
   Int                  idx;
   VexGuestX86SegDescr* gdt;

   vg_assert(8 == sizeof(VexGuestX86SegDescr));
   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));

   if (info == NULL)
      return VG_(mk_SysRes_Error)( VKI_EFAULT );

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }

   idx = info->entry_number;

   if (idx == -1) {
      /* Find and use the first free entry. */
      for (idx = 0; idx < VEX_GUEST_X86_GDT_NENT; idx++) {
         if (gdt[idx].LdtEnt.Words.word1 == 0 
             && gdt[idx].LdtEnt.Words.word2 == 0)
            break;
      }

      if (idx == VEX_GUEST_X86_GDT_NENT)
         return VG_(mk_SysRes_Error)( VKI_ESRCH );
   } else if (idx < 0 || idx >= VEX_GUEST_X86_GDT_NENT) {
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   translate_to_hw_format(info, &gdt[idx], 0);

   VG_TRACK( pre_mem_write, Vg_CoreSysCall, tid,
             "set_thread_area(info->entry)",
             (Addr) & info->entry_number, sizeof(unsigned int) );
   info->entry_number = idx;
   VG_TRACK( post_mem_write, Vg_CoreSysCall, tid,
             (Addr) & info->entry_number, sizeof(unsigned int) );

   return VG_(mk_SysRes_Success)( 0 );
}


static SysRes sys_get_thread_area ( ThreadId tid, vki_modify_ldt_t* info )
{
   Int idx;
   VexGuestX86SegDescr* gdt;

   vg_assert(sizeof(HWord) == sizeof(VexGuestX86SegDescr*));
   vg_assert(8 == sizeof(VexGuestX86SegDescr));

   if (info == NULL)
      return VG_(mk_SysRes_Error)( VKI_EFAULT );

   idx = info->entry_number;

   if (idx < 0 || idx >= VEX_GUEST_X86_GDT_NENT)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   gdt = (VexGuestX86SegDescr*)VG_(threads)[tid].arch.vex.guest_GDT;

   /* If the thread doesn't have a GDT, allocate it now. */
   if (!gdt) {
      gdt = alloc_zeroed_x86_GDT();
      VG_(threads)[tid].arch.vex.guest_GDT = (HWord)gdt;
   }

   info->base_addr = ( gdt[idx].LdtEnt.Bits.BaseHi << 24 ) |
                     ( gdt[idx].LdtEnt.Bits.BaseMid << 16 ) |
                     gdt[idx].LdtEnt.Bits.BaseLow;
   info->limit = ( gdt[idx].LdtEnt.Bits.LimitHi << 16 ) |
                   gdt[idx].LdtEnt.Bits.LimitLow;
   info->seg_32bit = gdt[idx].LdtEnt.Bits.Default_Big;
   info->contents = ( gdt[idx].LdtEnt.Bits.Type >> 2 ) & 0x3;
   info->read_exec_only = ( gdt[idx].LdtEnt.Bits.Type & 0x1 ) ^ 0x1;
   info->limit_in_pages = gdt[idx].LdtEnt.Bits.Granularity;
   info->seg_not_present = gdt[idx].LdtEnt.Bits.Pres ^ 0x1;
   info->useable = gdt[idx].LdtEnt.Bits.Sys;
   info->reserved = 0;

   return VG_(mk_SysRes_Success)( 0 );
}

/* ---------------------------------------------------------------------
   More thread stuff
   ------------------------------------------------------------------ */

void VG_(cleanup_thread) ( ThreadArchState* arch )
{
   /* Release arch-specific resources held by this thread. */
   /* On x86, we have to dump the LDT and GDT. */
   deallocate_LGDTs_for_thread( &arch->vex );
}  


static void setup_child ( /*OUT*/ ThreadArchState *child, 
                          /*IN*/  ThreadArchState *parent,
                          Bool inherit_parents_GDT )
{
   /* We inherit our parent's guest state. */
   child->vex = parent->vex;
   child->vex_shadow = parent->vex_shadow;

   /* We inherit our parent's LDT. */
   if (parent->vex.guest_LDT == (HWord)NULL) {
      /* We hope this is the common case. */
      child->vex.guest_LDT = (HWord)NULL;
   } else {
      /* No luck .. we have to take a copy of the parent's. */
      child->vex.guest_LDT = (HWord)alloc_zeroed_x86_LDT();
      copy_LDT_from_to( (VexGuestX86SegDescr*)parent->vex.guest_LDT, 
                        (VexGuestX86SegDescr*)child->vex.guest_LDT );
   }

   /* Either we start with an empty GDT (the usual case) or inherit a
      copy of our parents' one (Quadrics Elan3 driver -style clone
      only). */
   child->vex.guest_GDT = (HWord)NULL;

   if (inherit_parents_GDT && parent->vex.guest_GDT != (HWord)NULL) {
      child->vex.guest_GDT = (HWord)alloc_zeroed_x86_GDT();
      copy_GDT_from_to( (VexGuestX86SegDescr*)parent->vex.guest_GDT,
                        (VexGuestX86SegDescr*)child->vex.guest_GDT );
   }
}  


/* ---------------------------------------------------------------------
   PRE/POST wrappers for x86/Linux-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(x86_netbsdelf2, name)
#define POST(name)      DEFN_POST_TEMPLATE(x86_netbsdelf2, name)

/* Add prototypes for the wrappers declared here, so that gcc doesn't
   harass us for not having prototypes.  Really this is a kludge --
   the right thing to do is to make these wrappers 'static' since they
   aren't visible outside this file, but that requires even more macro
   magic. */
DECL_TEMPLATE(x86_netbsdelf2, sys_stat64);
DECL_TEMPLATE(x86_netbsdelf2, sys_fstat64);
DECL_TEMPLATE(x86_netbsdelf2, sys_lstat64);
DECL_TEMPLATE(x86_netbsdelf2, sys_clone);
DECL_TEMPLATE(x86_netbsdelf2, old_mmap);
DECL_TEMPLATE(x86_netbsdelf2, sys_sigreturn);
DECL_TEMPLATE(x86_netbsdelf2, sys_ipc);
DECL_TEMPLATE(x86_netbsdelf2, sys_modify_ldt);
DECL_TEMPLATE(x86_netbsdelf2, sys_set_thread_area);
DECL_TEMPLATE(x86_netbsdelf2, sys_get_thread_area);
DECL_TEMPLATE(x86_netbsdelf2, sys_ptrace);
DECL_TEMPLATE(x86_netbsdelf2, sys_sigaction);
DECL_TEMPLATE(x86_netbsdelf2, old_select);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_ocreat);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_lseek);
DECL_TEMPLATE(x86_netbsdelf2, sys_break);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_sigvec);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_sigblock);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_sigsetmask);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_sigsuspend);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_sigstack);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_osemsys);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_omsgsys);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_oshmsys);
DECL_TEMPLATE(x86_netbsdelf2, sys_syscall);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_semctl);
DECL_TEMPLATE(x86_netbsdelf2, sys_semget);
DECL_TEMPLATE(x86_netbsdelf2, sys_semop);
DECL_TEMPLATE(x86_netbsdelf2, sys_semop);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_msgctl);
DECL_TEMPLATE(x86_netbsdelf2, sys_msgget);
DECL_TEMPLATE(x86_netbsdelf2, sys_msgsnd);
DECL_TEMPLATE(x86_netbsdelf2, sys_msgrcv);
DECL_TEMPLATE(x86_netbsdelf2, sys_shmat);
DECL_TEMPLATE(x86_netbsdelf2, sys_compat_shmctl);
DECL_TEMPLATE(x86_netbsdelf2, sys_shmdt);
DECL_TEMPLATE(x86_netbsdelf2, sys_shmget);
DECL_TEMPLATE(x86_netbsdelf2, sys_minherit);
DECL_TEMPLATE(x86_netbsdelf2, sys_getcontext);
DECL_TEMPLATE(x86_netbsdelf2, sys_setcontext);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_create);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_exit);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_self);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_wait);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_suspend);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_continue);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_wakeup);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_getprivate);
DECL_TEMPLATE(x86_netbsdelf2, sys_lwp_setprivate);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_register);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_stacks);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_enable);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_setconcurrency);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_yield);
DECL_TEMPLATE(x86_netbsdelf2, sys_sa_preempt);
DECL_TEMPLATE(x86_netbsdelf2, sys_pmc_get_info);
DECL_TEMPLATE(x86_netbsdelf2, sys_pmc_control);
DECL_TEMPLATE(x86_netbsdelf2, sys_rasctl);

PRE(old_select)
{
   /* struct sel_arg_struct {
      unsigned long n;
      fd_set *inp, *outp, *exp;
      struct timeval *tvp;
      };
   */
   PRE_REG_READ1(long, "old_select", struct sel_arg_struct *, args);
   PRE_MEM_READ( "old_select(args)", ARG1, 5*sizeof(UWord) );
   *flags |= SfMayBlock;
   {
      UInt* arg_struct = (UInt*)ARG1;
      UInt a1, a2, a3, a4, a5;

      a1 = arg_struct[0];
      a2 = arg_struct[1];
      a3 = arg_struct[2];
      a4 = arg_struct[3];
      a5 = arg_struct[4];

      PRINT("old_select ( %d, %p, %p, %p, %p )", a1,a2,a3,a4,a5);
      if (a2 != (Addr)NULL)
         PRE_MEM_READ( "old_select(readfds)",   a2, a1/8 /* __FD_SETSIZE/8 */ );
      if (a3 != (Addr)NULL)
         PRE_MEM_READ( "old_select(writefds)",  a3, a1/8 /* __FD_SETSIZE/8 */ );
      if (a4 != (Addr)NULL)
         PRE_MEM_READ( "old_select(exceptfds)", a4, a1/8 /* __FD_SETSIZE/8 */ );
      if (a5 != (Addr)NULL)
         PRE_MEM_READ( "old_select(timeout)", a5, sizeof(struct vki_timeval) );
   }
}

PRE(sys_clone)
{
   UInt cloneflags;

   PRINT("sys_clone ( %x, %p, %p, %p, %p )",ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(int, "clone",
                 unsigned long, flags,
                 void *, child_stack,
                 int *, parent_tidptr,
                 vki_modify_ldt_t *, tlsinfo,
                 int *, child_tidptr);

   if (ARG1 & VKI_CLONE_PARENT_SETTID) {
      PRE_MEM_WRITE("clone(parent_tidptr)", ARG3, sizeof(Int));
      if (!VG_(is_addressable)(ARG3, sizeof(Int), VKI_PROT_WRITE)) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
   }
   if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID)) {
      PRE_MEM_WRITE("clone(child_tidptr)", ARG5, sizeof(Int));
      if (!VG_(is_addressable)(ARG5, sizeof(Int), VKI_PROT_WRITE)) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
   }
   if (ARG1 & VKI_CLONE_SETTLS) {
      PRE_MEM_READ("clone(tls_user_desc)", ARG4, sizeof(vki_modify_ldt_t));
      if (!VG_(is_addressable)(ARG4, sizeof(vki_modify_ldt_t), VKI_PROT_READ)) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
   }

   cloneflags = ARG1;

   if (!ML_(client_signal_OK)(ARG1 & VKI_CSIGNAL)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   /* Be ultra-paranoid and filter out any clone-variants we don't understand:
      - ??? specifies clone flags of 0x100011
      - ??? specifies clone flags of 0x1200011.
      - NPTL specifies clone flags of 0x7D0F00.
      - The Quadrics Elan3 driver specifies clone flags of 0xF00.
      Everything else is rejected. 
   */
   if (
          (cloneflags == 0x100011 || cloneflags == 0x1200011
                                  || cloneflags == 0x7D0F00
                                  || cloneflags == 0x790F00
                                  || cloneflags == 0x3D0F00
                                  || cloneflags == 0xF00
                                  || cloneflags == 0xF21)) {
     /* OK */
   }
   else {
      /* Nah.  We don't like it.  Go away. */
      goto reject;
   }

   /* Only look at the flags we really care about */
   switch (cloneflags & (VKI_CLONE_VM | VKI_CLONE_FS 
                         | VKI_CLONE_FILES | VKI_CLONE_VFORK)) {
   case VKI_CLONE_VM | VKI_CLONE_FS | VKI_CLONE_FILES:
      /* thread creation */
      SET_STATUS_from_SysRes(
         do_clone(tid,
                  ARG1,         /* flags */
                  (Addr)ARG2,   /* child ESP */
                  (Int *)ARG3,  /* parent_tidptr */
                  (Int *)ARG5,  /* child_tidptr */
                  (vki_modify_ldt_t *)ARG4)); /* set_tls */
      break;

   case VKI_CLONE_VFORK | VKI_CLONE_VM: /* vfork */
      /* FALLTHROUGH - assume vfork == fork */
      cloneflags &= ~(VKI_CLONE_VFORK | VKI_CLONE_VM);

   case 0: /* plain fork */
      SET_STATUS_from_SysRes(
         do_fork_clone(tid,
                       cloneflags,      /* flags */
                       (Addr)ARG2,      /* child ESP */
                       (Int *)ARG3,     /* parent_tidptr */
                       (Int *)ARG5));   /* child_tidptr */
      break;

   default:
   reject:
      /* should we just ENOSYS? */
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "Unsupported clone() flags: 0x%x", ARG1);
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "The only supported clone() uses are:");
      VG_(message)(Vg_UserMsg, " - via a threads library (LinuxThreads or NPTL)");
      VG_(message)(Vg_UserMsg, " - via the implementation of fork or vfork");
      VG_(message)(Vg_UserMsg, " - for the Quadrics Elan3 user-space driver");
      VG_(unimplemented)
         ("Valgrind does not support general clone().");
   }

   if (SUCCESS) {
      if (ARG1 & VKI_CLONE_PARENT_SETTID)
         POST_MEM_WRITE(ARG3, sizeof(Int));
      if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID))
         POST_MEM_WRITE(ARG5, sizeof(Int));

      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }
}

PRE(sys_sigreturn)
{
   ThreadState* tst;
   PRINT("sigreturn ( )");

   vg_assert(VG_(is_valid_tid)(tid));
   vg_assert(tid >= 1 && tid < VG_N_THREADS);
   vg_assert(VG_(is_running_thread)(tid));

   /* Adjust esp to point to start of frame; skip back up over
      sigreturn sequence's "popl %eax" and handler ret addr */
   tst = VG_(get_ThreadState)(tid);
   tst->arch.vex.guest_ESP -= sizeof(Addr)+sizeof(Word);

   /* This is only so that the EIP is (might be) useful to report if
      something goes wrong in the sigreturn */
   ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);

   VG_(sigframe_destroy)(tid, False);

   /* For unclear reasons, it appears we need the syscall to return
      without changing %EAX.  Since %EAX is the return value, and can
      denote either success or failure, we must set up so that the
      driver logic copies it back unchanged.  Also, note %EAX is of
      the guest registers written by VG_(sigframe_destroy). */
   SET_STATUS_from_SysRes( VG_(mk_SysRes_x86_netbsdelf2)( tst->arch.vex.guest_EAX ) );

   /* Check to see if some any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

PRE(sys_modify_ldt)
{
   PRINT("sys_modify_ldt ( %d, %p, %d )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(int, "modify_ldt", int, func, void *, ptr,
                 unsigned long, bytecount);
   
   if (ARG1 == 0) {
      /* read the LDT into ptr */
      PRE_MEM_WRITE( "modify_ldt(ptr)", ARG2, ARG3 );
   }
   if (ARG1 == 1 || ARG1 == 0x11) {
      /* write the LDT with the entry pointed at by ptr */
      PRE_MEM_READ( "modify_ldt(ptr)", ARG2, sizeof(vki_modify_ldt_t) );
   }
   /* "do" the syscall ourselves; the kernel never sees it */
   SET_STATUS_from_SysRes( sys_modify_ldt( tid, ARG1, (void*)ARG2, ARG3 ) );

   if (ARG1 == 0 && SUCCESS && RES > 0) {
      POST_MEM_WRITE( ARG2, RES );
   }
}

PRE(sys_set_thread_area)
{
   PRINT("sys_set_thread_area ( %p )", ARG1);
   PRE_REG_READ1(int, "set_thread_area", struct user_desc *, u_info)
   PRE_MEM_READ( "set_thread_area(u_info)", ARG1, sizeof(vki_modify_ldt_t) );

   /* "do" the syscall ourselves; the kernel never sees it */
   SET_STATUS_from_SysRes( sys_set_thread_area( tid, (void *)ARG1 ) );
}

PRE(sys_get_thread_area)
{
   PRINT("sys_get_thread_area ( %p )", ARG1);
   PRE_REG_READ1(int, "get_thread_area", struct user_desc *, u_info)
   PRE_MEM_WRITE( "get_thread_area(u_info)", ARG1, sizeof(vki_modify_ldt_t) );

   /* "do" the syscall ourselves; the kernel never sees it */
   SET_STATUS_from_SysRes( sys_get_thread_area( tid, (void *)ARG1 ) );

   if (SUCCESS) {
      POST_MEM_WRITE( ARG1, sizeof(vki_modify_ldt_t) );
   }
}

// Parts of this are x86-specific, but the *PEEK* cases are generic.
// XXX: Why is the memory pointed to by ARG3 never checked?
PRE(sys_ptrace)
{
   PRINT("sys_ptrace ( %d, %d, %p, %p )", ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(int, "ptrace", 
                 long, request, long, pid, long, addr, long, data);
   switch (ARG1) {
   case VKI_PTRACE_PEEKTEXT:
   case VKI_PTRACE_PEEKDATA:
   case VKI_PTRACE_PEEKUSR:
      PRE_MEM_WRITE( "ptrace(peek)", ARG4, 
		     sizeof (long));
      break;
   case VKI_PTRACE_GETREGS:
      PRE_MEM_WRITE( "ptrace(getregs)", ARG4, 
		     sizeof (struct vki_user_regs_struct));
      break;
   case VKI_PTRACE_GETFPREGS:
      PRE_MEM_WRITE( "ptrace(getfpregs)", ARG4, 
		     sizeof (struct vki_user_i387_struct));
      break;
   case VKI_PTRACE_GETFPXREGS:
      PRE_MEM_WRITE( "ptrace(getfpxregs)", ARG4, 
                     sizeof(struct vki_user_fxsr_struct) );
      break;
   case VKI_PTRACE_SETREGS:
      PRE_MEM_READ( "ptrace(setregs)", ARG4, 
		     sizeof (struct vki_user_regs_struct));
      break;
   case VKI_PTRACE_SETFPREGS:
      PRE_MEM_READ( "ptrace(setfpregs)", ARG4, 
		     sizeof (struct vki_user_i387_struct));
      break;
   case VKI_PTRACE_SETFPXREGS:
      PRE_MEM_READ( "ptrace(setfpxregs)", ARG4, 
                     sizeof(struct vki_user_fxsr_struct) );
      break;
   default:
      break;
   }
}

POST(sys_ptrace)
{
   switch (ARG1) {
   case VKI_PTRACE_PEEKTEXT:
   case VKI_PTRACE_PEEKDATA:
   case VKI_PTRACE_PEEKUSR:
      POST_MEM_WRITE( ARG4, sizeof (long));
      break;
   case VKI_PTRACE_GETREGS:
      POST_MEM_WRITE( ARG4, sizeof (struct vki_user_regs_struct));
      break;
   case VKI_PTRACE_GETFPREGS:
      POST_MEM_WRITE( ARG4, sizeof (struct vki_user_i387_struct));
      break;
   case VKI_PTRACE_GETFPXREGS:
      POST_MEM_WRITE( ARG4, sizeof(struct vki_user_fxsr_struct) );
      break;
   default:
      break;
   }
}

static Addr deref_Addr ( ThreadId tid, Addr a, Char* s )
{
   Addr* a_p = (Addr*)a;
   PRE_MEM_READ( s, (Addr)a_p, sizeof(Addr) );
   return *a_p;
}
 
PRE(sys_ipc)
{
   PRINT("sys_ipc ( %d, %d, %d, %d, %p, %d )", ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   // XXX: this is simplistic -- some args are not used in all circumstances.
   PRE_REG_READ6(int, "ipc",
                 vki_uint, call, int, first, int, second, int, third,
                 void *, ptr, long, fifth)

   switch (ARG1 /* call */) {
   case VKI_SEMOP:
      ML_(generic_PRE_sys_semop)( tid, ARG2, ARG5, ARG3 );
      *flags |= SfMayBlock;
      break;
   case VKI_SEMGET:
      break;
   case VKI_SEMCTL:
   {
      UWord arg = deref_Addr( tid, ARG5, "semctl(arg)" );
      ML_(generic_PRE_sys_semctl)( tid, ARG2, ARG3, ARG4, arg );
      break;
   }
   case VKI_SEMTIMEDOP:
      ML_(generic_PRE_sys_semtimedop)( tid, ARG2, ARG5, ARG3, ARG6 );
      *flags |= SfMayBlock;
      break;
   case VKI_MSGSND:
      ML_(generic_PRE_sys_msgsnd)( tid, ARG2, ARG5, ARG3, ARG4 );
      if ((ARG4 & VKI_IPC_NOWAIT) == 0)
         *flags |= SfMayBlock;
      break;
   case VKI_MSGRCV:
   {
      Addr msgp;
      Word msgtyp;
 
      msgp = deref_Addr( tid,
			 (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgp),
			 "msgrcv(msgp)" );
      msgtyp = deref_Addr( tid,
			   (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgtyp),
			   "msgrcv(msgp)" );

      ML_(generic_PRE_sys_msgrcv)( tid, ARG2, msgp, ARG3, msgtyp, ARG4 );

      if ((ARG4 & VKI_IPC_NOWAIT) == 0)
         *flags |= SfMayBlock;
      break;
   }
   case VKI_MSGGET:
      break;
   case VKI_MSGCTL:
      ML_(generic_PRE_sys_msgctl)( tid, ARG2, ARG3, ARG5 );
      break;
   case VKI_SHMAT:
   {
      UWord w;
      PRE_MEM_WRITE( "shmat(raddr)", ARG4, sizeof(Addr) );
      w = ML_(generic_PRE_sys_shmat)( tid, ARG2, ARG5, ARG3 );
      if (w == 0)
         SET_STATUS_Failure( VKI_EINVAL );
      else
         ARG5 = w;
      break;
   }
   case VKI_SHMDT:
      if (!ML_(generic_PRE_sys_shmdt)(tid, ARG5))
	 SET_STATUS_Failure( VKI_EINVAL );
      break;
   case VKI_SHMGET:
      break;
   case VKI_SHMCTL: /* IPCOP_shmctl */
      ML_(generic_PRE_sys_shmctl)( tid, ARG2, ARG3, ARG5 );
      break;
   default:
      VG_(message)(Vg_DebugMsg, "FATAL: unhandled syscall(ipc) %d", ARG1 );
      VG_(core_panic)("... bye!\n");
      break; /*NOTREACHED*/
   }   
}

POST(sys_ipc)
{
   vg_assert(SUCCESS);
   switch (ARG1 /* call */) {
   case VKI_SEMOP:
   case VKI_SEMGET:
      break;
   case VKI_SEMCTL:
   {
      UWord arg = deref_Addr( tid, ARG5, "semctl(arg)" );
      ML_(generic_PRE_sys_semctl)( tid, ARG2, ARG3, ARG4, arg );
      break;
   }
   case VKI_SEMTIMEDOP:
   case VKI_MSGSND:
      break;
   case VKI_MSGRCV:
   {
      Addr msgp;
      Word msgtyp;

      msgp = deref_Addr( tid,
			 (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgp),
			 "msgrcv(msgp)" );
      msgtyp = deref_Addr( tid,
			   (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgtyp),
			   "msgrcv(msgp)" );

      ML_(generic_POST_sys_msgrcv)( tid, RES, ARG2, msgp, ARG3, msgtyp, ARG4 );
      break;
   }
   case VKI_MSGGET:
      break;
   case VKI_MSGCTL:
      ML_(generic_POST_sys_msgctl)( tid, RES, ARG2, ARG3, ARG5 );
      break;
   case VKI_SHMAT:
   {
      Addr addr;

      /* force readability. before the syscall it is
       * indeed uninitialized, as can be seen in
       * glibc/sysdeps/unix/sysv/linux/shmat.c */
      POST_MEM_WRITE( ARG4, sizeof( Addr ) );

      addr = deref_Addr ( tid, ARG4, "shmat(addr)" );
      if ( addr > 0 ) { 
         ML_(generic_POST_sys_shmat)( tid, addr, ARG2, ARG5, ARG3 );
      }
      break;
   }
   case VKI_SHMDT:
      ML_(generic_POST_sys_shmdt)( tid, RES, ARG5 );
      break;
   case VKI_SHMGET:
      break;
   case VKI_SHMCTL:
      ML_(generic_POST_sys_shmctl)( tid, RES, ARG2, ARG3, ARG5 );
      break;
   default:
      VG_(message)(Vg_DebugMsg,
		   "FATAL: unhandled syscall(ipc) %d",
		   ARG1 );
      VG_(core_panic)("... bye!\n");
      break; /*NOTREACHED*/
   }
}

PRE(old_mmap)
{
   /* struct mmap_arg_struct {           
         unsigned long addr;
         unsigned long len;
         unsigned long prot;
         unsigned long flags;
         unsigned long fd;
         unsigned long offset;
   }; */
   UWord a1, a2, a3, a4, a5, a6;

   UWord* args = (UWord*)ARG1;
   PRE_REG_READ1(long, "old_mmap", struct mmap_arg_struct *, args);
   PRE_MEM_READ( "old_mmap(args)", (Addr)args, 6*sizeof(UWord) );

   a1 = args[0];
   a2 = args[1];
   a3 = args[2];
   a4 = args[3];
   a5 = args[4];
   a6 = args[5];

   PRINT("old_mmap ( %p, %llu, %d, %d, %d, %d )",
         a1, (ULong)a2, a3, a4, a5, a6 );

   if (a2 == 0) {
      /* SuSV3 says: If len is zero, mmap() shall fail and no mapping
         shall be established. */
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   if (/*(a4 & VKI_MAP_FIXED) &&*/ (0 != (a1 & (VKI_PAGE_SIZE-1)))) {
      /* zap any misaligned addresses. */
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   if (a4 & VKI_MAP_FIXED) {
      if (!ML_(valid_client_addr)(a1, a2, tid, "old_mmap")) {
         PRINT("old_mmap failing: %p-%p\n", a1, a1+a2);
         SET_STATUS_Failure( VKI_ENOMEM );
      }
   } else {
      Addr a = VG_(find_map_space)(a1, a2, True);
      if (0) VG_(printf)("find_map_space(%p, %d) -> %p\n",a1,a2,a);
      if (a == 0 && a1 != 0) {
         a1 = VG_(find_map_space)(0, a2, True);
      }
      else
         a1 = a;
      if (a1 == 0)
         SET_STATUS_Failure( VKI_ENOMEM );
      else
         a4 |= VKI_MAP_FIXED;
   }

   if (! FAILURE) {
      SysRes res = VG_(mmap_native)((void*)a1, a2, a3, a4, a5, a6);
      SET_STATUS_from_SysRes(res);
      if (!res.isError) {
         vg_assert(ML_(valid_client_addr)(res.val, a2, tid, "old_mmap"));
         ML_(mmap_segment)( (Addr)res.val, a2, a3, a4, a5, a6 );
      }
   }

   if (0)
   VG_(printf)("old_mmap( %p, fixed %d ) -> %s(%p)\n", 
               args[0], 
               args[3]&VKI_MAP_FIXED, 
               FAILURE ? "Fail" : "Success", RES_unchecked);

   /* Stay sane */
   if (SUCCESS && (args[3] & VKI_MAP_FIXED))
      vg_assert(RES == args[0]);
}

// XXX: lstat64/fstat64/stat64 are generic, but not necessarily
// applicable to every architecture -- I think only to 32-bit archs.
// We're going to need something like linux/core_os32.h for such
// things, eventually, I think.  --njn
// for netbsd, these are just stubs, I have put the I die here macro
//   so that when an error is seen, it is tested and fixed The Right
// Way. By the way this involves pulling in the right stat64 structure
// from the sources, piece of cake :p
PRE(sys_lstat64)
{
	I_die_here;
/*    PRINT("sys_lstat64 ( %p(%s), %p )",ARG1,ARG1,ARG2); */
/*    PRE_REG_READ2(long, "lstat64", char *, file_name, struct stat64 *, buf); */
/*    PRE_MEM_RASCIIZ( "lstat64(file_name)", ARG1 ); */
/*    PRE_MEM_WRITE( "lstat64(buf)", ARG2, sizeof(struct vki_stat64) ); */
}

POST(sys_lstat64)
{
	I_die_here;
/*    vg_assert(SUCCESS); */
/*    if (RES == 0) { */
/*       POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) ); */
/*    } */
/* XXX -NetBSD first pull in a stat64 structure then fix this */
}

PRE(sys_stat64)
{
	I_die_here;
/*    PRINT("sys_stat64 ( %p, %p )",ARG1,ARG2); */
/*    PRE_REG_READ2(long, "stat64", char *, file_name, struct stat64 *, buf); */
/*    PRE_MEM_RASCIIZ( "stat64(file_name)", ARG1 ); */
/*    PRE_MEM_WRITE( "stat64(buf)", ARG2, sizeof(struct vki_stat64) ); */
}

POST(sys_stat64)
{
	I_die_here;
/*    POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) ); */
}

PRE(sys_fstat64)
{
	I_die_here;
/*    PRINT("sys_fstat64 ( %d, %p )",ARG1,ARG2); */
/*    PRE_REG_READ2(long, "fstat64", unsigned long, fd, struct stat64 *, buf); */
/*    PRE_MEM_WRITE( "fstat64(buf)", ARG2, sizeof(struct vki_stat64) ); */
}

POST(sys_fstat64)
{
	I_die_here;
/*    POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) ); */
}


/* Convert from non-RT to RT sigset_t's */
static 
void convert_sigset_to_rt(const vki_old_sigset_t *oldset, vki_sigset_t *set)
{
   VG_(sigemptyset)(set);
   set->sig[0] = *oldset;
}
PRE(sys_sigaction)
{
   struct vki_sigaction new, old;
   struct vki_sigaction *newp, *oldp;

   PRINT("sys_sigaction ( %d, %p, %p )", ARG1,ARG2,ARG3);
   PRE_REG_READ3(int, "sigaction",
                 int, signum, const struct old_sigaction *, act,
                 struct old_sigaction *, oldact);

   newp = oldp = NULL;

   if (ARG2 != 0) {
      struct vki_old_sigaction *sa = (struct vki_old_sigaction *)ARG2;
      PRE_MEM_READ( "rt_sigaction(act->sa_handler)", (Addr)&sa->ksa_handler, sizeof(sa->ksa_handler));
      PRE_MEM_READ( "rt_sigaction(act->sa_mask)", (Addr)&sa->sa_mask, sizeof(sa->sa_mask));
      PRE_MEM_READ( "rt_sigaction(act->sa_flags)", (Addr)&sa->sa_flags, sizeof(sa->sa_flags));
      if (sa->sa_flags & VKI_SA_RESTORER)
         PRE_MEM_READ( "rt_sigaction(act->sa_restorer)", (Addr)&sa->sa_restorer, sizeof(sa->sa_restorer));
   }

   if (ARG3 != 0) {
      PRE_MEM_WRITE( "sigaction(oldact)", ARG3, sizeof(struct vki_old_sigaction));
      oldp = &old;
   }

   //jrs 20050207: what?!  how can this make any sense?
   //if (VG_(is_kerror)(SYSRES))
   //   return;

   if (ARG2 != 0) {
      struct vki_old_sigaction *oldnew = (struct vki_old_sigaction *)ARG2;

      new.ksa_handler = oldnew->ksa_handler;
      new.sa_flags = oldnew->sa_flags;
      new.sa_restorer = oldnew->sa_restorer;
      convert_sigset_to_rt(&oldnew->sa_mask, &new.sa_mask);
      newp = &new;
   }

   SET_STATUS_from_SysRes( VG_(do_sys_sigaction)(ARG1, newp, oldp) );

   if (ARG3 != 0 && SUCCESS && RES == 0) {
      struct vki_old_sigaction *oldold = (struct vki_old_sigaction *)ARG3;

      oldold->ksa_handler = oldp->ksa_handler;
      oldold->sa_flags = oldp->sa_flags;
      oldold->sa_restorer = oldp->sa_restorer;
      oldold->sa_mask = oldp->sa_mask.sig[0];
   }
}

POST(sys_sigaction)
{
   vg_assert(SUCCESS);
   if (RES == 0 && ARG3 != 0)
      POST_MEM_WRITE( ARG3, sizeof(struct vki_old_sigaction));
}

PRE(sys_compat_ocreat)
{
   I_die_here;
}

PRE(sys_compat_lseek)
{
   I_die_here;
}

/* XXX: Do the following really have to be in here?  Not in ...netbsdelf2.c? */
/* From sys_socketcall */

PRE(sys_break)
{
   I_die_here;
}

POST(sys_break)
{
   I_die_here;
}

PRE(sys_compat_sigvec)
{
   I_die_here;
}

POST(sys_compat_sigvec)
{
   I_die_here;
}

PRE(sys_compat_sigblock)
{
   I_die_here;
}

PRE(sys_compat_sigsetmask)
{
   I_die_here;
}

PRE(sys_compat_sigsuspend)
{
   I_die_here;
}

PRE(sys_compat_sigstack)
{
   I_die_here;
}

POST(sys_compat_sigstack)
{
   I_die_here;
}

PRE(sys_compat_osemsys)
{
   I_die_here;
}

PRE(sys_compat_omsgsys)
{
   I_die_here;
}

PRE(sys_compat_oshmsys)
{
   I_die_here;
}

PRE(sys_syscall)
{
   I_die_here;
}

POST(sys_syscall)
{
   I_die_here;
}

PRE(sys_compat_semctl)
{
   I_die_here;
}

POST(sys_compat_semctl)
{
   I_die_here;
}

PRE(sys_semget)
{
   I_die_here;
}

PRE(sys_semop)
{
   I_die_here;
}

POST(sys_semop)
{
   I_die_here;
}

PRE(sys_compat_msgctl)
{
   I_die_here;
}

POST(sys_compat_msgctl)
{
   I_die_here;
}

PRE(sys_msgget)
{
   I_die_here;
}

PRE(sys_msgsnd)
{
   I_die_here;
}

PRE(sys_msgrcv)
{
   I_die_here;
}

POST(sys_msgrcv)
{
   I_die_here;
}

PRE(sys_shmat)
{
   I_die_here;
}

POST(sys_shmat)
{
   I_die_here;
}

PRE(sys_compat_shmctl)
{
   I_die_here;
}

POST(sys_compat_shmctl)
{
   I_die_here;
}

PRE(sys_shmdt)
{
   I_die_here;
}

POST(sys_shmdt)
{
   I_die_here;
}

PRE(sys_shmget)
{
   I_die_here;
}

POST(sys_shmget)
{
   I_die_here;
}

// XXX: Maybe we need a POST too
PRE(sys_minherit)
{
   I_die_here;
}

PRE(sys_getcontext)
{
   I_die_here;
}

POST(sys_getcontext)
{
   I_die_here;
}

PRE(sys_setcontext)
{
   I_die_here;
}

POST(sys_setcontext)
{
   I_die_here;
}

PRE(sys_lwp_create)
{
   I_die_here;
}

POST(sys_lwp_create)
{
   I_die_here;
}

PRE(sys_lwp_exit)
{
   I_die_here;
}

POST(sys_lwp_exit)
{
   I_die_here;
}

PRE(sys_lwp_self)
{
   I_die_here;
}

POST(sys_lwp_self)
{
   I_die_here;
}

PRE(sys_lwp_wait)
{
   I_die_here;
}

POST(sys_lwp_wait)
{
   I_die_here;
}

PRE(sys_lwp_suspend)
{
   I_die_here;
}

POST(sys_lwp_suspend)
{
   I_die_here;
}

PRE(sys_lwp_continue)
{
   I_die_here;
}

POST(sys_lwp_continue)
{
   I_die_here;
}
 
PRE(sys_lwp_wakeup)
{
   I_die_here;
}

POST(sys_lwp_wakeup)
{
   I_die_here;
}

PRE(sys_lwp_getprivate)
{
   I_die_here;
}

POST(sys_lwp_getprivate)
{
   I_die_here;
}

PRE(sys_lwp_setprivate)
{
   I_die_here;
}

POST(sys_lwp_setprivate)
{
   I_die_here;
}

PRE(sys_sa_register)
{
   I_die_here;
}

POST(sys_sa_register)
{
   I_die_here;
}

PRE(sys_sa_stacks)
{
   I_die_here;
}

POST(sys_sa_stacks)
{
   I_die_here;
}

PRE(sys_sa_enable)
{
   I_die_here;
}

POST(sys_sa_enable)
{
   I_die_here;
}

PRE(sys_sa_setconcurrency)
{
   I_die_here;
}

POST(sys_sa_setconcurrency)
{
   I_die_here;
}

PRE(sys_sa_yield)
{
   I_die_here;
}

POST(sys_sa_yield)
{
   I_die_here;
}

PRE(sys_sa_preempt)
{
   I_die_here;
}

POST(sys_sa_preempt)
{
   I_die_here;
}

PRE(sys_pmc_get_info)
{
   I_die_here;
}

POST(sys_pmc_get_info)
{
   I_die_here;
}

PRE(sys_pmc_control)
{
   I_die_here;
}

POST(sys_pmc_control)
{
   I_die_here;
}

PRE(sys_rasctl)
{
   I_die_here;
}

POST(sys_rasctl)
{
   I_die_here;
}

#undef PRE
#undef POST


/* ---------------------------------------------------------------------
   The x86/Linux syscall table
   ------------------------------------------------------------------ */

/* Add an x86-netbsd specific wrapper to a syscall table. */
#define PLAX_(sysno, name)    WRAPPER_ENTRY_X_(x86_netbsdelf2, sysno, name) 
#define PLAXY(sysno, name)    WRAPPER_ENTRY_XY(x86_netbsdelf2, sysno, name)


// This table maps from __NR_xxx syscall numbers (from
// linux/include/asm-i386/unistd.h) to the appropriate PRE/POST sys_foo()
// wrappers on x86 (as per sys_call_table in linux/arch/i386/kernel/entry.S).
//
// For those syscalls not handled by Valgrind, the annotation indicate its
// arch/OS combination, eg. */* (generic), */Linux (Linux only), ?/?
// (unknown).

// Importing NetBSD's syscall numbers : change what is necessary ,
// remove the pre and post wrappers or put in stubs that fail, again
// we will write it later when a program actually fails over it. 
const SyscallTableEntry ML_(syscall_table)[] = {
//zz    //   (restart_syscall)                             // 0
   GENX_(__NR_exit,              sys_exit),           // 1
   GENX_(__NR_fork,              sys_fork),           // 2
   GENXY(__NR_read,              sys_read),           // 3
   GENX_(__NR_write,             sys_write),          // 4

   GENXY(__NR_open,              sys_open),           // 5
   GENXY(__NR_close,             sys_close),          // 6
   GENXY(__NR_wait4,             sys_wait4),          // 7
   PLAX_(__NR_compat_43_ocreat,  sys_compat_ocreat),  // 8
   GENX_(__NR_link,              sys_link),           // 9

   GENX_(__NR_unlink,            sys_unlink),         // 10
//   GENX_(__NR_execve,            sys_execve),       // 11 obsolete 
   GENX_(__NR_chdir,             sys_chdir),          // 12
   GENX_(__NR_fchdir,            sys_fchdir),         // 13
   GENX_(__NR_mknod,             sys_mknod),          // 14

   GENX_(__NR_chmod,             sys_chmod),          // 15
   GENX_(__NR_chown,             sys_chown),          // 16 ## P
   GENX_(__NR_break,             sys_ni_syscall),     // 17
   NBSDXY(__NR_getfsstat,        sys_getfsstat),      // 18 
   PLAX_(__NR_compat_43_olseek,  sys_compat_lseek),   // 19

   GENX_(__NR_getpid,            sys_getpid),         // 20
   NBSDX_(__NR_mount,            sys_mount),          // 21
   NBSDX_(__NR_unmount,          sys_unmount),        // 22
   GENX_(__NR_setuid,            sys_setuid16),       // 23 ## P
   GENX_(__NR_getuid,            sys_getuid16),       // 24 ## P

   GENX_(__NR_geteuid,           sys_geteuid16),      // 25
   PLAXY(__NR_ptrace,            sys_ptrace),         // 26
   NBSDXY(__NR_recvmsg,          sys_recvmsg),        // 27
   NBSDX_(__NR_sendmsg,          sys_sendmsg),        // 28
   NBSDXY(__NR_recvfrom,         sys_recvfrom),       // 29

   NBSDXY(__NR_accept,           sys_accept),         // 30
   NBSDXY(__NR_getpeername,      sys_getpeername),    // 31
   NBSDXY(__NR_getsockname,      sys_getsockname),    // 32
   GENX_(__NR_access,            sys_access),         // 33
   NBSDX_(__NR_chflags,          sys_chflags),        // 34

   NBSDX_(__NR_fchflags,         sys_fchflags),       // 35
   GENX_(__NR_sync,              sys_sync),           // 36
   GENX_(__NR_kill,              sys_kill),           // 37
   NBSDXY(__NR_compat_43_stat43, sys_compat_stat),    // 38
   GENX_(__NR_getppid,           sys_getppid),        // 39

   NBSDXY(__NR_compat_43_lstat43,sys_compat_lstat),   // 40
   GENXY(__NR_dup,               sys_dup),            // 41
   GENXY(__NR_pipe,              sys_pipe),           // 42
   GENX_(__NR_getegid,           sys_getegid16),      // 43
   GENX_(__NR_profil,            sys_ni_syscall),     // 44

   GENX_(__NR_ktrace,            sys_ni_syscall),     // 45
   NBSDXY(__NR_compat_13_sigaction13, sys_compat_sigaction),     // 46
   GENX_(__NR_getgid,            sys_getgid16),       // 47
   NBSDXY(__NR_compat_13_sigprocmask13, sys_compat_sigprocmask), // 48
   NBSDX_(__NR___getlogin,       sys_getlogin),       // 49

   NBSDX_(__NR___setlogin,       sys_setlogin),       // 50
   GENX_(__NR_acct,              sys_acct),           // 51
   NBSDXY(__NR_compat_13_sigpending13, sys_compat_sigpending),   // 52
   NBSDXY(__NR_compat_13_sigaltstack13, sys_compat_sigaltstack), // 53
   GENXY(__NR_ioctl,             sys_ioctl),          // 54

   // Might as well , this sounds silly to implement in vgrind:
   GENX_(__NR_compat_12_oreboot, sys_ni_syscall),     // 55
   NBSDX_(__NR_revoke,           sys_revoke),         // 56
   GENX_(__NR_symlink,           sys_symlink),        // 57
   GENX_(__NR_readlink,          sys_readlink),       // 58
   GENX_(__NR_execve,            sys_execve),         // 59

   GENX_(__NR_umask,             sys_umask),          // 60
   GENX_(__NR_chroot,            sys_chroot),         // 61
   NBSDX_(__NR_compat_43_fstat43,sys_ni_syscall),     // 62
   NBSDX_(__NR_compat_43_ogetkerninfo,sys_ni_syscall),// 63
   NBSDX_(__NR_compat_43_ogetpagesize,sys_ni_syscall),// 64

   NBSDX_(__NR_compat_12_msync,  sys_ni_syscall),     // 65
   NBSDX_(__NR_vfork,            sys_vfork),          // 66
// (__NR_vread,     sys_vread),                       // 67 obsolete
// (__NR_vwrite,    sys_vwrite),                      // 68 obsolete
   NBSDX_(__NR_sbrk,             sys_ni_syscall),     // 69

   NBSDX_(__NR_sstk,             sys_ni_syscall),     // 70
   NBSDX_(__NR_compat_43_ommap,  sys_ni_syscall),     // 71 XXX
   NBSDX_(__NR_vadvise,          sys_ni_syscall),     // 72 Whats this? investigate
   NBSDX_(__NR_munmap,           sys_munmap),         // 73
   NBSDX_(__NR_mprotect,         sys_mprotect),       // 74

   NBSDX_(__NR_madvise,          sys_madvise),        // 75
// (__NR_vhangup,   sys_vhangup),                     // 76 obsolete
// (__NR_vlimit,    sys_vlimit),                      // 77 obsolete
   GENXY(__NR_mincore,           sys_mincore),        // 78
   GENXY(__NR_getgroups,         sys_getgroups16),    // 79

   GENX_(__NR_setgroups,         sys_setgroups16),    // 80
   GENX_(__NR_getpgrp,           sys_getpgrp),        // 81
   GENX_(__NR_setpgid,           sys_setpgid),        // 82
   GENXY(__NR_setitimer,         sys_setitimer),      // 83
   NBSDXY(__NR_compat_43_owait,  sys_compat_owait),   // 84

   NBSDX_(__NR_compat_12_oswapon,sys_compat_oswapon), // 85
   GENXY(__NR_getitimer,         sys_getitimer),      // 86
   NBSDXY(__NR_compat_43_ogethostname,   sys_compat_ogethostname),  // 87
   NBSDX_(__NR_compat_43_osethostname,   sys_compat_osethostname),  // 88
   NBSDX_(__NR_compat_43_ogetdtablesize, sys_compat_ogetdtablesize),// 89

   GENXY(__NR_dup2,              sys_dup2),           // 90
   GENX_(91,                     sys_ni_syscall),     // 91
   GENXY(__NR_fcntl,             sys_fcntl),          // 92
// XXX: Old or new select?
   PLAX_(__NR_select,            old_select),         // 93
   GENX_(94,                     sys_ni_syscall),     // 94

   GENX_(__NR_fsync,             sys_fsync),          // 95
   GENX_(__NR_setpriority,       sys_setpriority),    // 96
   NBSDXY(__NR_socket,           sys_socket),         // 97
   NBSDXY(__NR_connect,          sys_connect),        // 98
   NBSDXY(__NR_compat_43_oaccept,sys_compat_oaccept), // 99

   GENX_(__NR_getpriority,       sys_getpriority),    // 100
   NBSDX_(__NR_compat_43_osend,  sys_compat_osend),   // 101
   NBSDXY(__NR_compat_43_orecv,  sys_compat_orecv),   // 102
   // XXX: Can we just use sys_sigreturn here?
   PLAX_(__NR_compat_13_sigreturn13, sys_sigreturn),  // 103
   NBSDXY(__NR_bind,             sys_bind),           // 104

   NBSDX_(__NR_setsockopt,       sys_setsockopt),     // 105
   NBSDXY(__NR_listen,           sys_listen),         // 106
// (__NR_vtimes,    sys_vtimes),                      // 107 obsolete
   PLAXY(__NR_compat_43_osigvec,  sys_compat_sigvec), // 108
// XXX: Maybe this should be PLAXY?
   PLAX_(__NR_compat_43_osigblock,sys_compat_sigblock),// 109

// XXX: Maybe these two should be PLAXY?
   PLAX_(__NR_compat_43_osigsetmask,sys_compat_sigsetmask),   // 110
   PLAX_(__NR_compat_13_sigsuspend13,sys_compat_sigsuspend),  // 111
   PLAXY(__NR_compat_43_osigstack,  sys_compat_sigstack),     // 112  XXX What's this?
   NBSDXY(__NR_recvmsg,          sys_compat_orecvmsg),// 113
   NBSDX_(__NR_sendmsg,          sys_compat_osendmsg),// 114

// (__NR_vtrace,    sys_vtrace),                      // 115 obsolete
   GENXY(__NR_gettimeofday,      sys_gettimeofday),   // 116
   GENXY(__NR_getrusage,         sys_getrusage),      // 117
   NBSDXY(__NR_getsockopt,       sys_getsockopt),     // 118
// (__NR_resuba,    sys_resuba),                      // 119 obsolete

   GENXY(__NR_readv,             sys_readv),          // 120
   GENX_(__NR_writev,            sys_writev),         // 121
   GENX_(__NR_settimeofday,      sys_settimeofday),   // 122
   GENX_(__NR_fchown,            sys_fchown16),       // 123
   GENX_(__NR_fchmod,            sys_fchmod),         // 124

   NBSDXY(__NR_compat_43_orecvfrom, sys_compat_orecvfrom), // 125
   GENX_(__NR_setreuid,          sys_setreuid16),     // 126
   GENX_(__NR_setregid,          sys_setregid16),     // 127
   GENX_(__NR_rename,            sys_rename),         // 128
   NBSDX_(__NR_compat_43_otruncate, sys_compat_otruncate),  // 129

   NBSDX_(__NR_compat_43_oftruncate,sys_compat_oftruncate), // 130
   GENX_(__NR_flock,             sys_flock),          // 131
   NBSDX_(__NR_mkfifo,           sys_mkfifo),         // 132
   NBSDX_(__NR_sendto,           sys_sendto),         // 133  (not PLAX_?)
   NBSDXY(__NR_shutdown,         sys_shutdown),       // 134  (not PLAXY?)

   NBSDXY(__NR_socketpair,       sys_socketpair),     // 135
   GENX_(__NR_mkdir,             sys_mkdir),          // 136
   GENX_(__NR_rmdir,             sys_rmdir),          // 137
   GENX_(__NR_utimes,            sys_utimes),         // 138
// (__NR_compat_42_osigreturn,   sys_compat_osigreturn), // 139 obsolete

   NBSDXY(__NR_adjtime,          sys_adjtime),        // 140
   NBSDXY(__NR_compat_43_ogetpeername,sys_compat_ogetpeername), // 141
   NBSDXY(__NR_compat_43_ogethostid,  sys_compat_ogethostid),   // 142
   NBSDX_(__NR_compat_43_osethostid,  sys_compat_osethostid),   // 143
// XXX?
   GENXY(__NR_compat_43_ogetrlimit, sys_getrlimit),   // 144

// XXX?
   GENX_(__NR_compat_43_osetrlimit, sys_ni_syscall),   // 145
   NBSDX_(__NR_compat_43_okillpg,sys_compat_okillpg), // 146
   GENX_(__NR_setsid,            sys_setsid),         // 147
   GENX_(__NR_quotactl,          sys_quotactl),       // 148
   NBSDX_(__NR_compat_43_oquota, sys_compat_oquota),  // 149 XXX What's this?

   NBSDXY(__NR_compat_43_ogetsockname,sys_compat_ogetsockname),// 150
   GENX_(151,                    sys_ni_syscall),     // 151
   GENX_(152,                    sys_ni_syscall),     // 152
   GENX_(153,                    sys_ni_syscall),     // 153
   GENX_(154,                    sys_ni_syscall),     // 154

// XXX: Linux equivalent?
   NBSDXY(__NR_nfssvc,           sys_nfssvc),         // 155
   NBSDXY(__NR_compat_43_ogetdirentries, sys_compat_ogetdirentries), // 156
   GENXY(__NR_statfs,            sys_statfs),         // 157
   GENXY(__NR_fstatfs,           sys_fstatfs),        // 158
   GENX_(159,                    sys_ni_syscall),     // 159

   GENX_(160,                    sys_ni_syscall),     // 160
   NBSDXY(__NR_getfh,            sys_getfh),          // 161
   NBSDXY(__NR_compat_09_ogetdomainname, sys_compat_ogetdomainname), // 162
   NBSDX_(__NR_compat_09_osetdomainname, sys_compat_osetdomainname), // 163
   NBSDXY(__NR_compat_09_ouname, sys_compat_uname),   // 164

   NBSDXY(__NR_sysarch,          sys_sysarch),        // 165  XXX What's this?
   GENX_(166,                    sys_ni_syscall),     // 166
   GENX_(167,                    sys_ni_syscall),     // 167
   GENX_(168,                    sys_ni_syscall),     // 168
   PLAX_(__NR_compat_10_osemsys, sys_compat_osemsys), // 169  XXX What's this?

   PLAX_(__NR_compat_10_omsgsys, sys_compat_omsgsys), // 170  XXX What's this?
   PLAX_(__NR_compat_10_oshmsys, sys_compat_oshmsys), // 171  XXX What's this?
   GENX_(172,                    sys_ni_syscall),     // 172
   NBSDXY(__NR_pread,            sys_pread),          // 173
   NBSDX_(__NR_pwrite,           sys_pwrite),         // 174

   NBSDXY(__NR_ntp_gettime,      sys_ntp_gettime),    // 175
   NBSDXY(__NR_ntp_adjtime,      sys_ntp_adjtime),    // 176
   GENX_(177,                    sys_ni_syscall),     // 177
   GENX_(178,                    sys_ni_syscall),     // 178
   GENX_(179,                    sys_ni_syscall),     // 179

   GENX_(180,                    sys_ni_syscall),     // 180
   GENX_(__NR_setgid,            sys_setgid16),       // 181
   NBSDX_(__NR_setegid,          sys_setegid),        // 182
   NBSDX_(__NR_seteuid,          sys_seteuid),        // 183
   NBSDXY(__NR_lfs_bmapv,        sys_lfs_bmapv),      // 184

   NBSDXY(__NR_lfs_markv,        sys_lfs_markv),      // 185  XXX Is this an XY?
   NBSDXY(__NR_lfs_segclean,     sys_lfs_segclean),   // 186  XXX Same here; XY?
   NBSDXY(__NR_lfs_segwait,      sys_lfs_segwait),    // 187  XXX Same here; XY?
   NBSDXY(__NR_compat_12_stat12, sys_compat_stat),    // 188  XXX sys_compat_stat is originally for compat_43_stat.  Think of better naming?
   NBSDXY(__NR_compat_12_fstat12,sys_compat_fstat),   // 189  XXX sys_compat_fstat is originally for compat_43_fstat.  Think of better naming?

   NBSDXY(__NR_compat_12_lstat12,sys_compat_lstat),   // 190  XXX sys_compat_lstat is originally for compat_43_lstat.  Think of better naming?
   NBSDXY(__NR_pathconf,         sys_pathconf),       // 191
   NBSDXY(__NR_fpathconf,        sys_fpathconf),      // 192
   GENX_(193,                    sys_ni_syscall),     // 193
   GENXY(__NR_getrlimit,         sys_old_getrlimit),  // 194

   GENX_(__NR_setrlimit,         sys_setrlimit),      // 195
   NBSDXY(__NR_compat_12_getdirentries, sys_compat_getdirentries), // 196
   PLAX_(__NR_mmap,              old_mmap),           // 197
   PLAXY(__NR___syscall,         sys_syscall),        // 198
   GENX_(__NR_lseek,             sys_lseek),          // 199

   GENX_(__NR_truncate,          sys_truncate),       // 200
   GENX_(__NR_ftruncate,         sys_ftruncate),      // 201
   NBSDXY(__NR___sysctl,         sys_sysctl),         // 202
   GENX_(__NR_mlock,             sys_mlock),          // 203
   GENX_(__NR_munlock,           sys_munlock),        // 204

   NBSDX_(__NR_undelete,         sys_undelete),       // 205
   NBSDX_(__NR_futimes,          sys_futimes),        // 206
   GENX_(__NR_getpgid,           sys_getpgid),        // 207
   // Might as well , this sounds silly to implement in vgrind:
   GENX_(__NR_reboot,            sys_ni_syscall),     // 208
   GENXY(__NR_poll,              sys_poll),           // 209

   GENX_(210,                    sys_ni_syscall),     // 210
   GENX_(211,                    sys_ni_syscall),     // 211
   GENX_(212,                    sys_ni_syscall),     // 212
   GENX_(213,                    sys_ni_syscall),     // 213
   GENX_(214,                    sys_ni_syscall),     // 214

   GENX_(215,                    sys_ni_syscall),     // 215
   GENX_(216,                    sys_ni_syscall),     // 216
   GENX_(217,                    sys_ni_syscall),     // 217
   GENX_(218,                    sys_ni_syscall),     // 218
   GENX_(219,                    sys_ni_syscall),     // 219

   PLAXY(__NR_compat_14___semctl,sys_compat_semctl),  // 220
   PLAX_(__NR_semget,            sys_semget),         // 221
   PLAXY(__NR_semop,             sys_semop),          // 222   (maybe PLAX_)
   PLAX_(__NR_semconfig,         sys_semop),          // 223   What's this?
   PLAXY(__NR_compat_14_msgctl,  sys_compat_msgctl),  // 224

   PLAX_(__NR_msgget,            sys_msgget),         // 225
   PLAX_(__NR_msgsnd,            sys_msgsnd),         // 226
   PLAXY(__NR_msgrcv,            sys_msgrcv),         // 227
   PLAXY(__NR_shmat,             sys_shmat),          // 228
   PLAXY(__NR_compat_14_shmctl,  sys_compat_shmctl),  // 229

   PLAXY(__NR_shmdt,             sys_shmdt),          // 230
   PLAXY(__NR_shmget,            sys_shmget),         // 231
// XXX: Note: There may be trouble here.  stuff like (timer_create+7) in the
//       linux versions may indicate a stupid reliance on position of
//       timer_create in the syscall table.
   GENXY(__NR_clock_gettime,     sys_clock_gettime),  // 232
   GENX_(__NR_clock_settime,     sys_clock_settime),  // 233
   GENXY(__NR_clock_getres,      sys_clock_getres),   // 234

   GENXY(__NR_timer_create,      sys_timer_create),   // 235
   GENX_(__NR_timer_delete,      sys_timer_delete),   // 236
   GENXY(__NR_timer_settime,     sys_timer_settime),  // 237
   GENXY(__NR_timer_gettime,     sys_timer_gettime),  // 238
   GENX_(__NR_timer_getoverrun,  sys_timer_getoverrun),// 239

   GENXY(__NR_nanosleep,         sys_nanosleep),      // 240
   GENX_(__NR_fdatasync,         sys_fdatasync),      // 241
   GENX_(__NR_mlockall,          sys_mlockall),       // 242
   GENX_(__NR_munlockall,        sys_munlockall),     // 243
// XXX: Is this really the same as rt_sigtimedwait??
   GENX_(__NR___sigtimedwait,    sys_rt_sigtimedwait),// 244

   GENX_(__NR__ksem_init,        sys_ni_syscall),     // 247  XXX: What's this?
   GENX_(__NR__ksem_open,        sys_ni_syscall),     // 248  XXX: What's this?
   GENX_(__NR__ksem_unlink,      sys_ni_syscall),     // 249  XXX: What's this?

   GENX_(__NR__ksem_close,       sys_ni_syscall),     // 250  XXX: What's this?
   GENX_(__NR__ksem_post,        sys_ni_syscall),     // 251  XXX: What's this?
   GENX_(__NR__ksem_wait,        sys_ni_syscall),     // 252  XXX: What's this?
   GENX_(__NR__ksem_trywait,     sys_ni_syscall),     // 253  XXX: What's this?
   GENX_(__NR__ksem_getvalue,    sys_ni_syscall),     // 254  XXX: What's this?

   GENX_(__NR__ksem_destroy,     sys_ni_syscall),     // 255  XXX: What's this?
   GENX_(256,                    sys_ni_syscall),     // 256
   GENX_(257,                    sys_ni_syscall),     // 257
   GENX_(258,                    sys_ni_syscall),     // 258
   GENX_(259,                    sys_ni_syscall),     // 259

   GENX_(260,                    sys_ni_syscall),     // 260
   GENX_(261,                    sys_ni_syscall),     // 261
   GENX_(262,                    sys_ni_syscall),     // 262
   GENX_(263,                    sys_ni_syscall),     // 263
   GENX_(264,                    sys_ni_syscall),     // 264

   GENX_(265,                    sys_ni_syscall),     // 265
   GENX_(266,                    sys_ni_syscall),     // 266
   GENX_(267,                    sys_ni_syscall),     // 267
   GENX_(268,                    sys_ni_syscall),     // 268
   GENX_(269,                    sys_ni_syscall),     // 269

// Only slightly different semantics from normal rename call
   GENX_(__NR___posix_rename,    sys_rename),         // 270
   NBSDXY(__NR_swapctl,          sys_swapctl),        // 271
   GENXY(__NR_getdents,          sys_getdents),       // 272
   PLAX_(__NR_minherit,          sys_minherit),       // 273
   PLAX_(__NR_minherit,          sys_minherit),       // 273
// The following 3 funcs only differ in behaviour on symlinks from their
// non-l-prefixed versions (so valgrind doesn't have to do anything else)
   GENX_(__NR_lchmod,            sys_chmod),          // 274

   GENX_(__NR_lchown,            sys_lchown),         // 275
   GENX_(__NR_lutimes,           sys_utimes),         // 276
// XXX: Can we just use the normal versions of these functions?
   GENX_(__NR___msync13,         sys_msync),          // 277
   GENXY(__NR___stat13,          sys_newstat),        // 278
   GENXY(__NR___lstat13,         sys_newlstat),       // 279

   GENXY(__NR___fstat13,         sys_newfstat),       // 280
// XXX: Same thing?
   GENXY(__NR___sigaltstack14,   sys_sigaltstack),    // 281
// XXX: Can we just use the normal vfork routine (which is fork)?
   GENX_(__NR___vfork14,         sys_fork),           // 282
// Only slightly different semantics from normal chown/fchown/lchown call
   GENX_(__NR___posix_chown,     sys_chown),          // 283
   GENX_(__NR___posix_fchown,    sys_fchown16),       // 284

   GENX_(__NR___posix_lchown,    sys_lchown),         // 285
   GENX_(__NR_getsid,            sys_getsid),         // 286
   PLAX_(__NR___clone,           sys_clone),          // 287
   GENX_(__NR_fktrace,           sys_ni_syscall),     // 288 XXX: ktrace too ni_
   NBSDXY(__NR_preadv,           sys_preadv),         // 289

   NBSDX_(__NR_pwritev,          sys_pwritev),        // 290
// XXX: Are the following funcs the same thing?
   PLAXY(__NR_compat_16___sigaction14, sys_sigaction),// 291
   GENXY(__NR___sigpending14,    sys_sigpending),     // 292
   GENXY(__NR___sigprocmask14,   sys_sigprocmask),    // 293
   GENX_(__NR___sigsuspend14,    sys_sigsuspend),     // 294

   PLAX_(__NR_compat_16___sigreturn14, sys_sigreturn),// 295
   GENXY(__NR___getcwd,          sys_getcwd),         // 296
   NBSDX_(__NR_fchroot,          sys_fchroot),        // 297
   NBSDXY(__NR_fhopen,           sys_fhopen),         // 298
   NBSDXY(__NR_fhstat,           sys_fhstat),         // 299

   NBSDXY(__NR_fhstatfs,         sys_fhstatfs),       // 300
// XXX: Same thing?
   PLAXY(__NR_____semctl13,      sys_compat_semctl),  // 301
   PLAXY(__NR___msgctl13,        sys_compat_msgctl),  // 302
   PLAXY(__NR___shmctl13,        sys_compat_shmctl),  // 303
// Again, just slightly diff semantics on symlinks..
   NBSDX_(__NR_lchflags,         sys_chflags),        // 304

   NBSDX_(__NR_issetugid,        sys_issetugid),      // 305
   GENX_(__NR_utrace,            sys_ni_syscall),     // 306
   PLAXY(__NR_getcontext,        sys_getcontext),     // 307
   PLAXY(__NR_setcontext,        sys_setcontext),     // 308
   PLAXY(__NR__lwp_create,       sys_lwp_create),     // 309

   PLAXY(__NR__lwp_exit,         sys_lwp_exit),       // 310
   PLAXY(__NR__lwp_self,         sys_lwp_self),       // 311
   PLAXY(__NR__lwp_wait,         sys_lwp_wait),       // 312
   PLAXY(__NR__lwp_suspend,      sys_lwp_suspend),    // 313
   PLAXY(__NR__lwp_continue,     sys_lwp_continue),   // 314
 
   PLAXY(__NR__lwp_wakeup,       sys_lwp_wakeup),     // 315
   PLAXY(__NR__lwp_getprivate,   sys_lwp_getprivate), // 316
   PLAXY(__NR__lwp_setprivate,   sys_lwp_setprivate), // 317
   GENX_(318,                    sys_ni_syscall),     // 318
   GENX_(319,                    sys_ni_syscall),     // 319

   GENX_(320,                    sys_ni_syscall),     // 320
   GENX_(321,                    sys_ni_syscall),     // 321
   GENX_(322,                    sys_ni_syscall),     // 322
   GENX_(323,                    sys_ni_syscall),     // 323
   GENX_(324,                    sys_ni_syscall),     // 324

   GENX_(325,                    sys_ni_syscall),     // 325
   GENX_(326,                    sys_ni_syscall),     // 326
   GENX_(327,                    sys_ni_syscall),     // 327
   GENX_(328,                    sys_ni_syscall),     // 328
   GENX_(329,                    sys_ni_syscall),     // 329

// XXX: Prolly some of these can be PLAX_  (not sure if it's PLA* or NBSD* or
//        even GEN*, though (scheduler activations are theoretically not nbsd
//        specific, but this API may be...))
   PLAXY(__NR_sa_register,       sys_sa_register),    // 330
   PLAXY(__NR_sa_stacks,         sys_sa_stacks),      // 331
   PLAXY(__NR_sa_enable,         sys_sa_enable),      // 332
   PLAXY(__NR_sa_setconcurrency, sys_sa_setconcurrency),  // 333
   PLAXY(__NR_sa_yield,          sys_sa_yield),       // 334

   PLAXY(__NR_sa_preempt,        sys_sa_preempt),     // 335
   GENX_(336,                    sys_ni_syscall),     // 336
   GENX_(337,                    sys_ni_syscall),     // 337
   GENX_(338,                    sys_ni_syscall),     // 338
   GENX_(339,                    sys_ni_syscall),     // 339

// XXX: What to do with the trampoline stuff?
   GENX_(__NR___sigaction_sigtramp, sys_ni_syscall),  // 340
   PLAXY(__NR_pmc_get_info,      sys_pmc_get_info),   // 341
// XXX: Looks like this can just be a PLAX_ instead
   PLAXY(__NR_pmc_control,       sys_pmc_control),    // 342
   PLAXY(__NR_rasctl,            sys_rasctl),         // 343
   NBSDXY(__NR_kqueue,           sys_kqueue),         // 344

   NBSDXY(__NR_kevent,           sys_kevent),         // 345
   GENX_(346,                    sys_ni_syscall),     // 346
   GENX_(347,                    sys_ni_syscall),     // 347
   GENX_(348,                    sys_ni_syscall),     // 348
   GENX_(349,                    sys_ni_syscall),     // 349

   GENX_(350,                    sys_ni_syscall),     // 350
   GENX_(351,                    sys_ni_syscall),     // 351
   GENX_(352,                    sys_ni_syscall),     // 352
   GENX_(353,                    sys_ni_syscall),     // 353
   NBSDX_(__NR_fsync_range,      sys_fsync_range),    // 354

   NBSDXY(__NR_uuidgen,          sys_uuidgen)         // 355
};

const UInt ML_(syscall_table_size) = 
            sizeof(ML_(syscall_table)) / sizeof(ML_(syscall_table)[0]);

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
