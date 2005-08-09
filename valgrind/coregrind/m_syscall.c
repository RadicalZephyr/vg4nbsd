
/*--------------------------------------------------------------------*/
/*--- Doing syscalls.                                  m_syscall.c ---*/
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
#include "pub_core_syscall.h"

/* ---------------------------------------------------------------------
   Building syscall return values.
   ------------------------------------------------------------------ */

/* Make a SysRes value from an syscall return value.  This is
   Linux-specific.

   From:
   http://sources.redhat.com/cgi-bin/cvsweb.cgi/libc/sysdeps/unix/sysv/
   linux/i386/sysdep.h?
   rev=1.28&content-type=text/x-cvsweb-markup&cvsroot=glibc

   Linux uses a negative return value to indicate syscall errors,
   unlike most Unices, which use the condition codes' carry flag.

   Since version 2.1 the return value of a system call might be
   negative even if the call succeeded.  E.g., the 'lseek' system call
   might return a large offset.  Therefore we must not anymore test
   for < 0, but test for a real error by making sure the value in %eax
   is a real error number.  Linus said he will make sure the no
   syscall returns a value in -1 .. -4095 as a valid result so we can
   safely test with -4095.
*/
SysRes VG_(mk_SysRes) ( UWord val ) {
   SysRes res;
#if defined(VGP_x86_linux)
   res.isError = val >= -4095 && val <= -1;
   res.val     = res.isError ? -val : val;
#elif defined(VGP_amd64_linux)
   res.isError = val >= -4095 && val <= -1;
   res.val     = res.isError ? -val : val;
#elif defined(VGP_x86_netbsdelf2)
   res.isError = val >= -4095 && val <= -1; /* XXX -NetBSD */
   res.val     = res.isError ? -val : val;

#else
#  error Unknown platform
#endif
   return res;
}

SysRes VG_(mk_SysRes_Error) ( UWord val ) {
   SysRes r = { val, True };
   return r;
}

SysRes VG_(mk_SysRes_Success) ( UWord val ) {
   SysRes r = { val, False };
   return r;
}


/* ---------------------------------------------------------------------
   A function for doing syscalls.
   ------------------------------------------------------------------ */

static UWord do_syscall_WRK (
          UWord syscall_no, 
          UWord a1, UWord a2, UWord a3,
          UWord a4, UWord a5, UWord a6
       );
#if defined(VGP_x86_netbsdelf2)
asm(
    /* its easier for us, we need syscall number in eax, and its
       argument in stack, do_syscall pushes the arguments into the
          stack, then the syscall number, then ..something , pop that
          something into ecx , pop the syscall number into eax. push
          back that something onto the stack and we are good to go */
      
    "do_syscall_WRK:\n"
    "popl %ecx\n"
    "popl %eax\n"
    "push %ecx\n"
    "int $0x80\n"
    "push %ecx\n"
    "jae 1f\n"
    "movl $-1,%eax\n"
    "1:\n"
    "ret\n"
    );

/*
 * All args on the stack, syscall number in %eax.
 */
/* asm( */
/* "do_syscall_WRK:\n" */
/* "	movl	4+ 1(%esp),%eax\n"	/\* Put syscall no in eax and *\/ */
/* "	movl	4+ 4(%esp),%ebx\n"	/\* copy all other arguments over *\/ */
/* "	push	%ebx\n"			/\* to form a new stack for the *\/ */
/* "	movl	8+ 8(%esp),%ebx\n"	/\* syscall.  I don't really like *\/ */
/* "	push	%ebx\n"			/\* this.  But hey, who likes x86 *\/ */
/* "	movl	16+ 16(%esp),%ebx\n"	/\* asm at all? *\/ */
/* "	push	%ebx\n" */
/* "	movl	20+ 20(%esp),%ebx\n" */
/* "	push	%ebx\n" */
/* "	movl	24+ 24(%esp),%ebx\n" */
/* "	push	%ebx\n" */
/* "	movl	28+ 28(%esp),%ebx\n" */
/* "	push	%ebx\n" */
/* "	pushl	do_syscall_WRK_ret\n"	/\* Push new return value *\/ */
/* "	int	$0x80\n" */
/* "do_syscall_WRK_ret:\n" */
/* "	popl    %ebx\n"			/\* Pop return value *\/ */
/* "	addl	24, %esp\n"		/\* Remove all 6 args *\/ */
/* "	pushl	%ebx\n"			/\* Before returning, re-push retval *\/ */
/* "	ret\n" */
/* ); */
#elif defined(VGP_x86_linux)
/* Incoming args (syscall number + up to 6 args) come on the stack.
   (ie. the C calling convention).

   The syscall number goes in %eax.  The args are passed to the syscall in
   the regs %ebx, %ecx, %edx, %esi, %edi, %ebp, ie. the kernel's syscall
   calling convention.

   %eax gets the return value.  Not sure which registers the kernel
   clobbers, so we preserve all the callee-save regs (%esi, %edi, %ebx,
   %ebp).
*/
asm(
"do_syscall_WRK:\n"
"	push	%esi\n"
"	push	%edi\n"
"	push	%ebx\n"
"	push	%ebp\n"
"	movl	16+ 4(%esp),%eax\n"
"	movl	16+ 8(%esp),%ebx\n"
"	movl	16+12(%esp),%ecx\n"
"	movl	16+16(%esp),%edx\n"
"	movl	16+20(%esp),%esi\n"
"	movl	16+24(%esp),%edi\n"
"	movl	16+28(%esp),%ebp\n"
"	int	$0x80\n"
"	popl	%ebp\n"
"	popl	%ebx\n"
"	popl	%edi\n"
"	popl	%esi\n"
"	ret\n"
);
#elif defined(VGP_amd64_linux)
/* Incoming args (syscall number + up to 6 args) come in %rdi, %rsi,
   %rdx, %rcx, %r8, %r9, and the last one on the stack (ie. the C
   calling convention).

   The syscall number goes in %rax.  The args are passed to the syscall in
   the regs %rdi, %rsi, %rdx, %r10, %r8, %r9 (yes, really %r10, not %rcx),
   ie. the kernel's syscall calling convention.

   %rax gets the return value.  %rcx and %r11 are clobbered by the syscall;
   no matter, they are caller-save (the syscall clobbers no callee-save
   regs, so we don't have to do any register saving/restoring).
*/
asm(
"do_syscall_WRK:\n"
        /* Convert function calling convention --> syscall calling
           convention */
"	movq	%rdi, %rax\n"
"	movq	%rsi, %rdi\n"
"	movq	%rdx, %rsi\n"
"	movq	%rcx, %rdx\n"
"	movq	%r8,  %r10\n"
"	movq	%r9,  %r8\n"
"	movq    8(%rsp), %r9\n"	 /* last arg from stack */
"	syscall\n"
"	ret\n"
);
#else
#  error Unknown platform
#endif

SysRes VG_(do_syscall) ( UWord sysno, UWord a1, UWord a2, UWord a3,
                                      UWord a4, UWord a5, UWord a6 )
{
   UWord val = do_syscall_WRK(sysno,a1,a2,a3,a4,a5,a6);
   return VG_(mk_SysRes)( val );
}

/*--------------------------------------------------------------------*/
/*--- end                                                        ---*/
/*--------------------------------------------------------------------*/
