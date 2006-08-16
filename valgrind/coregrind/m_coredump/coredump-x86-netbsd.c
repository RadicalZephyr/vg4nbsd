
/*--------------------------------------------------------------------*/
/*--- Dumping core.                          coredump-x86-netbsd.c ---*/
/*--------------------------------------------------------------------*/

/***
 * XXX Sjamaan: Sure this is OS-specific?  This is just a copy of the
 * Linux code.  We should take a closer look at this.
 */
 
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
#include "pub_core_coredump.h"
#include "pub_core_threadstate.h"

#include "priv_elf.h"

void ML_(fill_elfregs_from_tst)(struct vki_user_regs_struct* regs, 
                                const ThreadArchState* arch)
{
   regs->r_eflags = LibVEX_GuestX86_get_eflags( &((ThreadArchState*)arch)->vex );
   regs->r_esp    = arch->vex.guest_ESP;
   regs->r_eip    = arch->vex.guest_EIP;

   regs->r_ebx    = arch->vex.guest_EBX;
   regs->r_ecx    = arch->vex.guest_ECX;
   regs->r_edx    = arch->vex.guest_EDX;
   regs->r_esi    = arch->vex.guest_ESI;
   regs->r_edi    = arch->vex.guest_EDI;
   regs->r_ebp    = arch->vex.guest_EBP;
   regs->r_eax    = arch->vex.guest_EAX;

   regs->r_cs     = arch->vex.guest_CS;
   regs->r_ds     = arch->vex.guest_DS;
   regs->r_ss     = arch->vex.guest_SS;
   regs->r_es     = arch->vex.guest_ES;
   regs->r_fs     = arch->vex.guest_FS;
   regs->r_gs     = arch->vex.guest_GS;
}

//:: static void fill_fpu(vki_elf_fpregset_t *fpu, const Char *from)
//:: {
//::    if (VG_(have_ssestate)) {
//::       UShort *to;
//::       Int i;
//:: 
//::       /* This is what the kernel does */
//::       VG_(memcpy)(fpu, from, 7*sizeof(long));
//::    
//::       to = (UShort *)&fpu->st_space[0];
//::       from += 18 * sizeof(UShort);
//:: 
//::       for (i = 0; i < 8; i++, to += 5, from += 8) 
//:: 	 VG_(memcpy)(to, from, 5*sizeof(UShort));
//::    } else
//::       VG_(memcpy)(fpu, from, sizeof(*fpu));
//:: }

void ML_(fill_elffpregs_from_tst)(vki_elf_fpregset_t* fpu,
                                  const ThreadArchState* arch)
{
//::    fill_fpu(fpu, (const Char *)&arch->m_sse);
}

void ML_(fill_elffpxregs_from_tst)(vki_elf_fpxregset_t* xfpu,
                                   const ThreadArchState* arch)
{
//::    xfpu->cwd = ?;
//::    xfpu->swd = ?;
//::    xfpu->twd = ?;
//::    xfpu->fop = ?;
//::    xfpu->fip = ?;
//::    xfpu->fcs = ?;
//::    xfpu->foo = ?;
//::    xfpu->fos = ?;
//::    xfpu->mxcsr = ?;
   xfpu->reserved = 0;
//::    xfpu->st_space = ?;

#  define DO(n)  VG_(memcpy)(xfpu->xmm_space + n * 4, &arch->vex.guest_XMM##n, sizeof(arch->vex.guest_XMM##n))
   DO(0);  DO(1);  DO(2);  DO(3);  DO(4);  DO(5);  DO(6);  DO(7);
#  undef DO

   VG_(memset)(xfpu->padding, 0, sizeof(xfpu->padding));
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
