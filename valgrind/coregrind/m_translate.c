
/*--------------------------------------------------------------------*/
/*--- The JITter proper: register allocation & code improvement    ---*/
/*---                                                m_translate.c ---*/
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
#include "pub_core_aspacemgr.h"

#include "pub_core_machine.h"       // For VG_(machine_get_VexArchInfo)
                                    // and VG_(get_SP)
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_options.h"
#include "pub_core_profile.h"

#include "pub_core_debuginfo.h"     // Needed for pub_core_redir :(
#include "pub_core_redir.h"         // For VG_(code_redirect)()

#include "pub_core_signals.h"       // For VG_(synth_fault_{perms,mapping})()
#include "pub_core_stacks.h"        // For VG_(unknown_SP_update)()
#include "pub_core_tooliface.h"     // For VG_(tdict)
#include "pub_core_translate.h"
#include "pub_core_transtab.h"


/*------------------------------------------------------------*/
/*--- %SP-update pass                                      ---*/
/*------------------------------------------------------------*/

static Bool need_to_handle_SP_assignment(void)
{
   return ( VG_(tdict).track_new_mem_stack_4  ||
            VG_(tdict).track_die_mem_stack_4  ||
            VG_(tdict).track_new_mem_stack_8  ||
            VG_(tdict).track_die_mem_stack_8  ||
            VG_(tdict).track_new_mem_stack_12 ||
            VG_(tdict).track_die_mem_stack_12 ||
            VG_(tdict).track_new_mem_stack_16 ||
            VG_(tdict).track_die_mem_stack_16 ||
            VG_(tdict).track_new_mem_stack_32 ||
            VG_(tdict).track_die_mem_stack_32 ||
            VG_(tdict).track_new_mem_stack    ||
            VG_(tdict).track_die_mem_stack    );
}

/* NOTE: this comment is out of date */

/* For tools that want to know about %ESP changes, this pass adds
   in the appropriate hooks.  We have to do it after the tool's
   instrumentation, so the tool doesn't have to worry about the CCALLs
   it adds in, and we must do it before register allocation because
   spilled temps make it much harder to work out the %esp deltas.
   Thus we have it as an extra phase between the two. 
   
   We look for "GETL %ESP, t_ESP", then track ADDs and SUBs of
   literal values to t_ESP, and the total delta of the ADDs/SUBs.  Then if
   "PUTL t_ESP, %ESP" happens, we call the helper with the known delta.  We
   also cope with "MOVL t_ESP, tX", making tX the new t_ESP.  If any other
   instruction clobbers t_ESP, we don't track it anymore, and fall back to
   the delta-is-unknown case.  That case is also used when the delta is not
   a nice small amount, or an unknown amount.
*/

static
IRBB* vg_SP_update_pass ( IRBB*             bb_in, 
                          VexGuestLayout*   layout, 
                          Addr64            orig_addr_noredir,
                          VexGuestExtents*  vge,
                          IRType            gWordTy, 
                          IRType            hWordTy )
{
   Int      i, j, minoff_ST, maxoff_ST, sizeof_SP, offset_SP;
   IRDirty  *dcall, *d;
   IRStmt*  st;
   IRExpr*  e;
   IRArray* descr;
   IRTemp   curr;
   IRType   typeof_SP;
   Long     delta;

   /* Set up BB */
   IRBB* bb     = emptyIRBB();
   bb->tyenv    = dopyIRTypeEnv(bb_in->tyenv);
   bb->next     = dopyIRExpr(bb_in->next);
   bb->jumpkind = bb_in->jumpkind;

   curr  = IRTemp_INVALID;
   delta = 0;

   sizeof_SP = layout->sizeof_SP;
   offset_SP = layout->offset_SP;
   typeof_SP = sizeof_SP==4 ? Ity_I32 : Ity_I64;
   vg_assert(sizeof_SP == 4 || sizeof_SP == 8);

#  define IS_ADD(op) (sizeof_SP==4 ? ((op)==Iop_Add32) : ((op)==Iop_Add64))
#  define IS_SUB(op) (sizeof_SP==4 ? ((op)==Iop_Sub32) : ((op)==Iop_Sub64))

#  define IS_ADD_OR_SUB(op) (IS_ADD(op) || IS_SUB(op))

#  define GET_CONST(con)                                                \
       (sizeof_SP==4 ? (Long)(Int)(con->Ico.U32)                        \
                     : (Long)(con->Ico.U64))

#  define DO(kind, syze)                                                \
      do {                                                              \
         if (!VG_(tdict).track_##kind##_mem_stack_##syze) \
            goto generic;                                               \
                                                                        \
         /* I don't know if it's really necessary to say that the */    \
         /* call reads the stack pointer.  But anyway, we do. */        \
         dcall = unsafeIRDirty_0_N(                                     \
                    1/*regparms*/,                                      \
                    "track_" #kind "_mem_stack_" #syze,                 \
                    VG_(tdict).track_##kind##_mem_stack_##syze,         \
                    mkIRExprVec_1(IRExpr_Tmp(curr))                     \
                 );                                                     \
         dcall->nFxState = 1;                                           \
         dcall->fxState[0].fx     = Ifx_Read;                           \
         dcall->fxState[0].offset = layout->offset_SP;                  \
         dcall->fxState[0].size   = layout->sizeof_SP;                  \
                                                                        \
         addStmtToIRBB( bb, IRStmt_Dirty(dcall) );                      \
      } while (0)

   for (i = 0; i <  bb_in->stmts_used; i++) {

      st = bb_in->stmts[i];
      if (!st)
         continue;

      /* t = Get(sp):   curr = t, delta = 0 */
      if (st->tag != Ist_Tmp) goto case2;
      e = st->Ist.Tmp.data;
      if (e->tag != Iex_Get)              goto case2;
      if (e->Iex.Get.offset != offset_SP) goto case2;
      if (e->Iex.Get.ty != typeof_SP)     goto case2;
      curr = st->Ist.Tmp.tmp;
      delta = 0;
      addStmtToIRBB( bb, st );
      continue;

     case2:
      /* t' = curr +/- const:   curr = t',  delta +=/-= const */
      if (st->tag != Ist_Tmp) goto case3;
      e = st->Ist.Tmp.data;
      if (e->tag != Iex_Binop) goto case3;
      if (e->Iex.Binop.arg1->tag != Iex_Tmp) goto case3;
      if (e->Iex.Binop.arg1->Iex.Tmp.tmp != curr) goto case3;
      if (e->Iex.Binop.arg2->tag != Iex_Const) goto case3;
      if (!IS_ADD_OR_SUB(e->Iex.Binop.op)) goto case3;
      curr = st->Ist.Tmp.tmp;
      if (IS_ADD(e->Iex.Binop.op))
         delta += GET_CONST(e->Iex.Binop.arg2->Iex.Const.con);
      else
         delta -= GET_CONST(e->Iex.Binop.arg2->Iex.Const.con);
      addStmtToIRBB( bb, st );
      continue;

     case3:
      /* t' = curr:   curr = t' */
      if (st->tag != Ist_Tmp) goto case4;
      e = st->Ist.Tmp.data;
      if (e->tag != Iex_Tmp) goto case4;
      if (e->Iex.Tmp.tmp != curr) goto case4;
      curr = st->Ist.Tmp.tmp;
      addStmtToIRBB( bb, st );
      continue;

     case4:
      /* Put(sp) = curr */
      if (st->tag != Ist_Put) goto case5;
      if (st->Ist.Put.offset != offset_SP) goto case5;
      if (st->Ist.Put.data->tag != Iex_Tmp) goto case5;
      if (st->Ist.Put.data->Iex.Tmp.tmp == curr) {
         switch (delta) {
            case   0:              addStmtToIRBB(bb,st); delta = 0; continue;
            case   4: DO(die, 4);  addStmtToIRBB(bb,st); delta = 0; continue;
            case  -4: DO(new, 4);  addStmtToIRBB(bb,st); delta = 0; continue;
            case   8: DO(die, 8);  addStmtToIRBB(bb,st); delta = 0; continue;
            case  -8: DO(new, 8);  addStmtToIRBB(bb,st); delta = 0; continue;
            case  12: DO(die, 12); addStmtToIRBB(bb,st); delta = 0; continue;
            case -12: DO(new, 12); addStmtToIRBB(bb,st); delta = 0; continue;
            case  16: DO(die, 16); addStmtToIRBB(bb,st); delta = 0; continue;
            case -16: DO(new, 16); addStmtToIRBB(bb,st); delta = 0; continue;
            case  32: DO(die, 32); addStmtToIRBB(bb,st); delta = 0; continue;
            case -32: DO(new, 32); addStmtToIRBB(bb,st); delta = 0; continue;
            default:  goto generic;
         }
      } else {
         IRTemp old_SP;
        generic:
         /* Pass both the old and new SP values to this helper. */
         old_SP = newIRTemp(bb->tyenv, typeof_SP);
         addStmtToIRBB( 
            bb,
            IRStmt_Tmp( old_SP, IRExpr_Get(offset_SP, typeof_SP) ) 
         );

         dcall = unsafeIRDirty_0_N( 
                    2/*regparms*/, 
                    "VG_(unknown_SP_update)", &VG_(unknown_SP_update),
                    mkIRExprVec_2( IRExpr_Tmp(old_SP), st->Ist.Put.data ) 
                 );
         addStmtToIRBB( bb, IRStmt_Dirty(dcall) );

         addStmtToIRBB( bb, st );

         curr = st->Ist.Put.data->Iex.Tmp.tmp;
         delta = 0;
         continue;
      }

     case5:
      /* PutI or Dirty call which overlaps SP: complain.  We can't
         deal with SP changing in weird ways (well, we can, but not at
         this time of night).  */
      if (st->tag == Ist_PutI) {
         descr = st->Ist.PutI.descr;
         minoff_ST = descr->base;
         maxoff_ST = descr->base + descr->nElems * sizeofIRType(descr->elemTy) - 1;
         if (!(offset_SP > maxoff_ST || (offset_SP + sizeof_SP - 1) < minoff_ST))
            goto complain;
      }
      if (st->tag == Ist_Dirty) {
         d = st->Ist.Dirty.details;
         for (j = 0; j < d->nFxState; j++) {
            minoff_ST = d->fxState[j].offset;
            maxoff_ST = d->fxState[j].offset + d->fxState[j].size - 1;
            if (d->fxState[j].fx == Ifx_Read || d->fxState[j].fx == Ifx_None)
               continue;
            if (!(offset_SP > maxoff_ST || (offset_SP + sizeof_SP - 1) < minoff_ST))
               goto complain;
         }
      }

      /* well, not interesting.  Just copy and keep going. */
      addStmtToIRBB( bb, st );

   } /* for (i = 0; i <  bb_in->stmts_used; i++) */

   return bb;

  complain:
   VG_(core_panic)("vg_SP_update_pass: PutI or Dirty which overlaps SP");

}


/*------------------------------------------------------------*/
/*--- Main entry point for the JITter.                     ---*/
/*------------------------------------------------------------*/

/* Extra comments re self-checking translations and self-modifying
   code.  (JRS 14 Oct 05).

   There are 3 modes:
   (1) no checking: all code assumed to be not self-modifying
   (2) partial: known-problematic situations get a self-check
   (3) full checking: all translations get a self-check

   As currently implemented, the default is (2).  (3) is always safe,
   but very slow.  (1) works mostly, but fails for gcc nested-function
   code which uses trampolines on the stack; this situation is
   detected and handled by (2).

   ----------

   A more robust and transparent solution, which is not currently
   implemented, is a variant of (2): if a translation is made from an
   area which aspacem says does not have 'w' permission, then it can
   be non-self-checking.  Otherwise, it needs a self-check.

   This is complicated by Vex's basic-block chasing.  If a self-check
   is requested, then Vex will not chase over basic block boundaries
   (it's too complex).  However there is still a problem if it chases
   from a non-'w' area into a 'w' area.

   I think the right thing to do is:

   - if a translation request starts in a 'w' area, ask for a
     self-checking translation, and do not allow any chasing (make
     chase_into_ok return False).  Note that the latter is redundant
     in the sense that Vex won't chase anyway in this situation.

   - if a translation request starts in a non-'w' area, do not ask for
     a self-checking translation.  However, do not allow chasing (as
     determined by chase_into_ok) to go into a 'w' area.

   The result of this is that all code inside 'w' areas is self
   checking.

   To complete the trick, there is a caveat: we must watch the
   client's mprotect calls.  If pages are changed from non-'w' to 'w'
   then we should throw away all translations which intersect the
   affected area, so as to force them to be redone with self-checks.

   ----------

   The above outlines the conditions under which bb chasing is allowed
   from a self-modifying-code point of view.  There are other
   situations pertaining to function redirection in which it is
   necessary to disallow chasing, but those fall outside the scope of
   this comment.
*/

/* Vex dumps the final code in here.  Then we can copy it off
   wherever we like. */
#define N_TMPBUF 20000
static UChar tmpbuf[N_TMPBUF];

/* Function pointers we must supply to LibVEX in order that it
   can bomb out and emit messages under Valgrind's control. */
__attribute__ ((noreturn))
static
void failure_exit ( void )
{
   LibVEX_ShowAllocStats();
   VG_(core_panic)("LibVEX called failure_exit().");
}

static
void log_bytes ( HChar* bytes, Int nbytes )
{
  Int i;
  for (i = 0; i < nbytes-3; i += 4)
     VG_(printf)("%c%c%c%c", bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]);
  for (; i < nbytes; i++) 
     VG_(printf)("%c", bytes[i]);
}

/* Translate the basic block beginning at orig_addr, and add it to
   the translation cache & translation table.  Unless 'debugging' is true,
   in which case the call is being done for debugging purposes, so
   (a) throw away the translation once it is made, and (b) produce a
   load of debugging output. 

   'tid' is the identity of the thread needing this block.
*/

/* Look for reasons to disallow making translations from the given
   segment. */

static Bool translations_allowable_from_seg ( NSegment* seg )
{
#  if defined(VGA_x86)
   Bool allowR = True;
#  else
   Bool allowR = False;
#  endif

   return seg != NULL
          && (seg->kind == SkAnonC || seg->kind == SkFileC)
          && (seg->hasX || (seg->hasR && allowR));
}



/* This stops Vex from chasing into function entry points that we wish
   to redirect.  Chasing across them obviously defeats the redirect
   mechanism, with bad effects for Memcheck, Addrcheck, and possibly
   others.

   Also, we must stop Vex chasing into blocks for which we might want
   to self checking.

   This fn needs to know also the tid of the requesting thread, but
   it can't be passed in as a parameter since this fn is passed to
   Vex and that has no notion of tids.  So we clumsily pass it as
   a global, chase_into_ok__CLOSURE_tid.
*/
static ThreadId chase_into_ok__CLOSURE_tid;
static Bool     chase_into_ok ( Addr64 addr64 )
{
   NSegment* seg;

   /* Work through a list of possibilities why we might not want to
      allow a chase. */
   Addr addr = (Addr)addr64;

   /* All chasing disallowed if all bbs require self-checks. */
   if (VG_(clo_smc_check) == Vg_SmcAll)
      goto dontchase;

   /* Check the segment permissions. */
   seg = VG_(am_find_nsegment)(addr);
   if (!translations_allowable_from_seg(seg))
      goto dontchase;

   /* AAABBBCCC: if default self-checks are in force, reject if we
      would choose to have a self-check for the dest.  Note, this must
      match the logic at XXXYYYZZZ below. */
   if (VG_(clo_smc_check) == Vg_SmcStack) {
      ThreadId tid = chase_into_ok__CLOSURE_tid;
      if (seg
          && (seg->kind == SkAnonC || seg->kind == SkFileC)
          && seg->start <= VG_(get_SP)(tid)
          && VG_(get_SP)(tid)+sizeof(Word)-1 <= seg->end)
         goto dontchase;
   }

   /* Destination is redirected? */
   if (addr != VG_(code_redirect)(addr))
      goto dontchase;

   /* well, ok then.  go on and chase. */
   return True;

   vg_assert(0);
   /*NOTREACHED*/

  dontchase:
   if (0) VG_(printf)("not chasing into 0x%x\n", addr);
   return False;
}


Bool VG_(translate) ( ThreadId tid, 
                      Addr64   orig_addr,
                      Bool     debugging_translation,
                      Int      debugging_verbosity,
                      ULong    bbs_done )
{
   Addr64             redir, orig_addr_noredir = orig_addr;
   Int                tmpbuf_used, verbosity, i;
   Bool               notrace_until_done, do_self_check;
   UInt               notrace_until_limit = 0;
   NSegment*          seg;
   VexArch            vex_arch;
   VexArchInfo        vex_archinfo;
   VexGuestExtents    vge;
   VexTranslateResult tres;

   /* Make sure Vex is initialised right. */

   static Bool vex_init_done = False;

   if (!vex_init_done) {
      LibVEX_Init ( &failure_exit, &log_bytes, 
                    1,     /* debug_paranoia */ 
                    False, /* valgrind support */
                    &VG_(clo_vex_control) );
      vex_init_done = True;
   }

   /* profiling ... */
   VGP_PUSHCC(VgpTranslate);

   /* Look in the code redirect table to see if we should
      translate an alternative address for orig_addr. */
   redir = VG_(code_redirect)(orig_addr);

   if (redir != orig_addr && VG_(clo_verbosity) >= 2) {
      Bool ok;
      Char name1[64] = "";
      Char name2[64] = "";
      name1[0] = name2[0] = 0;
      ok = VG_(get_fnname_w_offset)(orig_addr, name1, 64);
      if (!ok) VG_(strcpy)(name1, "???");
      ok = VG_(get_fnname_w_offset)(redir, name2, 64);
      if (!ok) VG_(strcpy)(name2, "???");
      VG_(message)(Vg_DebugMsg, 
                   "REDIR: 0x%llx (%s) redirected to 0x%llx (%s)",
                   orig_addr, name1,
                   redir, name2 );
   }
   orig_addr = redir;

   /* If codegen tracing, don't start tracing until
      notrace_until_limit blocks have gone by.  This avoids printing
      huge amounts of useless junk when all we want to see is the last
      few blocks translated prior to a failure.  Set
      notrace_until_limit to be the number of translations to be made
      before --trace-codegen= style printing takes effect. */
   notrace_until_done
      = VG_(get_bbs_translated)() >= notrace_until_limit;

   if (!debugging_translation)
      VG_TRACK( pre_mem_read, Vg_CoreTranslate, 
                              tid, "(translator)", orig_addr, 1 );

   /* If doing any code printing, print a basic block start marker */
   if (VG_(clo_trace_flags) || debugging_translation) {
      Char fnname[64] = "";
      VG_(get_fnname_w_offset)(orig_addr, fnname, 64);
      VG_(printf)(
              "==== BB %d %s(0x%llx) BBs exec'd %lld ====\n",
              VG_(get_bbs_translated)(), fnname, orig_addr, 
              bbs_done);
   }

   /* Are we allowed to translate here? */

   seg = VG_(am_find_nsegment)(orig_addr);

   if (!translations_allowable_from_seg(seg)) {
      /* U R busted, sonny.  Place your hands on your head and step
         away from the orig_addr. */
      /* Code address is bad - deliver a signal instead */
      if (seg != NULL) {
         /* There's some kind of segment at the requested place, but we
            aren't allowed to execute code here. */
         VG_(synth_fault_perms)(tid, orig_addr);
      } else {
        /* There is no segment at all; we are attempting to execute in
           the middle of nowhere. */
         VG_(synth_fault_mapping)(tid, orig_addr);
      }
      return False;
   }

   /* Do we want a self-checking translation? */
   do_self_check = False;
   switch (VG_(clo_smc_check)) {
      case Vg_SmcNone:  do_self_check = False; break;
      case Vg_SmcAll:   do_self_check = True;  break;
      case Vg_SmcStack: 
         /* XXXYYYZZZ: must match the logic at AAABBBCCC above */
         do_self_check
            /* = seg ? toBool(seg->flags & SF_GROWDOWN) : False; */
            = seg 
              ? (seg->start <= VG_(get_SP)(tid)
                 && VG_(get_SP)(tid)+sizeof(Word)-1 <= seg->end)
              : False;
         break;
      default: 
         vg_assert2(0, "unknown VG_(clo_smc_check) value");
   }

   /* True if a debug trans., or if bit N set in VG_(clo_trace_codegen). */
   verbosity = 0;
   if (debugging_translation) {
      verbosity = debugging_verbosity;
   }
   else
   if ( (VG_(clo_trace_flags) > 0
        && VG_(get_bbs_translated)() >= VG_(clo_trace_notbelow) )) {
      verbosity = VG_(clo_trace_flags);
   }

   VGP_PUSHCC(VgpVexTime);
   
   /* ------ Actually do the translation. ------ */
   tl_assert2(VG_(tdict).tool_instrument,
              "you forgot to set VgToolInterface function 'tool_instrument'");

   /* Get the CPU info established at startup. */
   VG_(machine_get_VexArchInfo)( &vex_arch, &vex_archinfo );

   /* Set up closure arg for "chase_into_ok" */
   chase_into_ok__CLOSURE_tid = tid;

   tres = LibVEX_Translate ( 
             vex_arch, &vex_archinfo,
             vex_arch, &vex_archinfo,
             (UChar*)ULong_to_Ptr(orig_addr), 
             (Addr64)orig_addr, 
             (Addr64)orig_addr_noredir, 
             chase_into_ok,
             &vge,
             tmpbuf, N_TMPBUF, &tmpbuf_used,
             VG_(tdict).tool_instrument,
             need_to_handle_SP_assignment()
                ? vg_SP_update_pass
                : NULL,
             True, /* cleanup after instrumentation */
             do_self_check,
             NULL,
             verbosity
          );

   vg_assert(tres == VexTransOK);
   vg_assert(tmpbuf_used <= N_TMPBUF);
   vg_assert(tmpbuf_used > 0);

   VGP_POPCC(VgpVexTime);

   /* Tell aspacem of all segments that have had translations taken
      from them.  Optimisation: don't re-look up vge.base[0] since seg
      should already point to it. */

   vg_assert( vge.base[0] == (Addr64)orig_addr );
   if (seg->kind == SkFileC || seg->kind == SkAnonC)
      seg->hasT = True; /* has cached code */

   for (i = 1; i < vge.n_used; i++) {
      seg = VG_(am_find_nsegment)( vge.base[i] );
      if (seg->kind == SkFileC || seg->kind == SkAnonC)
         seg->hasT = True; /* has cached code */
   }

   /* Copy data at trans_addr into the translation cache. */
   vg_assert(tmpbuf_used > 0 && tmpbuf_used < 65536);

   // If debugging, don't do anything with the translated block;  we
   // only did this for the debugging output produced along the way.
   if (!debugging_translation) {
      // Note that we use orig_addr_noredir, not orig_addr, which
      // might have been changed by the redirection
      VG_(add_to_transtab)( &vge,
                            orig_addr_noredir,
                            (Addr)(&tmpbuf[0]), 
                            tmpbuf_used,
                            do_self_check );
   }

   VGP_POPCC(VgpTranslate);

   return True;
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

