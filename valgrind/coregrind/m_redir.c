/*--------------------------------------------------------------------*/
/*--- Management of function redirection and wrapping.             ---*/
/*---                                                   vg_redir.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an extensible x86 protected-mode
   emulator for monitoring program execution on x86-Unixes.

   Copyright (C) 2000-2005 Julian Seward 
      jseward@acm.org
   Copyright (C) 2003-2005 Jeremy Fitzhardinge
      jeremy@goop.org

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
#include "pub_core_debuginfo.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_redir.h"
#include "pub_core_skiplist.h"
#include "pub_core_trampoline.h"
#include "pub_core_transtab.h"

/*------------------------------------------------------------*/
/*--- General purpose redirection.                         ---*/
/*------------------------------------------------------------*/

#define TRACE_REDIR(format, args...) \
   if (VG_(clo_trace_redir)) { VG_(message)(Vg_DebugMsg, format, ## args); }

/*
  wraps and redirections, indexed by from_addr

  Redirection and wrapping are two distinct mechanisms which Valgrind
  can use to change the client's control flow.

  Redirection intercepts a call to a client function, and re-points it
  to a new piece of code (presumably functionally equivalent).  The
  original code is never run.

  Wrapping does call the client's original code, but calls "before"
  and "after" functions which can inspect (and perhaps modify) the
  function's arguments and return value.
 */
struct _CodeRedirect {
   enum redir_type {
      R_REDIRECT,		/* plain redirection */
      R_WRAPPER,		/* wrap with valgrind-internal code */
      R_CLIENT_WRAPPER,		/* wrap with client-side code */
   }		type;
   
   const Char	*from_lib;	/* library qualifier pattern */
   const Char	*from_sym;	/* symbol */
   Addr		from_addr;	/* old addr */

   Addr		to_addr;	/* used for redirection -- new addr */
   const FuncWrapper *wrapper;  /* used for wrapping */

   CodeRedirect *next;	        /* next pointer on unresolved list */
};

static Char *straddr(void *p)
{
   static Char buf[16];
   VG_(sprintf)(buf, "%p", *(Addr *)p);
   return buf;
}

static SkipList sk_resolved_redirs = 
   VG_SKIPLIST_INIT(CodeRedirect, from_addr, VG_(cmp_Addr), 
                    straddr, VG_AR_SYMTAB);

static CodeRedirect *unresolved_redirs = NULL;

static Bool soname_matches(const Char *pattern, const Char* soname)
{
   // pattern must start with "soname:"
   vg_assert(NULL != pattern);
   vg_assert(0 == VG_(strncmp)(pattern, "soname:", 7));

   if (NULL == soname)
      return False;
   
   return VG_(string_match)(pattern + 7, soname);
}

Bool VG_(is_resolved)(const CodeRedirect *redir)
{
   return redir->from_addr != 0;
}

// Prepends redir to the unresolved list.
static void add_redir_to_unresolved_list(CodeRedirect *redir)
{
   redir->next = unresolved_redirs;
   unresolved_redirs = redir;
}

static void add_redir_to_resolved_list(CodeRedirect *redir, Bool need_discard)
{
   vg_assert(redir->from_addr);

   switch (redir->type) {
   case R_REDIRECT: {
      CodeRedirect* r;
   
      TRACE_REDIR("  redir resolved (%s:%s=%p -> %p)", 
                  redir->from_lib, redir->from_sym, redir->from_addr,
                  redir->to_addr);

      vg_assert(redir->to_addr != 0);

      if (need_discard) {
         /* For some given (from, to) redir, the "from" function got
            loaded before the .so containing "to" became available so
            we need to discard any existing translations involving
            the "from" function.

            Note, we only really need to discard the first bb of the
            old entry point, and so we avoid the problem of having to
            figure out how big that bb was -- since it is at least 1
            byte of original code, we can just pass 1 as the original
            size to invalidate_translations() and it will indeed get
            rid of the translation. 

            Note, this is potentially expensive -- discarding
            translations requires a complete search through all of
            them.
         */
         TRACE_REDIR("Discarding translation due to redirect of already loaded function" );
         TRACE_REDIR("   %s:%s(%p) -> %p)", redir->from_lib, redir->from_sym,
                                            redir->from_addr, redir->to_addr );
         VG_(discard_translations)((Addr64)redir->from_addr, 1);
      }

      r = VG_(SkipList_Find_Exact)(&sk_resolved_redirs, &redir->from_addr);

      if (r == NULL) {
         VG_(SkipList_Insert)(&sk_resolved_redirs, redir);
      } else {
         /* XXX leak redir */
         TRACE_REDIR("  redir %s:%s:%p->%p duplicated\n",
                     redir->from_lib, redir->from_sym, redir->from_addr,
                     redir->to_addr);
      }
      break;
   }

   case R_WRAPPER:
      TRACE_REDIR("  wrapper resolved (%s:%s=%p -> wrapper)",
                  redir->from_lib, redir->from_sym, redir->from_addr);

      vg_assert(redir->wrapper);

      /* XXX redir leaked */
      //VG_(wrap_function)(redir->from_addr, redir->wrapper);
      break;

   case R_CLIENT_WRAPPER:
      vg_assert(redir->wrapper);
      VG_(core_panic)("not implemented");
      break;
   }
}

// Resolve a redir using si if possible.  Returns True if it succeeded.
static Bool resolve_redir_with_seginfo(CodeRedirect *redir, const SegInfo *si)
{
   Bool ok;

   vg_assert(si != NULL);
   vg_assert(redir->from_addr == 0 );
   vg_assert(redir->from_sym  != NULL);

   // Resolved if the soname matches and we find the symbol.
   ok = soname_matches(redir->from_lib, VG_(seginfo_soname)(si));
   if (ok) {
      redir->from_addr = VG_(reverse_search_one_symtab)(si, redir->from_sym);
      ok = ( redir->from_addr == 0 ? False : True );
   }
   return ok;   
}

// Resolve a redir using any SegInfo if possible.  This is called whenever
// a new sym-to-addr redir is created.  It covers the case where a
// replacement function is loaded after its replacee.
static Bool resolve_redir_with_existing_seginfos(CodeRedirect *redir)
{
   const SegInfo *si;

   for (si = VG_(next_seginfo)(NULL); 
        si != NULL; 
        si = VG_(next_seginfo)(si))
   {
      if (resolve_redir_with_seginfo(redir, si))
	 return True;
   }
   return False;
}

// Resolve as many unresolved redirs as possible with this SegInfo.  This
// should be called when a new SegInfo symtab is loaded.  It covers the case
// where a replacee function is loaded after its replacement function.
void VG_(resolve_existing_redirs_with_seginfo)(SegInfo *si)
{
   CodeRedirect **prevp = &unresolved_redirs;
   CodeRedirect *redir, *next;

   TRACE_REDIR("Just loaded %s (soname=%s),",
               VG_(seginfo_filename)(si), VG_(seginfo_soname)(si));
   TRACE_REDIR(" resolving any unresolved redirs with it");

   // Visit each unresolved redir - if it becomes resolved, then
   // move it from the unresolved list to the resolved list.
   for (redir = unresolved_redirs; redir != NULL; redir = next) {
      next = redir->next;

      if (resolve_redir_with_seginfo(redir, si)) {
	 *prevp = next;
	 redir->next = NULL;
         add_redir_to_resolved_list(redir, False);
      } else
	 prevp = &redir->next;
   }

   TRACE_REDIR(" Finished resolving");
}

/* Redirect a function at from_addr to a function at to_addr */
__attribute__((unused))    // It is used, but not on all platforms...
static void add_redirect_addr_to_addr( Addr from_addr, Addr to_addr )
{
   CodeRedirect *redir = VG_(SkipNode_Alloc)(&sk_resolved_redirs);

   vg_assert(0 != from_addr && 0 != to_addr);

   redir->type      = R_REDIRECT;

   redir->from_lib  = NULL;
   redir->from_sym  = NULL;
   redir->from_addr = from_addr;

   redir->to_addr   = to_addr;
   redir->wrapper   = 0;

   TRACE_REDIR("REDIRECT addr to addr: %p to %p", from_addr, to_addr);

   // This redirection is already resolved, put it straight in the list.
   add_redir_to_resolved_list(redir, True);
}

/* Redirect a lib/symbol reference to a function at addr */
static void add_redirect_sym_to_addr(
   const Char *from_lib, const Char *from_sym, Addr to_addr
)
{
   CodeRedirect *redir = VG_(SkipNode_Alloc)(&sk_resolved_redirs);

   vg_assert(from_lib && from_sym && 0 != to_addr);

   redir->type      = R_REDIRECT;
   redir->from_lib  = VG_(arena_strdup)(VG_AR_SYMTAB, from_lib);
   redir->from_sym  = VG_(arena_strdup)(VG_AR_SYMTAB, from_sym);
   redir->from_addr = 0;
   redir->to_addr   = to_addr;
   redir->wrapper   = 0;

   TRACE_REDIR("REDIR sym to addr: %s:%s to %p", from_lib, from_sym, to_addr);

   // Check against all existing segments to see if this redirection
   // can be resolved immediately (as will be the case when the replacement
   // function is loaded after the replacee).  Then add it to the
   // appropriate list.
   if (resolve_redir_with_existing_seginfos(redir)) {
      add_redir_to_resolved_list(redir, True);
   } else {
      add_redir_to_unresolved_list(redir);
   }
}

CodeRedirect *VG_(add_wrapper)(const Char *from_lib, const Char *from_sym,
			       const FuncWrapper *wrapper)
{
   CodeRedirect *redir = VG_(SkipNode_Alloc)(&sk_resolved_redirs);

   redir->type      = R_WRAPPER;
   redir->from_lib  = VG_(arena_strdup)(VG_AR_SYMTAB, from_lib);
   redir->from_sym  = VG_(arena_strdup)(VG_AR_SYMTAB, from_sym);
   redir->from_addr = 0;
   redir->to_addr   = 0;
   redir->wrapper   = wrapper;
   
   TRACE_REDIR("REDIR sym to wrapper: %s:%s to (%p,%p)",
               from_lib, from_sym, wrapper->before, wrapper->after);

   // Check against all existing segments to see if this redirection
   // can be resolved immediately.  Then add it to the appropriate list.
   if (resolve_redir_with_existing_seginfos(redir)) {
      add_redir_to_resolved_list(redir, True);
   } else {
      add_redir_to_unresolved_list(redir);
   }

   return redir;
}

/* If address 'a' is being redirected, return the redirected-to
   address. */
Addr VG_(code_redirect)(Addr a)
{
   CodeRedirect* r;

   r = VG_(SkipList_Find_Exact)(&sk_resolved_redirs, &a);
   if (r == NULL)
      return a;

   vg_assert(r->to_addr != 0);

   return r->to_addr;
}

void VG_(setup_code_redirect_table) ( void )
{
#if defined(VGP_x86_linux)
   /* Redirect _dl_sysinfo_int80, which is glibc's default system call
      routine, to our copy so that the special sysinfo unwind hack in
      m_stacktrace.c will kick in.  */
   add_redirect_sym_to_addr(
      "soname:ld-linux.so.2", "_dl_sysinfo_int80",
      (Addr)&VG_(x86_linux_REDIR_FOR__dl_sysinfo_int80)
   );

#elif defined(VGP_amd64_linux)

   /* Redirect vsyscalls to local versions */
   add_redirect_addr_to_addr(
      0xFFFFFFFFFF600000ULL,
      (Addr)&VG_(amd64_linux_REDIR_FOR_vgettimeofday) 
   );

   add_redirect_addr_to_addr( 
      0xFFFFFFFFFF600400ULL,
      (Addr)&VG_(amd64_linux_REDIR_FOR_vtime) 
   );

#elif defined(VGP_ppc32_linux)

   //CAB: TODO

#elif defined(VGP_x86_netbsdelf2)
   // NetBSD: TODO - XXXX 
/*  add_redirect_sym_to_addr( */
/*       "soname:ld-elf.so", "_dl_sysinfo_int80", */
/*       (Addr)&VG_(x86_linux_REDIR_FOR__dl_sysinfo_int80) */
/*    ); */

#else
#  error Unknown platform
#endif
}

/* Z-decode a symbol into library:func form, eg 
  
     _vgi_libcZdsoZd6__ZdlPv  -->  libc.so.6:_ZdlPv

   Uses the Z-encoding scheme described in pub_core_redir.h.
   Returns True if demangle OK, False otherwise.
*/
static Bool Z_decode(const Char* symbol, Char* result, Int nbytes)
{
#  define EMIT(ch)                    \
      do {                            \
         if (j >= nbytes)             \
            result[j-1] = 0;          \
         else                         \
            result[j++] = ch;         \
      } while (0)

   Bool error = False;
   Int i, j = 0;
   Int len = VG_(strlen)(symbol);
   if (0) VG_(printf)("idm: %s\n", symbol);

   i = VG_REPLACE_FUNCTION_PREFIX_LEN;

   /* Chew though the Z-encoded soname part. */
   while (True) {

      if (i >= len) 
         break;

      if (symbol[i] == '_')
         /* We found the underscore following the Z-encoded soname.
            Just copy the rest literally. */
         break;

      if (symbol[i] != 'Z') {
         EMIT(symbol[i]);
         i++;
         continue;
      }

      /* We've got a Z-escape.  Act accordingly. */
      i++;
      if (i >= len) {
         /* Hmm, Z right at the end.  Something's wrong. */
         error = True;
         EMIT('Z');
         break;
      }
      switch (symbol[i]) {
         case 'a': EMIT('*'); break;
         case 'p': EMIT('+'); break;
         case 'c': EMIT(':'); break;
         case 'd': EMIT('.'); break;
         case 'u': EMIT('_'); break;
         case 'h': EMIT('-'); break;
         case 's': EMIT(' '); break;
         case 'Z': EMIT('Z'); break;
         default: error = True; EMIT('Z'); EMIT(symbol[i]); break;
      }
      i++;
   }

   if (error || i >= len || symbol[i] != '_') {
      /* Something's wrong.  Give up. */
      VG_(message)(Vg_UserMsg, "intercept: error demangling: %s", symbol);
      EMIT(0);
      return False;
   }

   /* Copy the rest of the string verbatim. */
   i++;
   EMIT(':');
   while (True) {
     if (i >= len)
        break;
     EMIT(symbol[i]);
     i++;
   }

   EMIT(0);
   if (0) VG_(printf)("%s\n", result);
   return True;

#  undef EMIT
}

// Nb: this can change the string pointed to by 'symbol'.
static void handle_replacement_function( Char* symbol, Addr addr )
{
   Bool ok;
   Int  len  = VG_(strlen)(symbol) + 1 - VG_REPLACE_FUNCTION_PREFIX_LEN;
   Char *lib = VG_(arena_malloc)(VG_AR_SYMTAB, len+8);
   Char *func;

   // Put "soname:" at the start of lib
   VG_(strcpy)(lib, "soname:");

   ok = Z_decode(symbol, lib+7, len);
   if (ok) {
      // lib is "soname:<libname>:<fnname>".  Split the string at the 2nd ':'.
      func = lib + VG_(strlen)(lib)-1;
      while(*func != ':') func--;
      *func = '\0';
      func++;           // Move past the '\0'

      // Now lib is "soname:<libname>" and func is "<fnname>".
      if (0) VG_(printf)("lib A%sZ, func A%sZ\n", lib, func);
      add_redirect_sym_to_addr(lib, func, addr);

      // Overwrite the given Z-encoded name with just the fnname.
      VG_(strcpy)(symbol, func);
   }

   VG_(arena_free)(VG_AR_SYMTAB, lib);
}

static Addr __libc_freeres_wrapper = 0;

Addr VG_(get_libc_freeres_wrapper)(void)
{
   return __libc_freeres_wrapper;
}

// This is specifically for stringifying VG_(x) function names.  We
// need to do two macroexpansions to get the VG_ macro expanded before
// stringifying.
#define _STR(x) #x
#define STR(x)  _STR(x)

static void handle_load_notifier( Char* symbol, Addr addr )
{
   if (VG_(strcmp)(symbol, STR(VG_NOTIFY_ON_LOAD(freeres))) == 0)
      __libc_freeres_wrapper = addr;
//   else if (VG_(strcmp)(symbol, STR(VG_WRAPPER(pthread_startfunc_wrapper))) == 0)
//      VG_(pthread_startfunc_wrapper)((Addr)(si->offset + sym->st_value));
   else
      vg_assert2(0, "unrecognised load notification function: %s", symbol);
}

static Bool is_replacement_function(Char* s)
{
   return (0 == VG_(strncmp)(s,
                             VG_REPLACE_FUNCTION_PREFIX,
                             VG_REPLACE_FUNCTION_PREFIX_LEN));
}

static Bool is_load_notifier(Char* s)
{
   return (0 == VG_(strncmp)(s,
                             VG_NOTIFY_ON_LOAD_PREFIX,
                             VG_NOTIFY_ON_LOAD_PREFIX_LEN));
}

// Call this for each symbol loaded.  It determines if we need to do
// anything special with it.  It can modify 'symbol' in-place.
void VG_(maybe_redir_or_notify) ( Char* symbol, Addr addr )
{
   if (is_replacement_function(symbol))
      handle_replacement_function(symbol, addr);
   else 
   if (is_load_notifier(symbol))
      handle_load_notifier(symbol, addr);
}


//:: /*------------------------------------------------------------*/
//:: /*--- General function wrapping.                           ---*/
//:: /*------------------------------------------------------------*/
//:: 
//:: /* 
//::    TODO:
//::    - hook into the symtab machinery
//::    - client-side wrappers?
//::    - better interfaces for before() functions to get to arguments
//::    - handle munmap of code (dlclose())
//::    - handle thread exit
//::    - handle longjmp
//::  */
//:: struct callkey {
//::    ThreadId	tid;		/* calling thread	    */
//::    Addr		esp;		/* address of args on stack */
//::    Addr		eip;		/* return address	    */
//:: };
//:: 
//:: struct call_instance {
//::    struct callkey key;
//:: 
//::    const FuncWrapper	*wrapper;
//::    void		*nonce;
//:: };
//:: 
//:: static inline Addr addrcmp(Addr a, Addr b)
//:: {
//::    if (a < b)
//::       return -1;
//::    else if (a > b)
//::       return 1;
//::    else 
//::       return 0;
//:: }
//:: 
//:: static inline Int cmp(UInt a, UInt b)
//:: {
//::    if (a < b)
//::       return -1;
//::    else if (a > b)
//::       return 1;
//::    else 
//::       return 0;
//:: }
//:: 
//:: static Int keycmp(const void *pa, const void *pb)
//:: {
//::    const struct callkey *a = (const struct callkey *)pa;
//::    const struct callkey *b = (const struct callkey *)pb;
//::    Int ret;
//:: 
//::    if ((ret = cmp(a->tid, b->tid)))
//::       return ret;
//:: 
//::    if ((ret = addrcmp(a->esp, b->esp)))
//::       return ret;
//:: 
//::    return addrcmp(a->eip, b->eip);
//:: }
//:: 
//:: /* List of wrapped call invocations which are currently active */
//:: static SkipList wrapped_frames = VG_SKIPLIST_INIT(struct call_instance, key, keycmp, 
//:: 					       NULL, VG_AR_SYMTAB);
//:: 
//:: static struct call_instance *find_call(Addr retaddr, Addr argsp, ThreadId tid)
//:: {
//::    struct callkey key = { tid, argsp, retaddr };
//:: 
//::    return VG_(SkipList_Find_Exact)(&wrapped_frames, &key);
//:: }
//:: 
//:: static void wrapper_return(Addr retaddr);
//:: 
//:: /* Called from generated code via helper */
//:: void VG_(wrap_before)(ThreadState *tst, const FuncWrapper *wrapper)
//:: {
//::    Addr retaddr = VG_RETADDR(tst->arch);
//::    Addr argp = (Addr)&VG_FUNC_ARG(tst->arch, 0);
//::    void *nonce = NULL;
//::    Bool mf = VG_(my_fault);
//::    VG_(my_fault) = True;
//:: 
//::    if (wrapper->before) {
//::       va_list args = VG_VA_LIST(tst->arch);
//::       nonce = (*wrapper->before)(args);
//::    }
//:: 
//::    if (wrapper->after) {
//::       /* If there's an after function, make sure it gets called */
//::       struct call_instance *call;
//:: 
//::       call = find_call(retaddr, argp, tst->tid);
//:: 
//::       if (call != NULL) {
//:: 	 /* Found a stale outstanding call; clean it up and recycle
//:: 	    the structure */
//:: 	 if (call->wrapper->after)
//:: 	    (*call->wrapper->after)(call->nonce, RT_LONGJMP, 0);
//::       } else {
//:: 	 call = VG_(SkipNode_Alloc)(&wrapped_frames);
//:: 	 
//:: 	 call->key.tid = tst->tid;
//:: 	 call->key.esp = argp;
//:: 	 call->key.eip = retaddr;
//:: 
//:: 	 VG_(SkipList_Insert)(&wrapped_frames, call);
//:: 
//:: 	 wrapper_return(retaddr);
//::       }
//:: 
//::       call->wrapper = wrapper;
//::       call->nonce = nonce;
//::    } else 
//::       vg_assert(nonce == NULL);
//:: 
//::    VG_(my_fault) = mf;
//:: }
//:: 
//:: /* Called from generated code via helper */
//:: void VG_(wrap_after)(ThreadState *tst)
//:: {
//::    Addr EIP = VG_INSTR_PTR(tst->arch);	/* instruction after call */
//::    Addr ESP = VG_STACK_PTR(tst->arch);	/* pointer to args */
//::    Word ret = VG_RETVAL(tst->arch);		/* return value */
//::    struct call_instance *call;
//::    Bool mf = VG_(my_fault);
//:: 
//::    VG_(my_fault) = True;
//::    call = find_call(EIP, ESP, tst->tid);
//:: 
//::    if (0)
//::       VG_(printf)("wrap_after(%p,%p,%d) -> %p\n", EIP, ESP, tst->tid, call);
//:: 
//::    if (call != NULL) {
//::       if (call->wrapper->after)
//:: 	 (*call->wrapper->after)(call->nonce, RT_RETURN, ret);
//:: 
//::       VG_(SkipList_Remove)(&wrapped_frames, &call->key);
//::       VG_(SkipNode_Free)(&wrapped_frames, call);
//::    }
//::    VG_(my_fault) = mf;
//:: }
//:: 
//:: 
//:: struct wrapped_function {
//::    Addr	eip;			/* eip of function entrypoint */
//::    const FuncWrapper *wrapper;
//:: };
//:: 
//:: struct wrapper_return {
//::    Addr eip;			/* return address */
//:: };
//:: 
//:: /* A mapping from eip of wrapped function entrypoints to actual wrappers */
//:: static SkipList wrapped_functions = VG_SKIPLIST_INIT(struct wrapped_function, eip, VG_(cmp_Addr),
//:: 						  NULL, VG_AR_SYMTAB);
//:: 
//:: /* A set of EIPs which are return addresses for wrapped functions */
//:: static SkipList wrapper_returns = VG_SKIPLIST_INIT(struct wrapper_return, eip, VG_(cmp_Addr),
//:: 						NULL, VG_AR_SYMTAB);
//:: 
//:: /* Wrap function starting at eip */
//:: void VG_(wrap_function)(Addr eip, const FuncWrapper *wrapper)
//:: {
//::    struct wrapped_function *func;
//:: 
//::    if (0)
//::       VG_(printf)("wrapping %p with (%p,%p)\n", eip, wrapper->before, wrapper->after);
//:: 
//::    func = VG_(SkipList_Find_Exact)(&wrapped_functions, &eip);
//:: 
//::    if (func == NULL) {
//::       func = VG_(SkipNode_Alloc)(&wrapped_functions);
//::       VG_(invalidate_translations)(eip, 1, True);
//:: 
//::       func->eip = eip;
//::       VG_(SkipList_Insert)(&wrapped_functions, func);
//::    }
//:: 
//::    func->wrapper = wrapper;
//:: }
//:: 
//:: const FuncWrapper *VG_(is_wrapped)(Addr eip)
//:: {
//::    struct wrapped_function *func = VG_(SkipList_Find_Exact)(&wrapped_functions, &eip);
//:: 
//::    if (func)
//::       return func->wrapper;
//::    return NULL;
//:: }
//:: 
//:: Bool VG_(is_wrapper_return)(Addr eip)
//:: {
//::    struct wrapper_return *ret = VG_(SkipList_Find_Exact)(&wrapper_returns, &eip);
//:: 
//::    return ret != NULL;
//:: }
//:: 
//:: /* Mark eip as being the return address of a wrapper, so that the
//::    codegen will generate the appropriate call. */
//:: void wrapper_return(Addr eip)
//:: {
//::    struct wrapper_return *ret;
//:: 
//::    if (VG_(is_wrapper_return)(eip))
//::       return;
//:: 
//::    VG_(invalidate_translations)(eip, 1, True);
//:: 
//::    ret = VG_(SkipNode_Alloc)(&wrapper_returns);
//::    ret->eip = eip;
//:: 
//::    VG_(SkipList_Insert)(&wrapper_returns, ret);
//:: }
