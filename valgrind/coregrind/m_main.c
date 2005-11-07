
/*--------------------------------------------------------------------*/
/*--- Startup: the real stuff                             m_main.c ---*/
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

#define _FILE_OFFSET_BITS 64

#include "pub_core_basics.h"
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"     // Needed for pub_core_aspacemgr :(
#include "pub_core_aspacemgr.h"
#include "pub_core_debuglog.h"
#include "pub_core_errormgr.h"
#include "pub_core_execontext.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcmman.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_syscall.h"       // VG_(strerror)
#include "pub_core_machine.h"
#include "pub_core_main.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_profile.h"
#include "pub_core_redir.h"
#include "pub_core_scheduler.h"
#include "pub_core_signals.h"
#include "pub_core_stacks.h"        // For VG_(register_stack)
#include "pub_core_syswrap.h"
#include "pub_core_translate.h"     // For VG_(get_BB_profile)
#include "pub_core_tooliface.h"
#include "pub_core_trampoline.h"
#include "pub_core_transtab.h"
#include "pub_core_ume.h"

#include "memcheck/memcheck.h"

#ifndef AT_DCACHEBSIZE
#define AT_DCACHEBSIZE		19
#endif /* AT_DCACHEBSIZE */

#ifndef AT_ICACHEBSIZE
#define AT_ICACHEBSIZE		20
#endif /* AT_ICACHEBSIZE */

#ifndef AT_UCACHEBSIZE
#define AT_UCACHEBSIZE		21
#endif /* AT_UCACHEBSIZE */

#ifndef AT_SYSINFO
#define AT_SYSINFO		32
#endif /* AT_SYSINFO */

#ifndef AT_SYSINFO_EHDR
#define AT_SYSINFO_EHDR		33
#endif /* AT_SYSINFO_EHDR */

#ifndef AT_SECURE
#define AT_SECURE 23   /* secure mode boolean */
#endif	/* AT_SECURE */

/* redzone gap between client address space and shadow */
#define REDZONE_SIZE		(1 * 1024*1024)

/* size multiple for client address space */
#define CLIENT_SIZE_MULTIPLE	(1 * 1024*1024)

/* Proportion of client space for its heap (rest is for mmaps + stack) */
#define CLIENT_HEAP_PROPORTION   0.333

/* Number of file descriptors that Valgrind tries to reserve for
   it's own use - just a small constant. */
#define N_RESERVED_FDS (10)

#ifdef VGO_netbsdelf2
#define PTRACE_SETREGS PT_SETREGS
#define PTRACE_TRACEME PT_TRACE_ME
#define PTRACE_DETACH PT_DETACH
#endif


/*====================================================================*/
/*=== Ultra-basic startup stuff                                    ===*/
/*====================================================================*/

// HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK A
// temporary bootstrapping allocator, for use until such time as we
// can get rid of the circularites in allocator dependencies at
// startup.  There is also a copy of this in m_ume.c.
#define N_HACK_BYTES 10000
static Int   hack_bytes_used = 0;
static HChar hack_bytes[N_HACK_BYTES];

static void* hack_malloc ( Int n )
{
   VG_(debugLog)(1, "main", "  FIXME: hack_malloc(m_main)(%d)\n", n);
   while (n % 16) n++;
   if (hack_bytes_used + n > N_HACK_BYTES) {
     VG_(printf)("valgrind: N_HACK_BYTES(m_main) too low.  Sorry.\n");
     VG_(exit)(0);
   }
   hack_bytes_used += n;
   return (void*) &hack_bytes[hack_bytes_used - n];
}


/*====================================================================*/
/*=== Global entities not referenced from generated code           ===*/
/*====================================================================*/

/* ---------------------------------------------------------------------
   Startup stuff                            
   ------------------------------------------------------------------ */

/* stage1 (main) executable */
static Int vgexecfd = -1;

/* our argc/argv */
static Int  vg_argc;
static Char **vg_argv;


/*====================================================================*/
/*=== Counters, for profiling purposes only                        ===*/
/*====================================================================*/

static void print_all_stats ( void )
{
   VG_(print_tt_tc_stats)();
   VG_(print_scheduler_stats)();
   VG_(print_ExeContext_stats)();

   // Memory stats
   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_DebugMsg, "");
      VG_(message)(Vg_DebugMsg, 
         "------ Valgrind's internal memory use stats follow ------" );
      VG_(sanity_check_malloc_all)();
      VG_(message)(Vg_DebugMsg, "------" );
      VG_(print_all_arena_stats)();
      VG_(message)(Vg_DebugMsg, "");
   }
}


/*====================================================================*/
/*=== Check we were launched by stage 1                            ===*/
/*====================================================================*/

/* Look for our AUXV table */
static void scan_auxv(void* init_sp)
{
   struct ume_auxv *auxv = VG_(find_auxv)((UWord*)init_sp);

   for (; auxv->a_type != AT_NULL; auxv++) {
      switch(auxv->a_type) {
#     if defined(VGP_ppc32_linux)
         case AT_DCACHEBSIZE:
         case AT_ICACHEBSIZE:
         case AT_UCACHEBSIZE:
            if (auxv->u.a_val > 0) {
               VG_(cache_line_size_ppc32) = auxv->u.a_val;
               VG_(debugLog)(1, "main", 
                                "PPC32 cache line size %u (type %u)\n", 
                                (UInt)auxv->u.a_val, (UInt)auxv->a_type );
            }
            break;

         case AT_HWCAP:
            VG_(debugLog)(1, "main", "PPC32 hwcaps(1): 0x%x\n", (UInt)auxv->u.a_val);
            auxv->u.a_val &= ~0x10000000; /* claim there is no Altivec support */
            VG_(debugLog)(1, "main", "PPC32 hwcaps(2): 0x%x\n", (UInt)auxv->u.a_val);
            break;
#        endif

         case AT_PHDR:
		 VG_(printf)("AT_PHDR\n");
            VG_(valgrind_base) = VG_PGROUNDDN(auxv->u.a_val);
            break;

         default:
            break;
      }
   }
}


/*====================================================================*/
/*=== Address space determination                                  ===*/
/*====================================================================*/

extern char _start[];

static void layout_remaining_space(Addr argc_addr, float ratio)
{
   SysRes res;
   Addr   client_size, shadow_size;

   // VG_(valgrind_base) should have been set by scan_auxv, but if not,
   // this is a workable approximation
   if (VG_(valgrind_base) == 0) {
      VG_(valgrind_base) = VG_PGROUNDDN(&_start);
   }

   VG_(valgrind_last)  = VG_ROUNDUP(argc_addr, 0x10000) - 1; // stack
   VG_(printf)("valgrind base %p\n valgrind_last :%p\n",VG_(valgrind_base),VG_(valgrind_last));
   // This gives the client the largest possible address space while
   // taking into account the tool's shadow needs.
   client_size         = VG_ROUNDDN((VG_(valgrind_base)-REDZONE_SIZE) / (1.+ratio),
                         CLIENT_SIZE_MULTIPLE);
   VG_(client_base)    = 0  ;
   VG_(client_end)     = VG_(client_base) + client_size;
   /* where !FIXED mmap goes */
   VG_(client_mapbase) = VG_(client_base) +
         VG_PGROUNDDN((Addr)(client_size * CLIENT_HEAP_PROPORTION));

   VG_(shadow_base)    = VG_(client_end) + REDZONE_SIZE;
   VG_(shadow_end)     = /* VG_(valgrind_base) */ VG_(shadow_base) + 0x50000000;
   shadow_size         = VG_(shadow_end) - VG_(shadow_base);

#define SEGSIZE(a,b) ((VG_(b) - VG_(a))/(1024*1024))

   if (1)
      VG_(printf)(
         "client_base        %p (%dMB)\n"
         "client_mapbase     %p (%dMB)\n"
         "client_end         %p (%dMB)\n"
         "shadow_base        %p (%dMB)\n"
         "shadow_end         %p\n"
         "valgrind_base      %p (%dMB)\n"
         "valgrind_last      %p\n",
         VG_(client_base),       SEGSIZE(client_base,       client_mapbase),
         VG_(client_mapbase),    SEGSIZE(client_mapbase,    client_end),
         VG_(client_end),        SEGSIZE(client_end,        shadow_base),
         VG_(shadow_base),       SEGSIZE(shadow_base,       shadow_end),
         VG_(shadow_end),
         VG_(valgrind_base),     SEGSIZE(valgrind_base,     valgrind_last),
         VG_(valgrind_last)
      );

#undef SEGSIZE

   // Ban redzone

   res = VG_(mmap_native)((void *)VG_(client_end) , REDZONE_SIZE , VKI_PROT_NONE,
			  VKI_MAP_FIXED | VKI_MAP_ANONYMOUS|VKI_MAP_PRIVATE |VKI_MAP_NORESERVE,
               -1, 0);
   vg_assert(!res.isError);

   // Make client hole
   res = VG_(munmap_native)((void*)VG_(client_base), client_size);
   vg_assert(!res.isError);

   // Map shadow memory.
   // Initially all inaccessible, incrementally initialized as it is used
   if (shadow_size != 0) {
	   Addr shadow_s ;
	   int count;
	   Addr chunk = 0x4000000;
	   shadow_s = shadow_size;
	   for (count =0 ;  (shadow_s > 0 ); count ++ ) {
      res = VG_(mmap_native)((char *)VG_(shadow_base) + (count * chunk), /* shadow_size */ ((shadow_s >= chunk) ? chunk : shadow_s),
                  VKI_PROT_NONE,
                  VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS|VKI_MAP_FIXED|VKI_MAP_NORESERVE,
                  -1, 0);
      if (res.isError) {
         VG_(printf)(
          "valgrind: Could not allocate address space (%p bytes)\n"
          "valgrind:   for shadow memory\n"
          "valgrind: Possible causes:\n"
          "valgrind: - For some systems (especially under RedHat 8), Valgrind\n"
          "valgrind:   needs at least 1.5GB swap space.\n"
          "valgrind: - Or, your virtual memory size may be limited (check\n"
          "valgrind:   with 'ulimit -v').\n"
          "valgrind: - Or, your system may use a kernel that provides only a\n" 
          "valgrind:   too-small (eg. 2GB) user address space.\n"
          , (void*)shadow_size
         ); 
         VG_(exit)(1);
      }
      shadow_s -= chunk;
   }
   }
   
}

/*====================================================================*/
/*=== Command line setup                                           ===*/
/*====================================================================*/

// Note that we deliberately don't free the malloc'd memory.  See comment
// at call site.
static char* get_file_clo(char* dir)
{
   Int    n;
   SysRes fd;
   struct vki_stat s1;
   Char* f_clo = NULL;
   Char  filename[VKI_PATH_MAX];

   VG_(snprintf)(filename, VKI_PATH_MAX, "%s/.valgrindrc", 
                           ( NULL == dir ? "" : dir ) );
   fd = VG_(open)(filename, 0, VKI_S_IRUSR);
   if ( !fd.isError ) {
      if ( 0 == VG_(fstat)(fd.val, &s1) ) {
         f_clo = VG_(malloc)(s1.st_size+1);
         vg_assert(f_clo);
         n = VG_(read)(fd.val, f_clo, s1.st_size);
         if (n == -1) n = 0;
         f_clo[n] = '\0';
      }
      VG_(close)(fd.val);
   }
   return f_clo;
}

static Int count_args(char* s)
{
   Int n = 0;
   if (s) {
      char* cp = s;
      while (True) {
         // We have alternating sequences: blanks, non-blanks, blanks...
         // count the non-blanks sequences.
         while ( VG_(isspace)(*cp) )    cp++;
         if    ( !*cp )                 break;
         n++;
         while ( !VG_(isspace)(*cp) && *cp ) cp++;
      }
   }
   return n;
}

// Add args out of environment, skipping multiple spaces and "--" args.
// We split 's' into multiple strings by replacing whitespace with nuls,
// eg. "--aa --bb --cc" --> "--aa\0--bb\0--cc".  And for each new string
// carved out of 's', we put a pointer to it in 'to'.
static char** copy_args( char* s, char** to )
{
   if (s) {
      char* cp = s;
      while (True) {
         // We have alternating sequences: blanks, non-blanks, blanks...
         // copy the non-blanks sequences, and add terminating '\0'
         while ( VG_(isspace)(*cp) )    cp++;
         if    ( !*cp )                 break;
         *to++ = cp;
         while ( !VG_(isspace)(*cp) && *cp ) cp++;
         if ( *cp ) *cp++ = '\0';            // terminate if not the last
         if (VG_STREQ(to[-1], "--")) to--;   // undo any '--' arg
      }
   }
   return to;
}

// Augment command line with arguments from environment and .valgrindrc
// files.
static void augment_command_line(Int* vg_argc_inout, char*** vg_argv_inout)
{
   int    vg_argc0 = *vg_argc_inout;
   char** vg_argv0 = *vg_argv_inout;

   // get_file_clo() allocates the return value with malloc().  We do not
   // free f1_clo and f2_clo as they get put into vg_argv[] which must persist.
   char*  env_clo = VG_(getenv)(VALGRINDOPTS);
   char*  f1_clo  = get_file_clo( VG_(getenv)("HOME") );
   char*  f2_clo  = get_file_clo(".");

   /* copy any extra args from file or environment, if present */
   if ( (env_clo && *env_clo) || (f1_clo && *f1_clo) || (f2_clo && *f2_clo) ) {
      /* ' ' separated extra options */
      char **from;
      char **to;
      int orig_arg_count, env_arg_count, f1_arg_count, f2_arg_count;

      for ( orig_arg_count = 0; vg_argv0[orig_arg_count]; orig_arg_count++ );

      env_arg_count = count_args(env_clo);
      f1_arg_count  = count_args(f1_clo);
      f2_arg_count  = count_args(f2_clo);

      if (0)
	 VG_(printf)("extra-argc=%d %d %d\n",
                     env_arg_count, f1_arg_count, f2_arg_count);

      /* +2: +1 for null-termination, +1 for added '--' */
      from     = vg_argv0;
      vg_argv0 = VG_(malloc)( (orig_arg_count + env_arg_count + f1_arg_count 
                              + f2_arg_count + 2) * sizeof(char **));
      vg_assert(vg_argv0);
      to      = vg_argv0;

      /* copy argv[0] */
      *to++ = *from++;

      /* Copy extra args from env var and file, in the order: ~/.valgrindrc,
       * $VALGRIND_OPTS, ./.valgrindrc -- more local options are put later
       * to override less local ones. */
      to = copy_args(f1_clo,  to);
      to = copy_args(env_clo, to);
      to = copy_args(f2_clo,  to);
    
      /* copy original arguments, stopping at command or -- */
      while (*from) {
	 if (**from != '-')
	    break;
	 if (VG_STREQ(*from, "--")) {
	    from++;		/* skip -- */
	    break;
	 }
	 *to++ = *from++;
      }

      /* add -- */
      *to++ = "--";

      vg_argc0 = to - vg_argv0;

      /* copy rest of original command line, then NULL */
      while (*from) *to++ = *from++;
      *to = NULL;
   }

   *vg_argc_inout = vg_argc0;
   *vg_argv_inout = vg_argv0;
}

#define VG_CLO_SEP   '\01'

static void get_command_line( int argc, char** argv,
                              Int* vg_argc_out, Char*** vg_argv_out, 
                                                char*** cl_argv_out )
{
   int    vg_argc0;
   char** vg_argv0;
   char** cl_argv;
   char*  env_clo = VG_(getenv)(VALGRINDCLO);

   if (env_clo != NULL && *env_clo != '\0') {
      char *cp;
      char **cpp;

      /* OK, VALGRINDCLO is set, which means we must be a child of another
         Valgrind process using --trace-children, so we're getting all our
         arguments from VALGRINDCLO, and the entire command line belongs to
         the client (including argv[0]) */
      vg_argc0 = 1;		/* argv[0] */
      for (cp = env_clo; *cp; cp++)
	 if (*cp == VG_CLO_SEP)
	    vg_argc0++;

      vg_argv0 = VG_(malloc)(sizeof(char **) * (vg_argc0 + 1));
      vg_assert(vg_argv0);

      cpp = vg_argv0;

      *cpp++ = "valgrind";	/* nominal argv[0] */
      *cpp++ = env_clo;

      // Replace the VG_CLO_SEP args separator with '\0'
      for (cp = env_clo; *cp; cp++) {
	 if (*cp == VG_CLO_SEP) {
	    *cp++ = '\0';	/* chop it up in place */
	    *cpp++ = cp;
	 }
      }
      *cpp = NULL;
      cl_argv = argv;

   } else {
      Bool noaugment = False;

      /* Count the arguments on the command line. */
      vg_argv0 = argv;

      for (vg_argc0 = 1; vg_argc0 < argc; vg_argc0++) {
         Char* arg = argv[vg_argc0];
         if (arg[0] != '-') /* exe name */
	    break;
	 if (VG_STREQ(arg, "--")) { /* dummy arg */
	    vg_argc0++;
	    break;
	 }
         VG_BOOL_CLO(arg, "--command-line-only", noaugment)
      }
      cl_argv = &argv[vg_argc0];

      /* Get extra args from VALGRIND_OPTS and .valgrindrc files.
         Note we don't do this if getting args from VALGRINDCLO, as 
         those extra args will already be present in VALGRINDCLO.
         (We also don't do it when --command-line-only=yes.) */
      if (!noaugment)
	 augment_command_line(&vg_argc0, &vg_argv0);
   }

   if (1) {
      Int i;
      for (i = 0; i < vg_argc0; i++)
         VG_(printf)("vg_argv0[%d]=\"%s\"\n", i, vg_argv0[i]);
   }

   *vg_argc_out =         vg_argc0;
   *vg_argv_out = (Char**)vg_argv0;
   *cl_argv_out =         cl_argv;
}


/*====================================================================*/
/*=== Environment and stack setup                                  ===*/
/*====================================================================*/

/* Scan a colon-separated list, and call a function on each element.
   The string must be mutable, because we insert a temporary '\0', but
   the string will end up unmodified.  (*func) should return True if it
   doesn't need to see any more.

   This routine will return True if (*func) returns True and False if
   it reaches the end of the list without that happening.
*/
static Bool scan_colsep(char *colsep, Bool (*func)(const char *))
{
   char *cp, *entry;
   int end;

   if (colsep == NULL ||
       *colsep == '\0')
      return False;

   entry = cp = colsep;

   do {
      end = (*cp == '\0');

      if (*cp == ':' || *cp == '\0') {
	 char save = *cp;

	 *cp = '\0';
	 if ((*func)(entry)) {
            *cp = save;
	    return True;
         }
	 *cp = save;
	 entry = cp+1;
      }
      cp++;
   } while(!end);

   return False;
}

/* Prepare the client's environment.  This is basically a copy of our
   environment, except:
     LD_PRELOAD=$VALGRINDLIB/vg_preload_core.so:($VALGRINDLIB/vgpreload_TOOL.so:)?$LD_PRELOAD

   If this is missing, then it is added.

   Yummy.  String hacking in C.

   If this needs to handle any more variables it should be hacked
   into something table driven.
 */
static HChar **fix_environment(HChar **origenv, const HChar *preload)
{
   static const HChar preload_core_so[]    = "vg_preload_core.so";
   static const HChar ld_preload[]         = "LD_PRELOAD=";
   static const HChar valgrind_clo[]       = VALGRINDCLO "=";
   static const int  ld_preload_len       = sizeof(ld_preload)-1;
   static const int  valgrind_clo_len     = sizeof(valgrind_clo)-1;
   int ld_preload_done       = 0;
   HChar *preload_core_path;
   int   preload_core_path_len;
   int vgliblen = VG_(strlen)(VG_(libdir));
   HChar **cpp;
   HChar **ret;
   int envc;
   const int preloadlen = (preload == NULL) ? 0 : VG_(strlen)(preload);

   /* Find the vg_preload_core.so; also make room for the tool preload
      library */
   preload_core_path_len = sizeof(preload_core_so) + vgliblen + preloadlen + 16;
   /* FIXME */
   preload_core_path = /*VG_(malloc)*/ hack_malloc(preload_core_path_len);
   vg_assert(preload_core_path);

   if (preload)
      VG_(snprintf)(preload_core_path, preload_core_path_len, "%s/%s:%s", 
                    VG_(libdir), preload_core_so, preload);
   else
      VG_(snprintf)(preload_core_path, preload_core_path_len, "%s/%s", 
                    VG_(libdir), preload_core_so);
   
   /* Count the original size of the env */
   envc = 0;			/* trailing NULL */
   for (cpp = origenv; cpp && *cpp; cpp++)
      envc++;

   /* Allocate a new space */
   ret = /* FIXME VG_(malloc)*/ hack_malloc (sizeof(HChar *) * (envc+1+1)); /* 1 new entry + NULL */
   vg_assert(ret);

   /* copy it over */
   for (cpp = ret; *origenv; )
      *cpp++ = *origenv++;
   *cpp = NULL;
   
   vg_assert(envc == (cpp - ret));

   /* Walk over the new environment, mashing as we go */
   for (cpp = ret; cpp && *cpp; cpp++) {
      if (VG_(memcmp)(*cpp, ld_preload, ld_preload_len) == 0) {
	 int len = VG_(strlen)(*cpp) + preload_core_path_len;
	 HChar *cp = /*FIXME VG_(malloc)*/ hack_malloc(len);
         vg_assert(cp);

	 VG_(snprintf)(cp, len, "%s%s:%s",
                       ld_preload, preload_core_path, (*cpp)+ld_preload_len);

	 *cpp = cp;
	 
	 ld_preload_done = 1;
      } else if (VG_(memcmp)(*cpp, valgrind_clo, valgrind_clo_len) == 0) {
	 *cpp = "";
      }
   }

   /* Add the missing bits */
   if (!ld_preload_done) {
      int len = ld_preload_len + preload_core_path_len;
      HChar *cp = /*FIXME VG_(malloc)*/ hack_malloc (len);
      vg_assert(cp);
      
      VG_(snprintf)(cp, len, "%s%s", ld_preload, preload_core_path);
      
      ret[envc++] = cp;
   }

   //FIXME   VG_(free)(preload_core_path);
   ret[envc] = NULL;

   return ret;
}

extern char **environ;		/* our environment */

/* Add a string onto the string table, and return its address */
static char *copy_str(char **tab, const char *str)
{
   char *cp = *tab;
   char *orig = cp;

   while(*str)
      *cp++ = *str++;
   *cp++ = '\0';

   if (0)
      VG_(printf)("copied %p \"%s\" len %lld\n", orig, orig, (Long)(cp-orig));

   *tab = cp;

   return orig;
}

/* 
   This sets up the client's initial stack, containing the args,
   environment and aux vector.

   The format of the stack is:

   higher address +-----------------+
		  | Trampoline code |
		  +-----------------+
                  |                 |
		  : string table    :
		  |                 |
		  +-----------------+
		  | AT_NULL         |
		  -                 -
		  | auxv            |
		  +-----------------+
		  |  NULL           |
		  -                 -
		  | envp            |
		  +-----------------+
		  |  NULL           |
		  -                 -
		  | argv            |
		  +-----------------+
		  | argc            |
   lower address  +-----------------+ <- sp
                  | undefined       |
		  :                 :
 */
static Addr setup_client_stack(void* init_sp,
                               char **orig_argv, char **orig_envp, 
			       const struct exeinfo *info,
                               UInt** client_auxv)
{
   SysRes res;
   char **cpp;
   char *strtab;		/* string table */
   char *stringbase;
   Addr *ptr;
   struct ume_auxv *auxv;
   const struct ume_auxv *orig_auxv;
   const struct ume_auxv *cauxv;
   unsigned stringsize;		/* total size of strings in bytes */
   unsigned auxsize;		/* total size of auxv in bytes */
   int argc;			/* total argc */
   int envc;			/* total number of env vars */
   unsigned stacksize;		/* total client stack size */
   Addr cl_esp;	                /* client stack base (initial esp) */

   /* use our own auxv as a prototype */
   orig_auxv = VG_(find_auxv)(init_sp);

   /* ==================== compute sizes ==================== */

   /* first of all, work out how big the client stack will be */
   stringsize = 0;

   /* paste on the extra args if the loader needs them (ie, the #! 
      interpreter and its argument) */
   argc = 0;
   if (info->interp_name != NULL) {
      argc++;
      stringsize += VG_(strlen)(info->interp_name) + 1;
   }
   if (info->interp_args != NULL) {
      argc++;
      stringsize += VG_(strlen)(info->interp_args) + 1;
   }

   /* now scan the args we're given... */
   for (cpp = orig_argv; *cpp; cpp++) {
      argc++;
      stringsize += VG_(strlen)(*cpp) + 1;
   }
   
   /* ...and the environment */
   envc = 0;
   for (cpp = orig_envp; cpp && *cpp; cpp++) {
      envc++;
      stringsize += VG_(strlen)(*cpp) + 1;
   }

   /* now, how big is the auxv? */
   auxsize = sizeof(*auxv);	/* there's always at least one entry: AT_NULL */
   for (cauxv = orig_auxv; cauxv->a_type != AT_NULL; cauxv++) {
#ifdef AT_PLATFORM /* XXX -netbsd */
      if (cauxv->a_type == AT_PLATFORM)
	 stringsize += VG_(strlen)(cauxv->u.a_ptr) + 1;
#endif 
      auxsize += sizeof(*cauxv);
   }

#if defined(VGP_ppc32_linux)
   auxsize += 2 * sizeof(*cauxv);
#endif

   /* OK, now we know how big the client stack is */
   stacksize =
      sizeof(Word) +			/* argc */
      sizeof(char **)*argc +		/* argv */
      sizeof(char **) +			/* terminal NULL */
      sizeof(char **)*envc +		/* envp */
      sizeof(char **) +			/* terminal NULL */
      auxsize +				/* auxv */
      VG_ROUNDUP(stringsize, sizeof(Word)) +/* strings (aligned) */
      VKI_PAGE_SIZE;			/* page for trampoline code */

   if (0) VG_(printf)("stacksize = %d\n", stacksize);

   // decide where stack goes!
   VG_(clstk_end) = VG_(client_end);

   /* cl_esp is the client's stack pointer */
   cl_esp = VG_(clstk_end) - stacksize;
   cl_esp = VG_ROUNDDN(cl_esp, 16); /* make stack 16 byte aligned */

   /* base of the string table (aligned) */
   stringbase = strtab = (char *)(VG_(clstk_end) 
                         - VG_ROUNDUP(stringsize, sizeof(int)));

   VG_(clstk_base) = VG_PGROUNDDN(cl_esp);

   if (0)
      VG_(printf)("stringsize=%d auxsize=%d stacksize=%d\n"
                  "clstk_base %p\n"
                  "clstk_end  %p\n",
	          stringsize, auxsize, stacksize,
                  (void*)VG_(clstk_base), (void*)VG_(clstk_end));

   /* ==================== allocate space ==================== */

   /* allocate a stack - mmap enough space for the stack */
   res = VG_(mmap_native)((void *)VG_PGROUNDDN(cl_esp), 
              VG_(clstk_end) - VG_PGROUNDDN(cl_esp),
	      VKI_PROT_READ|VKI_PROT_WRITE|VKI_PROT_EXEC, 
	      VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS|VKI_MAP_FIXED, -1, 0);
   vg_assert(!res.isError); 

   /* ==================== copy client stack ==================== */

   ptr = (Addr*)cl_esp;

   /* --- argc --- */
   *ptr++ = argc;		/* client argc */

   /* --- argv --- */
   if (info->interp_name) {
      *ptr++ = (Addr)copy_str(&strtab, info->interp_name);
//FIXME      free(info->interp_name);
   }
   if (info->interp_args) {
      *ptr++ = (Addr)copy_str(&strtab, info->interp_args);
//FIXME      free(info->interp_args);
   }
   for (cpp = orig_argv; *cpp; ptr++, cpp++) {
      *ptr = (Addr)copy_str(&strtab, *cpp);
   }
   *ptr++ = 0;

   /* --- envp --- */
   VG_(client_envp) = (Char **)ptr;
   for (cpp = orig_envp; cpp && *cpp; ptr++, cpp++)
      *ptr = (Addr)copy_str(&strtab, *cpp);
   *ptr++ = 0;

   /* --- auxv --- */
   auxv = (struct ume_auxv *)ptr;
   *client_auxv = (UInt *)auxv;

#if defined(VGP_ppc32_linux)
   auxv[0].a_type  = AT_IGNOREPPC;
   auxv[0].u.a_val = AT_IGNOREPPC;
   auxv[1].a_type  = AT_IGNOREPPC;
   auxv[1].u.a_val = AT_IGNOREPPC;
   auxv += 2;
#endif

   for (; orig_auxv->a_type != AT_NULL; auxv++, orig_auxv++) {
      /* copy the entry... */
      *auxv = *orig_auxv;

      /* ...and fix up the copy */
      switch(auxv->a_type) {
      case AT_PHDR:
	 if (info->phdr == 0)
	    auxv->a_type = AT_IGNORE;
	 else
	    auxv->u.a_val = info->phdr;
	 break;

      case AT_PHNUM:
	 if (info->phdr == 0)
	    auxv->a_type = AT_IGNORE;
	 else
	    auxv->u.a_val = info->phnum;
	 break;

      case AT_BASE:
	 auxv->u.a_val = info->interp_base;
	 break;

#ifdef AT_PLATFORM
      case AT_PLATFORM:		/* points to a platform description string */
	 auxv->u.a_ptr = copy_str(&strtab, orig_auxv->u.a_ptr);
	 break;
#endif

      case AT_ENTRY:
	 auxv->u.a_val = info->entry;
	 break;

      case AT_IGNORE:
      case AT_PHENT:
      case AT_PAGESZ:
      case AT_FLAGS:
#ifdef AT_NOTELF
      case AT_NOTELF:
#endif
#ifdef AT_UID
      case AT_UID:
#endif
      case AT_EUID:
#ifdef AT_GID
      case AT_GID:
#endif 
      case AT_EGID:
#ifdef AT_CLKTCK
      case AT_CLKTCK:
#endif
#ifdef AT_HWCAP
      case AT_HWCAP:
#endif
#ifdef AT_FPUCW
      case AT_FPUCW:
#endif
      case AT_DCACHEBSIZE:
      case AT_ICACHEBSIZE:
      case AT_UCACHEBSIZE:
#if defined(VGP_ppc32_linux)
      case AT_IGNOREPPC:
#endif
	 /* All these are pointerless, so we don't need to do anything
	    about them. */
	 break;

      case AT_SECURE:
	 /* If this is 1, then it means that this program is running
	    suid, and therefore the dynamic linker should be careful
	    about LD_PRELOAD, etc.  However, since stage1 (the thing
	    the kernel actually execve's) should never be SUID, and we
	    need LD_PRELOAD to work for the client, we
	    set AT_SECURE to 0. */
	 auxv->u.a_val = 0;
	 break;

      case AT_SYSINFO:
	 /* Leave this unmolested for now, but we'll update it later
	    when we set up the client trampoline code page */
	 break;

#if !defined(VGP_ppc32_linux)
      case AT_SYSINFO_EHDR:
	 /* Trash this, because we don't reproduce it */
	 auxv->a_type = AT_IGNORE;
	 break;
#endif

      default:
	 /* stomp out anything we don't know about */
	 if (0)
	    VG_(printf)("stomping auxv entry %lld\n", (ULong)auxv->a_type);
	 auxv->a_type = AT_IGNORE;
	 break;
	 
      }
   }
   *auxv = *orig_auxv;
   vg_assert(auxv->a_type == AT_NULL);

   vg_assert((strtab-stringbase) == stringsize);

   /* We know the initial ESP is pointing at argc/argv */
   VG_(client_argc) = *(Int*)cl_esp;
   VG_(client_argv) = (Char**)(cl_esp + sizeof(HWord));

   if (0) VG_(printf)("startup SP = %p\n", cl_esp);
   return cl_esp;
}

/*====================================================================*/
/*=== Find executable                                              ===*/
/*====================================================================*/

/* Need a static copy because can't use dynamic mem allocation yet */
static HChar executable_name[VKI_PATH_MAX];

static Bool match_executable(const char *entry) {
   char buf[VG_(strlen)(entry) + VG_(strlen)(executable_name) + 2];

   /* empty PATH element means . */
   if (*entry == '\0')
      entry = ".";

   VG_(snprintf)(buf, sizeof(buf), "%s/%s", entry, executable_name);
   if (VG_(access)(buf, True/*r*/, False/*w*/, True/*x*/) == 0) {
      VG_(strncpy)( executable_name, buf, VKI_PATH_MAX-1 );
      executable_name[VKI_PATH_MAX-1] = 0;
      return True;
   }
   return False;
}

static const char* find_executable(const char* exec)
{
   vg_assert(NULL != exec);
   VG_(strncpy)( executable_name, exec, VKI_PATH_MAX-1 );
   executable_name[VKI_PATH_MAX-1] = 0;

   if (VG_(strchr)(executable_name, '/') == NULL) {
      /* no '/' - we need to search the path */
      char *path = VG_(getenv)("PATH");
      scan_colsep(path, match_executable);
   }
   return executable_name;
}


/*====================================================================*/
/*=== Loading tools                                                ===*/
/*====================================================================*/

/* Return a pointer to the tool_info struct.  Also looks to see if
   there's a matching vgpreload_*.so file, and returns its name in
   *preloadpath. */

/* HACK required because we can't use VG_(strdup) yet -- dynamic
   memory allocation is not running. */
static HChar load_tool__preloadpath[VKI_PATH_MAX];

static void load_tool( const char *toolname,
                       ToolInfo** toolinfo_out, char **preloadpath_out )
{
   extern ToolInfo VG_(tool_info);
   *toolinfo_out = &VG_(tool_info);

   Int    len = VG_(strlen)(VG_(libdir)) + VG_(strlen)(toolname) + 16;
   HChar  buf[len];

   VG_(snprintf)(buf, len, "%s/vgpreload_%s.so", VG_(libdir), toolname);
   if (VG_(access)(buf, True/*r*/, False/*w*/, False/*x*/) == 0 
       && len < VKI_PATH_MAX-1) {
      VG_(strncpy)( load_tool__preloadpath, buf, VKI_PATH_MAX-1 );
      load_tool__preloadpath[VKI_PATH_MAX-1] = 0;
      *preloadpath_out = load_tool__preloadpath;
   } else {
      VG_(printf)("valgrind: couldn't find preload file for tool %s\n", 
                  toolname);
      VG_(exit)(127);
   }
}


/*====================================================================*/
/*=== Command line errors                                          ===*/
/*====================================================================*/

static void revert_to_stderr ( void )
{
   vg_assert( !VG_(logging_to_socket) );
   VG_(clo_log_fd) = 2; /* stderr */
}

void VG_(bad_option) ( Char* opt )
{
   revert_to_stderr();
   VG_(printf)("valgrind: Bad option '%s'; aborting.\n", opt);
   VG_(printf)("valgrind: Use --help for more information.\n");
   VG_(exit)(1);
}

static void missing_prog ( void  )
{
   revert_to_stderr();
   VG_(printf)("valgrind: no program specified\n");
   VG_(printf)("valgrind: Use --help for more information.\n");
   VG_(exit)(1);
}

static void config_error ( Char* msg )
{
   revert_to_stderr();
   VG_(printf)("valgrind: Startup or configuration error:\n   %s\n", msg);
   VG_(printf)("valgrind: Unable to start up properly.  Giving up.\n");
   VG_(exit)(1);
}


/*====================================================================*/
/*=== Loading the client                                           ===*/
/*====================================================================*/

static void load_client(char* cl_argv[], const char* exec, Int need_help,
                 /*out*/struct exeinfo* info, /*out*/Addr* client_eip)
{
   // If they didn't specify an executable with --exec, and didn't specify 
   // --help, then use client argv[0] (searching $PATH if necessary).
   if (NULL == exec && !need_help) {
      if (cl_argv[0] == NULL || 
          ( NULL == (exec = find_executable(cl_argv[0])) ) )
      {
         missing_prog();
      }
   }

   info->map_base = VG_(client_mapbase);
   info->exe_base = VG_(client_base);
   info->exe_end  = VG_(client_end);
   info->argv     = cl_argv;

   if (need_help) {
      VG_(clexecfd) = -1;
      // Totally zero 'info' before continuing.
      VG_(memset)(info, 0, sizeof(*info));
   } else {
      Int ret;
      /* HACK: assumes VG_(open) always succeeds */
      VG_(clexecfd) = VG_(open)(exec, VKI_O_RDONLY, VKI_S_IRUSR)
                      .val;
      ret = VG_(do_exec)(exec, info);
      if (ret != 0) {
         VG_(printf)("valgrind: do_exec(%s) failed: %s\n",
                     exec, VG_(strerror)(ret));
         VG_(exit)(127);
      }
   }

   /* Copy necessary bits of 'info' that were filled in */
   *client_eip = info->init_eip;
   VG_(brk_base) = VG_(brk_limit) = info->brkbase;
}


/*====================================================================*/
/*=== Command-line: variables, processing, etc                     ===*/
/*====================================================================*/

// See pub_{core,tool}_options.h for explanations of all these.

static void usage ( Bool debug_help )
{
   Char* usage1 = 
"usage: valgrind --tool=<toolname> [options] prog-and-args\n"
"\n"
"  common user options for all Valgrind tools, with defaults in [ ]:\n"
"    --tool=<name>             use the Valgrind tool named <name> [memcheck]\n"
"    -h --help                 show this message\n"
"    --help-debug              show this message, plus debugging options\n"
"    --version                 show version\n"
"    -q --quiet                run silently; only print error msgs\n"
"    -v --verbose              be more verbose, incl counts of errors\n"
"    --trace-children=no|yes   Valgrind-ise child processes? [no]\n"
"    --track-fds=no|yes        track open file descriptors? [no]\n"
"    --time-stamp=no|yes       add timestamps to log messages? [no]\n"
"    --log-fd=<number>         log messages to file descriptor [2=stderr]\n"
"    --log-file=<file>         log messages to <file>.pid<pid>\n"
"    --log-file-exactly=<file> log messages to <file>\n"
"    --log-file-qualifier=<VAR> incorporate $VAR in logfile name [none]\n"
"    --log-socket=ipaddr:port  log messages to socket ipaddr:port\n"
"\n"
"  uncommon user options for all Valgrind tools:\n"
"    --run-libc-freeres=no|yes free up glibc memory at exit? [yes]\n"
"    --weird-hacks=hack1,hack2,...  recognised hacks: lax-ioctls,ioctl-mmap [none]\n"
"    --pointercheck=no|yes     enforce client address space limits [yes]\n"
"    --show-emwarns=no|yes     show warnings about emulation limits? [no]\n"
"    --smc-check=none|stack|all  checks for self-modifying code: none,\n"
"                              only for code found in stacks, or all [stack]\n"
"\n"
"  user options for Valgrind tools that report errors:\n"
"    --xml=yes                 all output is in XML (Memcheck/Nulgrind only)\n"
"    --xml-user-comment=STR    copy STR verbatim to XML output\n"
"    --demangle=no|yes         automatically demangle C++ names? [yes]\n"
"    --num-callers=<number>    show <num> callers in stack traces [12]\n"
"    --error-limit=no|yes      stop showing new errors if too many? [yes]\n"
"    --show-below-main=no|yes  continue stack traces below main() [no]\n"
"    --suppressions=<filename> suppress errors described in <filename>\n"
"    --gen-suppressions=no|yes|all    print suppressions for errors? [no]\n"
"    --db-attach=no|yes        start debugger when errors detected? [no]\n"
"    --db-command=<command>    command to start debugger [gdb -nw %%f %%p]\n"
"    --input-fd=<number>       file descriptor for input [0=stdin]\n"
"    --max-stackframe=<number> assume stack switch for SP changes larger\n"
"                              than <number> bytes [2000000]\n"
"\n";

   Char* usage2 = 
"\n"
"  debugging options for all Valgrind tools:\n"
"    --sanity-level=<number>   level of sanity checking to do [1]\n"
"    --profile=no|yes          profile? (tool must be built for it) [no]\n"
"    --trace-flags=<XXXXXXXX>   show generated code? (X = 0|1) [00000000]\n"
"    --profile-flags=<XXXXXXXX> ditto, but for profiling (X = 0|1) [00000000]\n"
"    --trace-notbelow=<number>    only show BBs above <number> [0]\n"
"    --trace-syscalls=no|yes   show all system calls? [no]\n"
"    --trace-signals=no|yes    show signal handling details? [no]\n"
"    --trace-symtab=no|yes     show symbol table details? [no]\n"
"    --trace-cfi=no|yes        show call-frame-info details? [no]\n"
"    --trace-sched=no|yes      show thread scheduler details? [no]\n"
"    --wait-for-gdb=yes|no     pause on startup to wait for gdb attach\n"
#if 0
"    --model-pthreads=yes|no   model the pthreads library [no]\n"
#endif
"    --command-line-only=no|yes  only use command line options [no]\n"
"\n"
"    --vex-iropt-verbosity             0 .. 9 [0]\n"
"    --vex-iropt-level                 0 .. 2 [2]\n"
"    --vex-iropt-precise-memory-exns   [no]\n"
"    --vex-iropt-unroll-thresh         0 .. 400 [120]\n"
"    --vex-guest-max-insns             1 .. 100 [50]\n"
"    --vex-guest-chase-thresh          0 .. 99  [10]\n"
"\n"
"    --trace-flags and --profile-flags values (omit the middle space):\n"
"       1000 0000   show conversion into IR\n"
"       0100 0000   show after initial opt\n"
"       0010 0000   show after instrumentation\n"
"       0001 0000   show after second opt\n"
"       0000 1000   show after tree building\n"
"       0000 0100   show selecting insns\n"
"       0000 0010   show after reg-alloc\n"
"       0000 0001   show final assembly\n"
"\n"
"  debugging options for Valgrind tools that report errors\n"
"    --dump-error=<number>     show translation for basic block associated\n"
"                              with <number>'th error context [0=show none]\n"
"\n";

   Char* usage3 =
"\n"
"  Extra options read from ~/.valgrindrc, $VALGRIND_OPTS, ./.valgrindrc\n"
"\n"
"  Valgrind is Copyright (C) 2000-2005 Julian Seward et al.\n"
"  and licensed under the GNU General Public License, version 2.\n"
"  Bug reports, feedback, admiration, abuse, etc, to: %s.\n"
"\n"
"  Tools are copyright and licensed by their authors.  See each\n"
"  tool's start-up message for more information.\n"
"\n";

   // Ensure the message goes to stdout
   VG_(clo_log_fd) = 1;
   vg_assert( !VG_(logging_to_socket) );

   VG_(printf)(usage1);
   if (VG_(details).name) {
      VG_(printf)("  user options for %s:\n", VG_(details).name);
      if (VG_(needs).command_line_options)
	 VG_TDICT_CALL(tool_print_usage);
      else
	 VG_(printf)("    (none)\n");
   }
   if (debug_help) {
      VG_(printf)(usage2);

      if (VG_(details).name) {
         VG_(printf)("  debugging options for %s:\n", VG_(details).name);
      
         if (VG_(needs).command_line_options)
            VG_TDICT_CALL(tool_print_debug_usage);
         else
            VG_(printf)("    (none)\n");
      }
   }
   VG_(printf)(usage3, VG_BUGS_TO);
   VG_(exit)(0);
}

static void pre_process_cmd_line_options
      ( Int* need_help, const char** tool, const char** exec )
{
   UInt i;

   LibVEX_default_VexControl(& VG_(clo_vex_control));

   /* parse the options we have (only the options we care about now) */
   for (i = 1; i < vg_argc; i++) {

      if (VG_STREQ(vg_argv[i], "--version")) {
         VG_(printf)("valgrind-" VERSION "\n");
         VG_(exit)(0);

      } else if (VG_CLO_STREQ(vg_argv[i], "--help") ||
                 VG_CLO_STREQ(vg_argv[i], "-h")) {
         *need_help = 1;

      } else if (VG_CLO_STREQ(vg_argv[i], "--help-debug")) {
         *need_help = 2;

      } else if (VG_CLO_STREQN(7, vg_argv[i], "--tool=")) {
	 *tool = &vg_argv[i][7];
	 
      } else if (VG_CLO_STREQN(7, vg_argv[i], "--exec=")) {
	 *exec = &vg_argv[i][7];
      }
   }
}

static void process_cmd_line_options( UInt* client_auxv, const char* toolname )
{
   SysRes sres;
   Int    i, eventually_log_fd;
   Int    toolname_len = VG_(strlen)(toolname);
   enum {
      VgLogTo_Fd,
      VgLogTo_File,
      VgLogTo_FileExactly,
      VgLogTo_Socket
   } log_to = VgLogTo_Fd;   // Where is logging output to be sent?

   /* log to stderr by default, but usage message goes to stdout */
   eventually_log_fd = 2; 

   /* Check for sane path in ./configure --prefix=... */
   if (VG_LIBDIR[0] != '/') 
     config_error("Please use absolute paths in "
                  "./configure --prefix=... or --libdir=...");

   for (i = 1; i < vg_argc; i++) {

      Char* arg = vg_argv[i];
      Char* colon = arg;

      /* Look for a colon in the switch name */
      while (*colon && *colon != ':' && *colon != '=')
         colon++;

      /* Look for matching "--toolname:foo" */
      if (*colon == ':') {
         if (VG_CLO_STREQN(2,            arg,                "--") && 
             VG_CLO_STREQN(toolname_len, arg+2,              toolname) &&
             VG_CLO_STREQN(1,            arg+2+toolname_len, ":"))
         {
            // prefix matches, convert "--toolname:foo" to "--foo"
            if (0)
               VG_(printf)("tool-specific arg: %s\n", arg);
            arg = VG_(strdup)(arg + toolname_len + 1);
            arg[0] = '-';
            arg[1] = '-';

         } else {
            // prefix doesn't match, skip to next arg
            continue;
         }
      }
      
      /* Ignore these options - they've already been handled */
      if (VG_CLO_STREQN( 7, arg, "--tool="))              goto skip_arg;
      if (VG_CLO_STREQN( 7, arg, "--exec="))              goto skip_arg;
      if (VG_CLO_STREQN(20, arg, "--command-line-only=")) goto skip_arg;

      if (     VG_CLO_STREQ(arg, "--"))                  goto skip_arg;

      else if (VG_CLO_STREQ(arg, "-v") ||
               VG_CLO_STREQ(arg, "--verbose"))
         VG_(clo_verbosity)++;

      else if (VG_CLO_STREQ(arg, "-q") ||
               VG_CLO_STREQ(arg, "--quiet"))
         VG_(clo_verbosity)--;

      else if (VG_CLO_STREQ(arg, "-d")) {
         /* do nothing */
      }

      else VG_BOOL_CLO(arg, "--xml",              VG_(clo_xml))
      else VG_BOOL_CLO(arg, "--db-attach",        VG_(clo_db_attach))
      else VG_BOOL_CLO(arg, "--demangle",         VG_(clo_demangle))
      else VG_BOOL_CLO(arg, "--error-limit",      VG_(clo_error_limit))
      else VG_BOOL_CLO(arg, "--pointercheck",     VG_(clo_pointercheck))
      else VG_BOOL_CLO(arg, "--show-emwarns",     VG_(clo_show_emwarns))
      else VG_NUM_CLO (arg, "--max-stackframe",   VG_(clo_max_stackframe))
      else VG_BOOL_CLO(arg, "--profile",          VG_(clo_profile))
      else VG_BOOL_CLO(arg, "--run-libc-freeres", VG_(clo_run_libc_freeres))
      else VG_BOOL_CLO(arg, "--show-below-main",  VG_(clo_show_below_main))
      else VG_BOOL_CLO(arg, "--time-stamp",       VG_(clo_time_stamp))
      else VG_BOOL_CLO(arg, "--track-fds",        VG_(clo_track_fds))
      else VG_BOOL_CLO(arg, "--trace-children",   VG_(clo_trace_children))
      else VG_BOOL_CLO(arg, "--trace-sched",      VG_(clo_trace_sched))
      else VG_BOOL_CLO(arg, "--trace-signals",    VG_(clo_trace_signals))
      else VG_BOOL_CLO(arg, "--trace-symtab",     VG_(clo_trace_symtab))
      else VG_BOOL_CLO(arg, "--trace-cfi",        VG_(clo_trace_cfi))
      else VG_BOOL_CLO(arg, "--trace-redir",      VG_(clo_trace_redir))
      else VG_BOOL_CLO(arg, "--trace-syscalls",   VG_(clo_trace_syscalls))
      else VG_BOOL_CLO(arg, "--trace-pthreads",   VG_(clo_trace_pthreads))
      else VG_BOOL_CLO(arg, "--wait-for-gdb",     VG_(clo_wait_for_gdb))
      else VG_BOOL_CLO(arg, "--model-pthreads",   VG_(clo_model_pthreads))

      else VG_STR_CLO (arg, "--db-command",       VG_(clo_db_command))
      else VG_STR_CLO (arg, "--weird-hacks",      VG_(clo_weird_hacks))

      else VG_NUM_CLO (arg, "--dump-error",       VG_(clo_dump_error))
      else VG_NUM_CLO (arg, "--input-fd",         VG_(clo_input_fd))
      else VG_NUM_CLO (arg, "--sanity-level",     VG_(clo_sanity_level))
      else VG_BNUM_CLO(arg, "--num-callers",      VG_(clo_backtrace_size), 1,
                                                  VG_DEEPEST_BACKTRACE)

      else if (VG_CLO_STREQ(arg, "--smc-check=none"))
         VG_(clo_smc_check) = Vg_SmcNone;
      else if (VG_CLO_STREQ(arg, "--smc-check=stack"))
         VG_(clo_smc_check) = Vg_SmcStack;
      else if (VG_CLO_STREQ(arg, "--smc-check=all"))
         VG_(clo_smc_check) = Vg_SmcAll;

      else VG_BNUM_CLO(arg, "--vex-iropt-verbosity",
                       VG_(clo_vex_control).iropt_verbosity, 0, 10)
      else VG_BNUM_CLO(arg, "--vex-iropt-level",
                       VG_(clo_vex_control).iropt_level, 0, 2)
      else VG_BOOL_CLO(arg, "--vex-iropt-precise-memory-exns",
                       VG_(clo_vex_control).iropt_precise_memory_exns)
      else VG_BNUM_CLO(arg, "--vex-iropt-unroll-thresh",
                       VG_(clo_vex_control).iropt_unroll_thresh, 0, 400)
      else VG_BNUM_CLO(arg, "--vex-guest-max-insns",
                       VG_(clo_vex_control).guest_max_insns, 1, 100)
      else VG_BNUM_CLO(arg, "--vex-guest-chase-thresh",
                       VG_(clo_vex_control).guest_chase_thresh, 0, 99)

      else if (VG_CLO_STREQN(9,  arg, "--log-fd=")) {
         log_to            = VgLogTo_Fd;
         VG_(clo_log_name) = NULL;
         eventually_log_fd = (Int)VG_(atoll)(&arg[9]);
      }

      else if (VG_CLO_STREQN(11, arg, "--log-file=")) {
         log_to            = VgLogTo_File;
         VG_(clo_log_name) = &arg[11];
      }

      else if (VG_CLO_STREQN(11, arg, "--log-file=")) {
         log_to            = VgLogTo_File;
         VG_(clo_log_name) = &arg[11];
      }

      else if (VG_CLO_STREQN(21, arg, "--log-file-qualifier=")) {
         VG_(clo_log_file_qualifier) = &arg[21];
      }

      else if (VG_CLO_STREQN(19, arg, "--log-file-exactly=")) {
         log_to            = VgLogTo_FileExactly;
         VG_(clo_log_name) = &arg[19];
      }

      else if (VG_CLO_STREQN(13, arg, "--log-socket=")) {
         log_to            = VgLogTo_Socket;
         VG_(clo_log_name) = &arg[13];
      }

      else if (VG_CLO_STREQN(19, arg, "--xml-user-comment=")) {
         VG_(clo_xml_user_comment) = &arg[19];
      }

      else if (VG_CLO_STREQN(15, arg, "--suppressions=")) {
         if (VG_(clo_n_suppressions) >= VG_CLO_MAX_SFILES) {
            VG_(message)(Vg_UserMsg, "Too many suppression files specified.");
            VG_(message)(Vg_UserMsg, 
                         "Increase VG_CLO_MAX_SFILES and recompile.");
            VG_(bad_option)(arg);
         }
         VG_(clo_suppressions)[VG_(clo_n_suppressions)] = &arg[15];
         VG_(clo_n_suppressions)++;
      }

      /* "stuvwxyz" --> stuvwxyz (binary) */
      else if (VG_CLO_STREQN(14, arg, "--trace-flags=")) {
         Int j;
         char* opt = & arg[14];
   
         if (8 != VG_(strlen)(opt)) {
            VG_(message)(Vg_UserMsg, 
                         "--trace-flags argument must have 8 digits");
            VG_(bad_option)(arg);
         }
         for (j = 0; j < 8; j++) {
            if      ('0' == opt[j]) { /* do nothing */ }
            else if ('1' == opt[j]) VG_(clo_trace_flags) |= (1 << (7-j));
            else {
               VG_(message)(Vg_UserMsg, "--trace-flags argument can only "
                                        "contain 0s and 1s");
               VG_(bad_option)(arg);
            }
         }
      }

      /* "stuvwxyz" --> stuvwxyz (binary) */
      else if (VG_CLO_STREQN(16, arg, "--profile-flags=")) {
         Int j;
         char* opt = & arg[16];
   
         if (8 != VG_(strlen)(opt)) {
            VG_(message)(Vg_UserMsg, 
                         "--profile-flags argument must have 8 digits");
            VG_(bad_option)(arg);
         }
         for (j = 0; j < 8; j++) {
            if      ('0' == opt[j]) { /* do nothing */ }
            else if ('1' == opt[j]) VG_(clo_profile_flags) |= (1 << (7-j));
            else {
               VG_(message)(Vg_UserMsg, "--profile-flags argument can only "
                                        "contain 0s and 1s");
               VG_(bad_option)(arg);
            }
         }
      }

      else VG_NUM_CLO (arg, "--trace-notbelow",   VG_(clo_trace_notbelow))

      else if (VG_CLO_STREQ(arg, "--gen-suppressions=no"))
         VG_(clo_gen_suppressions) = 0;
      else if (VG_CLO_STREQ(arg, "--gen-suppressions=yes"))
         VG_(clo_gen_suppressions) = 1;
      else if (VG_CLO_STREQ(arg, "--gen-suppressions=all"))
         VG_(clo_gen_suppressions) = 2;

      else if ( ! VG_(needs).command_line_options
             || ! VG_TDICT_CALL(tool_process_cmd_line_option, arg) ) {
         VG_(bad_option)(arg);
      }
    skip_arg:
      if (arg != vg_argv[i]) {
         //FIXME         free(arg);
      }
   }

   /* Make VEX control parameters sane */

   if (VG_(clo_vex_control).guest_chase_thresh
       >= VG_(clo_vex_control).guest_max_insns)
      VG_(clo_vex_control).guest_chase_thresh
         = VG_(clo_vex_control).guest_max_insns - 1;

   if (VG_(clo_vex_control).guest_chase_thresh < 0)
      VG_(clo_vex_control).guest_chase_thresh = 0;

   /* Check various option values */

   if (VG_(clo_verbosity) < 0)
      VG_(clo_verbosity) = 0;

   if (VG_(clo_db_attach) && VG_(clo_trace_children)) {
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, 
         "--db-attach=yes conflicts with --trace-children=yes");
      VG_(message)(Vg_UserMsg, 
         "Please choose one or the other, but not both.");
      VG_(bad_option)("--db-attach=yes and --trace-children=yes");
   }

   if (VG_(clo_gen_suppressions) > 0 && 
       !VG_(needs).core_errors && !VG_(needs).tool_errors) {
      VG_(message)(Vg_UserMsg, 
                   "Can't use --gen-suppressions= with this tool,");
      VG_(message)(Vg_UserMsg, 
                   "as it doesn't generate errors.");
      VG_(bad_option)("--gen-suppressions=");
   }

   /* If we've been asked to emit XML, mash around various other
      options so as to constrain the output somewhat, and to remove
      any need for user input during the run. */
   if (VG_(clo_xml)) {
      /* Disable suppression generation (requires user input) */
      VG_(clo_gen_suppressions) = 0;
      /* Disable attaching to GDB (requires user input) */
      VG_(clo_db_attach) = False;
      /* Set a known verbosity level */
      VG_(clo_verbosity) = 1;
      /* Disable error limits (this might be a bad idea!) */
      VG_(clo_error_limit) = False;
      /* Disable emulation warnings */
      VG_(clo_show_emwarns) = False;
      /* Disable waiting for GDB to debug Valgrind */
      VG_(clo_wait_for_gdb) = False;
      /* No file-descriptor leak checking yet */
      VG_(clo_track_fds) = False;
      /* Disable timestamped output */
      VG_(clo_time_stamp) = False;
      /* Also, we want to set options for the leak checker, but that
         will have to be done in Memcheck's flag-handling code, not
         here. */
   }

   /* All non-logging-related options have been checked.  If the logging
      option specified is ok, we can switch to it, as we know we won't
      have to generate any other command-line-related error messages.
      (So far we should be still attached to stderr, so we can show on
      the terminal any problems to do with processing command line
      opts.)
   
      So set up logging now.  After this is done, VG_(clo_log_fd)
      should be connected to whatever sink has been selected, and we
      indiscriminately chuck stuff into it without worrying what the
      nature of it is.  Oh the wonder of Unix streams. */

   vg_assert(VG_(clo_log_fd) == 2 /* stderr */);
   vg_assert(VG_(logging_to_socket) == False);

   switch (log_to) {

      case VgLogTo_Fd: 
         vg_assert(VG_(clo_log_name) == NULL);
         VG_(clo_log_fd) = eventually_log_fd;
         break;

      case VgLogTo_File: {
         HChar  logfilename[1000];
	 Int    seq  = 0;
	 Int    pid  = VG_(getpid)();
         HChar* qual = NULL;

         vg_assert(VG_(clo_log_name) != NULL);
         vg_assert(VG_(strlen)(VG_(clo_log_name)) <= 900); /* paranoia */

	 if (VG_(clo_log_file_qualifier)) {
            qual = VG_(getenv)(VG_(clo_log_file_qualifier));
	 }

	 for (;;) {
            HChar pidtxt[20], seqtxt[20];

            VG_(sprintf)(pidtxt, "%d", pid);

            if (seq == 0)
               seqtxt[0] = 0;
            else
               VG_(sprintf)(seqtxt, ".%d", seq);

	    seq++;

            /* Result:
                  if (qual)      base_name ++ "." ++ qual ++ seqtxt
                  if (not qual)  base_name ++ "." ++ pid  ++ seqtxt
            */
            VG_(sprintf)( logfilename, 
                          "%s.%s%s",
                          VG_(clo_log_name), 
                          qual ? qual : pidtxt,
                          seqtxt );

            // EXCL: it will fail with EEXIST if the file already exists.
            sres
	       = VG_(open)(logfilename, 
			   VKI_O_CREAT|VKI_O_WRONLY|VKI_O_EXCL|VKI_O_TRUNC, 
			   VKI_S_IRUSR|VKI_S_IWUSR);
	    if (!sres.isError) {
               eventually_log_fd = sres.val;
	       VG_(clo_log_fd) = VG_(safe_fd)(eventually_log_fd);
	       break; /* for (;;) */
	    } else {
               // If the file already existed, we try the next name.  If it
               // was some other file error, we give up.
	       if (sres.val != VKI_EEXIST) {
		  VG_(message)(Vg_UserMsg, 
			       "Can't create/open log file '%s.pid%d'; giving up!", 
			       VG_(clo_log_name), pid);
		  VG_(bad_option)(
		     "--log-file=<file> (didn't work out for some reason.)");
                  /*NOTREACHED*/
	       }
	    }
	 }
         break; /* switch (VG_(clo_log_to)) */
      }

      case VgLogTo_FileExactly: {
         vg_assert(VG_(clo_log_name) != NULL);
         vg_assert(VG_(strlen)(VG_(clo_log_name)) <= 900); /* paranoia */

         sres
            = VG_(open)(VG_(clo_log_name),
                        VKI_O_CREAT|VKI_O_WRONLY|VKI_O_TRUNC, 
                        VKI_S_IRUSR|VKI_S_IWUSR);
         if (!sres.isError) {
            eventually_log_fd = sres.val;
            VG_(clo_log_fd) = VG_(safe_fd)(eventually_log_fd);
         } else {
            VG_(message)(Vg_UserMsg, 
                         "Can't create/open log file '%s'; giving up!", 
                         VG_(clo_log_name));
            VG_(bad_option)(
               "--log-file-exactly=<file> (didn't work out for some reason.)");
            /*NOTREACHED*/
	 }
         break; /* switch (VG_(clo_log_to)) */
      }

      case VgLogTo_Socket: {
         vg_assert(VG_(clo_log_name) != NULL);
         vg_assert(VG_(strlen)(VG_(clo_log_name)) <= 900); /* paranoia */
         eventually_log_fd = VG_(connect_via_socket)( VG_(clo_log_name) );
         if (eventually_log_fd == -1) {
            VG_(message)(Vg_UserMsg, 
               "Invalid --log-socket=ipaddr or --log-socket=ipaddr:port spec"); 
            VG_(message)(Vg_UserMsg, 
               "of '%s'; giving up!", VG_(clo_log_name) );
            VG_(bad_option)(
               "--log-socket=");
            /*NOTREACHED*/
	 }
         if (eventually_log_fd == -2) {
            VG_(message)(Vg_UserMsg, 
               "valgrind: failed to connect to logging server '%s'.",
               VG_(clo_log_name) ); 
            VG_(message)(Vg_UserMsg, 
                "Log messages will sent to stderr instead." );
            VG_(message)(Vg_UserMsg, 
                "" );
            /* We don't change anything here. */
            vg_assert(VG_(clo_log_fd) == 2);
	 } else {
            vg_assert(eventually_log_fd > 0);
            VG_(clo_log_fd) = eventually_log_fd;
            VG_(logging_to_socket) = True;
         }
         break;
      }
   }


   /* Check that the requested tool actually supports XML output. */
   if (VG_(clo_xml) && !VG_STREQ(toolname, "memcheck")
                    && !VG_STREQ(toolname, "none")) {
      VG_(clo_xml) = False;
      VG_(message)(Vg_UserMsg, 
         "Currently only Memcheck|None supports XML output."); 
      VG_(bad_option)("--xml=yes");
      /*NOTREACHED*/
   }

   // Move log_fd into the safe range, so it doesn't conflict with any app fds.
   // XXX: this is more or less duplicating the behaviour of the calls to
   // VG_(safe_fd)() above, although this does not close the original fd.
   // Perhaps the VG_(safe_fd)() calls above should be removed, and this
   // code should be replaced with a call to VG_(safe_fd)().   --njn
   eventually_log_fd = VG_(fcntl)(VG_(clo_log_fd), VKI_F_DUPFD, VG_(fd_hard_limit));
   if (eventually_log_fd < 0)
      VG_(message)(Vg_UserMsg, "valgrind: failed to move logfile fd into safe range");
   else {
      VG_(clo_log_fd) = eventually_log_fd;
      VG_(fcntl)(VG_(clo_log_fd), VKI_F_SETFD, VKI_FD_CLOEXEC);
   }

   /* Ok, the logging sink is running now.  Print a suitable preamble.
      If logging to file or a socket, write details of parent PID and
      command line args, to help people trying to interpret the
      results of a run which encompasses multiple processes. */

   if (VG_(clo_xml)) {
      VG_(message)(Vg_UserMsg, "<?xml version=\"1.0\"?>");
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "<valgrindoutput>");
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "<protocolversion>1</protocolversion>");
      VG_(message)(Vg_UserMsg, "");
   }

   HChar* xpre  = VG_(clo_xml) ? "  <line>" : "";
   HChar* xpost = VG_(clo_xml) ? "</line>" : "";

   if (VG_(clo_verbosity > 0)) {

      if (VG_(clo_xml))
         VG_(message)(Vg_UserMsg, "<preamble>");

      /* Tool details */
      VG_(message)(Vg_UserMsg, "%s%s%s%s, %s.%s",
                   xpre,
                   VG_(details).name, 
                   NULL == VG_(details).version ? "" : "-",
                   NULL == VG_(details).version 
                      ? (Char*)"" : VG_(details).version,
                   VG_(details).description,
                   xpost);
      VG_(message)(Vg_UserMsg, "%s%s%s", 
                               xpre, VG_(details).copyright_author, xpost);

      /* Core details */
      VG_(message)(Vg_UserMsg,
         "%sUsing LibVEX rev %s, a library for dynamic binary translation.%s",
         xpre, LibVEX_Version(), xpost );
      VG_(message)(Vg_UserMsg, 
         "%sCopyright (C) 2004-2005, and GNU GPL'd, by OpenWorks LLP.%s",
         xpre, xpost );
      VG_(message)(Vg_UserMsg,
         "%sUsing valgrind-%s, a dynamic binary instrumentation framework.%s",
         xpre, VERSION, xpost);
      VG_(message)(Vg_UserMsg, 
         "%sCopyright (C) 2000-2005, and GNU GPL'd, by Julian Seward et al.%s",
         xpre, xpost );

      if (VG_(clo_xml))
         VG_(message)(Vg_UserMsg, "</preamble>");
   }

   if (!VG_(clo_xml) && VG_(clo_verbosity) > 0 && log_to != VgLogTo_Fd) {
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, 
         "My PID = %d, parent PID = %d.  Prog and args are:",
         VG_(getpid)(), VG_(getppid)() );
      for (i = 0; i < VG_(client_argc); i++) 
         VG_(message)(Vg_UserMsg, "   %s", VG_(client_argv)[i]);
      if (VG_(clo_log_file_qualifier)) {
         HChar* val = VG_(getenv)(VG_(clo_log_file_qualifier));
         VG_(message)(Vg_UserMsg, "");
         VG_(message)(Vg_UserMsg, "Log file qualifier: var %s, value %s.",
                                  VG_(clo_log_file_qualifier),
                                  val ? val : "");
      }
   }
   else
   if (VG_(clo_xml)) {
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "<pid>%d</pid>", VG_(getpid)());
      VG_(message)(Vg_UserMsg, "<ppid>%d</ppid>", VG_(getppid)());
      VG_(message)(Vg_UserMsg, "<tool>%t</tool>", toolname);
      if (VG_(clo_log_file_qualifier)) {
         HChar* val = VG_(getenv)(VG_(clo_log_file_qualifier));
         VG_(message)(Vg_UserMsg, "<logfilequalifier> <var>%t</var> "
                                  "<value>%t</value> </logfilequalifier>",
                                  VG_(clo_log_file_qualifier),
                                  val ? val : "");
      }
      if (VG_(clo_xml_user_comment)) {
         /* Note: the user comment itself is XML and is therefore to
            be passed through verbatim (%s) rather than escaped
            (%t). */
         VG_(message)(Vg_UserMsg, "<usercomment>%s</usercomment>",
                                  VG_(clo_xml_user_comment));
      }
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "<args>");
      VG_(message)(Vg_UserMsg, "  <vargv>");
      for (i = 0; i < vg_argc; i++) {
         HChar* tag = i==0 ? "exe" : "arg";
         VG_(message)(Vg_UserMsg, "    <%s>%t</%s>", 
                                  tag, vg_argv[i], tag);
      }
      VG_(message)(Vg_UserMsg, "  </vargv>");
      VG_(message)(Vg_UserMsg, "  <argv>");
      for (i = 0; i < VG_(client_argc); i++) {
         HChar* tag = i==0 ? "exe" : "arg";
         VG_(message)(Vg_UserMsg, "    <%s>%t</%s>", 
                                  tag, VG_(client_argv)[i], tag);
      }
      VG_(message)(Vg_UserMsg, "  </argv>");
      VG_(message)(Vg_UserMsg, "</args>");
   }

   if (VG_(clo_verbosity) > 1) {
      SysRes fd;
      if (log_to != VgLogTo_Fd)
         VG_(message)(Vg_DebugMsg, "");
      VG_(message)(Vg_DebugMsg, "Valgrind library directory: %s", VG_(libdir));
      VG_(message)(Vg_DebugMsg, "Command line");
      for (i = 0; i < VG_(client_argc); i++)
         VG_(message)(Vg_DebugMsg, "   %s", VG_(client_argv)[i]);

      VG_(message)(Vg_DebugMsg, "Startup, with flags:");
      for (i = 1; i < vg_argc; i++) {
         VG_(message)(Vg_DebugMsg, "   %s", vg_argv[i]);
      }

      VG_(message)(Vg_DebugMsg, "Contents of /proc/version:");
      fd = VG_(open) ( "/proc/version", VKI_O_RDONLY, 0 );
      if (fd.isError) {
         VG_(message)(Vg_DebugMsg, "  can't open /proc/version");
      } else {
#        define BUF_LEN    256
         Char version_buf[BUF_LEN];
         Int n = VG_(read) ( fd.val, version_buf, BUF_LEN );
         vg_assert(n <= BUF_LEN);
         if (n > 0) {
            version_buf[n-1] = '\0';
            VG_(message)(Vg_DebugMsg, "  %s", version_buf);
         } else {
            VG_(message)(Vg_DebugMsg, "  (empty?)");
         }
         VG_(close)(fd.val);
#        undef BUF_LEN
      }
   }

   if (VG_(clo_n_suppressions) < VG_CLO_MAX_SFILES-1 &&
       (VG_(needs).core_errors || VG_(needs).tool_errors)) {
      /* If we haven't reached the max number of suppressions, load
         the default one. */
      static const Char default_supp[] = "default.supp";
      Int len = VG_(strlen)(VG_(libdir)) + 1 + sizeof(default_supp);
      Char *buf = VG_(arena_malloc)(VG_AR_CORE, len);
      VG_(sprintf)(buf, "%s/%s", VG_(libdir), default_supp);
      VG_(clo_suppressions)[VG_(clo_n_suppressions)] = buf;
      VG_(clo_n_suppressions)++;
   }
}

// Build the string for VALGRINDCLO.
Char* VG_(build_child_VALGRINDCLO)( Char* exename )
{
   /* If we're tracing the children, then we need to start it
      with our starter+arguments, which are copied into VALGRINDCLO,
      except the --exec= option is changed if present.
   */
   Int i;
   Char *exec;
   Char *cp;
   Char *optvar;
   Int  optlen, execlen;

   // All these allocated blocks are not free - because we're either
   // going to exec, or panic when we fail.

   // Create --exec= option: "--exec=<exename>"
   exec = VG_(arena_malloc)(VG_AR_CORE, 
                            VG_(strlen)( exename ) + 7/*--exec=*/ + 1/*\0*/);
   vg_assert(NULL != exec);
   VG_(sprintf)(exec, "--exec=%s", exename);

   // Allocate space for optvar (may overestimate by counting --exec twice,
   // no matter)
   optlen = 1;
   for (i = 0; i < vg_argc; i++)
      optlen += VG_(strlen)(vg_argv[i]) + 1;
   optlen += VG_(strlen)(exec)+1;
   optvar = VG_(arena_malloc)(VG_AR_CORE, optlen);

   // Copy all valgrind args except the old --exec (if present)
   // VG_CLO_SEP is the separator.
   cp = optvar;
   for (i = 1; i < vg_argc; i++) {
      Char *arg = vg_argv[i];
      
      if (VG_CLO_STREQN(7, arg, "--exec=")) {
         // don't copy existing --exec= arg
      } else if (VG_CLO_STREQ(arg, "--")) {
         // stop at "--"
         break;
      } else {
         // copy non "--exec" arg
         Int len = VG_(strlen)(arg);
         VG_(memcpy)(cp, arg, len);
         cp += len;
         *cp++ = VG_CLO_SEP;
      }
   }
   // Add the new --exec= option
   execlen = VG_(strlen)(exec);
   VG_(memcpy)(cp, exec, execlen);
   cp += execlen;
   *cp++ = VG_CLO_SEP;

   *cp = '\0';

   return optvar;
}

// Build "/proc/self/fd/<execfd>".
Char* VG_(build_child_exename)( void )
{
   Char* exename = VG_(arena_malloc)(VG_AR_CORE, 64);
   vg_assert(NULL != exename);
#ifdef VGO_netbsdelf2
   VG_(sprintf)(exename, "/proc/curproc/fd/%d", vgexecfd);
#else
   VG_(sprintf)(exename, "/proc/self/fd/%d", vgexecfd);
#endif
   return exename;
}


/*====================================================================*/
/*=== File descriptor setup                                        ===*/
/*====================================================================*/

static void setup_file_descriptors(void)
{
   struct vki_rlimit rl;

   /* Get the current file descriptor limits. */
   if (VG_(getrlimit)(VKI_RLIMIT_NOFILE, &rl) < 0) {
      rl.rlim_cur = 1024;
      rl.rlim_max = 1024;
   }

   /* Work out where to move the soft limit to. */
   if (rl.rlim_cur + N_RESERVED_FDS <= rl.rlim_max) {
      rl.rlim_cur = rl.rlim_cur + N_RESERVED_FDS;
   } else {
      rl.rlim_cur = rl.rlim_max;
   }

   /* Reserve some file descriptors for our use. */
   VG_(fd_soft_limit) = rl.rlim_cur - N_RESERVED_FDS;
   VG_(fd_hard_limit) = rl.rlim_cur - N_RESERVED_FDS;

   VG_(setrlimit)(VKI_RLIMIT_NOFILE, &rl);


   if (vgexecfd != -1)
      vgexecfd = VG_(safe_fd)( vgexecfd );
   if (VG_(clexecfd) != -1)
	   VG_(clexecfd) = VG_(safe_fd)( VG_(clexecfd) );
}

/*====================================================================*/
/*===  Initialise program data/text, etc.                          ===*/
/*====================================================================*/

static void build_valgrind_map_callback ( Addr start, SizeT size, UInt prot,
					  UInt dev, UInt ino, ULong foffset, 
					  const UChar* filename )
{
   /* Only record valgrind mappings for now, without loading any
      symbols.  This is so we know where the free space is before we
      start allocating more memory (note: heap is OK, it's just mmap
      which is the problem here). */
   if (start >= VG_(client_end) && start < VG_(valgrind_last)) {
      VG_(debugLog)(2, "main",
                    "valgrind-seg: %p-%p prot 0x%x file=%s\n",
                    (void*)start, (void*)(start+size), prot, filename);
      VG_(map_file_segment)(start, size, prot,
                            SF_MMAP|SF_NOSYMS|SF_VALGRIND,
                            dev, ino, foffset, filename);
      /* update VG_(valgrind_last) if it looks wrong */
      if (start+size > VG_(valgrind_last))
         VG_(valgrind_last) = start+size-1;
   }
}

// Global var used to pass local data to callback
Addr sp_at_startup___global_arg = 0;

/* 
   This second pass adds in client mappings, and loads symbol tables
   for all interesting mappings.  The trouble is that things can
   change as we go, because we're calling the Tool to track memory as
   we find it.

   So for Valgrind mappings, we don't replace any mappings which
   aren't still identical (which will include the .so mappings, so we
   will load their symtabs)>
 */
static void build_segment_map_callback ( Addr start, SizeT size, UInt prot,
					 UInt dev, UInt ino, ULong foffset,
					 const UChar* filename )
{
   UInt flags;
   Bool is_stack_segment;
   Addr r_esp;

   is_stack_segment 
      = (start == VG_(clstk_base) && (start+size) == VG_(clstk_end));

   VG_(debugLog)(2, "main",
                 "any-seg: %p-%p prot 0x%x stack=%d file=%s\n",
                 (void*)start, (void*)(start+size), prot, is_stack_segment, 
                 filename);

   if (is_stack_segment)
      flags = SF_STACK | SF_GROWDOWN;
   else
      flags = SF_MMAP;

   if (filename != NULL)
      flags |= SF_FILE;

#if 0
   // This needs to be fixed properly.   jrs 20050307
   if (start >= VG_(client_end) && start < VG_(valgrind_last)) {
      Segment *s = VG_(find_segment_before)(start);

      /* We have to be a bit careful about inserting new mappings into
	 the Valgrind part of the address space.  We're actively
	 changing things as we parse these mappings, particularly in
	 shadow memory, and so we don't want to overwrite those
	 changes.  Therefore, we only insert/update a mapping if it is
	 mapped from a file or it exactly matches an existing mapping.

	 NOTE: we're only talking about the Segment list mapping
	 metadata; this doesn't actually mmap anything more. */
      if (filename || (s && s->addr == start && s->len == size)) {
	 flags |= SF_VALGRIND;
	 VG_(map_file_segment)(start, size, prot, flags, dev, ino, foffset, filename);
      } else {
	 /* assert range is already mapped */
	 vg_assert(VG_(is_addressable)(start, size, VKI_PROT_NONE));
      }
   } else
#endif
      VG_(map_file_segment)(start, size, prot, flags, dev, ino, foffset, filename);

   if (VG_(is_client_addr)(start) && VG_(is_client_addr)(start+size-1)) {
	   VG_TRACK( new_mem_startup, start, size,
		     !!(prot & VKI_PROT_READ), 
                     !!(prot & VKI_PROT_WRITE), 
                     !!(prot & VKI_PROT_EXEC));
   }

   /* If this is the stack segment mark all below %esp as noaccess. */
   r_esp = sp_at_startup___global_arg;
   vg_assert(0 != r_esp);
   if (is_stack_segment) {
      if (0) {
         VG_(message)(Vg_DebugMsg, "invalidating stack area: %p .. %p",
                      start,r_esp);
         VG_(message)(Vg_DebugMsg, "  validating stack area: %p .. %p",
                      r_esp, start+size);
      }
      VG_TRACK( die_mem_stack, start, r_esp-start );
      // what's this for?
      //VG_TRACK( post_mem_write, r_esp, (start+size)-r_esp );
   }
}

/*====================================================================*/
/*===  Initialise the first thread.                                ===*/
/*====================================================================*/

/* Given a pointer to the ThreadArchState for thread 1 (the root
   thread), initialise the VEX guest state, and copy in essential
   starting values.
*/
static void init_thread1state ( Addr client_ip, 
                                Addr sp_at_startup,
                                /*inout*/ ThreadArchState* arch )
{
#if defined(VGA_x86)
   vg_assert(0 == sizeof(VexGuestX86State) % 8);

   /* Zero out the initial state, and set up the simulated FPU in a
      sane way. */
   LibVEX_GuestX86_initialise(&arch->vex);

   /* Zero out the shadow area. */
   VG_(memset)(&arch->vex_shadow, 0, sizeof(VexGuestX86State));

   /* Put essential stuff into the new state. */
   arch->vex.guest_ESP = sp_at_startup;
   arch->vex.guest_EIP = client_ip;

   /* initialise %cs, %ds and %ss to point at the operating systems
      default code, data and stack segments */
   asm volatile("movw %%cs, %0" : : "m" (arch->vex.guest_CS));
   asm volatile("movw %%ds, %0" : : "m" (arch->vex.guest_DS));
   asm volatile("movw %%ss, %0" : : "m" (arch->vex.guest_SS));

#elif defined(VGA_amd64)
   vg_assert(0 == sizeof(VexGuestAMD64State) % 8);

   /* Zero out the initial state, and set up the simulated FPU in a
      sane way. */
   LibVEX_GuestAMD64_initialise(&arch->vex);

   /* Zero out the shadow area. */
   VG_(memset)(&arch->vex_shadow, 0, sizeof(VexGuestAMD64State));

   /* Put essential stuff into the new state. */
   arch->vex.guest_RSP = sp_at_startup;
   arch->vex.guest_RIP = client_ip;

#elif defined(VGA_ppc32)
   vg_assert(0 == sizeof(VexGuestPPC32State) % 8);

   /* Zero out the initial state, and set up the simulated FPU in a
      sane way. */
   LibVEX_GuestPPC32_initialise(&arch->vex);

   /* Zero out the shadow area. */
   VG_(memset)(&arch->vex_shadow, 0, sizeof(VexGuestPPC32State));

   /* Put essential stuff into the new state. */
   arch->vex.guest_GPR1 = sp_at_startup;
   arch->vex.guest_CIA  = client_ip;

#else
#  error Unknown arch
#endif
   // Tell the tool that we just wrote to the registers.
   VG_TRACK( post_reg_write, Vg_CoreStartup, /*tid*/1, /*offset*/0,
             sizeof(VexGuestArchState));
}


/*====================================================================*/
/*=== BB profiling                                                 ===*/
/*====================================================================*/

static 
void show_BB_profile ( BBProfEntry tops[], UInt n_tops, ULong score_total )
{
   ULong score_cumul,   score_here;
   Char  buf_cumul[10], buf_here[10];
   Char  name[64];
   Int   r;

   VG_(printf)("\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("--- BEGIN BB Profile (summary of scores)                ---\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("\n");

   VG_(printf)("Total score = %lld\n\n", score_total);

   score_cumul = 0;
   for (r = 0; r < n_tops; r++) {
      if (tops[r].addr == 0)
         continue;
      name[0] = 0;
      VG_(get_fnname_w_offset)(tops[r].addr, name, 64);
      name[63] = 0;
      score_here = tops[r].score;
      score_cumul += score_here;
      VG_(percentify)(score_cumul, score_total, 2, 6, buf_cumul);
      VG_(percentify)(score_here,  score_total, 2, 6, buf_here);
      VG_(printf)("%3d: (%9lld %s)   %9lld %s      0x%llx %s\n",
                  r,
                  score_cumul, buf_cumul,
                  score_here,  buf_here, tops[r].addr, name );
   }

   VG_(printf)("\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("--- BB Profile (BB details)                             ---\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("\n");

   score_cumul = 0;
   for (r = 0; r < n_tops; r++) {
      if (tops[r].addr == 0)
         continue;
      name[0] = 0;
      VG_(get_fnname_w_offset)(tops[r].addr, name, 64);
      name[63] = 0;
      score_here = tops[r].score;
      score_cumul += score_here;
      VG_(percentify)(score_cumul, score_total, 2, 6, buf_cumul);
      VG_(percentify)(score_here,  score_total, 2, 6, buf_here);
      VG_(printf)("\n");
      VG_(printf)("=-=-=-=-=-=-=-=-=-=-=-=-=-= begin BB rank %d "
                  "=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n", r);
      VG_(printf)("%3d: (%9lld %s)   %9lld %s      0x%llx %s\n",
                  r,
                  score_cumul, buf_cumul,
                  score_here,  buf_here, tops[r].addr, name );
      VG_(printf)("\n");
      VG_(translate)(0, tops[r].addr, True, VG_(clo_profile_flags), 0);
      VG_(printf)("=-=-=-=-=-=-=-=-=-=-=-=-=-=  end BB rank %d  "
                  "=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n", r);
   }

   VG_(printf)("\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("--- END BB Profile                                      ---\n");
   VG_(printf)("-----------------------------------------------------------\n");
   VG_(printf)("\n");
}


/*====================================================================*/
/*=== main()                                                       ===*/
/*====================================================================*/

/*
  This code decides on the layout of the client and Valgrind address
  spaces, loads valgrind.so and the tool.so into the valgrind part,
  loads the client executable (and the dynamic linker, if necessary)
  into the client part, and calls into Valgrind proper.

  The code is careful not to allow spurious mappings to appear in the
  wrong parts of the address space.  In particular, to make sure
  dlopen puts things in the right place, it will pad out the forbidden
  chunks of address space so that dlopen is forced to put things where
  we want them.

  The memory map it creates is:

  client_base    +-------------------------+
                 | client address space    |
	         :                         :
	         :                         :
		 | client stack            |
  client_end     +-------------------------+
                 | redzone                 |
  shadow_base    +-------------------------+
                 |                         |
	         : shadow memory for tools :
	         | (may be 0 sized)        |
  shadow_end     +-------------------------+
  valgrind_base  +-------------------------+
                 | kickstart executable    |
                 | valgrind heap  vvvvvvvvv| (barely used)
                 -                         -
                 | valgrind .so files      |
		 | and mappings            |
                 -                         -
                 | valgrind stack ^^^^^^^^^|
  valgrind_last  +-------------------------+
		 : kernel                  :

  Nb: Before we can do general allocations with VG_(arena_malloc)() and
  VG_(mmap)(), we need to build the segment skip-list, so we know where
  we can put things.  However, building that structure requires
  allocating memory.  So we need to a bootstrapping process.  It's done
  by making VG_(arena_malloc)() have a special static superblock that's
  used for the first 1MB's worth of allocations.  This is enough to
  build the segment skip-list.
*/


Int main(Int argc, HChar **argv, HChar **envp)
{
         HChar** cl_argv;
   const HChar*  tool = "memcheck";   // default to Memcheck
   const HChar*  exec = NULL;
         HChar*  preload;             /* tool-specific LD_PRELOAD .so */
         HChar** env;
         Int     need_help = 0;      // 0 = no, 1 = --help, 2 = --help-debug
         struct exeinfo info;
         ToolInfo* toolinfo = NULL;
         Addr      client_eip;
         Addr      sp_at_startup;  /* client's SP at the point we
				      gained control. */
         UInt*     client_auxv;
         Int       loglevel, i;
         struct vki_rlimit zero = { 0, 0 };

   //============================================================
   // Nb: startup is complex.  Prerequisites are shown at every step.
   //
   // *** Be very careful when messing with the order ***
   //
   // TODO (JRS 9 Aug 05): 
   //    - there's circular dependencies with VG_(getenv).
   //      TODO: review and clarify all issues to do with
   //      environment variables.
   //      
   //============================================================
   
   /* This is needed to make VG_(getenv) usable early. */
   VG_(client_envp) = (Char**)envp;

   //--------------------------------------------------------------
   // Start up the logging mechanism
   //   p: none
   //--------------------------------------------------------------
   /* Start the debugging-log system ASAP.  First find out how many 
      "-d"s were specified.  This is a pre-scan of the command line. */
   VG_(printf)("In stage 2 main!\n");
   loglevel = 0;
   for (i = 1; i < argc; i++) {
      if (argv[i][0] != '-')
         break;
      if (VG_STREQ(argv[i], "--")) 
         break;
      if (VG_STREQ(argv[i], "-d")) 
         loglevel++;
   }

   VG_(printf)("dooing debuglog startup\n");
   /* ... and start the debug logger.  Now we can safely emit logging
      messages all through startup. */
   VG_(debugLog_startup)(loglevel, "Stage 2 (main)");

   VG_(printf)("after debuglog startup\n");
   //============================================================
   // Command line argument handling order:
   // * If --help/--help-debug are present, show usage message 
   //   (including the tool-specific usage)
   // * (If no --tool option given, default to Memcheck)
   // * Then, if client is missing, abort with error msg
   // * Then, if any cmdline args are bad, abort with error msg
   //============================================================

   // Get the current process datasize rlimit, and set it to zero.
   // This prevents any internal uses of brk() from having any effect.
   // We remember the old value so we can restore it on exec, so that
   // child processes will have a reasonable brk value.
//   VG_(getrlimit)(VKI_RLIMIT_DATA, &VG_(client_rlimit_data));
   // zero.rlim_max = VG_(client_rlimit_data).rlim_max;
   //  VG_(setrlimit)(VKI_RLIMIT_DATA, &zero);

   // Get the current process stack rlimit.
   VG_(getrlimit)(VKI_RLIMIT_STACK, &VG_(client_rlimit_stack));

   //--------------------------------------------------------------
   // Check we were launched by stage1
   //   p: none
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Doing scan_auxv()\n");
   {
   void* init_sp = argv - 1;
   scan_auxv(init_sp);
   }

   //--------------------------------------------------------------
   // Look for alternative libdir                                  
   //   p: none
   //--------------------------------------------------------------
   if (1) {  HChar *cp = VG_(getenv)(VALGRINDLIB);
      if (cp != NULL)
	 VG_(libdir) = cp;
   }

   //--------------------------------------------------------------
   // Get valgrind args + client args (inc. from VALGRIND_OPTS/.valgrindrc).
   // Pre-process the command line.
   //   p: none
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Preprocess command line opts\n");
   get_command_line(argc, argv, &vg_argc, &vg_argv, &cl_argv);
   pre_process_cmd_line_options(&need_help, &tool, &exec);

   /* If this process was created by exec done by another Valgrind
      process, the arguments will only show up at this point.  Hence
      we need to also snoop around in vg_argv to see if anyone is
      asking for debug logging. */
   if (loglevel == 0) {
      for (i = 1; i < vg_argc; i++) {
         if (vg_argv[i][0] != '-')
            break;
         if (VG_STREQ(vg_argv[i], "--")) 
            break;
         if (VG_STREQ(vg_argv[i], "-d")) 
            loglevel++;
      }
      VG_(debugLog_startup)(loglevel, "Stage 2 (second go)");
   }

   //==============================================================
   // Nb: once a tool is specified, the tool.so must be loaded even if 
   // they specified --help or didn't specify a client program.
   //==============================================================

   //--------------------------------------------------------------
   // With client padded out, map in tool
   //   p: set-libdir                     [for VG_(libdir)]
   //   p: pre_process_cmd_line_options() [for 'tool']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Loading tool\n");
   load_tool(tool, &toolinfo, &preload);

   //==============================================================
   // Can use VG_(malloc)() and VG_(arena_malloc)() only after load_tool()
   // -- redzone size is now set.  This is checked by vg_malloc2.c.
   //==============================================================
   
   //--------------------------------------------------------------
   // Finalise address space layout
   //   p: load_tool()  [for 'toolinfo']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Laying out remaining space\n");
   layout_remaining_space( (Addr) & argc, toolinfo->shadow_ratio );

   //--------------------------------------------------------------
   // Load client executable, finding in $PATH if necessary
   //   p: pre_process_cmd_line_options()  [for 'exec', 'need_help']
   //   p: layout_remaining_space          [so there's space]
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Loading client\n");
   load_client(cl_argv, exec, need_help, &info, &client_eip);

   //--------------------------------------------------------------
   // Everything in place, remove padding done by stage1
   //   p: layout_remaining_space()  [everything must be mapped in before now]  
   //   p: load_client()             [ditto] 
   //--------------------------------------------------------------
   //as_unpad((void *)VG_(shadow_end), (void *)~0, padfile);
   //as_closepadfile(padfile);  // no more padding

   //--------------------------------------------------------------
   // Set up client's environment
   //   p: set-libdir  [for VG_(libdir)]
   //   p: load_tool() [for 'preload']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Setup client env\n");
   env = fix_environment(envp, preload);

   //--------------------------------------------------------------
   // Setup client stack, eip, and VG_(client_arg[cv])
   //   p: load_client()     [for 'info']
   //   p: fix_environment() [for 'env']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Setup client stack\n");
   { 
   void* init_sp = argv - 1;

   sp_at_startup = setup_client_stack(init_sp, cl_argv, env, &info,
                                      &client_auxv);
   //FIXME   free(env);
   }

   VG_(debugLog)(2, "main",
                    "Client info: "
                    "entry=%p client esp=%p vg_argc=%d brkbase=%p\n",
                    (void*)client_eip, (void*)sp_at_startup, vg_argc, 
                    (void*)VG_(brk_base) );

   //==============================================================
   // Finished setting up operating environment.  Now initialise
   // Valgrind.  (This is where the old VG_(main)() started.)
   //==============================================================

   //--------------------------------------------------------------
   // setup file descriptors
   //   p: n/a
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Setup file descriptors\n");
   setup_file_descriptors();
   VG_(printf)("after setup\n");

   //--------------------------------------------------------------
   // Build segment map (Valgrind segments only)
   //   p: tl_pre_clo_init()  [to setup new_mem_startup tracker]
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Parse /proc/self/maps (round 1)\n");
   VG_(parse_procselfmaps) ( build_valgrind_map_callback );

   //==============================================================
   // Can use VG_(arena_malloc)() with non-CORE arena after segments set up
   //==============================================================

   //--------------------------------------------------------------
   // Init tool: pre_clo_init, process cmd line, post_clo_init
   //   p: setup_client_stack()      [for 'VG_(client_arg[cv]']
   //   p: load_tool()               [for 'toolinfo']
   //   p: setup_file_descriptors()  [for 'VG_(fd_xxx_limit)']
   //   p: parse_procselfmaps        [so VG segments are setup so tool can
   //                                 call VG_(malloc)]
   //--------------------------------------------------------------
   {
      Char* s;
      Bool  ok;
      VG_(debugLog)(1, "main", "Initialise the tool\n");
      (*toolinfo->tl_pre_clo_init)();
      ok = VG_(sanity_check_needs)( VG_(shadow_base) != VG_(shadow_end), &s );
      if (!ok) {
         VG_(tool_panic)(s);
      }
   }

   // If --tool and --help/--help-debug was given, now give the core+tool
   // help message
   if (need_help) {
      usage(/*--help-debug?*/2 == need_help);
   }
   process_cmd_line_options(client_auxv, tool);

   VG_TDICT_CALL(tool_post_clo_init);

   //--------------------------------------------------------------
   // Build segment map (all segments)
   //   p: shadow/redzone segments
   //   p: setup_client_stack()  [for 'sp_at_startup']
   //   p: init tool             [for 'new_mem_startup']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Parse /proc/self/maps (round 2)\n");
   sp_at_startup___global_arg = sp_at_startup;
   VG_(parse_procselfmaps) ( build_segment_map_callback );  /* everything */
   sp_at_startup___global_arg = 0;

   //==============================================================
   // Can use VG_(map)() after segments set up
   //==============================================================

   //--------------------------------------------------------------
   // Allow GDB attach
   //   p: process_cmd_line_options()  [for VG_(clo_wait_for_gdb)]
   //--------------------------------------------------------------
   /* Hook to delay things long enough so we can get the pid and
      attach GDB in another shell. */
   if (VG_(clo_wait_for_gdb)) {
      Long q, iters;
      VG_(debugLog)(1, "main", "Wait for GDB\n");
      VG_(printf)("pid=%d, entering delay loop\n", VG_(getpid)());
      /* jrs 20050206: I don't understand why this works on x86.  On
         amd64 the obvious analogues (jump *$rip or jump *$rcx) don't
         work. */
      /* do "jump *$eip" to skip this in gdb (x86) */
      //VG_(do_syscall0)(__NR_pause);

#     if defined(VGP_x86_linux) || defined(VGP_x86_netbsdelf2)
      iters = 5;
#     elif defined(VGP_amd64_linux)
      iters = 10;
#     elif defined(VGP_ppc32_linux)
      iters = 5;
#     else
#     error "Unknown plat"
#     endif

      iters *= 1000*1000*1000;
      for (q = 0; q < iters; q++) 
         ;
   }

   //--------------------------------------------------------------
   // Search for file descriptors that are inherited from our parent
   //   p: process_cmd_line_options  [for VG_(clo_track_fds)]
   //--------------------------------------------------------------
   if (VG_(clo_track_fds)) {
      VG_(debugLog)(1, "main", "Init preopened fds\n");
      VG_(init_preopened_fds)();
   }

   //--------------------------------------------------------------
   // Initialise the scheduler
   //   p: setup_file_descriptors() [else VG_(safe_fd)() breaks]
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Initialise scheduler\n");
   VG_(scheduler_init)();

   //--------------------------------------------------------------
   // Initialise the pthread model
   //   p: ?
   //      load_client()          [for 'client_eip']
   //      setup_client_stack()   [for 'sp_at_startup']
   //      setup_scheduler()      [for the rest of state 1 stuff]
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Initialise thread 1's state\n");
   init_thread1state(client_eip, sp_at_startup, &VG_(threads)[1].arch);

   //--------------------------------------------------------------
   // Initialise the pthread model
   //   p: ?
   //--------------------------------------------------------------
   //if (VG_(clo_model_pthreads))
   //   VG_(pthread_init)();

   //--------------------------------------------------------------
   // Initialise the signal handling subsystem
   //   p: n/a
   //--------------------------------------------------------------
   // Nb: temporarily parks the saved blocking-mask in saved_sigmask.
   VG_(debugLog)(1, "main", "Initialise signal management\n");
//  VG_(sigstartup_actions)();

   //--------------------------------------------------------------
   // Perhaps we're profiling Valgrind?
   //   p: process_cmd_line_options()  [for VG_(clo_profile)]
   //   p: others?
   //
   // XXX: this seems to be broken?   It always says the tool wasn't built
   // for profiling;  vg_profile.c's functions don't seem to be overriding
   // vg_dummy_profile.c's?
   //
   // XXX: want this as early as possible.  Looking for --profile
   // in pre_process_cmd_line_options() could get it earlier.
   //--------------------------------------------------------------
   if (VG_(clo_profile))
      VG_(init_profiling)();

   VGP_PUSHCC(VgpStartup);

   //--------------------------------------------------------------
   // Read suppression file
   //   p: process_cmd_line_options()  [for VG_(clo_suppressions)]
   //--------------------------------------------------------------
   if (VG_(needs).core_errors || VG_(needs).tool_errors) {
      VG_(debugLog)(1, "main", "Load suppressions\n");
      VG_(load_suppressions)();
   }

   //--------------------------------------------------------------
   // Initialise translation table and translation cache
   //   p: read_procselfmaps  [so the anonymous mmaps for the TT/TC
   //         aren't identified as part of the client, which would waste
   //         > 20M of virtual address space.]
   //--------------------------------------------------------------
   VG_(init_tt_tc)();
   VG_(debugLog)(1, "main", "Initialise TT/TC\n");


   //--------------------------------------------------------------
   // Initialise the redirect table.
   //   p: parse_procselfmaps? [XXX for debug info?]
   //   p: init_tt_tc [so it can call VG_(search_transtab) safely]
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Initialise redirects\n");
   VG_(setup_code_redirect_table)();

   //--------------------------------------------------------------
   // Tell the tool about permissions in our handwritten assembly
   // helpers.
   //   p: init tool             [for 'new_mem_startup']
   //--------------------------------------------------------------
   VG_(debugLog)(1, "main", "Tell tool about permissions for asm helpers\n");
   VG_TRACK( new_mem_startup,
             (Addr)&VG_(trampoline_stuff_start),
             &VG_(trampoline_stuff_end) - &VG_(trampoline_stuff_start),
             False, /* readable? */
             False, /* writable? */
             True   /* executable? */ );

   //--------------------------------------------------------------
   // Verbosity message
   //   p: end_rdtsc_calibration [so startup message is printed first]
   //--------------------------------------------------------------
   if (VG_(clo_verbosity) == 1 && !VG_(clo_xml))
      VG_(message)(Vg_UserMsg, "For more details, rerun with: -v");
   if (VG_(clo_verbosity) > 0)
      VG_(message)(Vg_UserMsg, "");

   //--------------------------------------------------------------
   // Setup pointercheck
   //   p: layout_remaining_space() [for VG_(client_{base,end})]
   //   p: process_cmd_line_options() [for VG_(clo_pointercheck)]
   //--------------------------------------------------------------
   if (VG_(clo_pointercheck))
      VG_(clo_pointercheck) =
         VG_(setup_pointercheck)( VG_(client_base), VG_(client_end));

   //--------------------------------------------------------------
   // register client stack
   //--------------------------------------------------------------
   VG_(printf)("registering client stack... ");
   VG_(clstk_id) = VG_(register_stack)(VG_(clstk_base), VG_(clstk_end));
   VG_(printf)("registered! ");
   //--------------------------------------------------------------
   // Run!
   //--------------------------------------------------------------
   VGP_POPCC(VgpStartup);

   if (VG_(clo_xml)) {
      HChar buf[50];
      VG_(ctime)(buf);
      VG_(message)(Vg_UserMsg, "<status> <state>RUNNING</state> "
                               "<time>%t</time> </status>", buf);
      VG_(message)(Vg_UserMsg, "");
   }

   VG_(debugLog)(1, "main", "Running thread 1\n");
   /* As a result of the following call, the last thread standing
      eventually winds up running VG_(shutdown_actions_NORETURN) just
      below. */
   VG_(main_thread_wrapper_NORETURN)(1);

   /*NOTREACHED*/
   vg_assert(0);
}


/* Final clean-up before terminating the process.  
   Clean up the client by calling __libc_freeres() (if requested) 
   This is Linux-specific?
*/
static void final_tidyup(ThreadId tid)
{
   Addr __libc_freeres_wrapper;

   vg_assert(VG_(is_running_thread)(tid));
   
   if ( !VG_(needs).libc_freeres ||
        !VG_(clo_run_libc_freeres) ||
        0 == (__libc_freeres_wrapper = VG_(get_libc_freeres_wrapper)()) )
      return;			/* can't/won't do it */

   if (VG_(clo_verbosity) > 2  ||
       VG_(clo_trace_syscalls) ||
       VG_(clo_trace_sched))
      VG_(message)(Vg_DebugMsg, 
		   "Caught __NR_exit; running __libc_freeres()");
      
   /* point thread context to point to libc_freeres_wrapper */
   VG_(set_IP)(tid, __libc_freeres_wrapper);
   // XXX should we use a special stack?

   /* Block all blockable signals by copying the real block state into
      the thread's block state*/
   VG_(sigprocmask)(VKI_SIG_BLOCK, NULL, &VG_(threads)[tid].sig_mask);
   VG_(threads)[tid].tmp_sig_mask = VG_(threads)[tid].sig_mask;

   /* and restore handlers to default */
   VG_(set_default_handler)(VKI_SIGSEGV);
   VG_(set_default_handler)(VKI_SIGBUS);
   VG_(set_default_handler)(VKI_SIGILL);
   VG_(set_default_handler)(VKI_SIGFPE);

   // We were exiting, so assert that...
   vg_assert(VG_(is_exiting)(tid));
   // ...but now we're not again
   VG_(threads)[tid].exitreason = VgSrc_None;

   // run until client thread exits - ideally with LIBC_FREERES_DONE,
   // but exit/exitgroup/signal will do
   VG_(scheduler)(tid);

   vg_assert(VG_(is_exiting)(tid));
}

/* Do everything which needs doing when the last thread exits */
void VG_(shutdown_actions_NORETURN) ( ThreadId tid, 
                                      VgSchedReturnCode tids_schedretcode )
{
   VG_(debugLog)(1, "main", "entering VG_(shutdown_actions_NORETURN)\n");

   vg_assert( VG_(count_living_threads)() == 1 );
   vg_assert(VG_(is_running_thread)(tid));

   // Wait for all other threads to exit.
   VG_(reap_threads)(tid);

   VG_(clo_model_pthreads) = False;

   // Clean the client up before the final report
   final_tidyup(tid);

   // OK, done
   VG_(exit_thread)(tid);

   /* should be no threads left */
   vg_assert(VG_(count_living_threads)() == 0);

   VG_(threads)[tid].status = VgTs_Empty;
   //--------------------------------------------------------------
   // Finalisation: cleanup, messages, etc.  Order no so important, only
   // affects what order the messages come.
   //--------------------------------------------------------------
   if (VG_(clo_verbosity) > 0)
      VG_(message)(Vg_UserMsg, "");

   if (VG_(clo_xml)) {
      HChar buf[50];
      if (VG_(needs).core_errors || VG_(needs).tool_errors) {
         VG_(show_error_counts_as_XML)();
         VG_(message)(Vg_UserMsg, "");
      }
      VG_(ctime)(buf);
      VG_(message)(Vg_UserMsg, "<status> <state>FINISHED</state> "
                               "<time>%t</time> </status>", buf);
      VG_(message)(Vg_UserMsg, "");
   }

   /* Print out file descriptor summary and stats. */
   if (VG_(clo_track_fds))
      VG_(show_open_fds)();

   if (VG_(needs).core_errors || VG_(needs).tool_errors)
      VG_(show_all_errors)();

   VG_TDICT_CALL(tool_fini, 0/*exitcode*/);

   if (VG_(clo_xml)) {
      VG_(message)(Vg_UserMsg, "");
      VG_(message)(Vg_UserMsg, "</valgrindoutput>");
      VG_(message)(Vg_UserMsg, "");
   }

   VG_(sanity_check_general)( True /*include expensive checks*/ );

   if (VG_(clo_verbosity) > 1)
      print_all_stats();

   if (VG_(clo_profile))
      VG_(done_profiling)();

   if (VG_(clo_profile_flags) > 0) {
      #define N_MAX 100
      BBProfEntry tops[N_MAX];
      ULong score_total = VG_(get_BB_profile) (tops, N_MAX);
      show_BB_profile(tops, N_MAX, score_total);
   }

   /* Print Vex storage stats */
   if (0)
       LibVEX_ShowAllocStats();

   /* Ok, finally exit in the os-specific way, according to the scheduler's
      return code.  In short, if the (last) thread exited by calling
      sys_exit, do likewise; if the (last) thread stopped due to a fatal
      signal, terminate the entire system with that same fatal signal. */
   VG_(debugLog)(1, "core_os", 
                    "VG_(terminate_NORETURN)(tid=%lld)\n", (ULong)tid);

   vg_assert(VG_(count_living_threads)() == 0);

   switch (tids_schedretcode) {
   case VgSrc_ExitSyscall: /* the normal way out */
      VG_(exit)( VG_(threads)[tid].os_state.exitcode );
      /* NOT ALIVE HERE! */
      VG_(core_panic)("entered the afterlife in main() -- ExitSyscall");
      break; /* what the hell :) */

   case VgSrc_FatalSig:
      /* We were killed by a fatal signal, so replicate the effect */
      vg_assert(VG_(threads)[tid].os_state.fatalsig != 0);
      VG_(kill_self)(VG_(threads)[tid].os_state.fatalsig);
      VG_(core_panic)("main(): signal was supposed to be fatal");
      break;

   default:
      VG_(core_panic)("main(): unexpected scheduler return code");
   }
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
