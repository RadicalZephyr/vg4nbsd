
/*--------------------------------------------------------------------*/
/*--- High-level memory management.          pub_core_mallocfree.h ---*/
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

#ifndef __PUB_CORE_MALLOCFREE_H
#define __PUB_CORE_MALLOCFREE_H

#include "pub_tool_mallocfree.h"

//--------------------------------------------------------------------
// PURPOSE: high-level memory allocation (malloc/free), for the core and
// tools.
//--------------------------------------------------------------------

/* Allocation arenas.  

      CORE      for the core's general use.
      TOOL      for the tool to use (and the only one it uses).
      SYMTAB    for Valgrind's symbol table storage.
      CLIENT    for the client's mallocs/frees, if the tool replaces glibc's
                    malloc() et al -- redzone size is chosen by the tool.
      DEMANGLE  for the C++ demangler.
      EXECTXT   for storing ExeContexts.
      ERRORS    for storing CoreErrors.

   When adding a new arena, remember also to add it to ensure_mm_init(). 
*/
typedef Int ArenaId;

#define VG_N_ARENAS        7

#define VG_AR_CORE         0
#define VG_AR_TOOL         1
#define VG_AR_SYMTAB       2
#define VG_AR_CLIENT       3
#define VG_AR_DEMANGLE     4
#define VG_AR_EXECTXT      5
#define VG_AR_ERRORS       6

// This is both the minimum payload size of a malloc'd block, and its
// minimum alignment.  Must be a power of 2 greater than 4, and should be
// greater than 8.
#define VG_MIN_MALLOC_SZB        8

extern void* VG_(arena_malloc)  ( ArenaId arena, SizeT nbytes );
extern void  VG_(arena_free)    ( ArenaId arena, void* ptr );
extern void* VG_(arena_calloc)  ( ArenaId arena, 
                                  SizeT nmemb, SizeT bytes_per_memb );
extern void* VG_(arena_realloc) ( ArenaId arena, void* ptr, SizeT size );
extern void* VG_(arena_memalign)( ArenaId aid, SizeT req_alignB, 
                                               SizeT req_pszB );
extern Char* VG_(arena_strdup)  ( ArenaId aid, const Char* s);

/* Sets the size of the redzones at the start and end of heap blocks.  This
   must be called before any of VG_(malloc) and friends are called. */
extern void  VG_(set_client_malloc_redzone_szB) ( SizeT rz_szB );

extern SizeT VG_(arena_payload_szB) ( ArenaId aid, void* payload );

extern void  VG_(sanity_check_malloc_all) ( void );

extern void  VG_(print_all_arena_stats) ( void );

#endif   // __PUB_CORE_MALLOCFREE_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
