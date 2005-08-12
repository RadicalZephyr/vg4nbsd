
/*--------------------------------------------------------------------*/
/*--- The address space manager.              pub_core_aspacemgr.h ---*/
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

#ifndef __PUB_CORE_ASPACEMGR_H
#define __PUB_CORE_ASPACEMGR_H

//--------------------------------------------------------------------
// PURPOSE: This module deals with management of the entire process
// address space.  Almost everything depends upon it, including dynamic
// memory management.  Hence this module is almost completely
// standalone; the only module it uses is m_debuglog.  DO NOT CHANGE
// THIS.
// [XXX: actually, this is far from true... especially that to #include
// this header, you have to #include pub_core_debuginfo in order to 
// see the SegInfo type, which is very bad...]
//--------------------------------------------------------------------

#include "pub_tool_aspacemgr.h"

// Address space globals
extern Addr VG_(client_base);	 // client address space limits
extern Addr VG_(client_end);
extern Addr VG_(client_mapbase); // base of mappings
extern Addr VG_(clstk_base);	 // client stack range
extern Addr VG_(clstk_end);
extern UWord VG_(clstk_id);      // client stack id

extern Addr VG_(brk_base);	 // start of brk
extern Addr VG_(brk_limit);	 // current brk
extern Addr VG_(shadow_base);	 // tool's shadow memory
extern Addr VG_(shadow_end);
extern Addr VG_(valgrind_base);	 // valgrind's address range
extern Addr VG_(valgrind_last);  // Nb: last byte, rather than one past the end

// Direct access to these system calls.
extern SysRes VG_(mmap_native)     ( void* start, SizeT length, UInt prot,
                                     UInt flags, UInt fd, OffT offset );
extern SysRes VG_(munmap_native)   ( void* start, SizeT length );
extern SysRes VG_(mprotect_native) ( void *start, SizeT length, UInt prot );

/* A Segment is mapped piece of client memory.  This covers all kinds
   of mapped memory (exe, brk, mmap, .so, shm, stack, etc)

   We encode relevant info about each segment with these constants.
*/
#define SF_SHARED   (1 <<  0) // shared
#define SF_SHM      (1 <<  1) // SYSV SHM (also SF_SHARED)
#define SF_MMAP     (1 <<  2) // mmap memory
#define SF_FILE     (1 <<  3) // mapping is backed by a file
#define SF_STACK    (1 <<  4) // is a stack
#define SF_GROWDOWN (1 <<  5) // segment grows down
#define SF_NOSYMS   (1 <<  6) // don't load syms, even if present
#define SF_CORE     (1 <<  7) // allocated by core on behalf of the client
#define SF_VALGRIND (1 <<  8) // a valgrind-internal mapping - not in client
#define SF_CODE     (1 <<  9) // segment contains cached code

typedef struct _Segment Segment;

struct _Segment {
   UInt         prot;         // VKI_PROT_*
   UInt         flags;        // SF_*

   Addr         addr;         // mapped addr (page aligned)
   SizeT        len;          // size of mapping (page aligned)

   // These are valid if (flags & SF_FILE)
   OffT        offset;        // file offset
   const Char* filename;      // filename (NULL if unknown)
   Int         fnIdx;         // filename table index (-1 if unknown)
   UInt        dev;           // device
   UInt        ino;           // inode

   SegInfo*    seginfo;       // symbol table, etc
};

/* segment mapped from a file descriptor */
extern void VG_(map_fd_segment)  (Addr addr, SizeT len, UInt prot, UInt flags, 
				  Int fd, ULong off, const Char *filename);

/* segment mapped from a file */
extern void VG_(map_file_segment)(Addr addr, SizeT len, UInt prot, UInt flags, 
				  UInt dev, UInt ino, ULong off, const Char *filename);

/* simple segment */
extern void VG_(map_segment)     (Addr addr, SizeT len, UInt prot, UInt flags);

extern void VG_(unmap_range)   (Addr addr, SizeT len);
extern void VG_(mprotect_range)(Addr addr, SizeT len, UInt prot);
extern Addr VG_(find_map_space)(Addr base, SizeT len, Bool for_client);

/* Find the segment containing a, or NULL if none. */
extern Segment *VG_(find_segment)(Addr a);

/* a is an unmapped address (is checked).  Find the next segment 
   along in the address space, or NULL if none. */
extern Segment *VG_(find_segment_above_unmapped)(Addr a);

/* a is a mapped address (in a segment, is checked).  Find the
   next segment along. */
extern Segment *VG_(find_segment_above_mapped)(Addr a);

extern Bool VG_(seg_contains)(const Segment *s, Addr ptr, SizeT size);
extern Bool VG_(seg_overlaps)(const Segment *s, Addr ptr, SizeT size);

extern Segment *VG_(split_segment)(Addr a);

extern void VG_(pad_address_space)  (Addr start);
extern void VG_(unpad_address_space)(Addr start);

///* Search /proc/self/maps for changes which aren't reflected in the
//   segment list */
//extern void VG_(sync_segments)(UInt flags);

/* Return string for prot */
extern const HChar *VG_(prot_str)(UInt prot);

/* Parses /proc/self/maps, calling `record_mapping' for each entry. */
extern 
void VG_(parse_procselfmaps) (
   void (*record_mapping)( Addr addr, SizeT len, UInt prot,
			   UInt dev, UInt ino, ULong foff,
                           const UChar *filename ) );

// Pointercheck
extern Bool VG_(setup_pointercheck) ( Addr client_base, Addr client_end );

#endif   // __PUB_CORE_ASPACEMGR_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
