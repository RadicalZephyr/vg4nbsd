
/*--------------------------------------------------------------------*/
/*--- User-mode execve(), and other stuff shared between stage1    ---*/
/*--- and stage2.                                          m_ume.c ---*/
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


#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

// It seems that on SuSE 9.1 (x86) something in <fcntl.h> messes up stuff
// acquired indirectly from vki-x86-linux.h.  Therefore our headers must be
// included ahead of the glibc ones.  This fix is a kludge;  the right
// solution is to entirely remove the glibc dependency.
#include "pub_core_basics.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_machine.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcfile.h"    // VG_(close) et al
#include "pub_core_libcproc.h"    // VG_(geteuid), VG_(getegid)
#include "pub_core_libcassert.h"  // VG_(exit), vg_assert
#include "pub_core_syscall.h"     // VG_(strerror)
#include "pub_core_mallocfree.h"  // VG_(malloc), VG_(free)

#include "pub_core_debuginfo.h"   // Needed for pub_core_aspacemgr.h :(
#include "pub_core_aspacemgr.h"   // VG_(mmap_native)
#include "vki_unistd.h"           // mmap-related constants

#include "pub_core_ume.h"

//#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

//#include <string.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <assert.h>


// HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK A
// temporary bootstrapping allocator, for use until such time as we
// can get rid of the circularites in allocator dependencies at
// startup.  There is also a copy of this in m_main.c.
#define N_HACK_BYTES 10000
static Int   hack_bytes_used = 0;
static HChar hack_bytes[N_HACK_BYTES];

static void* hack_malloc ( Int n )
{
   VG_(debugLog)(1, "ume", "  FIXME: hack_malloc(m_ume)(%d)\n", n);
   while (n % 16) n++;
   if (hack_bytes_used + n > N_HACK_BYTES) {
     VG_(printf)("valgrind: N_HACK_BYTES(m_ume) too low.  Sorry.\n");
     VG_(exit)(0);
   }
   hack_bytes_used += n;
   return (void*) &hack_bytes[hack_bytes_used - n];
}

static HChar* hack_strdup ( HChar* str )
{
   HChar* p = hack_malloc( 1 + VG_(strlen)(str) );
   VG_(strcpy)(p, str);
   return p;
}

#if	VG_WORDSIZE == 8
#define ESZ(x)	Elf64_##x
#elif	VG_WORDSIZE == 4
#define ESZ(x)	Elf32_##x
#else
#error VG_WORDSIZE needs to ==4 or ==8
#endif

struct elfinfo
{
   ESZ(Ehdr)	e;
   ESZ(Phdr)	*p;
   int		fd;
};

static void check_mmap(SysRes res, void* base, int len)
{
   if (res.isError) {
      VG_(printf)("valgrind: mmap(%p, %d) failed in UME.\n", base, len);
      VG_(exit)(1);
   }
}

//zz // 'extra' allows the caller to pass in extra args to 'fn', like free
//zz // variables to a closure.
//zz void VG_(foreach_map)(int (*fn)(char *start, char *end,
//zz                                 const char *perm, off_t offset,
//zz                                 int maj, int min, int ino, void* extra),
//zz                       void* extra)
//zz {
//zz    static char buf[10240];
//zz    char *bufptr = buf;
//zz    int ret, fd;
//zz 
//zz    fd = open("/proc/self/maps", O_RDONLY);
//zz 
//zz    if (fd == -1) {
//zz       perror("open /proc/self/maps");
//zz       return;
//zz    }
//zz 
//zz    ret = read(fd, buf, sizeof(buf));
//zz 
//zz    if (ret == -1) {
//zz       perror("read /proc/self/maps");
//zz       close(fd);
//zz       return;
//zz    }
//zz    close(fd);
//zz 
//zz    if (ret == sizeof(buf)) {
//zz       VG_(printf)("coregrind/m_ume.c: buf too small\n");
//zz       return;
//zz    }
//zz 
//zz    while(bufptr && bufptr < buf+ret) {
//zz       char perm[5];
//zz       ULong offset;
//zz       int maj, min;
//zz       int ino;
//zz       void *segstart, *segend;
//zz 
//zz       sscanf(bufptr, "%p-%p %s %llx %x:%x %d",
//zz 	     &segstart, &segend, perm, &offset, &maj, &min, &ino);
//zz       bufptr = strchr(bufptr, '\n');
//zz       if (bufptr != NULL)
//zz 	 bufptr++; /* skip \n */
//zz 
//zz       if (!(*fn)(segstart, segend, perm, offset, maj, min, ino, extra))
//zz 	 break;
//zz    }
//zz }
//zz 
//zz /*------------------------------------------------------------*/
//zz /*--- Stack switching                                      ---*/
//zz /*------------------------------------------------------------*/
//zz 
//zz // __attribute__((noreturn))
//zz // void VG_(jump_and_switch_stacks) ( Addr stack, Addr dst );
//zz #if defined(VGA_x86)
//zz // 4(%esp) == stack
//zz // 8(%esp) == dst
//zz asm(
//zz ".global vgPlain_jump_and_switch_stacks\n"
//zz "vgPlain_jump_and_switch_stacks:\n"
//zz "   movl   %esp, %esi\n"      // remember old stack pointer
//zz "   movl   4(%esi), %esp\n"   // set stack
//zz "   pushl  8(%esi)\n"         // dst to stack
//zz "   movl $0, %eax\n"          // zero all GP regs
//zz "   movl $0, %ebx\n"
//zz "   movl $0, %ecx\n"
//zz "   movl $0, %edx\n"
//zz "   movl $0, %esi\n"
//zz "   movl $0, %edi\n"
//zz "   movl $0, %ebp\n"
//zz "   ret\n"                    // jump to dst
//zz "   ud2\n"                    // should never get here
//zz );
//zz #elif defined(VGA_amd64)
//zz // %rdi == stack
//zz // %rsi == dst
//zz asm(
//zz ".global vgPlain_jump_and_switch_stacks\n"
//zz "vgPlain_jump_and_switch_stacks:\n"
//zz "   movq   %rdi, %rsp\n"   // set stack
//zz "   pushq  %rsi\n"         // dst to stack
//zz "   movq $0, %rax\n"       // zero all GP regs
//zz "   movq $0, %rbx\n"
//zz "   movq $0, %rcx\n"
//zz "   movq $0, %rdx\n"
//zz "   movq $0, %rsi\n"
//zz "   movq $0, %rdi\n"
//zz "   movq $0, %rbp\n"
//zz "   movq $0, %r8\n"
//zz "   movq $0, %r9\n"
//zz "   movq $0, %r10\n"
//zz "   movq $0, %r11\n"
//zz "   movq $0, %r12\n"
//zz "   movq $0, %r13\n"
//zz "   movq $0, %r14\n"
//zz "   movq $0, %r15\n"
//zz "   ret\n"                 // jump to dst
//zz "   ud2\n"                 // should never get here
//zz );
//zz 
//zz #elif defined(VGA_ppc32)
//zz /* Jump to 'dst', but first set the stack pointer to 'stack'.  Also,
//zz    clear all the integer registers before entering 'dst'.  It's
//zz    important that the stack pointer is set to exactly 'stack' and not
//zz    (eg) stack - apparently_harmless_looking_small_offset.  Basically
//zz    because the code at 'dst' might be wanting to scan the area above
//zz    'stack' (viz, the auxv array), and putting spurious words on the
//zz    stack confuses it.
//zz */
//zz // %r3 == stack
//zz // %r4 == dst
//zz asm(
//zz ".global vgPlain_jump_and_switch_stacks\n"
//zz "vgPlain_jump_and_switch_stacks:\n"
//zz "   mtctr %r4\n\t"         // dst to %ctr
//zz "   mr %r1,%r3\n\t"        // stack to %sp
//zz "   li 0,0\n\t"            // zero all GP regs
//zz "   li 3,0\n\t"
//zz "   li 4,0\n\t"
//zz "   li 5,0\n\t"
//zz "   li 6,0\n\t"
//zz "   li 7,0\n\t"
//zz "   li 8,0\n\t"
//zz "   li 9,0\n\t"
//zz "   li 10,0\n\t"
//zz "   li 11,0\n\t"
//zz "   li 12,0\n\t"
//zz "   li 13,0\n\t"           // CAB: This right? r13 = small data area ptr
//zz "   li 14,0\n\t"
//zz "   li 15,0\n\t"
//zz "   li 16,0\n\t"
//zz "   li 17,0\n\t"
//zz "   li 18,0\n\t"
//zz "   li 19,0\n\t"
//zz "   li 20,0\n\t"
//zz "   li 21,0\n\t"
//zz "   li 22,0\n\t"
//zz "   li 23,0\n\t"
//zz "   li 24,0\n\t"
//zz "   li 25,0\n\t"
//zz "   li 26,0\n\t"
//zz "   li 27,0\n\t"
//zz "   li 28,0\n\t"
//zz "   li 29,0\n\t"
//zz "   li 30,0\n\t"
//zz "   li 31,0\n\t"
//zz "   mtxer 0\n\t"
//zz "   mtcr 0\n\t"
//zz "   mtlr %r0\n\t"
//zz "   bctr\n\t"              // jump to dst
//zz "   trap\n"                // should never get here
//zz );
//zz 
//zz #else
//zz #  error Unknown architecture
//zz #endif

/*------------------------------------------------------------*/
/*--- Finding auxv on the stack                            ---*/
/*------------------------------------------------------------*/
#if defined(VGO_netbsdelf2)
/* in netbsd ld_elf.so this calculation is defined using Elf_Addr
 */
struct ume_auxv *VG_(find_auxv)(UWord* sp)
{
	char ** argu;
	long argc = 0;
	argu = ( const char **) &sp[1];
	printf("The argu is %s\n",argu[0]);
	argc = *(long *)sp;
	sp+=2+argc ; /* skip over argc arguments and null terminator */
        while(*sp++!=0) { } /* skip over environment and null terminator */
	return (struct ume_auxv *)sp;
}

#else
struct ume_auxv *VG_(find_auxv)(UWord* sp)
{
   sp++;                // skip argc (Nb: is word-sized, not int-sized!)

   while (*sp != 0)     // skip argv
      sp++;
   sp++;

   while (*sp != 0)     // skip env
      sp++;
   sp++;
   
#if defined(VGA_ppc32)
# if defined AT_IGNOREPPC
   while (*sp == AT_IGNOREPPC)        // skip AT_IGNOREPPC entries
      sp += 2;
# endif
#endif

   return (struct ume_auxv *)sp;
}

#endif
/*------------------------------------------------------------*/
/*--- Loading ELF files                                    ---*/
/*------------------------------------------------------------*/

static 
struct elfinfo *readelf(int fd, const char *filename)
{
   struct elfinfo *e = hack_malloc(sizeof(*e));
   int phsz;

   vg_assert(e);
   e->fd = fd;

   if (VG_(pread)(fd, &e->e, sizeof(e->e), 0) != sizeof(e->e)) {
      VG_(printf)("valgrind: %s: can't read ELF header: %s\n", 
                  filename, VG_(strerror)(errno));
      goto bad;
   }

   if (VG_(memcmp)(&e->e.e_ident[0], ELFMAG, SELFMAG) != 0) {
      VG_(printf)("valgrind: %s: bad ELF magic number\n", filename);
      goto bad;
   }
   if (e->e.e_ident[EI_CLASS] != VG_ELF_CLASS) {
      VG_(printf)("valgrind: wrong ELF executable class "
                  "(eg. 32-bit instead of 64-bit)\n");
      goto bad;
   }
   if (e->e.e_ident[EI_DATA] != VG_ELF_DATA2XXX) {
      VG_(printf)("valgrind: executable has wrong endian-ness\n");
      goto bad;
   }
   if (!(e->e.e_type == ET_EXEC || e->e.e_type == ET_DYN)) {
      VG_(printf)("valgrind: this is not an executable\n");
      goto bad;
   }

   if (e->e.e_machine != VG_ELF_MACHINE) {
      VG_(printf)("valgrind: executable is not for "
                  "this architecture\n");
      goto bad;
   }

   if (e->e.e_phentsize != sizeof(ESZ(Phdr))) {
      VG_(printf)("valgrind: sizeof ELF Phdr wrong\n");
      goto bad;
   }

   phsz = sizeof(ESZ(Phdr)) * e->e.e_phnum;
   e->p = hack_malloc(phsz);
   vg_assert(e->p);

   if (VG_(pread)(fd, e->p, phsz, e->e.e_phoff) != phsz) {
      VG_(printf)("valgrind: can't read phdr: %s\n", 
                  VG_(strerror)(errno));
      //FIXME      VG_(free)(e->p);
      goto bad;
   }

   return e;

  bad:
    //FIXME    VG_(free)(e);
   return NULL;
}

/* Map an ELF file.  Returns the brk address. */
static
ESZ(Addr) mapelf(struct elfinfo *e, ESZ(Addr) base)
{
   Int    i;
   SysRes res;
   ESZ(Addr) elfbrk = 0;

   for(i = 0; i < e->e.e_phnum; i++) {
      ESZ(Phdr) *ph = &e->p[i];
      ESZ(Addr) addr, brkaddr;
      ESZ(Word) memsz;

      if (ph->p_type != PT_LOAD)
	 continue;

      addr    = ph->p_vaddr+base;
      memsz   = ph->p_memsz;
      brkaddr = addr+memsz;

      if (brkaddr > elfbrk)
	 elfbrk = brkaddr;
   }

   for(i = 0; i < e->e.e_phnum; i++) {
      ESZ(Phdr) *ph = &e->p[i];
      ESZ(Addr) addr, bss, brkaddr;
      ESZ(Off) off;
      ESZ(Word) filesz;
      ESZ(Word) memsz;
      unsigned prot = 0;

      if (ph->p_type != PT_LOAD)
	 continue;

      if (ph->p_flags & PF_X) prot |= VKI_PROT_EXEC;
      if (ph->p_flags & PF_W) prot |= VKI_PROT_WRITE;
      if (ph->p_flags & PF_R) prot |= VKI_PROT_READ;

      addr    = ph->p_vaddr+base;
      off     = ph->p_offset;
      filesz  = ph->p_filesz;
      bss     = addr+filesz;
      memsz   = ph->p_memsz;
      brkaddr = addr+memsz;

      // Tom says: In the following, do what the Linux kernel does and only
      // map the pages that are required instead of rounding everything to
      // the specified alignment (ph->p_align).  (AMD64 doesn't work if you
      // use ph->p_align -- part of stage2's memory gets trashed somehow.)
      //
      // The condition handles the case of a zero-length segment.
      if (VG_PGROUNDUP(bss)-VG_PGROUNDDN(addr) > 0) {
         res = VG_(mmap_native)
                    ((char *)VG_PGROUNDDN(addr),
                    VG_PGROUNDUP(bss)-VG_PGROUNDDN(addr),
                    prot, VKI_MAP_FIXED|VKI_MAP_PRIVATE, 
                    e->fd, VG_PGROUNDDN(off)
               );
         check_mmap(res, (char*)VG_PGROUNDDN(addr),
                    VG_PGROUNDUP(bss)-VG_PGROUNDDN(addr));
      }

      // if memsz > filesz, fill the remainder with zeroed pages
      if (memsz > filesz) {
	 UInt bytes;

	 bytes = VG_PGROUNDUP(brkaddr)-VG_PGROUNDUP(bss);
	 if (bytes > 0) {
	    res = VG_(mmap_native)(
                     (Char *)VG_PGROUNDUP(bss), bytes,
		     prot, VKI_MAP_FIXED|VKI_MAP_ANONYMOUS|VKI_MAP_PRIVATE, 
                     -1, 0
                  );
            check_mmap(res, (char*)VG_PGROUNDUP(bss), bytes);
         }

	 bytes = bss & (VKI_PAGE_SIZE - 1);

         // The 'prot' condition allows for a read-only bss
         if ((prot & VKI_PROT_WRITE) && (bytes > 0)) {
	    bytes = VKI_PAGE_SIZE - bytes;
	    VG_(memset)((char *)bss, 0, bytes);
	 }
      }
   }

   return elfbrk;
}

// Forward declaration.
static int do_exec_inner(const char *exe, struct exeinfo *info);

static int match_ELF(const char *hdr, int len)
{
   ESZ(Ehdr) *e = (ESZ(Ehdr) *)hdr;
   return (len > sizeof(*e)) && VG_(memcmp)(&e->e_ident[0], ELFMAG, SELFMAG) == 0;
}

static int load_ELF(char *hdr, int len, int fd, const char *name,
                    struct exeinfo *info)
{
   struct elfinfo *e;
   struct elfinfo *interp = NULL;
   ESZ(Addr) minaddr = ~0;	/* lowest mapped address */
   ESZ(Addr) maxaddr = 0;	/* highest mapped address */
   ESZ(Addr) interp_addr = 0;	/* interpreter (ld.so) address */
   ESZ(Word) interp_size = 0;	/* interpreter size */
   ESZ(Word) interp_align = VKI_PAGE_SIZE;
   int i;
   void *entry;
   ESZ(Addr) ebase = 0;

#ifdef HAVE_PIE
   ebase = info->exe_base;
#endif

   printf("In load_ELF!\n");
   e = readelf(fd, name);

   if (e == NULL)
      return ENOEXEC;

   /* The kernel maps position-independent executables at TASK_SIZE*2/3;
      duplicate this behavior as close as we can. */
   if (e->e.e_type == ET_DYN && ebase == 0) {
      ebase = VG_PGROUNDDN(info->exe_base + (info->exe_end - info->exe_base) * 2 / 3);
   }

   info->phnum = e->e.e_phnum;
   info->entry = e->e.e_entry + ebase;
   info->phdr = 0;

   for(i = 0; i < e->e.e_phnum; i++) {
      ESZ(Phdr) *ph = &e->p[i];

      switch(ph->p_type) {
      case PT_PHDR:
      printf("in pt_hdr\n");
	 info->phdr = ph->p_vaddr + ebase;
	 printf("info->phdr = ph->p_vaddr + ebase; (%p + %p = %p)\n", ph->p_vaddr, ebase, info->phdr);
	 break;

      case PT_LOAD:
	 printf ("in pt_load\n");
	 if (ph->p_vaddr < minaddr)
	    minaddr = ph->p_vaddr;
	 if (ph->p_vaddr+ph->p_memsz > maxaddr)
	    maxaddr = ph->p_vaddr+ph->p_memsz;
	 break;

      case PT_DYNAMIC:
         printf ("in pt_dynamic\n");
	 if (ph->p_vaddr < minaddr)
	    minaddr = ph->p_vaddr;
	 if (ph->p_vaddr+ph->p_memsz > maxaddr)
	    maxaddr = ph->p_vaddr+ph->p_memsz;
	 printf("pt_dynamic_addr = %p [this must match obj->dynamic in ld.so_elf]\n", ph->p_vaddr);
	 break;
			
      case PT_INTERP: {
	 char *buf = hack_malloc(ph->p_filesz+1);
	 int j;
	 int intfd;
	 int baseaddr_set;

         vg_assert(buf);
	 VG_(pread)(fd, buf, ph->p_filesz, ph->p_offset);
	 buf[ph->p_filesz] = '\0';

	 intfd = open(buf, O_RDONLY);
	 if (intfd == -1) {
	    VG_(printf)("valgrind: m_ume.c: can't open interpreter\n");
	    VG_(exit)(1);
	 }

	 interp = readelf(intfd, buf);
	 if (interp == NULL) {
	    VG_(printf)("valgrind: m_ume.c: can't read interpreter\n");
	    return 1;
	 }
	  //FIXME    VG_(free)(buf);

	 baseaddr_set = 0;
	 for(j = 0; j < interp->e.e_phnum; j++) {
	    ESZ(Phdr) *iph = &interp->p[j];
	    ESZ(Addr) end;

	    if (iph->p_type != PT_LOAD)
	       continue;
	    
	    if (!baseaddr_set) {
	       interp_addr  = iph->p_vaddr;
	       interp_align = iph->p_align;
	       baseaddr_set = 1;
	    }

	    /* assumes that all segments in the interp are close */
	    end = (iph->p_vaddr - interp_addr) + iph->p_memsz;

	    if (end > interp_size)
	       interp_size = end;
	 }
	 break;

      default:
         // do nothing
         break;
      }
      }
   }

   printf("interp_addr = %p\n", interp_addr);
   if (info->phdr == 0)
      info->phdr = minaddr + ebase + e->e.e_phoff;

   if (info->exe_base != info->exe_end) {
      if (minaddr >= maxaddr ||
	  (minaddr + ebase < info->exe_base ||
	   maxaddr + ebase > info->exe_end)) {
	 VG_(printf)("Executable range %p-%p is outside the\n"
                     "acceptable range %p-%p\n",
                     (void *)minaddr + ebase, (void *)maxaddr + ebase,
                     (void *)info->exe_base,  (void *)info->exe_end);
	 return ENOMEM;
      }
   }

 /*XXX-  for netbsd I am not sure if this check is right ,
   info->exe_end etc are based on  some assumptions which are not
      valid for linux, for example it assumes stack on top i think ,
      this warrants more investigation. 
       */
   info->brkbase = mapelf(e, ebase);	/* map the executable */

   if (info->brkbase == 0)
      return ENOMEM;

   if(!interp)
	   printf("interp is null\n");
   else 
	   printf("interp =  %p\n",interp);

   if (interp != NULL) {
      /* reserve a chunk of address space for interpreter */
      SysRes res;
      Char*  base = (Char *)info->exe_base;
      Char*  baseoff;
      Int flags = VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS;

      if (info->map_base != 0) {
	 base = (char *)VG_ROUNDUP(info->map_base, interp_align);
	 flags |= VKI_MAP_FIXED;
      }

      printf("doing mmap here\n");
      res = VG_(mmap_native)(base, interp_size, VKI_PROT_NONE, flags, -1, 0);
      check_mmap(res, base, interp_size);
      vg_assert(!res.isError);
      base = (Char*)res.val;

      baseoff = base - interp_addr;

      mapelf(interp, (ESZ(Addr))baseoff);
      printf("after  mmap and mapelf here\n");
      VG_(close)(interp->fd);

      entry = baseoff + interp->e.e_entry;
      info->interp_base = (ESZ(Addr))base;
      printf("info interp_base = %p\n " ,info->interp_base);

       //FIXME    VG_(free)(interp->p);
       //FIXME    VG_(free)(interp);
   } else
      entry = (void *)(ebase + e->e.e_entry);

   info->exe_base = minaddr + ebase;
   info->exe_end  = maxaddr + ebase;

   info->init_eip = (Addr)entry;
   printf("info->init_eip: %x",info->init_eip);
    //FIXME    VG_(free)(e->p);
    //FIXME    VG_(free)(e);

   return 0;
}


static int match_script(const char *hdr, Int len)
{
   return (len > 2) && VG_(memcmp)(hdr, "#!", 2) == 0;
}

static int load_script(char *hdr, int len, int fd, const char *name,
                       struct exeinfo *info)
{
   char *interp;
   char *const end = hdr+len;
   char *cp;
   char *arg = NULL;
   int eol;

   interp = hdr + 2;
   while(interp < end && (*interp == ' ' || *interp == '\t'))
      interp++;

   if (*interp != '/')
      return ENOEXEC;		/* absolute path only for interpreter */

   /* skip over interpreter name */
   for(cp = interp; cp < end && *cp != ' ' && *cp != '\t' && *cp != '\n'; cp++)
      ;

   eol = (*cp == '\n');

   *cp++ = '\0';

   if (!eol && cp < end) {
      /* skip space before arg */
      while (cp < end && (*cp == '\t' || *cp == ' '))
	 cp++;

      /* arg is from here to eol */
      arg = cp;
      while (cp < end && *cp != '\n')
	 cp++;
      *cp = '\0';
   }
   
   info->interp_name = hack_strdup(interp);
   vg_assert(NULL != info->interp_name);
   if (arg != NULL && *arg != '\0') {
      info->interp_args = hack_strdup(arg);
      vg_assert(NULL != info->interp_args);
   }

   if (info->argv && info->argv[0] != NULL)
      info->argv[0] = (char *)name;

   if (0)
      VG_(printf)("#! script: interp_name=\"%s\" interp_args=\"%s\"\n",
                  info->interp_name, info->interp_args);

   return do_exec_inner(interp, info);
}

/* 
   Emulate the normal Unix permissions checking algorithm.

   If owner matches, then use the owner permissions, else
   if group matches, then use the group permissions, else
   use other permissions.

   Note that we can't deal with SUID/SGID, so we refuse to run them
   (otherwise the executable may misbehave if it doesn't have the
   permissions it thinks it does).
*/
static int check_perms(int fd)
{
   struct stat st;

   if (fstat(fd, &st) == -1) 
      return errno;

   if (st.st_mode & (S_ISUID | S_ISGID)) {
      //VG_(printf)("Can't execute suid/sgid executable %s\n", exe);
      return EACCES;
   }

   if (VG_(geteuid)() == st.st_uid) {
      if (!(st.st_mode & S_IXUSR))
	 return EACCES;
   } else {
      int grpmatch = 0;

      if (VG_(getegid)() == st.st_gid)
	 grpmatch = 1;
      else {
	 gid_t groups[32];
	 int ngrp = getgroups(32, groups);
	 int i;

	 for(i = 0; i < ngrp; i++)
	    if (groups[i] == st.st_gid) {
	       grpmatch = 1;
	       break;
	    }
      }

      if (grpmatch) {
	 if (!(st.st_mode & S_IXGRP))
	    return EACCES;
      } else if (!(st.st_mode & S_IXOTH))
	 return EACCES;
   }

   return 0;
}

static int do_exec_inner(const char *exe, struct exeinfo *info)
{
   int fd;
   int err;
   char buf[VKI_PAGE_SIZE];
   int bufsz;
   int i;
   int ret;
   static const struct {
      int (*match)(const char *hdr, int len);
      int (*load) (      char *hdr, int len, int fd2, const char *name,
                         struct exeinfo *);
   } formats[] = {
      { match_ELF,    load_ELF },
      { match_script, load_script },
   };

   fd = open(exe, O_RDONLY);
   if (fd == -1) {
      if (0)
	 VG_(printf)("Can't open executable %s: %s\n",
                     exe, VG_(strerror)(errno));
      return errno;
   }

   err = check_perms(fd);
   if (err != 0) {
      VG_(close)(fd);
      return err;
   }

   bufsz = VG_(pread)(fd, buf, sizeof(buf), 0);
   if (bufsz < 0) {
      VG_(printf)("Can't read executable header: %s\n",
                  VG_(strerror)(errno));
      VG_(close)(fd);
      return errno;
   }

   ret = ENOEXEC;
   for(i = 0; i < sizeof(formats)/sizeof(*formats); i++) {
      if ((formats[i].match)(buf, bufsz)) {
	 ret = (formats[i].load)(buf, bufsz, fd, exe, info);
	 break;
      }
   }

   VG_(close)(fd);

   return ret;
}

// See ume.h for an indication of which entries of 'info' are inputs, which
// are outputs, and which are both.
int VG_(do_exec)(const char *exe, struct exeinfo *info)
{
   info->interp_name = NULL;
   info->interp_args = NULL;

   return do_exec_inner(exe, info);
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
