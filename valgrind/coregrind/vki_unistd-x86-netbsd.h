
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

#ifndef __VKI_UNISTD_X86_NETBSD_H
#define __VKI_UNISTD_X86_NETBSD_H

// From $SRCDIR/sys/sys/syscall.h generated from sys/sys/syscalls.master 

/*
 * NOTE: You will find RENAME_HACK at some places in this file.  This means
 * valgrind requires a definition (for example __NR_stat) which NetBSD does
 * not have.  The equivalent NetBSD syscall is aliased by the required name.
 * (in the __NR_stat case __NR___stat13).  I'm not sure if this really is
 * a hack... anyway, you can spot them easily if a better idea is thought of
 * to fix this situation.
 */

#define	__NR_syscall	0

/* syscall: "exit" ret: "void" args: "int" */
#define	__NR_exit	1

/* syscall: "fork" ret: "int" args: */
#define	__NR_fork	2

/* syscall: "read" ret: "ssize_t" args: "int" "void *" "size_t" */
#define	__NR_read	3

/* syscall: "write" ret: "ssize_t" args: "int" "const void *" "size_t" */
#define	__NR_write	4

/* syscall: "open" ret: "int" args: "const char *" "int" "..." */
#define	__NR_open	5

/* syscall: "close" ret: "int" args: "int" */
#define	__NR_close	6

/* syscall: "wait4" ret: "int" args: "int" "int *" "int" "struct rusage *" */
#define	__NR_wait4	7

/* syscall: "compat_43_ocreat" ret: "int" args: "const char *" "mode_t" */
#define	__NR_compat_43_ocreat	8

/* syscall: "link" ret: "int" args: "const char *" "const char *" */
#define	__NR_link	9

/* syscall: "unlink" ret: "int" args: "const char *" */
#define	__NR_unlink	10

				/* 11 is obsolete execv */
/* syscall: "chdir" ret: "int" args: "const char *" */
#define	__NR_chdir	12

/* syscall: "fchdir" ret: "int" args: "int" */
#define	__NR_fchdir	13

/* syscall: "mknod" ret: "int" args: "const char *" "mode_t" "dev_t" */
#define	__NR_mknod	14

/* syscall: "chmod" ret: "int" args: "const char *" "mode_t" */
#define	__NR_chmod	15

/* syscall: "chown" ret: "int" args: "const char *" "uid_t" "gid_t" */
#define	__NR_chown	16

/* syscall: "break" ret: "int" args: "char *" */
#define	__NR_break	17

/* syscall: "getfsstat" ret: "int" args: "struct statfs *" "long" "int" */
#define	__NR_getfsstat	18

/* syscall: "compat_43_olseek" ret: "long" args: "int" "long" "int" */
#define	__NR_compat_43_olseek	19

/* syscall: "getpid" ret: "pid_t" args: */
#define	__NR_getpid	20

/* syscall: "mount" ret: "int" args: "const char *" "const char *" "int" "void *" */
#define	__NR_mount	21

/* syscall: "unmount" ret: "int" args: "const char *" "int" */
#define	__NR_unmount	22

/* syscall: "setuid" ret: "int" args: "uid_t" */
#define	__NR_setuid	23

/* syscall: "getuid" ret: "uid_t" args: */
#define	__NR_getuid	24


/* syscall: "geteuid" ret: "uid_t" args: */
#define	__NR_geteuid	25

/* syscall: "ptrace" ret: "int" args: "int" "pid_t" "caddr_t" "int" */
#define	__NR_ptrace	26

/* syscall: "recvmsg" ret: "ssize_t" args: "int" "struct msghdr *" "int" */
#define	__NR_recvmsg	27

/* syscall: "sendmsg" ret: "ssize_t" args: "int" "const struct msghdr *" "int" */
#define	__NR_sendmsg	28

/* syscall: "recvfrom" ret: "ssize_t" args: "int" "void *" "size_t" "int" "struct sockaddr *" "unsigned int *" */
#define	__NR_recvfrom	29

/* syscall: "accept" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	__NR_accept	30

/* syscall: "getpeername" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	__NR_getpeername	31

/* syscall: "getsockname" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	__NR_getsockname	32

/* syscall: "access" ret: "int" args: "const char *" "int" */
#define	__NR_access	33

/* syscall: "chflags" ret: "int" args: "const char *" "u_long" */
#define	__NR_chflags	34

/* syscall: "fchflags" ret: "int" args: "int" "u_long" */
#define	__NR_fchflags	35

/* syscall: "sync" ret: "void" args: */
#define	__NR_sync	36

/* syscall: "kill" ret: "int" args: "int" "int" */
#define	__NR_kill	37

/* syscall: "compat_43_stat43" ret: "int" args: "const char *" "struct stat43 *" */
#define	__NR_compat_43_stat43	38

/* syscall: "getppid" ret: "pid_t" args: */
#define	__NR_getppid	39

/* syscall: "compat_43_lstat43" ret: "int" args: "const char *" "struct stat43 *" */
#define	__NR_compat_43_lstat43	40

/* syscall: "dup" ret: "int" args: "int" */
#define	__NR_dup	41

/* syscall: "pipe" ret: "int" args: */
#define	__NR_pipe	42

/* syscall: "getegid" ret: "gid_t" args: */
#define	__NR_getegid	43

/* syscall: "profil" ret: "int" args: "caddr_t" "size_t" "u_long" "u_int" */
#define	__NR_profil	44


/* syscall: "ktrace" ret: "int" args: "const char *" "int" "int" "int" */
#define	__NR_ktrace	45

/* syscall: "compat_13_sigaction13" ret: "int" args: "int" "const struct sigaction13 *" "struct sigaction13 *" */
#define	__NR_compat_13_sigaction13	46

/* syscall: "getgid" ret: "gid_t" args: */
#define	__NR_getgid	47


/* syscall: "compat_13_sigprocmask13" ret: "int" args: "int" "int" */
#define	__NR_compat_13_sigprocmask13	48

/* syscall: "__getlogin" ret: "int" args: "char *" "size_t" */
#define	__NR___getlogin	49

/* syscall: "__setlogin" ret: "int" args: "const char *" */
#define	__NR___setlogin	50

/* syscall: "acct" ret: "int" args: "const char *" */
#define	__NR_acct	51

/* syscall: "compat_13_sigpending13" ret: "int" args: */
#define	__NR_compat_13_sigpending13	52

/* syscall: "compat_13_sigaltstack13" ret: "int" args: "const struct sigaltstack13 *" "struct sigaltstack13 *" */
#define	__NR_compat_13_sigaltstack13	53

/* syscall: "ioctl" ret: "int" args: "int" "u_long" "..." */
#define	__NR_ioctl	54

/* syscall: "compat_12_oreboot" ret: "int" args: "int" */
#define	__NR_compat_12_oreboot	55

/* syscall: "revoke" ret: "int" args: "const char *" */
#define	__NR_revoke	56

/* syscall: "symlink" ret: "int" args: "const char *" "const char *" */
#define	__NR_symlink	57

/* syscall: "readlink" ret: "int" args: "const char *" "char *" "size_t" */
#define	__NR_readlink	58

/* syscall: "execve" ret: "int" args: "const char *" "char *const *" "char *const *" */
#define	__NR_execve	59

/* syscall: "umask" ret: "mode_t" args: "mode_t" */
#define	__NR_umask	60

/* syscall: "chroot" ret: "int" args: "const char *" */
#define	__NR_chroot	61

/* syscall: "compat_43_fstat43" ret: "int" args: "int" "struct stat43 *" */
#define	__NR_compat_43_fstat43	62

/* syscall: "compat_43_ogetkerninfo" ret: "int" args: "int" "char *" "int *" "int" */
#define	__NR_compat_43_ogetkerninfo	63

/* syscall: "compat_43_ogetpagesize" ret: "int" args: */
#define	__NR_compat_43_ogetpagesize	64

/* syscall: "compat_12_msync" ret: "int" args: "caddr_t" "size_t" */
#define	__NR_compat_12_msync	65

/* syscall: "vfork" ret: "int" args: */
#define	__NR_vfork	66

				/* 67 is obsolete vread */
				/* 68 is obsolete vwrite */
/* syscall: "sbrk" ret: "int" args: "intptr_t" */
#define	__NR_sbrk	69

/* syscall: "sstk" ret: "int" args: "int" */
#define	__NR_sstk	70

/* syscall: "compat_43_ommap" ret: "int" args: "caddr_t" "size_t" "int" "int" "int" "long" */
#define	__NR_compat_43_ommap	71

/* syscall: "vadvise" ret: "int" args: "int" */
#define	__NR_vadvise	72

/* syscall: "munmap" ret: "int" args: "void *" "size_t" */
#define	__NR_munmap	73

/* syscall: "mprotect" ret: "int" args: "void *" "size_t" "int" */
#define	__NR_mprotect	74

/* syscall: "madvise" ret: "int" args: "void *" "size_t" "int" */
#define	__NR_madvise	75

				/* 76 is obsolete vhangup */
				/* 77 is obsolete vlimit */
/* syscall: "mincore" ret: "int" args: "void *" "size_t" "char *" */
#define	__NR_mincore	78

/* syscall: "getgroups" ret: "int" args: "int" "gid_t *" */
#define	__NR_getgroups	79

/* syscall: "setgroups" ret: "int" args: "int" "const gid_t *" */
#define	__NR_setgroups	80

/* syscall: "getpgrp" ret: "int" args: */
#define	__NR_getpgrp	81

/* syscall: "setpgid" ret: "int" args: "int" "int" */
#define	__NR_setpgid	82

/* syscall: "setitimer" ret: "int" args: "int" "const struct itimerval *" "struct itimerval *" */
#define	__NR_setitimer	83

/* syscall: "compat_43_owait" ret: "int" args: */
#define	__NR_compat_43_owait	84

/* syscall: "compat_12_oswapon" ret: "int" args: "const char *" */
#define	__NR_compat_12_oswapon	85

/* syscall: "getitimer" ret: "int" args: "int" "struct itimerval *" */
#define	__NR_getitimer	86

/* syscall: "compat_43_ogethostname" ret: "int" args: "char *" "u_int" */
#define	__NR_compat_43_ogethostname	87

/* syscall: "compat_43_osethostname" ret: "int" args: "char *" "u_int" */
#define	__NR_compat_43_osethostname	88

/* syscall: "compat_43_ogetdtablesize" ret: "int" args: */
#define	__NR_compat_43_ogetdtablesize	89

/* syscall: "dup2" ret: "int" args: "int" "int" */
#define	__NR_dup2	90

/* syscall: "fcntl" ret: "int" args: "int" "int" "..." */
#define	__NR_fcntl	92

/* syscall: "select" ret: "int" args: "int" "fd_set *" "fd_set *" "fd_set *" "struct timeval *" */
#define	__NR_select	93

/* syscall: "fsync" ret: "int" args: "int" */
#define	__NR_fsync	95

/* syscall: "setpriority" ret: "int" args: "int" "int" "int" */
#define	__NR_setpriority	96

/* syscall: "socket" ret: "int" args: "int" "int" "int" */
#define	__NR_socket	97

/* syscall: "connect" ret: "int" args: "int" "const struct sockaddr *" "unsigned int" */
#define	__NR_connect	98

/* syscall: "compat_43_oaccept" ret: "int" args: "int" "caddr_t" "int *" */
#define	__NR_compat_43_oaccept	99

/* syscall: "getpriority" ret: "int" args: "int" "int" */
#define	__NR_getpriority	100

/* syscall: "compat_43_osend" ret: "int" args: "int" "caddr_t" "int" "int" */
#define	__NR_compat_43_osend	101

/* syscall: "compat_43_orecv" ret: "int" args: "int" "caddr_t" "int" "int" */
#define	__NR_compat_43_orecv	102

/* syscall: "compat_13_sigreturn13" ret: "int" args: "struct sigcontext13 *" */
#define	__NR_compat_13_sigreturn13	103

/* syscall: "bind" ret: "int" args: "int" "const struct sockaddr *" "unsigned int" */
#define	__NR_bind	104

/* syscall: "setsockopt" ret: "int" args: "int" "int" "int" "const void *" "unsigned int" */
#define	__NR_setsockopt	105

/* syscall: "listen" ret: "int" args: "int" "int" */
#define	__NR_listen	106

				/* 107 is obsolete vtimes */
/* syscall: "compat_43_osigvec" ret: "int" args: "int" "struct sigvec *" "struct sigvec *" */
#define	__NR_compat_43_osigvec	108

/* syscall: "compat_43_osigblock" ret: "int" args: "int" */
#define	__NR_compat_43_osigblock	109

/* syscall: "compat_43_osigsetmask" ret: "int" args: "int" */
#define	__NR_compat_43_osigsetmask	110

/* syscall: "compat_13_sigsuspend13" ret: "int" args: "int" */
#define	__NR_compat_13_sigsuspend13	111

/* syscall: "compat_43_osigstack" ret: "int" args: "struct sigstack *" "struct sigstack *" */
#define	__NR_compat_43_osigstack	112

/* syscall: "compat_43_orecvmsg" ret: "int" args: "int" "struct omsghdr *" "int" */
#define	__NR_compat_43_orecvmsg	113

/* syscall: "compat_43_osendmsg" ret: "int" args: "int" "caddr_t" "int" */
#define	__NR_compat_43_osendmsg	114

				/* 115 is obsolete vtrace */
/* syscall: "gettimeofday" ret: "int" args: "struct timeval *" "struct timezone *" */
#define	__NR_gettimeofday	116

/* syscall: "getrusage" ret: "int" args: "int" "struct rusage *" */
#define	__NR_getrusage	117

/* syscall: "getsockopt" ret: "int" args: "int" "int" "int" "void *" "unsigned int *" */
#define	__NR_getsockopt	118

				/* 119 is obsolete resuba */
/* syscall: "readv" ret: "ssize_t" args: "int" "const struct iovec *" "int" */
#define	__NR_readv	120

/* syscall: "writev" ret: "ssize_t" args: "int" "const struct iovec *" "int" */
#define	__NR_writev	121

/* syscall: "settimeofday" ret: "int" args: "const struct timeval *" "const struct timezone *" */
#define	__NR_settimeofday	122

/* syscall: "fchown" ret: "int" args: "int" "uid_t" "gid_t" */
#define	__NR_fchown	123

/* syscall: "fchmod" ret: "int" args: "int" "mode_t" */
#define	__NR_fchmod	124

/* syscall: "compat_43_orecvfrom" ret: "int" args: "int" "caddr_t" "size_t" "int" "caddr_t" "int *" */
#define	__NR_compat_43_orecvfrom	125

/* syscall: "setreuid" ret: "int" args: "uid_t" "uid_t" */
#define	__NR_setreuid	126

/* syscall: "setregid" ret: "int" args: "gid_t" "gid_t" */
#define	__NR_setregid	127

/* syscall: "rename" ret: "int" args: "const char *" "const char *" */
#define	__NR_rename	128

/* syscall: "compat_43_otruncate" ret: "int" args: "const char *" "long" */
#define	__NR_compat_43_otruncate	129

/* syscall: "compat_43_oftruncate" ret: "int" args: "int" "long" */
#define	__NR_compat_43_oftruncate	130

/* syscall: "flock" ret: "int" args: "int" "int" */
#define	__NR_flock	131

/* syscall: "mkfifo" ret: "int" args: "const char *" "mode_t" */
#define	__NR_mkfifo	132

/* syscall: "sendto" ret: "ssize_t" args: "int" "const void *" "size_t" "int" "const struct sockaddr *" "unsigned int" */
#define	__NR_sendto	133

/* syscall: "shutdown" ret: "int" args: "int" "int" */
#define	__NR_shutdown	134

/* syscall: "socketpair" ret: "int" args: "int" "int" "int" "int *" */
#define	__NR_socketpair	135

/* syscall: "mkdir" ret: "int" args: "const char *" "mode_t" */
#define	__NR_mkdir	136

/* syscall: "rmdir" ret: "int" args: "const char *" */
#define	__NR_rmdir	137

/* syscall: "utimes" ret: "int" args: "const char *" "const struct timeval *" */
#define	__NR_utimes	138

				/* 139 is obsolete 4.2 sigreturn */
/* syscall: "adjtime" ret: "int" args: "const struct timeval *" "struct timeval *" */
#define	__NR_adjtime	140

/* syscall: "compat_43_ogetpeername" ret: "int" args: "int" "caddr_t" "int *" */
#define	__NR_compat_43_ogetpeername	141

/* syscall: "compat_43_ogethostid" ret: "int32_t" args: */
#define	__NR_compat_43_ogethostid	142

/* syscall: "compat_43_osethostid" ret: "int" args: "int32_t" */
#define	__NR_compat_43_osethostid	143

/* syscall: "compat_43_ogetrlimit" ret: "int" args: "int" "struct orlimit *" */
#define	__NR_compat_43_ogetrlimit	144

/* syscall: "compat_43_osetrlimit" ret: "int" args: "int" "const struct orlimit *" */
#define	__NR_compat_43_osetrlimit	145

/* syscall: "compat_43_okillpg" ret: "int" args: "int" "int" */
#define	__NR_compat_43_okillpg	146

/* syscall: "setsid" ret: "int" args: */
#define	__NR_setsid	147

/* syscall: "quotactl" ret: "int" args: "const char *" "int" "int" "caddr_t" */
#define	__NR_quotactl	148

/* syscall: "compat_43_oquota" ret: "int" args: */
#define	__NR_compat_43_oquota	149

/* syscall: "compat_43_ogetsockname" ret: "int" args: "int" "caddr_t" "int *" */
#define	__NR_compat_43_ogetsockname	150


/* syscall: "nfssvc" ret: "int" args: "int" "void *" */
#define	__NR_nfssvc	155

/* syscall: "compat_43_ogetdirentries" ret: "int" args: "int" "char *" "u_int" "long *" */
#define	__NR_compat_43_ogetdirentries	156

/* syscall: "statfs" ret: "int" args: "const char *" "struct statfs *" */
#define	__NR_statfs	157

/* syscall: "fstatfs" ret: "int" args: "int" "struct statfs *" */
#define	__NR_fstatfs	158

/* syscall: "getfh" ret: "int" args: "const char *" "fhandle_t *" */
#define	__NR_getfh	161

/* syscall: "compat_09_ogetdomainname" ret: "int" args: "char *" "int" */
#define	__NR_compat_09_ogetdomainname	162

/* syscall: "compat_09_osetdomainname" ret: "int" args: "char *" "int" */
#define	__NR_compat_09_osetdomainname	163

/* syscall: "compat_09_ouname" ret: "int" args: "struct outsname *" */
#define	__NR_compat_09_ouname	164

/* syscall: "sysarch" ret: "int" args: "int" "void *" */
#define	__NR_sysarch	165


/* syscall: "compat_10_osemsys" ret: "int" args: "int" "int" "int" "int" "int" */
#define	__NR_compat_10_osemsys	169


				/* 169 is excluded 1.0 semsys */


/* syscall: "compat_10_omsgsys" ret: "int" args: "int" "int" "int" "int" "int" "int" */
#define	__NR_compat_10_omsgsys	170


/* syscall: "compat_10_oshmsys" ret: "int" args: "int" "int" "int" "int" */
#define	__NR_compat_10_oshmsys	171


/* syscall: "pread" ret: "ssize_t" args: "int" "void *" "size_t" "int" "off_t" */
#define	__NR_pread	173

/* syscall: "pwrite" ret: "ssize_t" args: "int" "const void *" "size_t" "int" "off_t" */
#define	__NR_pwrite	174

/* syscall: "ntp_gettime" ret: "int" args: "struct ntptimeval *" */
#define	__NR_ntp_gettime	175


/* syscall: "ntp_adjtime" ret: "int" args: "struct timex *" */
#define	__NR_ntp_adjtime	176

/* syscall: "setgid" ret: "int" args: "gid_t" */
#define	__NR_setgid	181

/* syscall: "setegid" ret: "int" args: "gid_t" */
#define	__NR_setegid	182

/* syscall: "seteuid" ret: "int" args: "uid_t" */
#define	__NR_seteuid	183


#define	__NR_lfs_bmapv	184

/* syscall: "lfs_markv" ret: "int" args: "fsid_t *" "struct block_info *" "int" */
#define	__NR_lfs_markv	185

/* syscall: "lfs_segclean" ret: "int" args: "fsid_t *" "u_long" */
#define	__NR_lfs_segclean	186

/* syscall: "lfs_segwait" ret: "int" args: "fsid_t *" "struct timeval *" */
#define	__NR_lfs_segwait	187


/* syscall: "compat_12_stat12" ret: "int" args: "const char *" "struct stat12 *" */
#define	__NR_compat_12_stat12	188

/* syscall: "compat_12_fstat12" ret: "int" args: "int" "struct stat12 *" */
#define	__NR_compat_12_fstat12	189

/* syscall: "compat_12_lstat12" ret: "int" args: "const char *" "struct stat12 *" */
#define	__NR_compat_12_lstat12	190

/* syscall: "pathconf" ret: "long" args: "const char *" "int" */
#define	__NR_pathconf	191

/* syscall: "fpathconf" ret: "long" args: "int" "int" */
#define	__NR_fpathconf	192

/* syscall: "getrlimit" ret: "int" args: "int" "struct rlimit *" */
#define	__NR_getrlimit	194

/* syscall: "setrlimit" ret: "int" args: "int" "const struct rlimit *" */
#define	__NR_setrlimit	195

/* syscall: "compat_12_getdirentries" ret: "int" args: "int" "char *" "u_int" "long *" */
#define	__NR_compat_12_getdirentries	196

/* syscall: "mmap" ret: "void *" args: "void *" "size_t" "int" "int" "int" "long" "off_t" */
#define	__NR_mmap	197

/* syscall: "__syscall" ret: "quad_t" args: "quad_t" "..." */
#define	__NR___syscall	198

/* syscall: "lseek" ret: "off_t" args: "int" "int" "off_t" "int" */
#define	__NR_lseek	199

/* syscall: "truncate" ret: "int" args: "const char *" "int" "off_t" */
#define	__NR_truncate	200

/* syscall: "ftruncate" ret: "int" args: "int" "int" "off_t" */
#define	__NR_ftruncate	201

/* syscall: "__sysctl" ret: "int" args: "int *" "u_int" "void *" "size_t *" "void *" "size_t" */
#define	__NR___sysctl	202

/* syscall: "mlock" ret: "int" args: "const void *" "size_t" */
#define	__NR_mlock	203

/* syscall: "munlock" ret: "int" args: "const void *" "size_t" */
#define	__NR_munlock	204

/* syscall: "undelete" ret: "int" args: "const char *" */
#define	__NR_undelete	205

/* syscall: "futimes" ret: "int" args: "int" "const struct timeval *" */
#define	__NR_futimes	206

/* syscall: "getpgid" ret: "pid_t" args: "pid_t" */
#define	__NR_getpgid	207

/* syscall: "reboot" ret: "int" args: "int" "char *" */
#define	__NR_reboot	208

/* syscall: "poll" ret: "int" args: "struct pollfd *" "u_int" "int" */
#define	__NR_poll	209



/* syscall: "compat_14___semctl" ret: "int" args: "int" "int" "int" "union __semun *" */
#define	__NR_compat_14___semctl	220

/* syscall: "semget" ret: "int" args: "key_t" "int" "int" */
#define	__NR_semget	221

/* syscall: "semop" ret: "int" args: "int" "struct sembuf *" "size_t" */
#define	__NR_semop	222

/* syscall: "semconfig" ret: "int" args: "int" */
#define	__NR_semconfig	223

/* syscall: "compat_14_msgctl" ret: "int" args: "int" "int" "struct msqid_ds14 *" */
#define	__NR_compat_14_msgctl	224

/* syscall: "msgget" ret: "int" args: "key_t" "int" */
#define	__NR_msgget	225

/* syscall: "msgsnd" ret: "int" args: "int" "const void *" "size_t" "int" */
#define	__NR_msgsnd	226


#define	__NR_msgrcv	227


#define	__NR_shmat	228


#define	__NR_compat_14_shmctl	229


#define	__NR_shmdt	230


#define	__NR_shmget	231


#define	__NR_clock_gettime	232


#define	__NR_clock_settime	233


#define	__NR_clock_getres	234


#define	__NR_timer_create	235


#define	__NR_timer_delete	236


#define	__NR_timer_settime	237


#define	__NR_timer_gettime	238


#define	__NR_timer_getoverrun	239


#define	__NR_nanosleep	240


#define	__NR_fdatasync	241


#define	__NR_mlockall	242


#define	__NR_munlockall	243


#define	__NR___sigtimedwait	244


#define	__NR__ksem_init	247

#define	__NR__ksem_open	248


#define	__NR__ksem_unlink	249


#define	__NR__ksem_close	250


#define	__NR__ksem_post	251

#define	__NR__ksem_wait	252


#define	__NR__ksem_trywait	253


#define	__NR__ksem_getvalue	254


#define	__NR__ksem_destroy	255


#define	__NR___posix_rename	270


#define	__NR_swapctl	271


#define	__NR_getdents	272


#define	__NR_minherit	273


#define	__NR_lchmod	274


#define	__NR_lchown	275


#define	__NR_lutimes	276


#define	__NR___msync13	277


#define	__NR___stat13	278
/* RENAME_HACK */
#define __NR_stat  __NR___stat13


#define	__NR___fstat13	279
#define __NR_fstat  __NR___fstat13


#define	__NR___lstat13	280


#define	__NR___sigaltstack14	281


#define	__NR___vfork14	282
#define	__NR___posix_chown	283
#define	__NR___posix_fchown	284
#define	__NR___posix_lchown	285
#define	__NR_getsid	286

#define	__NR___clone	287
/* RENAME_HACK */
#define	__NR_clone	__NR___clone

#define	__NR_fktrace	288
#define	__NR_preadv	289


#define	__NR_pwritev	290


#define	__NR_compat_16___sigaction14	291


#define	__NR___sigpending14	292


#define	__NR___sigprocmask14	293


#define	__NR___sigsuspend14	294


#define	__NR_compat_16___sigreturn14	295


#define	__NR___getcwd	296
// RENAME_HACK
#define __NR_getcwd  __NR___getcwd


#define	__NR_fchroot	297


#define	__NR_fhopen	298


#define	__NR_fhstat	299


#define	__NR_fhstatfs	300



#define	__NR_____semctl13	301





#define	__NR___msgctl13	302




#define	__NR___shmctl13	303



#define	__NR_lchflags	304


#define	__NR_issetugid	305


#define	__NR_utrace	306


#define	__NR_getcontext	307


#define	__NR_setcontext	308


#define	__NR__lwp_create	309


#define	__NR__lwp_exit	310


#define	__NR__lwp_self	311


#define	__NR__lwp_wait	312


#define	__NR__lwp_suspend	313


#define	__NR__lwp_continue	314


#define	__NR__lwp_wakeup	315


#define	__NR__lwp_getprivate	316


#define	__NR__lwp_setprivate	317


#define	__NR_sa_register	330


#define	__NR_sa_stacks	331


#define	__NR_sa_enable	332


#define	__NR_sa_setconcurrency	333


#define	__NR_sa_yield	334


#define	__NR_sa_preempt	335



#define	__NR___sigaction_sigtramp	340


#define	__NR_pmc_get_info	341


#define	__NR_pmc_control	342


#define	__NR_rasctl	343


#define	__NR_kqueue	344


#define	__NR_kevent	345


#define	__NR_fsync_range	354


#define	__NR_uuidgen	355

/* syscall: "fstatvfs1" ret: "int" args: "int" "struct statvfs *" "int" */
#define __NR_fstatvfs1   358


/* syscall: "__fstat30" ret: "int" args: "int" "struct stat *" */
#define __NR___fstat30   388

/* syscall: "__lstat30" ret: "int" args: "const char *" "struct stat *" */
#define __NR___lstat30   389

#endif /* _VG_ASM_I386_UNISTD_H_ */
