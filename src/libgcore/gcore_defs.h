/* gcore_defs.h -- core analysis suite
 *
 * Copyright (C) 2010 FUJITSU LIMITED
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef GCORE_DEFS_H_
#define GCORE_DEFS_H_

#include <stdio.h>
#include <elf.h>

#if defined(X86_64) || defined(ARM64)
#define GCORE_ARCH_COMPAT 1
#endif

#ifdef X86_64
#include <gcore_compat_x86.h>
#endif

#ifdef ARM64
#include <gcore_compat_arm.h>
#endif

#define PN_XNUM 0xffff

#define ELF_CORE_EFLAGS 0

#ifdef X86_64
#define ELF_EXEC_PAGESIZE 4096

#define ELF_MACHINE EM_X86_64
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS64
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_X86_64

#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Off Elf64_Off

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Nhdr Elf64_Nhdr
#endif

#ifdef X86
#define ELF_EXEC_PAGESIZE 4096

#define ELF_MACHINE EM_386
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_386

#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Off Elf32_Off

#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Nhdr Elf32_Nhdr
#endif

#ifdef ARM
#define ELF_EXEC_PAGESIZE 4096

#define ELF_MACHINE EM_ARM
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_ARM

#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Off Elf32_Off

#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Nhdr Elf32_Nhdr
#endif

#ifdef MIPS
#define ELF_EXEC_PAGESIZE 4096

#define ELF_MACHINE EM_MIPS
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_MIPS

#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Off Elf32_Off

#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Nhdr Elf32_Nhdr
#endif

#ifdef ARM64
#define ELF_EXEC_PAGESIZE PAGESIZE()

#define ELF_MACHINE EM_AARCH64
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS64
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_AARCH64

#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Off Elf64_Off

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Nhdr Elf64_Nhdr

#ifndef NT_ARM_TLS
#define NT_ARM_TLS      0x401           /* ARM TLS register */
#endif
#endif

#ifdef PPC64
#define ELF_EXEC_PAGESIZE PAGESIZE()

#define ELF_MACHINE EM_PPC64
#define ELF_OSABI ELFOSABI_NONE

#define ELF_CLASS ELFCLASS64

#ifndef ELF_DATA
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELF_DATA ELFDATA2LSB
#else
#define ELF_DATA ELFDATA2MSB
#endif
#endif

#define ELF_ARCH EM_PPC64

#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Off Elf64_Off

#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Nhdr Elf64_Nhdr
#endif

#ifndef NT_FILE
#define NT_FILE 0x46494c45
#endif

#define PAGE_ALIGN(X) roundup(X, ELF_EXEC_PAGESIZE)

#ifdef divideup
#undef divideup
#endif
#define divideup(x, y)  (((x) + ((y) - 1)) / (y))

/*
 * gcore_regset.c
 *
 * The regset interface is fully borrowed from the library with the
 * same name in kernel used in the implementation of collecting note
 * information. See include/regset.h in detail.
 */
struct user_regset;
struct task_context;

/**
 * user_regset_active_fn - type of @active function in &struct user_regset
 * @target:	thread being examined
 * @regset:	task context being examined
 *
 * Return TRUE if there is an interesting resource.
 * Return FALSE otherwise.
 */
typedef int user_regset_active_fn(struct task_context *target,
				  const struct user_regset *regset);

/**
 * user_regset_get_fn - type of @get function in &struct user_regset
 * @target:	task context being examined
 * @regset:	regset being examined
 * @size:	amount of data to copy, in bytes
 * @buf:	if a user-space pointer to copy into
 *
 * Fetch register values. Return TRUE on success and FALSE otherwise.
 * The @size is in bytes.
 */
typedef int user_regset_get_fn(struct task_context *target,
			       const struct user_regset *regset,
			       unsigned int size,
			       void *buf);

struct elf_thread_core_info;

/**
 * user_regset_callback_fn - type of @callback function in &struct user_regset
 * @t:   thread core information
 * @regset:	regset being examined
 *
 * Edit thread core information contained in @t in terms of @regset.
 * This call is optional; the pointer is %NULL if there is no requirement to
 * edit.
 */
typedef void user_regset_callback_fn(struct elf_thread_core_info *t,
				     const struct user_regset *regset);

/**
 * struct user_regset - accessible thread CPU state
 * @size:		Size in bytes of a slot (register).
 * @core_note_type:	ELF note @n_type value used in core dumps.
 * @get:		Function to fetch values.
 * @active:		Function to report if regset is active, or %NULL.
 *
 * @name:               Note section name.
 * @callback:           Function to edit thread core information, or %NULL.
 *
 * This data structure describes machine resource to be retrieved as
 * process core dump. Each member of this structure characterizes the
 * resource and the operations necessary in core dump process.
 *
 * @get provides a means of retrieving the corresponding resource;
 * @active provides a means of checking if the resource exists; @size
 * means a size of the machine resource in bytes; @core_note_type is a
 * type of note information; @name is a note section name representing
 * the owner originator that handles this kind of the machine
 * resource; @callback is an extra operation to edit another note
 * information of the same thread, required when the machine resource
 * is collected.
 */
struct user_regset {
	user_regset_get_fn		*get;
	user_regset_active_fn		*active;
	unsigned int 			size;
	unsigned int 			core_note_type;
	char                            *name;
	user_regset_callback_fn         *callback;
};

/**
 * struct user_regset_view - available regsets
 * @name:	Identifier, e.g. UTS_MACHINE string.
 * @regsets:	Array of @n regsets available in this view.
 * @n:		Number of elements in @regsets.
 * @e_machine:	ELF header @e_machine %EM_* value written in core dumps.
 * @e_flags:	ELF header @e_flags value written in core dumps.
 * @ei_osabi:	ELF header @e_ident[%EI_OSABI] value written in core dumps.
 *
 * A regset view is a collection of regsets (&struct user_regset,
 * above).  This describes all the state of a thread that are
 * collected as note information of process core dump.
 */
struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	uint32_t e_flags;
	uint16_t e_machine;
	uint8_t ei_osabi;
};

/**
 * task_user_regset_view - Return the process's regset view.
 *
 * Return the &struct user_regset_view. By default, it returns
 * &gcore_default_regset_view.
 *
 * This is defined as a weak symbol. If there's another
 * task_user_regset_view at linking time, it is used instead, useful
 * to support different kernel version or architecture.
 */
extern const struct user_regset_view *task_user_regset_view(void);
extern void gcore_default_regsets_init(void);

#ifdef X86
#define REGSET_VIEW_NAME "i386"
#define REGSET_VIEW_MACHINE EM_386
#endif

#ifdef X86_64
#define REGSET_VIEW_NAME "x86_64"
#define REGSET_VIEW_MACHINE EM_X86_64
#endif

#ifdef IA64
#define REGSET_VIEW_NAME "ia64"
#define REGSET_VIEW_MACHINE EM_IA_64
#endif

#ifdef ARM
#define REGSET_VIEW_NAME "arm"
#define REGSET_VIEW_MACHINE EM_ARM
#endif

#ifdef ARM64
#define REGSET_VIEW_NAME "aarch64"
#define REGSET_VIEW_MACHINE EM_AARCH64
#endif

#ifdef MIPS
#define REGSET_VIEW_NAME "mips"
#define REGSET_VIEW_MACHINE EM_MIPS
#endif

#ifdef PPC64
#define REGSET_VIEW_NAME "ppc64"
#define REGSET_VIEW_MACHINE EM_PPC64
#endif

extern int gcore_arch_get_fp_valid(struct task_context *tc);

/*
 * gcore_dumpfilter.c
 */
#define GCORE_DUMPFILTER_ANON_PRIVATE    (0x1)
#define GCORE_DUMPFILTER_ANON_SHARED     (0x2)
#define GCORE_DUMPFILTER_MAPPED_PRIVATE  (0x4)
#define GCORE_DUMPFILTER_MAPPED_SHARED   (0x8)
#define GCORE_DUMPFILTER_ELF_HEADERS     (0x10)
#define GCORE_DUMPFILTER_HUGETLB_PRIVATE (0x20)
#define GCORE_DUMPFILTER_HUGETLB_SHARED  (0x40)
#define GCORE_DUMPFILTER_DONTDUMP        (0x80)

#define GCORE_DUMPFILTER_MAX_LEVEL (GCORE_DUMPFILTER_ANON_PRIVATE	\
				    |GCORE_DUMPFILTER_ANON_SHARED	\
				    |GCORE_DUMPFILTER_MAPPED_PRIVATE	\
				    |GCORE_DUMPFILTER_MAPPED_SHARED	\
				    |GCORE_DUMPFILTER_ELF_HEADERS	\
				    |GCORE_DUMPFILTER_HUGETLB_PRIVATE	\
				    |GCORE_DUMPFILTER_HUGETLB_SHARED	\
				    |GCORE_DUMPFILTER_DONTDUMP)

#define GCORE_DUMPFILTER_DEFAULT (GCORE_DUMPFILTER_ANON_PRIVATE		\
				  | GCORE_DUMPFILTER_ANON_SHARED	\
				  | GCORE_DUMPFILTER_HUGETLB_PRIVATE)

extern int gcore_dumpfilter_set(ulong filter);
extern void gcore_dumpfilter_set_default(void);
extern ulong gcore_dumpfilter_get(void);
extern ulong gcore_dumpfilter_vma_dump_size(ulong vma);

/*
 * gcore_verbose.c
 */
#define VERBOSE_PROGRESS  0x1
#define VERBOSE_NONQUIET  0x2
#define VERBOSE_PAGEFAULT 0x4
#define VERBOSE_DEFAULT_LEVEL VERBOSE_PAGEFAULT
#define VERBOSE_MAX_LEVEL (VERBOSE_PROGRESS + VERBOSE_NONQUIET + \
			   VERBOSE_PAGEFAULT)

#define VERBOSE_DEFAULT_ERROR_HANDLE (FAULT_ON_ERROR | QUIET)
#define VERBOSE_DEFAULT_ERROR_HANDLE_USER (RETURN_ON_ERROR | QUIET)

/*
 * Verbose flag is set each time gcore is executed. The same verbose
 * flag value is used for all the tasks given together in the command
 * line.
 */
extern void gcore_verbose_set_default(void);

/**
 * gcore_verbose_set() - set verbose level
 *
 * @level verbose level intended to be assigend: might be minus and
 *        larger than VERBOSE_DEFAULT_LEVEL.
 *
 * If @level is a minus value or strictly larger than VERBOSE_MAX_LEVEL,
 * return FALSE. Otherwise, update a global date, gvd, to @level, and returns
 * TRUE.
 */
extern int gcore_verbose_set(ulong level);

/**
 * gcore_verbose_get() - get verbose level
 *
 * Return the current verbose level contained in the global data.
 */
extern ulong gcore_verbose_get(void);

/**
 * gcore_verbose_error_handle() - get error handle
 *
 * Return the current error_handle contained in the global data.
 */
extern ulong gcore_verbose_error_handle(void);

/**
 * gcore_verbose_error_handle_user() - get error handle for user-space memory
 *
 * Return the current error_handle for user-space memory contained in
 * the global data.
 */
extern ulong gcore_verbose_error_handle_user(void);

/*
 * Helper printing functions for respective verbose flags
 */

/**
 * verbosef() - print verbose information if flag is set currently.
 *
 * @flag   verbose flag that is currently concerned about.
 * @format printf style format that is printed into standard output.
 *
 * Always returns FALSE.
 */
#define verbosef(vflag, eflag, ...)					\
	({								\
		if (gcore_verbose_get() & (vflag)) {			\
			(void) error((eflag), __VA_ARGS__);		\
		}							\
		FALSE;							\
	})

/**
 * progressf() - print progress verbose information
 *
 * @format printf style format that is printed into standard output.
 *
 * Print progress verbose informaiton if VERBOSE_PROGRESS is set currently.
 */
#define progressf(...) verbosef(VERBOSE_PROGRESS, INFO, __VA_ARGS__)

/**
 * pagefaultf() - print page fault verbose information
 *
 * @format printf style format that is printed into standard output.
 *
 * print pagefault verbose informaiton if VERBOSE_PAGEFAULT is set currently.
 */
#define pagefaultf(...) verbosef(VERBOSE_PAGEFAULT, WARNING, __VA_ARGS__)

/*
 * gcore_x86.c
 */
extern struct gcore_x86_table *gxt;

extern void gcore_x86_table_init(void);

#ifdef X86_64
struct user_regs_struct {
	unsigned long	r15;
	unsigned long	r14;
	unsigned long	r13;
	unsigned long	r12;
	unsigned long	bp;
	unsigned long	bx;
	unsigned long	r11;
	unsigned long	r10;
	unsigned long	r9;
	unsigned long	r8;
	unsigned long	ax;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	orig_ax;
	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
	unsigned long	fs_base;
	unsigned long	gs_base;
	unsigned long	ds;
	unsigned long	es;
	unsigned long	fs;
	unsigned long	gs;
};

struct user_regs_struct32 {
	uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
	unsigned short ds, __ds, es, __es;
	unsigned short fs, __fs, gs, __gs;
	uint32_t orig_eax, eip;
	unsigned short cs, __cs;
	uint32_t eflags, esp;
	unsigned short ss, __ss;
};
#endif

#ifdef X86
struct user_regs_struct {
	unsigned long	bx;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	bp;
	unsigned long	ax;
	unsigned long	ds;
	unsigned long	es;
	unsigned long	fs;
	unsigned long	gs;
	unsigned long	orig_ax;
	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
};
#endif

#ifdef ARM
struct user_fp {
	struct fp_reg {
		unsigned int sign1:1;
		unsigned int unused:15;
		unsigned int sign2:1;
		unsigned int exponent:14;
		unsigned int j:1;
		unsigned int mantissa1:31;
		unsigned int mantissa0:32;
	} fpregs[8];
	unsigned int fpsr:32;
	unsigned int fpcr:32;
	unsigned char ftype[8];
	unsigned int init_flag;
};

struct user_vfp {
	unsigned long long fpregs[32];
	unsigned long fpscr;
};

struct user_regs_struct{
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
	unsigned long r4;
	unsigned long r5;
	unsigned long r6;
	unsigned long r7;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long fp;
	unsigned long ip;
	unsigned long sp;
	unsigned long lr;
	unsigned long pc;
	unsigned long cpsr;
	unsigned long ORIG_r0;
};

#define ARM_VFPREGS_SIZE ( 32 * 8 /*fpregs*/ + 4 /*fpscr*/ )
#endif

#ifdef ARM64

typedef unsigned int __u32;
/*
 * User structures for general purpose, floating point and debug registers.
 */
struct user_pt_regs {
        __u64           regs[31];
        __u64           sp;
        __u64           pc;
        __u64           pstate;
};

struct user_fpsimd_state {
        __uint128_t     vregs[32];
        __u32           fpsr;
        __u32           fpcr;
};

struct user_hwdebug_state {
        __u32           dbg_info;
        __u32           pad;
        struct {
                __u64   addr;
                __u32   ctrl;
                __u32   pad;
        }               dbg_regs[16];
};

/* Type for a general-purpose register.  */
typedef unsigned long elf_greg_t;

/* And the whole bunch of them.  We could have used `struct
   pt_regs' directly in the typedef, but tradition says that
   the register set is an array, which does have some peculiar
   semantics, so leave it that way.  */
#define ELF_NGREG (sizeof (struct user_pt_regs) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

/* Register set for the floating-point registers.  */
typedef struct user_fpsimd_state elf_fpregset_t;

#ifdef GCORE_ARCH_COMPAT
/* AArch32 registers. */
struct user_regs_struct32{
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t fp;
	uint32_t ip;
	uint32_t sp;
	uint32_t lr;
	uint32_t pc;
	uint32_t cpsr;
	uint32_t ORIG_r0;
};
#endif /* GCORE_ARCH_COMPAT */
#endif

#ifdef MIPS
struct user_regs_struct {
	unsigned long gregs[45];
};
#endif

#ifdef PPC64
/* taken from asm/ptrace.h */
struct user_regs_struct {
	unsigned long gpr[32];
	unsigned long nip;
	unsigned long msr;
	unsigned long orig_gpr3;	/* Used for restarting system calls */
	unsigned long ctr;
	unsigned long link;
	unsigned long xer;
	unsigned long ccr;
#ifdef __powerpc64__
	unsigned long softe;		/* Soft enabled/disabled */
#else
	unsigned long mq;		/* 601 only (not used at present) */
			/* Used on APUS to hold IPL value. */
#endif
	unsigned long trap;		/* Reason for being here */
	/* N.B. for critical exceptions on 4xx, the dar and dsisr
	   fields are overloaded to hold srr0 and srr1. */
	unsigned long dar;		/* Fault registers */
	unsigned long dsisr;		/* on 4xx/Book-E used for ESR */
	unsigned long result;		/* Result of a system call */
};
#endif

#if defined(X86) || defined(X86_64) || defined(ARM) || defined(MIPS)
typedef ulong elf_greg_t;
#define ELF_NGREG (sizeof(struct user_regs_struct) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];
#endif

#if defined(X86) || defined(ARM) || defined(MIPS)
#define PAGE_SIZE 4096
#endif
#if defined(ARM64) || defined(PPC64)
#define PAGE_SIZE PAGESIZE()
#endif

extern int gcore_is_arch_32bit_emulation(struct task_context *tc);
extern ulong gcore_arch_get_gate_vma(void);
extern char *gcore_arch_vma_name(ulong vma);
extern int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void);

/*
 * gcore_coredump_table.c
 */
extern void gcore_coredump_table_init(void);

/*
 * gcore_coredump.c
 */
extern void gcore_coredump(void);

/*
 * gcore_global_data.c
 */
extern struct gcore_one_session_data *gcore;
extern struct gcore_coredump_table *ggt;
extern struct gcore_offset_table gcore_offset_table;
extern struct gcore_size_table gcore_size_table;
extern struct gcore_machdep_table *gcore_machdep;

/*
 * Misc
 */
enum pid_type
{
        PIDTYPE_PID,
        PIDTYPE_PGID,
        PIDTYPE_SID,
        PIDTYPE_MAX
};

struct elf_siginfo
{
        int     si_signo;                       /* signal number */
	int     si_code;                        /* extra code */
        int     si_errno;                       /* errno */
};

/* Parameters used to convert the timespec values: */
#define NSEC_PER_USEC   1000L
#define NSEC_PER_SEC    1000000000L

/* The clock frequency of the i8253/i8254 PIT */
#define PIT_TICK_RATE 1193182ul

/* Assume we use the PIT time source for the clock tick */
#define CLOCK_TICK_RATE         PIT_TICK_RATE

/* LATCH is used in the interval timer and ftape setup. */
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)  /* For divider */

/* Suppose we want to devide two numbers NOM and DEN: NOM/DEN, then we can
 * improve accuracy by shifting LSH bits, hence calculating:
 *     (NOM << LSH) / DEN
 * This however means trouble for large NOM, because (NOM << LSH) may no
 * longer fit in 32 bits. The following way of calculating this gives us
 * some slack, under the following conditions:
 *   - (NOM / DEN) fits in (32 - LSH) bits.
 *   - (NOM % DEN) fits in (32 - LSH) bits.
 */
#define SH_DIV(NOM,DEN,LSH) (   (((NOM) / (DEN)) << (LSH))              \
				+ ((((NOM) % (DEN)) << (LSH)) + (DEN) / 2) / (DEN))

/* HZ is the requested value. ACTHZ is actual HZ ("<< 8" is for accuracy) */
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))

/* TICK_NSEC is the time between ticks in nsec assuming real ACTHZ */
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))

#define cputime_add(__a, __b)           ((__a) +  (__b))
#define cputime_sub(__a, __b)           ((__a) -  (__b))

typedef unsigned long cputime_t;

#define cputime_zero                    (0UL)

struct task_cputime {
        cputime_t utime;
        cputime_t stime;
        unsigned long long sum_exec_runtime;
};

#define INIT_CPUTIME						\
        (struct task_cputime) {                                 \
                .utime = cputime_zero,                          \
			.stime = cputime_zero,                          \
			.sum_exec_runtime = 0,                          \
			}

static inline uint64_t div_u64_rem(uint64_t dividend, uint32_t divisor,
				   uint32_t *remainder)
{
        *remainder = dividend % divisor;
        return dividend / divisor;
}

static inline void
jiffies_to_timeval(const cputime_t jiffies, struct timeval *value)
{
        /*
         * Convert jiffies to nanoseconds and separate with
         * one divide.
         */
        uint32_t rem;

        value->tv_sec = div_u64_rem((uint64_t)jiffies * TICK_NSEC,
                                    NSEC_PER_SEC, &rem);
        value->tv_usec = rem / NSEC_PER_USEC;
}

static inline void
cputime_to_timeval(const cputime_t cputime, struct timeval *value)
{
	jiffies_to_timeval(cputime, value);
}

#ifdef GCORE_ARCH_COMPAT
static inline void
cputime_to_compat_timeval(const cputime_t cputime,
			  struct compat_timeval *value)
{
	struct timeval tv;
	cputime_to_timeval(cputime, &tv);
	value->tv_sec = tv.tv_sec;
	value->tv_usec = tv.tv_usec;
}
#endif

struct elf_prstatus
{
	struct elf_siginfo pr_info;	/* Info associated with signal */
	short	pr_cursig;		/* Current signal */
	unsigned long pr_sigpend;	/* Set of pending signals */
	unsigned long pr_sighold;	/* Set of held signals */
	int	pr_pid;
	int	pr_ppid;
	int	pr_pgrp;
	int	pr_sid;
	struct timeval pr_utime;	/* User time */
	struct timeval pr_stime;	/* System time */
	struct timeval pr_cutime;	/* Cumulative user time */
	struct timeval pr_cstime;	/* Cumulative system time */
	elf_gregset_t pr_reg;	/* GP registers */
	int pr_fpvalid;		/* True if math co-processor being used.  */
};

#if defined(X86) || defined(X86_64) || defined(ARM) || defined(MIPS)
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
#endif

#if defined(X86_64) || defined(ARM64) || defined(PPC64)
typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;
#endif

#ifdef ARM64
#ifndef __kernel_old_uid_t
typedef __kernel_uid_t  __kernel_old_uid_t;
typedef __kernel_gid_t  __kernel_old_gid_t;
#endif
#endif

typedef __kernel_old_uid_t      old_uid_t;
typedef __kernel_old_gid_t      old_gid_t;

#if defined(X86) || defined(ARM) || defined(MIPS)
typedef unsigned short __kernel_uid_t;
typedef unsigned short __kernel_gid_t;
#endif

#define overflowuid (symbol_exists("overflowuid"))
#define overflowgid (symbol_exists("overflowgid"))

#define high2lowuid(uid) ((uid) & ~0xFFFF ? (old_uid_t)overflowuid : (old_uid_t)(uid))
#define high2lowgid(gid) ((gid) & ~0xFFFF ? (old_gid_t)overflowgid : (old_gid_t)(gid))

#define __convert_uid(size, uid) \
        (size >= sizeof(uid) ? (uid) : high2lowuid(uid))
#define __convert_gid(size, gid) \
        (size >= sizeof(gid) ? (gid) : high2lowgid(gid))

#define SET_UID(var, uid) do { (var) = __convert_uid(sizeof(var), (uid)); } while (0)
#define SET_GID(var, gid) do { (var) = __convert_gid(sizeof(var), (gid)); } while (0)

#define MAX_USER_RT_PRIO        100
#define MAX_RT_PRIO             MAX_USER_RT_PRIO

#define PRIO_TO_NICE(prio)      ((prio) - MAX_RT_PRIO - 20)
#define TASK_NICE(p)            PRIO_TO_NICE((p)->static_prio)

static inline ulong ffz(ulong word)
{
        int num = 0;

#if defined(X86_64) || defined(IA64)
        if ((word & 0xffffffff) == 0) {
                num += 32;
                word >>= 32;
        }
#endif
        if ((word & 0xffff) == 0) {
                num += 16;
                word >>= 16;
        }
        if ((word & 0xff) == 0) {
                num += 8;
                word >>= 8;
        }
        if ((word & 0xf) == 0) {
                num += 4;
                word >>= 4;
        }
        if ((word & 0x3) == 0) {
                num += 2;
                word >>= 2;
        }
        if ((word & 0x1) == 0)
                num += 1;
        return num;
}

#define ELF_PRARGSZ     (80)    /* Number of chars for args */

struct elf_prpsinfo
{
        char    pr_state;       /* numeric process state */
        char    pr_sname;       /* char for pr_state */
        char    pr_zomb;        /* zombie */
        char    pr_nice;        /* nice val */
        unsigned long pr_flag;  /* flags */
        __kernel_uid_t  pr_uid;
        __kernel_gid_t  pr_gid;
        pid_t   pr_pid, pr_ppid, pr_pgrp, pr_sid;
        /* Lots missing */
        char    pr_fname[16];   /* filename of executable */
        char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

#ifdef GCORE_ARCH_COMPAT

struct compat_elf_siginfo
{
	compat_int_t			si_signo;
	compat_int_t			si_code;
	compat_int_t			si_errno;
};

struct compat_elf_prstatus
{
	struct compat_elf_siginfo	pr_info;
	short				pr_cursig;
	compat_ulong_t			pr_sigpend;
	compat_ulong_t			pr_sighold;
	compat_pid_t			pr_pid;
	compat_pid_t			pr_ppid;
	compat_pid_t			pr_pgrp;
	compat_pid_t			pr_sid;
	struct compat_timeval		pr_utime;
	struct compat_timeval		pr_stime;
	struct compat_timeval		pr_cutime;
	struct compat_timeval		pr_cstime;
	compat_elf_gregset_t		pr_reg;
	compat_int_t			pr_fpvalid;
};

struct compat_elf_prpsinfo
{
	char				pr_state;
	char				pr_sname;
	char				pr_zomb;
	char				pr_nice;
	compat_ulong_t			pr_flag;
	__compat_uid_t			pr_uid;
	__compat_gid_t			pr_gid;
	compat_pid_t			pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char				pr_fname[16];
	char				pr_psargs[ELF_PRARGSZ];
};

#endif /* GCORE_ARCH_COMPAT */

#define TASK_COMM_LEN 16

#define	CORENAME_MAX_SIZE 128

struct thread_group_list {
	struct thread_group_list *next;
	ulong task;
};

struct memelfnote
{
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

struct elf_note_info {
	void (*fill_prstatus_note)(struct elf_note_info *info,
				   struct task_context *tc,
				   struct memelfnote *memnote);
	void (*fill_psinfo_note)(struct elf_note_info *info,
				 struct task_context *tc,
				 struct memelfnote *memnote);
	void (*fill_auxv_note)(struct elf_note_info *info,
			       struct task_context *tc,
			       struct memelfnote *memnote);
	int (*fill_files_note)(struct elf_note_info *info,
			       struct task_context *tc,
			       struct memelfnote *memnote);
	size_t size;
	int thread_notes;
};

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 */
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
#define VM_IO           0x00004000      /* Memory mapped I/O or similar */
#define VM_RESERVED     0x00080000      /* Count as reserved_vm like IO */
#define VM_HUGETLB      0x00400000      /* Huge TLB Page VM */
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */
#define VM_ALWAYSDUMP   (gcore_machdep->vm_alwaysdump)
                                        /* Always include in core dumps */

extern ulong first_vma(ulong mmap, ulong gate_vma);
extern ulong next_vma(ulong this_vma, ulong gate_vma);

#define FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma)			\
	for (index = 0, vma = first_vma(mmap, gate_vma); vma;		\
	     ++index, vma = next_vma(vma, gate_vma))

extern struct task_context *
next_task_context(ulong tgid, struct task_context *tc);

static inline struct task_context *first_task_context(ulong tgid)
{
	return next_task_context(tgid, FIRST_CONTEXT());
}

#define FOR_EACH_TASK_IN_THREAD_GROUP(tgid, tc)				\
	for (tc = first_task_context(tgid); tc;				\
	     tc = next_task_context(tgid, tc))

extern int _init(void);
extern int _fini(void);
extern char *help_gcore[];
extern void cmd_gcore(void);

struct gcore_coredump_table {

	unsigned int (*get_inode_i_nlink)(ulong file);

	pid_t (*task_pid)(ulong task);
	pid_t (*task_pgrp)(ulong task);
	pid_t (*task_session)(ulong task);

	void (*thread_group_cputime)(ulong task,
				     struct task_cputime *cputime);

	__kernel_uid_t (*task_uid)(ulong task);
	__kernel_gid_t (*task_gid)(ulong task);
};

struct gcore_offset_table
{
	long cpuinfo_x86_hard_math;
	long cpuinfo_x86_x86_capability;
	long cred_gid;
	long cred_uid;
	long desc_struct_base0;
	long desc_struct_base1;
	long desc_struct_base2;
	long fpu_state;
	long inode_i_nlink;
	long nsproxy_pid_ns;
	long mm_context_t_vdso;
	long mm_struct_arg_start;
	long mm_struct_arg_end;
	long mm_struct_map_count;
	long mm_struct_reserved_vm;
	long mm_struct_saved_auxv;
	long mm_struct_saved_files;
	long mm_struct_context;
	long pid_level;
	long pid_namespace_level;
	long pt_regs_ax;
	long pt_regs_bp;
	long pt_regs_bx;
	long pt_regs_cs;
	long pt_regs_cx;
	long pt_regs_di;
	long pt_regs_ds;
	long pt_regs_dx;
	long pt_regs_es;
	long pt_regs_flags;
	long pt_regs_fs;
	long pt_regs_gs;
	long pt_regs_ip;
	long pt_regs_orig_ax;
	long pt_regs_si;
	long pt_regs_sp;
	long pt_regs_ss;
	long pt_regs_xfs;
	long pt_regs_xgs;
	long sched_entity_sum_exec_runtime;
	long signal_struct_cutime;
	long signal_struct_pgrp;
	long signal_struct_pids;
	long signal_struct_session;
	long signal_struct_stime;
	long signal_struct_sum_sched_runtime;
	long signal_struct_utime;
	long task_struct_cred;
	long task_struct_gid;
	long task_struct_group_leader;
	long task_struct_real_cred;
	long task_struct_real_parent;
	long task_struct_se;
	long task_struct_static_prio;
	long task_struct_uid;
	long task_struct_used_math;
	long task_struct_thread_pid;
	long thread_info_status;
	long thread_info_fpstate;
	long thread_info_vfpstate;
	long thread_struct_ds;
	long thread_struct_es;
	long thread_struct_fs;
	long thread_struct_fsindex;
	long thread_struct_fpu;
	long thread_struct_gs;
	long thread_struct_gsindex;
	long thread_struct_i387;
	long thread_struct_sp0;
	long thread_struct_tls_array;
	long thread_struct_usersp;
	long thread_struct_xstate;
	long thread_struct_io_bitmap_max;
	long thread_struct_io_bitmap_ptr;
	long thread_struct_fpsimd_state;
	long thread_struct_tp_value;
	long user_regset_n;
	long vfp_state_hard;
	long vfp_hard_struct_fpregs;
	long vfp_hard_struct_fpscr;
	long vm_area_struct_anon_vma;
	long vm_area_struct_vm_ops;
	long vm_area_struct_vm_private_data;
	long vm_operations_struct_name;
	long vm_special_mapping_name;
	long x8664_pda_oldrsp;
};

struct gcore_size_table
{
	long mm_context_t;
	long mm_struct_saved_auxv;
	long mm_struct_saved_files;
	long thread_struct_ds;
	long thread_struct_es;
	long thread_struct_fs;
	long thread_struct_fsindex;
	long thread_struct_gs;
	long thread_struct_gsindex;
	long thread_struct_tls_array;
	long vfp_hard_struct_fpregs;
	long vfp_hard_struct_fpscr;
	long vm_area_struct_anon_vma;
	long thread_xstate;
	long i387_union;
};

#define GCORE_OFFSET(X) (OFFSET_verify(gcore_offset_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define GCORE_SIZE(X) (SIZE_verify(gcore_size_table.X, (char *)__FUNCTION__, __FILE__, __LINE__, #X))
#define GCORE_VALID_MEMBER(X) (gcore_offset_table.X >= 0)
#define GCORE_ASSIGN_OFFSET(X) (gcore_offset_table.X)
#define GCORE_MEMBER_OFFSET_INIT(X, Y, Z) (GCORE_ASSIGN_OFFSET(X) = MEMBER_OFFSET(Y, Z))
#define GCORE_ASSIGN_SIZE(X) (gcore_size_table.X)
#define GCORE_SIZE_INIT(X, Y, Z) (GCORE_ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
#define GCORE_MEMBER_SIZE_INIT(X, Y, Z) (GCORE_ASSIGN_SIZE(X) = MEMBER_SIZE(Y, Z))
#define GCORE_STRUCT_SIZE_INIT(X, Y) (GCORE_ASSIGN_SIZE(X) = STRUCT_SIZE(Y))

#define GCORE_INVALID_MEMBER(X) (gcore_offset_table.X == INVALID_OFFSET)

#define GCORE_ANON_MEMBER_OFFSET_REQUEST ((struct datatype_member *)(-2))
#define GCORE_ANON_MEMBER_OFFSET(X,Y)    datatype_info((X), (Y), GCORE_ANON_MEMBER_OFFSET_REQUEST)
#define GCORE_ANON_MEMBER_OFFSET_INIT(X, Y, Z) (GCORE_ASSIGN_OFFSET(X) = ANON_MEMBER_OFFSET(Y, Z))

extern struct gcore_offset_table gcore_offset_table;
extern struct gcore_size_table gcore_size_table;

struct gcore_machdep_table
{
	ulong vm_alwaysdump;
};

/*
 * gcore flags
 */
#define GCF_SUCCESS     0x1
#define GCF_UNDER_COREDUMP 0x2

/**
 * Abstract Elf64 and Elf32 structures and operations on them in order
 * to support tasks in 32-bit mode on 64-bit machine. The current
 * target is IA32e compatibility mode on X86_64 only.
 *
 * Actual implementations for X86 and X86_64 is in gcore_elf_struct.c.
 */

struct gcore_elf_struct;

struct gcore_elf_operations
{
	void (*fill_elf_header)(struct gcore_elf_struct *this,
				uint16_t e_phnum, uint16_t e_machine,
				uint32_t e_flags, uint8_t ei_osabi);
	void (*fill_section_header)(struct gcore_elf_struct *this, int phnum);
	void (*fill_program_header)(struct gcore_elf_struct *this,
				    uint32_t p_type, uint32_t p_flags,
				    uint64_t p_offset, uint64_t p_vaddr,
				    uint64_t p_filesz, uint64_t p_memsz,
				    uint64_t p_align);
	void (*fill_note_header)(struct gcore_elf_struct *this,
				 uint32_t n_namesz, uint32_t n_descsz,
				 uint32_t n_type);

	/**
	 * A set of helper functions to perform write operation for
	 * respective ELF data structures.
	 *
	 *  @fd file descripter for a generated core dump file.
	 *
	 * - Return TRUE if write operation is successfully
	 *   done. Otherwise, return FALSE.
	 *
	 * - No exception is raised.
	 */
	int (*write_elf_header)(struct gcore_elf_struct *this, FILE *fp);
	int (*write_section_header)(struct gcore_elf_struct *this, FILE *fp);
	int (*write_program_header)(struct gcore_elf_struct *this, FILE *fp);
	int (*write_note_header)(struct gcore_elf_struct *this, FILE *fp,
				 off_t *offset);

	uint64_t (*get_e_phoff)(struct gcore_elf_struct *this);
	uint64_t (*get_e_shoff)(struct gcore_elf_struct *this);

	/**
	 * Get fields of section header.
	 */
	uint32_t (*get_sh_info)(struct gcore_elf_struct *this);

	size_t (*get_note_header_size)(struct gcore_elf_struct *this);

	off_t (*calc_segment_offset)(struct gcore_elf_struct *this);
};

struct gcore_elf_struct
{
	struct gcore_elf_operations *ops;
};

extern const struct gcore_elf_operations *gcore_elf64_get_operations(void);
extern const struct gcore_elf_operations *gcore_elf32_get_operations(void);

extern void gcore_elf_init(struct gcore_one_session_data *gcore);

/*
 * Data used during one session; one session means a period of core
 * dump processing for a given task. For example, suppose:
 *
 *     crash> gcore task1 task2
 *
 * Then, there're two sessions: one for task1 and the other for
 * task2. Session for task1 is not used for task2; all fields of which
 * is initialized at the beginning of dump processing for task2.
 */
struct gcore_one_session_data
{
	ulong flags;
	FILE *fp;
	ulong orig_task;
	char corename[CORENAME_MAX_SIZE + 1];
	struct gcore_elf_struct *elf;
};

static inline void gcore_arch_table_init(void)
{
#if defined (X86_64) || defined (X86)
	gcore_x86_table_init();
#endif
}

#ifdef X86_64
extern void gcore_x86_64_regsets_init(void);
extern void gcore_x86_32_regsets_init(void);
#define gcore_arch_regsets_init gcore_x86_64_regsets_init
#endif

#ifdef X86
extern void gcore_x86_32_regsets_init(void);
#define gcore_arch_regsets_init gcore_x86_32_regsets_init
#endif

#ifndef gcore_arch_regsets_init
extern void gcore_default_regsets_init(void);
#define gcore_arch_regsets_init gcore_default_regsets_init
#endif

#define VDSO_HIGH_BASE 0xffffe000U

extern ulong readswap(ulonglong pte_val, char *buf, ulong len, ulonglong vaddr);
extern void gcore_readmem_user(ulong addr, void *buf, long size, char *type);

#endif /* GCORE_DEFS_H_ */
