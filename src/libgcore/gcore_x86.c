/* x86.c -- core analysis suite
 *
 * Copyright (C) 2010, 2011 FUJITSU LIMITED
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
#if defined(X86) || defined(X86_64)

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>
#include <asm/ldt.h>

#undef MIN
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

struct gcore_x86_table
{
#ifdef X86_64
	ulong (*get_old_rsp)(int cpu);
	ulong (*user_stack_pointer)(struct task_context *tc);
#endif
	ulong (*get_thread_struct_fpu)(struct task_context *tc);
	ulong (*get_thread_struct_fpu_size)(void);
#ifdef X86_64
	int (*is_special_syscall)(int nr_syscall);
	int (*is_special_ia32_syscall)(int nr_syscall);
#endif
	int (*tsk_used_math)(ulong task);
};

static struct gcore_x86_table gcore_x86_table;
struct gcore_x86_table *gxt = &gcore_x86_table;

#ifdef X86_64
static ulong gcore_x86_64_get_old_rsp(int cpu);
static ulong gcore_x86_64_get_per_cpu__old_rsp(int cpu);
static ulong gcore_x86_64_get_cpu_pda_oldrsp(int cpu);
static ulong gcore_x86_64_get_cpu__pda_oldrsp(int cpu);

static ulong gcore_x86_64_user_stack_pointer_userrsp(struct task_context *tc);
static ulong gcore_x86_64_user_stack_pointer_pt_regs(struct task_context *tc);
#endif

static ulong
gcore_x86_get_thread_struct_fpu_fpregs_state(struct task_context *tc);
static ulong
gcore_x86_get_thread_struct_fpu_thread_xstate(struct task_context *tc);
static ulong gcore_x86_get_thread_struct_fpu_thread_xstate_size(void);
static ulong
gcore_x86_get_thread_struct_thread_xstate(struct task_context *tc);
static ulong gcore_x86_get_thread_struct_thread_xstate_size(void);
static ulong gcore_x86_get_thread_struct_i387(struct task_context *tc);
static ulong gcore_x86_get_thread_struct_i387_size(void);

#ifdef X86_64
static void gcore_x86_table_register_get_old_rsp(void);
#endif
static void gcore_x86_table_register_get_thread_struct_fpu(void);
#ifdef X86_64
static void gcore_x86_table_register_is_special_syscall(void);
static void gcore_x86_table_register_is_special_ia32_syscall(void);
#endif
static void gcore_x86_table_register_tsk_used_math(void);

#ifdef X86_64
static int is_special_syscall_v0(int nr_syscall);
static int is_special_syscall_v26(int nr_syscall);
#endif

static int test_bit(unsigned int nr, const ulong addr);

#ifdef X86_64
static int is_ia32_syscall_enabled(void);
static int is_special_ia32_syscall_v0(int nr_syscall);
static int is_special_ia32_syscall_v26(int nr_syscall);
#endif

static int tsk_used_math_v0(ulong task);
static int tsk_used_math_v11(ulong task);
static int tsk_used_math_v4_14(ulong task);

#ifdef X86_64
static void gcore_x86_64_regset_xstate_init(void);
#endif

static int genregs_get32(struct task_context *target,
			 const struct user_regset *regset, unsigned int size,
			 void *buf);
#ifdef X86
static void gcore_x86_32_regset_xstate_init(void);
#endif

static int get_xstate_regsets_number(void);

enum gcore_regset {
	REGSET_GENERAL,
	REGSET_FP,
	REGSET_XFP,
	REGSET_IOPERM64 = REGSET_XFP,
	REGSET_TLS,
	REGSET_IOPERM32,
	REGSET_XSTATE,
};

#define NT_386_TLS      0x200           /* i386 TLS slots (struct user_desc) */
#ifndef NT_386_IOPERM
#define NT_386_IOPERM	0x201		/* x86 io permission bitmap (1=deny) */
#endif
#define NT_X86_XSTATE   0x202           /* x86 extended state using xsave */
#define NT_PRXFPREG     0x46e62b7f      /* copied from gdb5.1/include/elf/common.h */

#define USER_XSTATE_FX_SW_WORDS 6

#define MXCSR_DEFAULT           0x1f80

#ifdef X86_64
/* This matches the 64bit FXSAVE format as defined by AMD. It is the same
   as the 32bit format defined by Intel, except that the selector:offset pairs for
   data and eip are replaced with flat 64bit pointers. */ 
struct user_i387_struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd; /* Note this is not the same as the 32bit/x87/FSAVE twd */
	unsigned short	fop;
	uint64_t	rip;
	uint64_t	rdp;
	uint32_t	mxcsr;
	uint32_t	mxcsr_mask;
	uint32_t	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	uint32_t	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	uint32_t	padding[24];
};
#endif

struct user_i387_ia32_struct {
	uint32_t	cwd;
	uint32_t	swd;
	uint32_t	twd;
	uint32_t	fip;
	uint32_t	fcs;
	uint32_t	foo;
	uint32_t	fos;
	uint32_t	st_space[20];   /* 8*10 bytes for each FP-reg = 80 bytes */
};

struct user32_fxsr_struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;	/* not compatible to 64bit twd */
	unsigned short	fop;
	int	fip;
	int	fcs;
	int	foo;
	int	fos;
	int	mxcsr;
	int	reserved;
	int	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	int	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
	int	padding[56];
};

struct i387_fsave_struct {
        uint32_t                     cwd;    /* FPU Control Word             */
        uint32_t                     swd;    /* FPU Status Word              */
        uint32_t                     twd;    /* FPU Tag Word                 */
        uint32_t                     fip;    /* FPU IP Offset                */
        uint32_t                     fcs;    /* FPU IP Selector              */
        uint32_t                     foo;    /* FPU Operand Pointer Offset   */
        uint32_t                     fos;    /* FPU Operand Pointer Selector */

        /* 8*10 bytes for each FP-reg = 80 bytes:                       */
        uint32_t                     st_space[20];

        /* Software status information [not touched by FSAVE ]:         */
        uint32_t                     status;
};

struct i387_fxsave_struct {
        uint16_t                     cwd; /* Control Word                    */
        uint16_t                     swd; /* Status Word                     */
        uint16_t                     twd; /* Tag Word                        */
        uint16_t                     fop; /* Last Instruction Opcode         */
        union {
                struct {
                        uint64_t     rip; /* Instruction Pointer             */
                        uint64_t     rdp; /* Data Pointer                    */
                };
                struct {
                        uint32_t     fip; /* FPU IP Offset                   */
                        uint32_t     fcs; /* FPU IP Selector                 */
                        uint32_t     foo; /* FPU Operand Offset              */
                        uint32_t     fos; /* FPU Operand Selector            */
                };
        };
        uint32_t                     mxcsr;          /* MXCSR Register State */
        uint32_t                     mxcsr_mask;     /* MXCSR Mask           */

        /* 8*16 bytes for each FP-reg = 128 bytes:                      */
        uint32_t                     st_space[32];

        /* 16*16 bytes for each XMM-reg = 256 bytes:                    */
        uint32_t                     xmm_space[64];

        uint32_t                     padding[12];

        union {
                uint32_t             padding1[12];
                uint32_t             sw_reserved[12];
        };

} __attribute__((aligned(16)));

struct i387_soft_struct {
        uint32_t                     cwd;
        uint32_t                     swd;
        uint32_t                     twd;
        uint32_t                     fip;
        uint32_t                     fcs;
        uint32_t                     foo;
        uint32_t                     fos;
        /* 8*10 bytes for each FP-reg = 80 bytes: */
        uint32_t                     st_space[20];
        uint8_t                      ftop;
        uint8_t                      changed;
        uint8_t                      lookahead;
        uint8_t                      no_update;
        uint8_t                      rm;
        uint8_t                      alimit;
        struct math_emu_info    *info;
        uint32_t                     entry_eip;
};

struct ymmh_struct {
        /* 16 * 16 bytes for each YMMH-reg = 256 bytes */
        uint32_t ymmh_space[64];
};

struct xsave_hdr_struct {
        uint64_t xstate_bv;
        uint64_t reserved1[2];
        uint64_t reserved2[5];
} __attribute__((packed));

struct xsave_struct {
        struct i387_fxsave_struct i387;
        struct xsave_hdr_struct xsave_hdr;
        struct ymmh_struct ymmh;
        /* new processor state extensions will go here */
} __attribute__ ((packed, aligned (64)));

union thread_xstate {
        struct i387_fsave_struct        fsave;
        struct i387_fxsave_struct       fxsave;
        struct i387_soft_struct         soft;
        struct xsave_struct             xsave;
};

#define NCAPINTS	9	/* N 32-bit words worth of info */

#define X86_FEATURE_FXSR	(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XSAVE       (4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_XSAVEOPT	(7*32+ 4) /* Optimized Xsave */

/*
 * Per process flags
 */
#define PF_USED_MATH    0x00002000      /* if unset the fpu must be initialized before use */

/*
 * Thread-synchronous status.
 *
 * This is different from the flags in that nobody else
 * ever touches our thread-synchronous status, so we don't
 * have to worry about atomic accesses.
 */
#define TS_USEDFPU		0x0001	/* FPU was used by this task
					   this quantum (SMP) */

static int
boot_cpu_has(int feature)
{
	uint32_t x86_capability[NCAPINTS];

	if (!symbol_exists("boot_cpu_data"))
		error(FATAL, "boot_cpu_data: symbol does not exist\n");

	readmem(symbol_value("boot_cpu_data") +
		GCORE_OFFSET(cpuinfo_x86_x86_capability), KVADDR,
		&x86_capability, sizeof(x86_capability),
		"boot_cpu_has: x86_capability",
		gcore_verbose_error_handle());

	return ((1UL << (feature % 32)) & x86_capability[feature / 32]) != 0;
}

static inline int
cpu_has_xsave(void)
{
	return boot_cpu_has(X86_FEATURE_XSAVE);
}

static inline int
cpu_has_xsaveopt(void)
{
	return boot_cpu_has(X86_FEATURE_XSAVEOPT);
}

static inline int
cpu_has_fxsr(void)
{
	return boot_cpu_has(X86_FEATURE_FXSR);
}

static int
task_used_fpu(ulong task)
{
	uint32_t status;

	readmem(task_to_context(task)->thread_info +
		GCORE_OFFSET(thread_info_status), KVADDR, &status,
		sizeof(uint32_t), "task_used_fpu: status",
		gcore_verbose_error_handle());

	return !!(status & TS_USEDFPU);
}

static void
init_fpu(ulong task)
{
	if (gxt->tsk_used_math(task) && is_task_active(task)
	    && task_used_fpu(task)) {
		/*
		 * The FPU values contained within thread->xstate may
		 * differ from what was contained at crash timing, but
		 * crash dump cannot restore the runtime FPU state,
		 * here I only warn that.
		 */
		error(WARNING, "FPU may be inaccurate: %d\n",
		      task_to_pid(task));
        }
}

static int
xfpregs_active(struct task_context *target,
	       const struct user_regset *regset)
{
	return gxt->tsk_used_math(target->task);
}

static int xfpregs_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size,
		       void *buf)
{
	union thread_xstate xstate;

	readmem(gxt->get_thread_struct_fpu(target), KVADDR, &xstate,
		sizeof(xstate),
		"xfpregs_get: xstate", gcore_verbose_error_handle());
	memcpy(buf, &xstate.fsave, MIN(size, sizeof(xstate.fsave)));

	init_fpu(target->task);

	return 0;
}

static inline int
fpregs_active(struct task_context *target,
	      const struct user_regset *regset)
{
	return !!gxt->tsk_used_math(target->task);
}

static void sanitize_i387_state(struct task_context *target)
{
	if (cpu_has_xsaveopt()) {
		/*
		 * I have yet to implement here since I don't have
		 * CPUes that supports XSAVEOPT instruction.
		 */
	}
}

#ifdef X86_64
static inline int have_hwfp(void)
{
	return TRUE;
}
#else

/*
 * CONFIG_MATH_EMULATION is set iff there's no math_emulate().
 */
static int is_set_config_math_emulation(void)
{
	return !symbol_exists("math_emulate");
}

static int have_hwfp(void)
{
	char hard_math;

	if (!is_set_config_math_emulation())
		return TRUE;

	readmem(symbol_value("cpuinfo_x86") + GCORE_OFFSET(cpuinfo_x86_hard_math),
		KVADDR, &hard_math, sizeof(hard_math), "have_hwfp: hard_math",
		gcore_verbose_error_handle());

	return hard_math ? TRUE : FALSE;
}
#endif /* X86_64 */

static int fpregs_soft_get(struct task_context *target,
			   const struct user_regset *regset,
			   unsigned int size,
			   void *buf)
{
	error(WARNING, "not support FPU software emulation\n");
	return 0;
}

static inline struct _fpxreg *
fpreg_addr(struct i387_fxsave_struct *fxsave, int n)
{
	return (void *)&fxsave->st_space + n * 16;
}

static inline uint32_t
twd_fxsr_to_i387(struct i387_fxsave_struct *fxsave)
{
	struct _fpxreg *st;
	uint32_t tos = (fxsave->swd >> 11) & 7;
	uint32_t twd = (unsigned long) fxsave->twd;
	enum {
		FP_EXP_TAG_VALID=0,
		FP_EXP_TAG_ZERO,
		FP_EXP_TAG_SPECIAL,
		FP_EXP_TAG_EMPTY,
	} tag;
	uint32_t ret = 0xffff0000u;
	int i;

	for (i = 0; i < 8; i++, twd >>= 1) {
		if (twd & 0x1) {
			st = fpreg_addr(fxsave, (i - tos) & 7);

			switch (st->exponent & 0x7fff) {
			case 0x7fff:
				tag = FP_EXP_TAG_SPECIAL;
				break;
			case 0x0000:
				if (!st->significand[0] &&
				    !st->significand[1] &&
				    !st->significand[2] &&
				    !st->significand[3])
					tag = FP_EXP_TAG_ZERO;
				else
					tag = FP_EXP_TAG_SPECIAL;
				break;
			default:
				if (st->significand[3] & 0x8000)
					tag = FP_EXP_TAG_VALID;
				else
					tag = FP_EXP_TAG_SPECIAL;
				break;
			}
		} else {
			tag = FP_EXP_TAG_EMPTY;
		}
		ret |= (uint32_t)tag << (2 * i);
	}
	return ret;
}

static void
convert_from_fxsr(struct user_i387_ia32_struct *env, struct task_context *target)
{
	union thread_xstate xstate;
	struct _fpreg *to;
	struct _fpxreg *from;
	int i;

	readmem(gxt->get_thread_struct_fpu(target), KVADDR, &xstate,
		sizeof(xstate), "convert_from_fxsr: xstate",
		gcore_verbose_error_handle());

	to = (struct _fpreg *) &env->st_space[0];
	from = (struct _fpxreg *) &xstate.fxsave.st_space[0];

	env->cwd = xstate.fxsave.cwd | 0xffff0000u;
	env->swd = xstate.fxsave.swd | 0xffff0000u;
	env->twd = twd_fxsr_to_i387(&xstate.fxsave);

#ifdef X86_64
	env->fip = xstate.fxsave.rip;
	env->foo = xstate.fxsave.rdp;
	if (is_task_active(target->task)) {
		error(WARNING, "cannot restore runtime fos and fcs\n");
	} else {
		char *pt_regs_buf;
		uint16_t ds;
		struct machine_specific *ms = machdep->machspec;

		pt_regs_buf = GETBUF(SIZE(pt_regs));

		readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs),
			KVADDR,	pt_regs_buf, SIZE(pt_regs),
			"convert_from_fxsr: regs",
			gcore_verbose_error_handle());

		readmem(target->task + OFFSET(task_struct_thread)
			+ GCORE_OFFSET(thread_struct_ds), KVADDR, &ds,
			sizeof(ds), "convert_from_fxsr: ds",
			gcore_verbose_error_handle());
			
		env->fos = 0xffff0000 | ds;
		env->fcs = ULONG(pt_regs_buf + ms->pto.cs);

		FREEBUF(pt_regs_buf);
	}
#endif

#ifdef X86
	env->fip = xstate.fxsave.fip;
	env->fcs = (uint16_t) xstate.fxsave.fcs | ((uint32_t) xstate.fxsave.fop << 16);
	env->foo = xstate.fxsave.foo;
	env->fos = xstate.fxsave.fos;
#endif

	for (i = 0; i < 8; ++i)
		memcpy(&to[i], &from[i], sizeof(to[0]));
}

static int fpregs_get(struct task_context *target,
		      const struct user_regset *regset,
		      unsigned int size,
		      void *buf)
{
	union thread_xstate xstate;

	init_fpu(target->task);

	if (!have_hwfp())
		return fpregs_soft_get(target, regset, size, buf);

	if (!cpu_has_fxsr()) {
		readmem(gxt->get_thread_struct_fpu(target), KVADDR, &xstate,
			sizeof(xstate),
			"fpregs_get: xstate", gcore_verbose_error_handle());
		memcpy(buf, &xstate.fsave, MIN(size, sizeof(xstate.fsave)));
		return 0;
	}

	sanitize_i387_state(target);

	convert_from_fxsr(buf, target);

        return 0;
}

static ulong gcore_x86_get_thread_struct_fpu_fpregs_state(struct task_context *tc)
{
	return tc->task +
		OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_fpu) +
		GCORE_OFFSET(fpu_state);
}

static ulong gcore_x86_get_thread_struct_fpu_thread_xstate(struct task_context *tc)
{
	ulong state;

	readmem(tc->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_fpu) + GCORE_OFFSET(fpu_state),
		KVADDR, &state, sizeof(state),
		"gcore_x86_get_thread_struct_fpu_thread_xstate: state",
		gcore_verbose_error_handle());

	return state;
}

static ulong gcore_x86_get_thread_struct_fpu_thread_xstate_size(void)
{
#ifdef X86_64
	return sizeof(struct user_i387_struct);
#else
	return sizeof(struct user_i387_ia32_struct);
#endif
}

static ulong gcore_x86_get_thread_struct_thread_xstate(struct task_context *tc)
{
	ulong xstate;

	readmem(tc->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_xstate), KVADDR, &xstate,
		sizeof(xstate),
		"gcore_x86_get_thread_struct_thread_xstate: xstate",
		gcore_verbose_error_handle());

	return xstate;
}

static ulong gcore_x86_get_thread_struct_thread_xstate_size(void)
{
	return GCORE_SIZE(thread_xstate);
}

static ulong gcore_x86_get_thread_struct_i387(struct task_context *tc)
{
	return tc->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_i387);
}

static ulong gcore_x86_get_thread_struct_i387_size(void)
{
	return GCORE_SIZE(i387_union);
}

/*
 * For an entry for REGSET_XSTATE both on x86 and x86_64, member n is
 * initiliazed dinamically at boot time.
 */
static int get_xstate_regsets_number(void)
{
	struct datatype_member datatype_member, *dm;
	ulong x86_64_regsets_xstate;
	unsigned int n;

	if (!symbol_exists("REGSET_XSTATE"))
		return 0;

	dm = &datatype_member;

	if (!arg_to_datatype("REGSET_XSTATE", dm, RETURN_ON_ERROR))
		return 0;

	x86_64_regsets_xstate = symbol_value("x86_64_regsets") +
		dm->value * STRUCT_SIZE("user_regset");

	readmem(x86_64_regsets_xstate + GCORE_OFFSET(user_regset_n),
		KVADDR, &n, sizeof(n), "fpregs_active: n", FAULT_ON_ERROR);

	return n;
}

static inline int
xstateregs_active(struct task_context *target,
		  const struct user_regset *regset)
{
	return cpu_has_xsave() && fpregs_active(target, regset)
		&& symbol_exists("xstate_fx_sw_bytes")
		&& !!get_xstate_regsets_number();
}

static int
xstateregs_get(struct task_context *target,
	       const struct user_regset *regset,
	       unsigned int size,
	       void *buf)
{
	union thread_xstate *xstate = (union thread_xstate *)buf;
	ulong xstate_fx_sw_bytes;

	readmem(target->task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_xstate), KVADDR, xstate,
		sizeof(union thread_xstate), "xstateregs_get: thread",
		gcore_verbose_error_handle());

        init_fpu(target->task);

	xstate_fx_sw_bytes = symbol_value("xstate_fx_sw_bytes");

        /*
         * Copy the 48bytes defined by the software first into the xstate
         * memory layout in the thread struct, so that we can copy the entire
         * xstateregs to the user using one user_regset_copyout().
         */
	readmem(xstate_fx_sw_bytes, KVADDR, &xstate->fxsave.sw_reserved,
		USER_XSTATE_FX_SW_WORDS * sizeof(uint64_t),
		"fill_xstate: sw_reserved", gcore_verbose_error_handle());

	return 0;
}

#ifdef X86_64
/*
 * we cannot use the same code segment descriptor for user and kernel
 * -- not even in the long flat mode, because of different DPL /kkeil
 * The segment offset needs to contain a RPL. Grr. -AK
 * GDT layout to get 64bit syscall right (sysret hardcodes gdt offsets)
 */
#define GDT_ENTRY_TLS_MIN 12
#endif

#ifdef X86
#define GDT_ENTRY_TLS_MIN 6
#endif

#define GDT_ENTRY_TLS_ENTRIES 3

/* TLS indexes for 64bit - hardcoded in arch_prctl */
#define FS_TLS 0
#define GS_TLS 1

#define GS_TLS_SEL ((GDT_ENTRY_TLS_MIN+GS_TLS)*8 + 3)
#define FS_TLS_SEL ((GDT_ENTRY_TLS_MIN+FS_TLS)*8 + 3)

/*
 * EFLAGS bits
 */
#define X86_EFLAGS_TF   0x00000100 /* Trap Flag */

#define __USER_DS 0x2b
#define __USER_CS 0x33

static inline int user_64bit_mode(struct user_regs_struct *regs)
{
	return regs->cs == __USER_CS;
}

/*
 * thread information flags
 * - these are process state flags that various assembly files
 *   may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 * Warning: layout of LSW is hardcoded in entry.S
 */
#define TIF_FORCED_TF           24      /* true if TF in eflags artificially */

struct desc_struct {
	uint16_t limit0;
	uint16_t base0;
	unsigned int base1: 8, type: 4, s: 1, dpl: 2, p: 1;
	unsigned int limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
} __attribute__((packed));

static inline ulong get_desc_base(const struct desc_struct *desc)
{
	return (ulong)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline ulong get_desc_limit(const struct desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static inline int desc_empty(const void *ptr)
{
	const uint32_t *desc = ptr;
	return !(desc[0] | desc[1]);
}

static void fill_user_desc(struct user_desc *info, int idx,
			   struct desc_struct *desc)

{
	memset(info, 0, sizeof(*info));
	info->entry_number = idx;
	info->base_addr = get_desc_base(desc);
	info->limit = get_desc_limit(desc);
	info->seg_32bit = desc->d;
	info->contents = desc->type >> 2;
	info->read_exec_only = !(desc->type & 2);
	info->limit_in_pages = desc->g;
	info->seg_not_present = !desc->p;
	info->useable = desc->avl;
#ifdef X86_64
        info->lm = desc->l;
#endif
}

static int regset_tls_active(struct task_context *target,
			     const struct user_regset *regset)
{
	int i, nr_entries;
	struct desc_struct *tls_array;

	nr_entries = GCORE_SIZE(thread_struct_tls_array) / sizeof(uint64_t);

	tls_array = (struct desc_struct *)GETBUF(GCORE_SIZE(thread_struct_tls_array));

	readmem(target->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_tls_array), KVADDR,
		tls_array, GCORE_SIZE(thread_struct_tls_array),
		"regset_tls_active: t",
		gcore_verbose_error_handle());

	for (i = 0; i < nr_entries; ++i) {
		if (!desc_empty(&tls_array[i])) {
			FREEBUF(tls_array);
			return TRUE;
		}
	}

	FREEBUF(tls_array);
	return FALSE;
}

static int regset_tls_get(struct task_context *target,
			  const struct user_regset *regset,
			  unsigned int size,
			  void *buf)
{
	struct user_desc *info = (struct user_desc *)buf;
	int i, nr_entries;
	struct desc_struct *tls_array;

	nr_entries = GCORE_SIZE(thread_struct_tls_array) / sizeof(uint64_t);

	tls_array = (struct desc_struct *)GETBUF(GCORE_SIZE(thread_struct_tls_array));

	readmem(target->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_tls_array), KVADDR,
		tls_array, GCORE_SIZE(thread_struct_tls_array),
		"regset_tls_active: tls_array",
		gcore_verbose_error_handle());

	for (i = 0; i < nr_entries; ++i) {
		fill_user_desc(&info[i], GDT_ENTRY_TLS_MIN + i, &tls_array[i]);
	}

	FREEBUF(tls_array);
	return 0;
}

#define IO_BITMAP_BITS  65536
#define IO_BITMAP_BYTES (IO_BITMAP_BITS/8)
#define IO_BITMAP_LONGS (IO_BITMAP_BYTES/sizeof(long))

static int
ioperm_active(struct task_context *target,
	      const struct user_regset *regset)
{
	ulong io_bitmap_ptr;
	unsigned int io_bitmap_max;
	ulong io_bitmap;

	if (MEMBER_EXISTS("thread_struct", "io_bitmap_max")) {
		readmem(target->task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_io_bitmap_max), KVADDR,
			&io_bitmap_max, sizeof(io_bitmap_max),
			"ioperm_active: io_bitmap_max",
			gcore_verbose_error_handle());
		readmem(target->task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_io_bitmap_ptr), KVADDR,
			&io_bitmap_ptr, sizeof(io_bitmap_ptr),
			"ioperm_get: io_bitmap_ptr",
			gcore_verbose_error_handle());
		return io_bitmap_max && io_bitmap_ptr;
	} else {
		readmem(target->task + OFFSET(task_struct_thread) +
			MEMBER_OFFSET("thread_struct", "io_bitmap"), KVADDR,
			&io_bitmap, sizeof(io_bitmap),
			"ioperm_active: io_bitmap",
			gcore_verbose_error_handle());
		if (!io_bitmap)
			return 0;
		readmem(io_bitmap + MEMBER_OFFSET("io_bitmap", "max"),
			KVADDR,
			&io_bitmap_max, sizeof(io_bitmap_max),
			"ioperm_get: io_bitmap->max",
			gcore_verbose_error_handle());
		return divideup(io_bitmap_max, regset->size);
	}
}

static int ioperm_get(struct task_context *target,
		      const struct user_regset *regset,
		      unsigned int size,
		      void *buf)
{
	ulong io_bitmap_ptr;
	ulong io_bitmap;

	if (MEMBER_EXISTS("thread_struct", "io_bitmap_max")) {
		readmem(target->task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_io_bitmap_ptr), KVADDR,
			&io_bitmap_ptr, sizeof(io_bitmap_ptr),
			"ioperm_get: io_bitmap_ptr", gcore_verbose_error_handle());
	} else {
		readmem(target->task + OFFSET(task_struct_thread) +
			MEMBER_OFFSET("thread_struct", "io_bitmap"), KVADDR,
			&io_bitmap, sizeof(io_bitmap),
			"ioperm_active: io_bitmap",
			gcore_verbose_error_handle());
		if (!io_bitmap)
			return -1;
		io_bitmap_ptr = io_bitmap + MEMBER_OFFSET("io_bitmap", "bitmap");
	}
	readmem(io_bitmap_ptr, KVADDR, buf, size, "ioperm_get: copy IO bitmap",
		gcore_verbose_error_handle());
	return 0;
}

#ifdef X86_64
#define __NR_rt_sigreturn	 15
#define __NR_clone		 56
#define __NR_fork		 57
#define __NR_vfork		 58
#define __NR_execve		 59
#define __NR_iopl		172
#define __NR_rt_sigsuspend      130
#define __NR_sigaltstack	131

static int is_special_syscall_v26(int nr_syscall)
{
	return nr_syscall == __NR_fork
		|| nr_syscall == __NR_execve
		|| nr_syscall == __NR_iopl
		|| nr_syscall == __NR_clone
		|| nr_syscall == __NR_rt_sigreturn
		|| nr_syscall == __NR_sigaltstack
		|| nr_syscall == __NR_vfork;
}

static int is_special_syscall_v0(int nr_syscall)
{
	return is_special_syscall_v26(nr_syscall)
		|| nr_syscall == __NR_rt_sigsuspend;
}

#define IA32_SYSCALL_VECTOR 0x80

#define __KERNEL_CS 0x10
#endif

//extern struct gate_struct idt_table[]; 
enum { 
	GATE_INTERRUPT = 0xE, 
	GATE_TRAP = 0xF, 
	GATE_CALL = 0xC,
}; 

#ifdef X86_64
/* 16byte gate */
struct gate_struct64 {
        uint16_t offset_low;
	uint16_t segment;
	unsigned int ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t zero1;
} __attribute__((packed));
#endif

#define PTR_LOW(x) ((unsigned long)(x) & 0xFFFF) 
#define PTR_MIDDLE(x) (((unsigned long)(x) >> 16) & 0xFFFF)
#define PTR_HIGH(x) ((unsigned long)(x) >> 32)

#ifdef X86_64
/*
 * compare gate structure data in crash kernel directly with the
 * expected data in order to check wheather IA32_EMULATION feature was
 * set or not.
 *
 * To check only wheather the space is filled with 0 or not is an
 * alternate way to acheve the same purpose, but here I don't do so.
 */
static int is_gate_set_ia32_syscall_vector(void)
{
	struct gate_struct64 gate, gate_idt;
	const ulong ia32_syscall_entry = symbol_value("ia32_syscall");

	gate.offset_low = PTR_LOW(ia32_syscall_entry);
	gate.segment = __KERNEL_CS;
	gate.ist = 0;
	gate.p = 1;
	gate.dpl = 0x3;
	gate.zero0 = 0;
	gate.zero1 = 0;
	gate.type = GATE_INTERRUPT;
	gate.offset_middle = PTR_MIDDLE(ia32_syscall_entry);
	gate.offset_high = PTR_HIGH(ia32_syscall_entry);

	readmem(symbol_value("idt_table") + 16 * IA32_SYSCALL_VECTOR, KVADDR,
		&gate_idt, sizeof(gate_idt), "is_gate_set_ia32_syscall_vector:"
		" idt_table[IA32_SYSCALL_VECTOR", gcore_verbose_error_handle());

	return !memcmp(&gate, &gate_idt, sizeof(struct gate_struct64));
}

#define IA32_SYSCALL_VECTOR          0x80

#define __NR_ia32_fork               2
#define __NR_ia32_execve             11
#define __NR_ia32_sigsuspend         72
#define __NR_ia32_iopl               110
#define __NR_ia32_sigreturn          119
#define __NR_ia32_clone              120
#define __NR_ia32_sys32_rt_sigreturn 173
#define __NR_ia32_rt_sigsuspend      179
#define __NR_ia32_sigaltstack        186
#define __NR_ia32_vfork              190

/*
 * is_special_ia32_syscall() field is initialized only when
 * IA32_SYSCALL_VECTOR(0x80) is set to used_vectors. This check is
 * made in gcore_x86_table_init().
 */
static inline int is_ia32_syscall_enabled(void)
{
	return !!gxt->is_special_ia32_syscall;
}

static int is_special_ia32_syscall_v0(int nr_syscall)
{
	return is_special_ia32_syscall_v26(nr_syscall)
		|| nr_syscall == __NR_ia32_sigsuspend
		|| nr_syscall == __NR_ia32_rt_sigsuspend;
}

static int is_special_ia32_syscall_v26(int nr_syscall)
{
	return nr_syscall == __NR_ia32_fork
		|| nr_syscall == __NR_ia32_sigreturn
		|| nr_syscall == __NR_ia32_execve
		|| nr_syscall == __NR_ia32_iopl
		|| nr_syscall == __NR_ia32_clone
		|| nr_syscall == __NR_ia32_sys32_rt_sigreturn
		|| nr_syscall == __NR_ia32_sigaltstack
		|| nr_syscall == __NR_ia32_vfork;
}
#endif /* X86_64 */

static int tsk_used_math_v0(ulong task)
{
	unsigned short used_math;

	readmem(task + GCORE_OFFSET(task_struct_used_math), KVADDR,
		&used_math, sizeof(used_math), "tsk_used_math_v0: used_math",
		gcore_verbose_error_handle());

	return !!used_math;
}

static int tsk_used_math_v11(ulong task)
{
	unsigned long flags;

	readmem(task + OFFSET(task_struct_flags), KVADDR, &flags,
		sizeof(flags), "tsk_used_math_v11: flags",
		gcore_verbose_error_handle());

	return !!(flags & PF_USED_MATH);
}

static int tsk_used_math_v4_14(ulong task)
{
	unsigned char initialized;

	if (!cpu_has_fxsr())
		return 0;

	readmem(task +
		OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_fpu) +
		MEMBER_OFFSET("fpu", "initialized"),
		KVADDR,
		&initialized,
		sizeof(initialized),
		"tsk_used_math_v4_14: initialized",
		gcore_verbose_error_handle());

	return !!initialized;
}

static inline int
user_mode(const struct user_regs_struct *regs)
{
	return !!(regs->cs & 0x3);
}

#ifdef X86_64
static int
test_tsk_thread_flag(ulong task, int bit)
{
	uint32_t flags;
	ulong thread_info;

	thread_info = task_to_thread_info(task);

	readmem(thread_info + OFFSET(thread_info_flags), KVADDR, &flags,
		sizeof(flags), "test_tsk_thread_flag: flags",
		gcore_verbose_error_handle());

	return !!((1UL << bit) & flags);
}

static void
restore_segment_registers(ulong task, struct user_regs_struct *regs)
{
	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_fs), KVADDR, &regs->fs_base,
		GCORE_SIZE(thread_struct_fs),
		"restore_segment_registers: fs", gcore_verbose_error_handle());

	if (!regs->fs_base) {

		readmem(task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_fsindex), KVADDR,
			&regs->fs_base, GCORE_SIZE(thread_struct_fsindex),
			"restore_segment_registers: fsindex",
			gcore_verbose_error_handle());

		if (regs->fs_base != FS_TLS_SEL)
			regs->fs_base = 0;
		else {
			struct desc_struct desc;

			readmem(task + OFFSET(task_struct_thread) +
				FS_TLS * SIZE(desc_struct), KVADDR, &desc,
				sizeof(desc),
				"restore_segment_registers: desc",
				gcore_verbose_error_handle());

			regs->fs_base = get_desc_base(&desc);
		}
	}

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_gsindex), KVADDR, &regs->gs_base,
		GCORE_SIZE(thread_struct_gsindex),
		"restore_segment_registers: gsindex", gcore_verbose_error_handle());

	if (!regs->gs_base) {

		readmem(task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_gs), KVADDR,	&regs->gs_base,
			GCORE_SIZE(thread_struct_gs),
			"restore_segment_registers: gs", gcore_verbose_error_handle());

		if (regs->gs_base != GS_TLS_SEL)
			regs->gs_base = 0;
		else {
			struct desc_struct desc;

			readmem(task + OFFSET(task_struct_thread) +
				GS_TLS * SIZE(desc_struct), KVADDR, &desc,
				sizeof(desc),
				"restore_segment_registers: desc",
				gcore_verbose_error_handle());

			regs->gs_base = get_desc_base(&desc);
		}
	}

	if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		regs->flags &= ~X86_EFLAGS_TF;

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_fsindex), KVADDR, &regs->fs,
		GCORE_SIZE(thread_struct_fsindex),
		"restore_segment_registers: fsindex",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_gsindex), KVADDR, &regs->gs,
		GCORE_SIZE(thread_struct_gsindex),
		"restore_segment_registers: gsindex",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_ds), KVADDR, &regs->ds,
		GCORE_SIZE(thread_struct_ds),
		"restore_segment_registers: ds",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_es), KVADDR, &regs->es,
		GCORE_SIZE(thread_struct_es),
		"restore_segment_registers: es",
		gcore_verbose_error_handle());

	regs->flags &= 0xffff;
	regs->fs_base &= 0xffff;
	regs->gs_base &= 0xffff;
	regs->ds &= 0xffff;
	regs->es &= 0xffff;
	regs->fs &= 0xffff;
	regs->gs &= 0xffff;

}

/**
 * restore_frame_pointer - restore user-mode frame pointer
 *
 * @task interesting task
 *
 * If the kernel is built with CONFIG_FRAME_POINTER=y, we can find a
 * user-mode frame pointer by tracing frame pointers from the one
 * saved at scheduler. The reasons why this is possible include the
 * fact that entry_64.S doesn't touch any callee-saved registers
 * including frame pointer, rbp.
 *
 * On the other hand, if the kernel is not built with
 * CONFIG_FRAME_POINTER=y, we need to depend on CFA information
 * provided by kernel debugging information.
 */
static ulong restore_frame_pointer(ulong task)
{
	ulong rsp, rbp, prev_rbp, stacktop, stackbase;

	/*
	 * rsp is saved in task->thread.sp during switch_to().
	 */
	readmem(task + OFFSET(task_struct_thread) +
		OFFSET(thread_struct_rsp), KVADDR, &rsp, sizeof(rsp),
		"restore_frame_pointer: rsp", gcore_verbose_error_handle());

	/*
	 * rbp is saved at the point referred to by rsp
	 */
	readmem(rsp, KVADDR, &rbp, sizeof(rbp), "restore_frame_pointer: rbp",
		gcore_verbose_error_handle());

	/*
	 * resume to the last rbp in user-mode.
	 *
	 * rbp in user-mode can have arbitrary value, so we need to
	 * check whether rbp points onto the kernel stack or not.
	 *
	 * To make this operation always terminate, we check if rbp
	 * value is strictly increasing (on x86_64, kernel stack grows
	 * in the decreasing direction), which is sufficient for
	 * termination property since the kernel stack size is finite.
	 *
	 * NOTE: This operation doesn't support tasks carrying in rbp
	 * the values except for any user-mode address.
	 *
	 * The reason is that if rbp in user-mode is accidentally
	 * equal to one of the remaining addresses in the kernel
	 * stack, we cannot distinguish it from the rbp actually
	 * pointing onto the kernel stack.
	 *
	 * It consequently takes, as rbp's, the value of another
	 * register referred to by the address.
	 */
	stackbase = machdep->get_stackbase(task);
	stacktop = machdep->get_stacktop(task);

	prev_rbp = 0;

	while (prev_rbp < rbp && rbp < stacktop && rbp >= stackbase) {
		prev_rbp = rbp;
		readmem(rbp, KVADDR, &rbp, sizeof(rbp),
			"restore_frame_pointer: resume rbp",
			gcore_verbose_error_handle());
	}

	return rbp;
}

/*
 * We should avoid using pt_regs directly since it depends on kernel
 * versions, and should also handle here using offsets prepared by
 * crash utility. But unwind() is currently implemented using pt_regs
 * and it's still under investigation on how to replace them by offset
 * handling. So, we're in the meanwhile forced to use unwind() without
 * any change.
 */

struct gcore_x86_64_pt_regs {
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        unsigned long r12;
        unsigned long rbp;
        unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
        unsigned long r11;
        unsigned long r10;
        unsigned long r9;
        unsigned long r8;
        unsigned long rax;
        unsigned long rcx;
        unsigned long rdx;
        unsigned long rsi;
        unsigned long rdi;
        unsigned long orig_rax;
/* end of arguments */
/* cpu exception frame or undefined */
        unsigned long rip;
        unsigned long cs;
        unsigned long eflags;
        unsigned long rsp;
        unsigned long ss;
/* top of stack page */
};

struct unwind_frame_info
{
	struct gcore_x86_64_pt_regs regs;
};

extern int unwind(struct unwind_frame_info *frame, int is_ehframe);

/**
 * restore_rest() - restore user-mode callee-saved registers
 *
 * @task interesting task object
 * @regs buffer into which register values are placed
 * @active_regs active register values
 *
 * SAVE_ARGS() doesn't save callee-saved registers: rbx, r12, r13, r14
 * and r15 because they are automatically saved at kernel stack frame
 * that is made by the first C function call from entry_64.S.
 *
 * To retrieve these values correctly, it is necessary to use CFA,
 * Cannonical Frame Address, which is specified as part of Dwarf, in
 * order to calculate accurate offsets to where individual register is
 * saved.
 *
 * @active_regs is a starting point of backtracing for active tasks.
 *
 * There are two kinds of sections for CFA to be placed in ELF's
 * debugging inforamtion sections: .eh_frame and .debug_frame. The
 * point is that two sections have differnet layout. Look carefully at
 * is_ehframe.
 */
static inline void restore_rest(ulong task, struct user_regs_struct *regs,
				const struct user_regs_struct *active_regs)
{
	struct unwind_frame_info frame;
	int first_frame;
	const int is_ehframe = (!st->dwarf_debug_frame_size && st->dwarf_eh_frame_size);

	/*
	 * For active processes, all values at crash are available, so
	 * we pass them to unwinder as an initial frame value.
	 *
	 * For suspended processes when panic occurs, only ip, sp and
	 * bp values will be passed to unwind(), this seems enough for
	 * backtracing currently.
	 */
	if (is_task_active(task)) {
		memcpy(&frame.regs, active_regs, sizeof(frame.regs));
	} else {
		unsigned long rsp, rbp;

		memset(&frame, 0, sizeof(frame));

		readmem(task + OFFSET(task_struct_thread) +
			OFFSET(thread_struct_rsp), KVADDR, &rsp, sizeof(rsp),
			"restore_rest: rsp",
			gcore_verbose_error_handle());
		readmem(rsp, KVADDR, &rbp, sizeof(rbp), "restore_rest: rbp",
			gcore_verbose_error_handle());

		frame.regs.rip = machdep->machspec->thread_return;
		frame.regs.rsp = rsp;
		frame.regs.rbp = rbp;
	}

	/*
	 * Unwind to the first stack frame in kernel.
	 *
	 * Object files built with recent tools contain Dwarf CFI
	 * version 3 or later, and dwarf unwinder in crash utility
	 * supports version 1 only; doesn't version 3 and later. It's
	 * under investigation.
	 *
	 */
	first_frame = FALSE;

	while (!unwind(&frame, is_ehframe))
		first_frame = TRUE;

	if (first_frame) {
		regs->r12 = frame.regs.r12;
		regs->r13 = frame.regs.r13;
		regs->r14 = frame.regs.r14;
		regs->r15 = frame.regs.r15;
		regs->bp = frame.regs.rbp;
		regs->bx = frame.regs.rbx;
	}

	/*
	 * If kernel was configured with CONFIG_FRAME_POINTER, we
	 * could trace the value of bp until its value became a
	 * user-space address. See comments of restore_frame_pointer.
	 */
	else if ((machdep->flags & FRAMEPOINTER) && !is_task_active(task)) {
		regs->bp = restore_frame_pointer(task);
	}
}

/**
 * gcore_x86_64_get_old_rsp_zero() - get rsp at per-cpu area
 *
 * @cpu target CPU's CPU id
 *
 * Given a CPU id, returns a RSP value saved at per-cpu area for the
 * CPU whose id is the given CPU id.
 *
 * This is a method of get_old_rsp() returning always 0 for when no
 * appropriate method is found.
 */
static ulong gcore_x86_64_get_old_rsp_zero(int cpu)
{
	error(WARNING, "failed to detect location of sp register, forcing 0.\n");
	return 0UL;
}

/**
 * gcore_x86_64_get_old_rsp() - get rsp at per-cpu area
 *
 * @cpu target CPU's CPU id
 *
 * Given a CPU id, returns a RSP value saved at per-cpu area for the
 * CPU whose id is the given CPU id.
 */
static ulong gcore_x86_64_get_old_rsp(int cpu)
{
	ulong old_rsp;

	readmem(symbol_value("old_rsp") + kt->__per_cpu_offset[cpu],
		KVADDR,	&old_rsp, sizeof(old_rsp),
		"gcore_x86_64_get_old_rsp: old_rsp",
		gcore_verbose_error_handle());

	return old_rsp;
}

/**
 * gcore_x86_64_get_per_cpu__old_rsp() - get rsp at per-cpu area
 *
 * @cpu target CPU's CPU id
 *
 * Given a CPU id, returns a RSP value saved at per-cpu area for the
 * CPU whose id is the given CPU id.
 */
static ulong gcore_x86_64_get_per_cpu__old_rsp(int cpu)
{
	ulong per_cpu__old_rsp;

	readmem(symbol_value("per_cpu__old_rsp") + kt->__per_cpu_offset[cpu],
		KVADDR,	&per_cpu__old_rsp, sizeof(per_cpu__old_rsp),
		"gcore_x86_64_get_per_cpu__old_rsp: per_cpu__old_rsp",
		gcore_verbose_error_handle());

	return per_cpu__old_rsp;
}

/**
 * gcore_x86_64_get_cpu_pda_oldrsp() - get rsp at per-cpu area
 *
 * @cpu target CPU's CPU id
 *
 * Given a CPU id, returns a RSP value saved at per-cpu area for the
 * CPU whose id is the given CPU id.
 */
static ulong gcore_x86_64_get_cpu_pda_oldrsp(int cpu)
{
	ulong oldrsp;
	char *cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	readmem(symbol_value("cpu_pda") + sizeof(ulong) * SIZE(x8664_pda),
		KVADDR, cpu_pda_buf, SIZE(x8664_pda),
		"gcore_x86_64_get_cpu_pda_oldrsp: cpu_pda_buf",
		gcore_verbose_error_handle());

	oldrsp = ULONG(cpu_pda_buf + GCORE_OFFSET(x8664_pda_oldrsp));

	FREEBUF(cpu_pda_buf);
	return oldrsp;
}

/**
 * gcore_x86_64_get_cpu__pda_oldrsp() - get rsp at per-cpu area
 *
 * @cpu target CPU's CPU id
 *
 * Given a CPU id, returns a RSP value saved at per-cpu area for the
 * CPU whose id is the given CPU id.
 */
static ulong gcore_x86_64_get_cpu__pda_oldrsp(int cpu)
{
	ulong oldrsp, x8664_pda, _cpu_pda;

	_cpu_pda = symbol_value("_cpu_pda");

	readmem(_cpu_pda + sizeof(ulong) * cpu, KVADDR, &x8664_pda,
		sizeof(x8664_pda),
		"gcore_x86_64_get__cpu_pda_oldrsp: _cpu_pda",
		gcore_verbose_error_handle());

	readmem(x8664_pda + GCORE_OFFSET(x8664_pda_oldrsp), KVADDR,
		&oldrsp, sizeof(oldrsp),
		"gcore_x86_64_get_cpu_pda_oldrsp: oldrsp",
		gcore_verbose_error_handle());

	return oldrsp;
}

static ulong gcore_x86_64_user_stack_pointer_userrsp(struct task_context *tc)
{
	ulong usersp;

	/*
	 * rsp is saved in per-CPU old_rsp, which is saved in
	 * thread->usersp at each context switch.
	 */
	if (is_task_active(tc->task))
		return gxt->get_old_rsp(tc->processor);

	readmem(tc->task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_usersp), KVADDR, &usersp,
		sizeof(usersp),
		"gcore_x86_64_user_stack_pointer_userrsp: usersp",
		gcore_verbose_error_handle());

	return usersp;
}

static ulong gcore_x86_64_user_stack_pointer_pt_regs(struct task_context *tc)
{
	char *pt_regs_buf;
	ulong sp0, sp;
	struct machine_specific *ms = machdep->machspec;

	pt_regs_buf = GETBUF(SIZE(pt_regs));

	readmem(tc->task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_sp0), KVADDR, &sp0,
		sizeof(sp0),
		"gcore_x86_64_user_stack_pointer_pt_regs: sp0",
		gcore_verbose_error_handle());

	readmem(sp0 - SIZE(pt_regs), KVADDR, pt_regs_buf, SIZE(pt_regs),
		"gcore_x86_64_user_stack_pointer_pt_regs: pt_regs",
		gcore_verbose_error_handle());

	sp = ULONG(pt_regs_buf + ms->pto.rsp);

	FREEBUF(pt_regs_buf);
	return sp;
}

static int
gcore_find_regs_from_bt_output(FILE *output, char *buf, size_t bufsize)
{
	while (fgets(buf, bufsize, output))
		if (strncmp(buf, "    RIP:", 8) == 0)
			return TRUE;

	return FALSE;
}

static int
gcore_get_regs_from_bt_output(FILE *output, struct user_regs_struct *regs)
{
	char buf[BUFSIZE];
	int items __attribute__ ((__unused__));

	if (gcore_find_regs_from_bt_output(output, buf, BUFSIZE) == FALSE)
		return FALSE;

	items = sscanf(buf, "    RIP: %016lx  RSP: %016lx  RFLAGS: %08lx\n",
	       &regs->ip, &regs->sp, &regs->flags);
	items = fscanf(output, "    RAX: %016lx  RBX: %016lx  RCX: %016lx\n",
	       &regs->ax, &regs->bx, &regs->cx);
	items = fscanf(output, "    RDX: %016lx  RSI: %016lx  RDI: %016lx\n",
	       &regs->dx, &regs->si, &regs->di);
	items = fscanf(output, "    RBP: %016lx   R8: %016lx   R9: %016lx\n",
	       &regs->bp, &regs->r8, &regs->r9);
	items = fscanf(output, "    R10: %016lx  R11: %016lx  R12: %016lx\n",
	       &regs->r10, &regs->r11, &regs->r12);
	items = fscanf(output, "    R13: %016lx  R14: %016lx  R15: %016lx\n",
	       &regs->r13, &regs->r14, &regs->r15);
	items = fscanf(output, "    ORIG_RAX: %016lx  CS: %04lx  SS: %04lx\n",
	       &regs->orig_ax, &regs->cs, &regs->ss);

	return TRUE;
}

static int
gcore_get_regs_from_eframe(struct task_context *tc,
			   struct user_regs_struct *regs)
{
	int ret;
	struct bt_info bt;

	BZERO(&bt, sizeof(struct bt_info));
	bt.stackbuf = NULL;
	bt.tc = tc;
	bt.task = tc->task;
	bt.stackbase = GET_STACKBASE(tc->task);
	bt.stacktop = GET_STACKTOP(tc->task);

	open_tmpfile();
	back_trace(&bt);
	rewind(pc->tmpfile);
	ret = gcore_get_regs_from_bt_output(pc->tmpfile, regs);
	close_tmpfile();

	return ret;
}

static void
get_regs_from_kvmdump_notes(struct task_context *target,
			    struct user_regs_struct *regs)
{
	struct kvm_register_set krs;

	BZERO(&krs, sizeof(krs));

	if (!get_kvm_register_set(target->processor, &krs))
		return;

	regs->cs = krs.x86.cs;
	regs->ss = krs.x86.ss;
	regs->ds = krs.x86.ds;
	regs->es = krs.x86.es;
	regs->fs = krs.x86.fs;
	regs->gs = krs.x86.gs;
	regs->ip = krs.x86.ip;
	regs->flags = krs.x86.flags;
	regs->ax = krs.x86.regs[0];
	regs->cx = krs.x86.regs[1];
	regs->dx = krs.x86.regs[2];
	regs->bx = krs.x86.regs[3];
	regs->sp = krs.x86.regs[4];
	regs->bp = krs.x86.regs[5];
	regs->si = krs.x86.regs[6];
	regs->di = krs.x86.regs[7];
	regs->r8 = krs.x86.regs[8];
	regs->r9 = krs.x86.regs[9];
	regs->r10 = krs.x86.regs[10];
	regs->r11 = krs.x86.regs[11];
	regs->r12 = krs.x86.regs[12];
	regs->r13 = krs.x86.regs[13];
	regs->r14 = krs.x86.regs[14];
	regs->r15 = krs.x86.regs[15];
}

static int get_active_regs(struct task_context *target,
			   struct user_regs_struct *regs)
{
	if (KVMDUMP_DUMPFILE()) {
		get_regs_from_kvmdump_notes(target, regs);
		return TRUE;
	}

	if ((NETDUMP_DUMPFILE() || KDUMP_DUMPFILE()) &&
	    exist_regs_in_elf_notes((void *)target)) {
		struct user_regs_struct *note =	get_regs_from_elf_notes(target);
		memcpy(regs, note, sizeof(struct user_regs_struct));
		return TRUE;
	}

	if (gcore_get_regs_from_eframe(target, regs)) {
		/*
		 * EFRAME contains CS and SS only. Here collects the
		 * remaining part of segment registers.
		 */
		restore_segment_registers(target->task, regs);
		return TRUE;
	}

	return FALSE;
}

enum gcore_kernel_entry
{
	GCORE_KERNEL_ENTRY_UNKNOWN = 0,
	GCORE_KERNEL_ENTRY_INVALID_VECTOR,
	GCORE_KERNEL_ENTRY_NMI_EXCEPTION,
	GCORE_KERNEL_ENTRY_INTEL_RESERVED,
	GCORE_KERNEL_ENTRY_IRQ,
	GCORE_KERNEL_ENTRY_SYSCALL,
	GCORE_KERNEL_ENTRY_SYSENTER32,
	GCORE_KERNEL_ENTRY_SYSCALL32,
	GCORE_KERNEL_ENTRY_INT80,
	GCORE_KERNEL_ENTRY_IA32_UNKNOWN
};

enum {
	GCORE_SYSCALL_OPCODE_BYTES = 2
};

static const unsigned char GCORE_OPCODE_SYSCALL[] = {0x0f, 0x05};
static const unsigned char GCORE_OPCODE_SYSENTER[] = {0x0f, 0x34};
static const unsigned char GCORE_OPCODE_INT80[] = {0xcd, 0x80};

/**
 * check how @target entered kernel-mode.
 * @target target task context object
 * @regs pt_regs structure at the bottom of @target's kernel stack
 */
static enum gcore_kernel_entry
check_kernel_entry(struct task_context *target, struct user_regs_struct *regs)
{
	/*
	 * regs->orig_ax contains either a signal number or an IRQ
	 * number: if >=0, it's a signal number; if <0, it's an IRQ
	 * number.
	 */
	if ((int)regs->orig_ax >= 0) {
		unsigned char opcode[GCORE_SYSCALL_OPCODE_BYTES];

		if (user_64bit_mode(regs))
			return GCORE_KERNEL_ENTRY_SYSCALL;

		gcore_readmem_user(regs->ip - sizeof(opcode),
				   opcode,
				   sizeof(opcode),
				   "check_context: opcode");

		if (memcmp(opcode, GCORE_OPCODE_SYSCALL, sizeof(opcode)) == 0)
			return GCORE_KERNEL_ENTRY_SYSCALL32;

		if (memcmp(opcode, GCORE_OPCODE_INT80, sizeof(opcode)) == 0)
			return GCORE_KERNEL_ENTRY_INT80;

		gcore_readmem_user(regs->ip
				   - 2 /* jmp enter_kernel or int 0x80 */
				   - 7 /* nop alignment bytes */
				   - sizeof(opcode), /* sysenter */
				   opcode,
				   sizeof(opcode),
				   "check_context: opcode 2");

		if (memcmp(opcode, GCORE_OPCODE_SYSENTER, sizeof(opcode)) == 0)
			return GCORE_KERNEL_ENTRY_SYSENTER32;

		return GCORE_KERNEL_ENTRY_IA32_UNKNOWN;

	} else {
		const int vector = (int)~regs->orig_ax;

		if (vector < 0 || vector > 255)
			return GCORE_KERNEL_ENTRY_INVALID_VECTOR;

		if (vector < 20)
			return GCORE_KERNEL_ENTRY_NMI_EXCEPTION;

		if (vector < 32)
			return GCORE_KERNEL_ENTRY_INTEL_RESERVED;

		if (vector < 256)
			return GCORE_KERNEL_ENTRY_IRQ;

	}

	return GCORE_KERNEL_ENTRY_UNKNOWN;
}

/**
 * Restore registers saved in system_call entry.
 * @target target task context object
 * @regs pt_regs structure at the bottom of @target's kernel stack
 * @active_regs active registers; used if @target is active
 */
static void
restore_regs_syscall_context(struct task_context *target,
			     struct user_regs_struct *regs,
			     struct user_regs_struct *active_regs)
{
	const int nr_syscall = (int)regs->orig_ax;

	if (gxt->user_stack_pointer)
		regs->sp = gxt->user_stack_pointer(target);

	/*
	 * entire registers are saved for special system calls.
	 */
	if (!gxt->is_special_syscall(nr_syscall))
		restore_rest(target->task, regs, active_regs);

	/*
	 * See FIXUP_TOP_OF_STACK in arch/x86/kernel/entry_64.S.
	 */
	regs->ss = __USER_DS;
	regs->cs = __USER_CS;
	regs->cx = (ulong)-1;
	regs->flags = regs->r11;

	restore_segment_registers(target->task, regs);
}

static void
restore_regs_ia32_syscall_common(struct task_context *target,
				 struct user_regs_struct *regs,
				 struct user_regs_struct *active_regs)
{
	const int nr_syscall = (int)regs->orig_ax;

	if (!gxt->is_special_ia32_syscall(nr_syscall))
		restore_rest(target->task, regs, active_regs);

	restore_segment_registers(target->task, regs);
}

static void
restore_regs_sysenter32_context(struct task_context *target,
				struct user_regs_struct *regs,
				struct user_regs_struct *active_regs)
{
	restore_regs_ia32_syscall_common(target, regs, active_regs);

	/*
	 * clear IF (bit 9): Interrupt enable flag
	 */
	regs->flags &= ~0x200;
}

static void
restore_regs_syscall32_context(struct task_context *target,
			       struct user_regs_struct *regs,
			       struct user_regs_struct *active_regs)
{
	restore_regs_ia32_syscall_common(target, regs, active_regs);
}

static int genregs_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	char *pt_regs_buf;
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;
	struct user_regs_struct active_regs;
	const int active = is_task_active(target->task);
	struct machine_specific *ms = machdep->machspec;

	BZERO(regs, sizeof(*regs));

	if (active && get_active_regs(target, &active_regs)) {
		if (user_mode(&active_regs)) {
			memcpy(regs, &active_regs, sizeof(*regs));
			return 0;
		}
	}

	/*
	 * SAVE_ARGS() and SAVE_ALL() macros save user-mode register
	 * values at kernel stack top when entering kernel-mode at
	 * interrupt.
	 */
	pt_regs_buf = GETBUF(SIZE(pt_regs));

	readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs), KVADDR,
		pt_regs_buf, SIZE(pt_regs), "genregs_get: pt_regs",
		gcore_verbose_error_handle());

	regs->ip = ULONG(pt_regs_buf + ms->pto.rip);
	regs->sp = ULONG(pt_regs_buf + ms->pto.rsp);
	regs->cs = ULONG(pt_regs_buf + ms->pto.cs);
	regs->ss = ULONG(pt_regs_buf + ms->pto.ss);
	regs->flags = ULONG(pt_regs_buf + ms->pto.eflags);
	regs->orig_ax = ULONG(pt_regs_buf + ms->pto.orig_rax);
	regs->bp = ULONG(pt_regs_buf + ms->pto.rbp);
	regs->ax = ULONG(pt_regs_buf + ms->pto.rax);
	regs->bx = ULONG(pt_regs_buf + ms->pto.rbx);
	regs->cx = ULONG(pt_regs_buf + ms->pto.rcx);
	regs->dx = ULONG(pt_regs_buf + ms->pto.rdx);
	regs->si = ULONG(pt_regs_buf + ms->pto.rsi);
	regs->di = ULONG(pt_regs_buf + ms->pto.rdi);
	regs->r8 = ULONG(pt_regs_buf + ms->pto.r8);
	regs->r9 = ULONG(pt_regs_buf + ms->pto.r9);
	regs->r10 = ULONG(pt_regs_buf + ms->pto.r10);
	regs->r11 = ULONG(pt_regs_buf + ms->pto.r11);
	regs->r12 = ULONG(pt_regs_buf + ms->pto.r12);
	regs->r13 = ULONG(pt_regs_buf + ms->pto.r13);
	regs->r14 = ULONG(pt_regs_buf + ms->pto.r14);
	regs->r15 = ULONG(pt_regs_buf + ms->pto.r15);

	FREEBUF(pt_regs_buf);

	switch (check_kernel_entry(target, regs)) {
	case GCORE_KERNEL_ENTRY_UNKNOWN:
		error(WARNING, "unknown kernel entry.\n");
		break;
	case GCORE_KERNEL_ENTRY_INVALID_VECTOR: {
		const int vector = (int)regs->orig_ax;
		error(WARNING, "unexpected IRQ number: %d.\n", vector);
		break;
	}
	case GCORE_KERNEL_ENTRY_INTEL_RESERVED: {
		const int vector = (int)regs->orig_ax;
		error(WARNING, "IRQ number %d is reserved by Intel\n", vector);
	}
		break;
	case GCORE_KERNEL_ENTRY_NMI_EXCEPTION:
		restore_segment_registers(target->task, regs);
		break;
	case GCORE_KERNEL_ENTRY_IA32_UNKNOWN:
		error(WARNING,
		      "system call instruction used could not be found\n");
	case GCORE_KERNEL_ENTRY_IRQ:
	case GCORE_KERNEL_ENTRY_INT80:
		/*
		 * The commit ff467594f2a4be01a0fa5e9ffc223fa930d232dd
		 * in the linux kernel begins saving all registers
		 * including callee-saved registers on the bottom of
		 * the kernel stack even on the IRQ entry. I'm very
		 * happy.
		 */
		if (THIS_KERNEL_VERSION < LINUX(4,2,0))
			restore_rest(target->task, regs, &active_regs);
		restore_rest(target->task, regs, &active_regs);
		restore_segment_registers(target->task, regs);
		break;
	case GCORE_KERNEL_ENTRY_SYSCALL:
		restore_regs_syscall_context(target, regs, &active_regs);
		break;
	case GCORE_KERNEL_ENTRY_SYSENTER32:
		restore_regs_sysenter32_context(target, regs, &active_regs);
		break;
	case GCORE_KERNEL_ENTRY_SYSCALL32:
		restore_regs_syscall32_context(target, regs, &active_regs);
		break;
	}

	return 0;
}
#endif /* X86_64 */

#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static inline int test_bit(unsigned int nr, const ulong addr)
{
	ulong nth_entry;

	readmem(addr + (nr / 64) * sizeof(ulong), KVADDR, &nth_entry,
		sizeof(nth_entry), "test_bit: nth_entry", gcore_verbose_error_handle());

	return !!((1UL << (nr % 64)) & nth_entry);
}

#ifdef X86_64
static void gcore_x86_table_register_get_old_rsp(void)
{
	if (symbol_exists("old_rsp"))
		gxt->get_old_rsp = gcore_x86_64_get_old_rsp;

	else if (symbol_exists("per_cpu__old_rsp"))
		gxt->get_old_rsp = gcore_x86_64_get_per_cpu__old_rsp;

	else if (symbol_exists("cpu_pda"))
		gxt->get_old_rsp = gcore_x86_64_get_cpu_pda_oldrsp;

	else if (symbol_exists("_cpu_pda"))
		gxt->get_old_rsp = gcore_x86_64_get_cpu__pda_oldrsp;

	else
		gxt->get_old_rsp = gcore_x86_64_get_old_rsp_zero;
}

static void gcore_x86_table_register_user_stack_pointer(void)
{
	if (MEMBER_EXISTS("thread_struct", "usersp") ||
	    MEMBER_EXISTS("thread_struct", "userrsp"))
		gxt->user_stack_pointer = gcore_x86_64_user_stack_pointer_userrsp;

	else if (MEMBER_EXISTS("thread_struct", "sp0"))
		gxt->user_stack_pointer = gcore_x86_64_user_stack_pointer_pt_regs;
}
#endif

static void gcore_x86_table_register_get_thread_struct_fpu(void)
{
	if (MEMBER_EXISTS("thread_struct", "fpu")) {
		if (MEMBER_OFFSET("fpu", "state") == 8)
			gxt->get_thread_struct_fpu =
				gcore_x86_get_thread_struct_fpu_thread_xstate;
		else
			gxt->get_thread_struct_fpu =
				gcore_x86_get_thread_struct_fpu_fpregs_state;
		gxt->get_thread_struct_fpu_size =
			gcore_x86_get_thread_struct_fpu_thread_xstate_size;
	} else if (MEMBER_EXISTS("thread_struct", "xstate")) {
		gxt->get_thread_struct_fpu =
			gcore_x86_get_thread_struct_thread_xstate;
		gxt->get_thread_struct_fpu_size =
			gcore_x86_get_thread_struct_thread_xstate_size;
	} else if (MEMBER_EXISTS("thread_struct", "i387")) {
		gxt->get_thread_struct_fpu =
			gcore_x86_get_thread_struct_i387;
		gxt->get_thread_struct_fpu_size =
			gcore_x86_get_thread_struct_i387_size;
	}
}

#ifdef X86_64
/*
 * Some special system calls got not special at v2.6.26.
 *
 * commit 5f0120b5786f5dbe097a946a2eb5d745ebc2b7ed
 */
static void gcore_x86_table_register_is_special_syscall(void)
{
	if (symbol_exists("stub_rt_sigsuspend"))
		gxt->is_special_syscall = is_special_syscall_v0;
	else
		gxt->is_special_syscall = is_special_syscall_v26;
}

/*
 * Some special system calls got not special at v2.6.26.
 *
 * commit 5f0120b5786f5dbe097a946a2eb5d745ebc2b7ed
 */
static void gcore_x86_table_register_is_special_ia32_syscall(void)
{
	if (symbol_exists("ia32_syscall") &&
	    ((symbol_exists("used_vectors") &&
	      test_bit(IA32_SYSCALL_VECTOR, symbol_value("used_vectors"))) ||
	     is_gate_set_ia32_syscall_vector())) {
		if (symbol_exists("stub32_rt_sigsuspend"))
			gxt->is_special_ia32_syscall =
				is_special_ia32_syscall_v0;
		else
			gxt->is_special_ia32_syscall =
				is_special_ia32_syscall_v26;
	}
}
#endif

/*
 * used_math member of task_struct structure was removed. Instead,
 * PF_USED_MATH was introduced and has been used now.
 *
 * Between 2.6.10 and 2.6.11.
 */
static void gcore_x86_table_register_tsk_used_math(void)
{
	if (MEMBER_EXISTS("fpu", "initialized"))
		gxt->tsk_used_math = tsk_used_math_v4_14;
	else if (GCORE_VALID_MEMBER(task_struct_used_math))
		gxt->tsk_used_math = tsk_used_math_v0;
	else
		gxt->tsk_used_math = tsk_used_math_v11;

}

#ifdef X86_64
void gcore_x86_table_init(void)
{
	gcore_x86_table_register_get_old_rsp();
	gcore_x86_table_register_user_stack_pointer();
	gcore_x86_table_register_get_thread_struct_fpu();
	gcore_x86_table_register_is_special_syscall();
	gcore_x86_table_register_is_special_ia32_syscall();
	gcore_x86_table_register_tsk_used_math();
}

static struct user_regset x86_64_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.size = sizeof(struct user_regs_struct),
		.get = genregs_get
	},
	[REGSET_FP] = {
		.core_note_type = NT_FPREGSET,
		.name = "CORE",
		.size = sizeof(struct user_i387_struct),
		.active = xfpregs_active,
		.get = xfpregs_get,
	},
	[REGSET_XSTATE] = {
		.name = "CORE",
		.size = sizeof(uint64_t),
		.active = xstateregs_active,
		.get = xstateregs_get,
	},
	[REGSET_IOPERM64] = {
		.core_note_type = NT_386_IOPERM,
		.name = "CORE",
		.size = IO_BITMAP_LONGS * sizeof(long),
		.active = ioperm_active,
		.get = ioperm_get
	},
};

static const struct user_regset_view x86_64_regset_view = {
	.name = "x86_64",
	.regsets = x86_64_regsets,
	.n = ARRAY_SIZE(x86_64_regsets),
	.e_machine = EM_X86_64,
};

/*
 * The number of registers for REGSET_XSTATE entry is specified
 * dynamically. So, we need to look at it directly.
 */
static void gcore_x86_64_regset_xstate_init(void)
{
	struct user_regset *regset_xstate = &x86_64_regsets[REGSET_XSTATE];

	regset_xstate->size = sizeof(uint64_t) * get_xstate_regsets_number();
}

void gcore_x86_64_regsets_init(void)
{
	gcore_x86_64_regset_xstate_init();

	x86_64_exception_frame(EFRAME_INIT, 0, NULL, NULL, NULL);
}

static int genregs_get32(struct task_context *target,
			 const struct user_regset *regset,
			 unsigned int size, void *buf)
{
	struct user_regs_struct32 *r32 = buf;
	struct user_regset *x86_64_gen = &x86_64_regsets[REGSET_GENERAL];
	struct user_regs_struct r64;

	if (x86_64_gen->get(target, x86_64_gen, sizeof(r64), &r64))
		return 1;

	BZERO(r32, sizeof(*r32));

	r32->ebx = r64.bx;
	r32->ecx = r64.cx;
	r32->edx = r64.dx;
	r32->esi = r64.si;
	r32->edi = r64.di;
	r32->ebp = r64.bp;
	r32->eax = r64.ax;
	r32->ds = r64.ds;
	r32->es = r64.es;
	r32->fs = r64.fs;
	r32->gs = r64.gs;
	r32->orig_eax = r64.orig_ax;
	r32->eip = r64.ip;
	r32->cs = r64.cs;
	r32->eflags = r64.flags;
	r32->esp = r64.sp;
	r32->ss = r64.ss;

	return 0;
}

#endif /* X86_64 */

#ifdef X86
static void
get_regs_from_kvmdump_notes(struct task_context *target,
			    struct user_regs_struct *regs)
{
	struct kvm_register_set krs;

	BZERO(&krs, sizeof(krs));

	if (!get_kvm_register_set(target->processor, &krs))
		return;

	regs->ax = krs.x86.regs[0];
	regs->cx = krs.x86.regs[1];
	regs->dx = krs.x86.regs[2];
	regs->bx = krs.x86.regs[3];
	regs->sp = krs.x86.regs[4];
	regs->bp = krs.x86.regs[5];
	regs->si = krs.x86.regs[6];
	regs->di = krs.x86.regs[7];
	regs->cs = krs.x86.cs;
	regs->ss = krs.x86.ss;
	regs->ds = krs.x86.ds;
	regs->es = krs.x86.es;
	regs->fs = krs.x86.fs;
	regs->gs = krs.x86.gs;
	regs->ip = krs.x86.ip;
	regs->flags = krs.x86.flags;
}

static int genregs_get32(struct task_context *target,
			 const struct user_regset *regset,
			 unsigned int size, void *buf)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;
	char *pt_regs_buf;
	ulonglong pt_regs_addr;

	if (is_task_active(target->task) && KVMDUMP_DUMPFILE()) {
		get_regs_from_kvmdump_notes(target, regs);
		if (user_mode(regs)) {
			return TRUE;
		}
	}

	pt_regs_buf = GETBUF(SIZE(pt_regs));

	pt_regs_addr = machdep->get_stacktop(target->task) - SIZE(pt_regs);

	/*
	 * The commit 07b047fc2466249aff7cdb23fa0b0955a7a00d48
	 * introduced 8-byte offset to match copy_thread().
	 */
	if (THIS_KERNEL_VERSION >= LINUX(2,6,16))
		pt_regs_addr -= 8;

	readmem(pt_regs_addr, KVADDR, pt_regs_buf, SIZE(pt_regs),
		"genregs_get32: regs", gcore_verbose_error_handle());

	BZERO(regs, sizeof(struct user_regs_struct));

        regs->ax = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_ax));
        regs->bp = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_bp));
        regs->bx = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_bx));
        regs->cs = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_cs));
        regs->cx = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_cx));
        regs->di = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_di));
        regs->ds = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_ds));
        regs->dx = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_dx));
        regs->es = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_es));
        regs->flags = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_flags));
        regs->ip = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_ip));
        regs->orig_ax = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_orig_ax));
        regs->si = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_si));
        regs->sp = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_sp));
        regs->ss = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_ss));

	if (GCORE_VALID_MEMBER(pt_regs_fs))
		regs->fs = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_fs));
	else if (GCORE_VALID_MEMBER(pt_regs_xfs))
		regs->fs = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_xfs));
	if (GCORE_VALID_MEMBER(pt_regs_gs))
		regs->gs = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_gs));
	else if (GCORE_VALID_MEMBER(pt_regs_xgs))
		regs->gs = ULONG(pt_regs_buf + GCORE_OFFSET(pt_regs_xgs));

	regs->ds &= 0xffff;
	regs->es &= 0xffff;
	regs->fs &= 0xffff;
	regs->gs &= 0xffff;
	regs->ss &= 0xffff;

	FREEBUF(pt_regs_buf);

	/*
	 * If LAZY_GS is set, 0 is pushed on gs position at kernel
	 * stack's bottom. Then, gs value we want is at thread->gs,
	 * saved during __switch_to().
	 */
	if (GCORE_VALID_MEMBER(pt_regs_gs) && regs->gs == 0) {
		readmem(target->task + OFFSET(task_struct_thread) +
			GCORE_OFFSET(thread_struct_gs), KVADDR, &regs->gs,
			sizeof(regs->gs), "genregs_get32: regs->gs",
			gcore_verbose_error_handle());

		regs->gs &= 0xffff;

                /*
		 * If gs is handled lazily, it's impossible to restore
		 * gs value for active tasks that had never been
		 * scheduled even once since entering kernel-execution
		 * mode.
		 */
		if (is_task_active(target->task))
			error(WARNING, "maybe cannot restore lazily-handled "
			      "GS for active tasks.\n");
	}

	return TRUE;
}

void gcore_x86_table_init(void)
{
	gcore_x86_table_register_get_thread_struct_fpu();
	gcore_x86_table_register_tsk_used_math();
}

#define user_regs_struct32 user_regs_struct

#endif /* X86 */

static struct user_regset x86_32_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.get = genregs_get32,
		.size = sizeof(struct user_regs_struct32),
	},
	[REGSET_FP] = {
		.core_note_type = NT_FPREGSET,
		.name = "CORE",
		.size = sizeof(struct user_i387_ia32_struct),
		.active = fpregs_active, .get = fpregs_get,
	},
	[REGSET_XSTATE] = {
		.name = "CORE",
		.active = xstateregs_active, .get = xstateregs_get,
	},
	[REGSET_XFP] = {
		.core_note_type = NT_PRXFPREG,
		.name = "LINUX",
		.size = sizeof(struct user32_fxsr_struct),
		.active = xfpregs_active, .get = xfpregs_get,
	},
	[REGSET_TLS] = {
		.core_note_type = NT_386_TLS,
		.name = "CORE",
		.size = GDT_ENTRY_TLS_ENTRIES * sizeof(struct user_desc),
		.active = regset_tls_active,
		.get = regset_tls_get,
	},
	[REGSET_IOPERM32] = {
		.core_note_type = NT_386_IOPERM,
		.name = "CORE",
		.size = IO_BITMAP_BYTES,
		.active = ioperm_active, .get = ioperm_get
	},
};

static const struct user_regset_view x86_32_regset_view = {
	.name = "x86_32",
	.regsets = x86_32_regsets,
	.n = ARRAY_SIZE(x86_32_regsets),
	.e_machine = EM_386,
};

/*
 * The number of registers for REGSET_XSTATE entry is specified
 * dynamically. So, we need to look at it directly.
 */
static void gcore_x86_32_regset_xstate_init(void)
{
	struct user_regset *regset_xstate = &x86_32_regsets[REGSET_XSTATE];

	regset_xstate->size = sizeof(uint32_t) * get_xstate_regsets_number();
}

void gcore_x86_32_regsets_init(void)
{
	gcore_x86_32_regset_xstate_init();
}

const struct user_regset_view *
task_user_regset_view(void)
{
#ifdef X86_64
	if (gcore_is_arch_32bit_emulation(CURRENT_CONTEXT()))
#endif
		return &x86_32_regset_view;
#ifdef X86_64
	return &x86_64_regset_view;
#endif
}

int gcore_is_arch_32bit_emulation(struct task_context *tc)
{
#ifdef X86_64
	struct user_regs_struct regs;

	(void) genregs_get(tc,
			   NULL,
			   sizeof(struct user_regs_struct),
			   &regs);

	return !user_64bit_mode(&regs);
#endif
	return FALSE;
}

/**
 * Return an address to gate_vma.
 */
ulong gcore_arch_get_gate_vma(void)
{
#ifdef X86_64
	if (gcore_is_arch_32bit_emulation(CURRENT_CONTEXT()))
		return 0UL;

	if (symbol_exists("vsyscall_mode")) {
		enum { ENUMERATE, NONE } vsyscall_mode;

		readmem(symbol_value("vsyscall_mode"),
			KVADDR,
			&vsyscall_mode,
			sizeof(vsyscall_mode),
			"gcore_arch_get_gate_vma: vsyscall_mode",
			gcore_verbose_error_handle());

		if (vsyscall_mode == NONE)
			return 0UL;
	}

	return symbol_value("gate_vma");
#else
	return 0UL;
#endif
}

char *gcore_arch_vma_name(ulong vma)
{
	ulong mm, vm_start, vdso;

	readmem(vma + OFFSET(vm_area_struct_vm_mm), KVADDR, &mm, sizeof(mm),
		"gcore_arch_vma_name: vma->vm_mm",
		gcore_verbose_error_handle());

	readmem(vma + OFFSET(vm_area_struct_vm_start), KVADDR, &vm_start,
		sizeof(vm_start), "gcore_arch_vma_name: vma->vm_start",
		gcore_verbose_error_handle());

	/*
	 * The commit "x86_64: Add vDSO for x86-64 with
	 * gettimeofday/clock_gettime/getcpu"
	 * (2aae950b21e4bc789d1fc6668faf67e8748300b7) adds vDSO
	 * support. Since then, the starting address of vDSO mapping
	 * is decided at the start of process execution and assigned
	 * at mm_context_t::vdso.
	 */
	if (GCORE_OFFSET(mm_context_t_vdso) >= 0) {
		readmem(mm + GCORE_OFFSET(mm_struct_context) +
			GCORE_OFFSET(mm_context_t_vdso), KVADDR, &vdso,
			sizeof(vdso), "gcore_arch_vma_name: mm->context.vdso",
			gcore_verbose_error_handle());
	} else {
		vdso = VDSO_HIGH_BASE;
	}

	if (mm && vm_start == vdso)
		return "[vdso]";
	if (vma == symbol_value("gate_vma"))
		return "[vsyscall]";
	return NULL;
}

/**
 * VM_ALWAYSDUMP flag was removed when introducing VM_DONTDUMP
 * flag. We need to determine which flag is present on a given
 * dumpfile. A simple idea is to look up existence of symbol
 * always_dump_vma, which was again newly introduced at the same time
 * of removal of VM_ALWAYSDUMP flag. Unfortunately, gcc removes the
 * function by function inlining optimization, we cannot use
 * it. Instead, as a workaround, we look up vsyscall page and try to
 * determine if the VM_ALWAYSDUMP flag is being set on the vma
 * corresponding to vsyscall page.
 */
int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
	char *mm_cache, *vma_cache;
	ulong target_vma, gate_vma = 0, vm_flags;
	struct task_context *tc;
	int i;

	target_vma = 0UL;

	/*
	 * Look at gate_vma on x86_32 since gate_vma.vm_flags in
	 * x86_32 had VM_ALWAYSDUMP; while the one in x86_64 not.
	 */
	if (machine_type("X86"))
		gate_vma = symbol_value("gate_vma");

	tc = FIRST_CONTEXT();
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		ulong vma, index, mmap = 0UL;

		if (is_kernel_thread(tc->task))
			continue;

		if (is_task_active(tc->task))
			continue;

		mm_cache = fill_mm_struct(task_mm(tc->task, TRUE));
		if (!mm_cache)
			continue;

		mmap = ULONG(mm_cache + OFFSET(mm_struct_mmap));

		FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
			if (gcore_arch_vma_name(vma)) {
				target_vma = vma;
				break;
			}
		}
	}

	if (!target_vma)
		return FALSE;

	vma_cache = fill_vma_cache(target_vma);
	vm_flags = ULONG(vma_cache + OFFSET(vm_area_struct_vm_flags));

	return (vm_flags & VM_ALWAYSDUMP) ? TRUE : FALSE;
}

int gcore_arch_get_fp_valid(struct task_context *tc)
{
	const struct user_regset *regset =
#ifdef X86_64
		gcore_is_arch_32bit_emulation(tc)
		? &x86_32_regsets[REGSET_FP]
		: &x86_64_regsets[REGSET_FP]
#else
		&x86_32_regsets[REGSET_FP]
#endif
		;
	char *buf = GETBUF(regset->size);
	int retval = FALSE;

	if (regset->active(tc, regset) &&
	    !regset->get(tc, regset, regset->size, buf))
		retval = TRUE;

	FREEBUF(buf);
	return retval;
}

#endif /* defined(X86) || defined(X86_64) */
