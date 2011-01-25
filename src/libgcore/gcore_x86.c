/* x86.c -- core analysis suite
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
#if defined(X86) || defined(X86_64)

#include "defs.h"
#ifdef X86_64
#include "unwind_x86_64.h"
#endif
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>
#include <asm/ldt.h>

struct gcore_x86_table
{
#ifdef X86_64
	ulong (*get_old_rsp)(int cpu);
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
#endif

static ulong gcore_x86_get_thread_struct_fpu_thread_xstate(struct task_context *tc);
static ulong gcore_x86_get_thread_struct_fpu_thread_xstate_size(void);
static ulong gcore_x86_get_thread_struct_thread_xstate(struct task_context *tc);
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

#ifdef X86_64
static void gcore_x86_64_regset_xstate_init(void);
#endif

#ifdef X86
static int genregs_get32(struct task_context *target,
			 const struct user_regset *regset, unsigned int size,
			 void *buf);
static void gcore_x86_32_regset_xstate_init(void);
#endif

static int get_xstate_regsets_number(void);

enum gcore_regset {
	REGSET_GENERAL,
	REGSET_FP,
	REGSET_XFP,
	REGSET_XSTATE,
	REGSET_IOPERM64,
	REGSET_TLS,
	REGSET_IOPERM32,
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
	struct i387_fxsave_struct *fxsave = (struct i387_fxsave_struct *)buf;
	union thread_xstate xstate;

	readmem(gxt->get_thread_struct_fpu(target), KVADDR, &xstate,
		gxt->get_thread_struct_fpu_size(),
		"xfpregs_get: xstate", gcore_verbose_error_handle());
	memcpy(buf, &xstate.fsave, sizeof(xstate.fsave));

	init_fpu(target->task);

	*fxsave = xstate.fxsave;

	return TRUE;
}

static void xfpregs_callback(struct elf_thread_core_info *t,
			    const struct user_regset *regset)
{
	t->prstatus.pr_fpvalid = 1;
}

static inline int
fpregs_active(struct task_context *target,
	      const struct user_regset *regset)
{
	return !!gxt->tsk_used_math(target->task);
}

#ifdef X86
static void sanitize_i387_state(struct task_context *target)
{
	if (cpu_has_xsaveopt()) {
		/*
		 * I have yet to implement here since I don't have
		 * CPUes that supports XSAVEOPT instruction.
		 */
	}
}
#endif

#ifdef X86_64
static inline int have_hwfp(void)
{
	return TRUE;
}
#endif

#ifdef X86
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

static int fpregs_soft_get(struct task_context *target,
			   const struct user_regset *regset,
			   unsigned int size,
			   void *buf)
{
	error(WARNING, "not support FPU software emulation\n");
	return TRUE;
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
		gxt->get_thread_struct_fpu_size(), "convert_from_fxsr: xstate",
		gcore_verbose_error_handle());

	to = (struct _fpreg *) &env->st_space[0];
	from = (struct _fpxreg *) &xstate.fxsave.st_space[0];

	env->cwd = xstate.fxsave.cwd | 0xffff0000u;
	env->swd = xstate.fxsave.swd | 0xffff0000u;
	env->twd = twd_fxsr_to_i387(&xstate.fxsave);

	if (STREQ(pc->machine_type, "X86_64")) {
		env->fip = xstate.fxsave.rip;
		env->foo = xstate.fxsave.rdp;
		if (is_task_active(target->task)) {
			error(WARNING, "cannot restore runtime fos and fcs\n");
		} else {
			struct user_regs_struct regs;
			uint16_t ds;

			readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs),
				KVADDR,	&regs, sizeof(regs),
				"convert_from_fxsr: regs",
				gcore_verbose_error_handle());

			readmem(target->task + OFFSET(task_struct_thread)
				+ GCORE_OFFSET(thread_struct_ds), KVADDR, &ds,
				sizeof(ds), "convert_from_fxsr: ds",
				gcore_verbose_error_handle());
			
			env->fos = 0xffff0000 | ds;
			env->fcs = regs.cs;
		}
	} else { /* X86 */
		env->fip = xstate.fxsave.fip;
		env->fcs = (uint16_t) xstate.fxsave.fcs | ((uint32_t) xstate.fxsave.fop << 16);
		env->foo = xstate.fxsave.foo;
		env->fos = xstate.fxsave.fos;
	}

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
			gxt->get_thread_struct_fpu_size(),
			"fpregs_get: xstate", gcore_verbose_error_handle());
		memcpy(buf, &xstate.fsave, sizeof(xstate.fsave));
		return TRUE;
	}

	sanitize_i387_state(target);

	convert_from_fxsr(buf, target);

        return TRUE;
}
#endif

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
	return GCORE_SIZE(thread_xstate);
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

	if (!symbol_exists("xstate_fx_sw_bytes"))
		error(FATAL, "xstate_fx_sw_bytes: symbol does not exist\n");

	xstate_fx_sw_bytes = symbol_value("xstate_fx_sw_bytes");

        /*
         * Copy the 48bytes defined by the software first into the xstate
         * memory layout in the thread struct, so that we can copy the entire
         * xstateregs to the user using one user_regset_copyout().
         */
	readmem(xstate_fx_sw_bytes, KVADDR, &xstate->fxsave.sw_reserved,
		USER_XSTATE_FX_SW_WORDS * sizeof(uint64_t),
		"fill_xstate: sw_reserved", gcore_verbose_error_handle());

	return TRUE;
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

#ifdef X86_64
#define __USER_CS       0x23
#define __USER_DS       0x2B
#endif

/*
 * thread information flags
 * - these are process state flags that various assembly files
 *   may need to access
 * - pending work-to-be-done flags are in LSW
 * - other flags in MSW
 * Warning: layout of LSW is hardcoded in entry.S
 */
#define TIF_FORCED_TF           24      /* true if TF in eflags artificially */

#ifdef X86
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

	for (i = 0; i < nr_entries; ++i)
		if (!desc_empty(&tls_array[i]))
			return TRUE;

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

	return TRUE;
}
#endif /* X86 */

#define IO_BITMAP_BITS  65536
#define IO_BITMAP_BYTES (IO_BITMAP_BITS/8)
#define IO_BITMAP_LONGS (IO_BITMAP_BYTES/sizeof(long))

static int
ioperm_active(struct task_context *target,
	      const struct user_regset *regset)
{
	unsigned int io_bitmap_max;

	readmem(target->task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_io_bitmap_max), KVADDR,
		&io_bitmap_max, sizeof(io_bitmap_max),
		"ioperm_active: io_bitmap_max", gcore_verbose_error_handle());

	return io_bitmap_max / regset->size;
}

static int ioperm_get(struct task_context *target,
		      const struct user_regset *regset,
		      unsigned int size,
		      void *buf)
{
	ulong io_bitmap_ptr;

	readmem(target->task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_io_bitmap_ptr), KVADDR,
		&io_bitmap_ptr, sizeof(io_bitmap_ptr),
		"ioperm_get: io_bitmap_ptr", gcore_verbose_error_handle());

	if (!io_bitmap_ptr)
		return FALSE;

	readmem(io_bitmap_ptr, KVADDR, buf, size, "ioperm_get: copy IO bitmap",
		gcore_verbose_error_handle());

	return TRUE;
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

static inline int
user_mode(const struct user_regs_struct *regs)
{
	return !!(regs->cs & 0x3);
}

#ifdef X86_64
static int
get_desc_base(ulong desc)
{
	uint16_t base0;
	uint8_t base1, base2;

	readmem(desc + GCORE_OFFSET(desc_struct_base0), KVADDR, &base0,
		sizeof(base0), "get_desc_base: base0", gcore_verbose_error_handle());

	readmem(desc + GCORE_OFFSET(desc_struct_base1), KVADDR, &base1,
		sizeof(base1), "get_desc_base: base1", gcore_verbose_error_handle());

	readmem(desc + GCORE_OFFSET(desc_struct_base2), KVADDR, &base2,
		sizeof(base2), "get_desc_base: base2", gcore_verbose_error_handle());

	return base0 | (base1 << 16) | (base2 << 24);
}

static int
test_tsk_thread_flag(ulong task, int bit)
{
	ulong thread_info, flags;

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

		regs->fs_base =
			regs->fs_base != FS_TLS_SEL
			? 0
			: get_desc_base(task + OFFSET(task_struct_thread) +
					FS_TLS * SIZE(desc_struct));

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

		regs->gs_base =
			regs->gs_base != GS_TLS_SEL
			? 0
			: get_desc_base(task + OFFSET(task_struct_thread) +
					GS_TLS * SIZE(desc_struct));

	}

	if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		regs->flags &= ~X86_EFLAGS_TF;

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_fsindex), KVADDR, &regs->fs,
		sizeof(regs->fs), "restore_segment_registers: fsindex",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_gsindex), KVADDR, &regs->gs,
		sizeof(regs->gs), "restore_segment_registers: gsindex",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_thread) +
		GCORE_OFFSET(thread_struct_es), KVADDR, &regs->es,
		sizeof(regs->es), "restore_segment_registers: es",
		gcore_verbose_error_handle());

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
	ulong rsp, rbp;

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
	 */
	while (IS_KVADDR(rbp))
		readmem(rbp, KVADDR, &rbp, sizeof(rbp),
			"restore_frame_pointer: resume rbp",
			gcore_verbose_error_handle());

	return rbp;
}

/**
 * restore_rest() - restore user-mode callee-saved registers
 *
 * @task interesting task object
 * @regs buffer into which register values are placed
 * @note_regs registers in NT_PRSTATUS saved at kernel crash
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
 * note_regs is a starting point of backtracing for active tasks.
 *
 * There are two kinds of sections for CFA to be placed in ELF's
 * debugging inforamtion sections: .eh_frame and .debug_frame. The
 * point is that two sections have differnet layout. Look carefully at
 * is_ehframe.
 */
static inline void restore_rest(ulong task, struct pt_regs *regs,
				const struct user_regs_struct *note_regs)
{
	int first_frame;
	struct unwind_frame_info frame;
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
		memcpy(&frame.regs, note_regs, sizeof(struct pt_regs));
	} else {
		unsigned long rsp, rbp;

		memset(&frame.regs, 0, sizeof(struct pt_regs));

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
	 */
	first_frame = TRUE;

	while (!unwind(&frame, is_ehframe)) {
		if (first_frame)
			first_frame = FALSE;
	}

	if (!first_frame) {
		regs->r12 = frame.regs.r12;
		regs->r13 = frame.regs.r13;
		regs->r14 = frame.regs.r14;
		regs->r15 = frame.regs.r15;
		regs->rbp = frame.regs.rbp;
		regs->rbx = frame.regs.rbx;
	}

	/*
	 * If kernel was configured with CONFIG_FRAME_POINTER, we
	 * could trace the value of bp until its value became a
	 * user-space address. See comments of restore_frame_pointer.
	 */
	if (machdep->flags & FRAMEPOINTER) {
		regs->rbp = restore_frame_pointer(task);
	}
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
	char *cpu_pda_buf;

	cpu_pda_buf = GETBUF(SIZE(x8664_pda));

	readmem(symbol_value("cpu_pda") + sizeof(ulong) * SIZE(x8664_pda),
		KVADDR, cpu_pda_buf, SIZE(x8664_pda),
		"gcore_x86_64_get_cpu_pda_oldrsp: cpu_pda_buf",
		gcore_verbose_error_handle());

	oldrsp = ULONG(cpu_pda_buf + GCORE_OFFSET(x8664_pda_oldrsp));

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

static int genregs_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;
	struct user_regs_struct note_regs;
	const int active = is_task_active(target->task);

	/*
	 * vmcore generated by kdump contains NT_PRSTATUS including
	 * general register values for active tasks.
	 */
	if (active && KDUMP_DUMPFILE()) {
		struct user_regs_struct *note_regs_p;

		note_regs_p = get_regs_from_elf_notes(CURRENT_CONTEXT());
		memcpy(&note_regs, note_regs_p, sizeof(struct user_regs_struct));

		/*
		 * If the task was in kernel-mode at the kernel crash, note
		 * information is not what we would like.
		 */
		if (user_mode(&note_regs)) {
			memcpy(regs, &note_regs, sizeof(struct user_regs_struct));
			return 0;
		}
	}

	/*
	 * SAVE_ARGS() and SAVE_ALL() macros save user-mode register
	 * values at kernel stack top when entering kernel-mode at
	 * interrupt.
	 */
	readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs), KVADDR,
		regs, size, "genregs_get: pt_regs", gcore_verbose_error_handle());

	/*
	 * regs->orig_ax contains either a signal number or an IRQ
	 * number: if >=0, it's a signal number; if <0, it's an IRQ
	 * number.
	 */
	if ((int)regs->orig_ax >= 0) {
		const int nr_syscall = (int)regs->orig_ax;

		/*
		 * rsp is saved in per-CPU old_rsp, which is saved in
		 * thread->usersp at each context switch.
		 */
		if (active) {
			regs->sp = gxt->get_old_rsp(target->processor);
		} else {
			readmem(target->task + OFFSET(task_struct_thread) +
				GCORE_OFFSET(thread_struct_usersp), KVADDR, &regs->sp,
				sizeof(regs->sp),
				"genregs_get: usersp", gcore_verbose_error_handle());
		}

		/*
		 * entire registers are saved for special system calls.
		 */
		if (!gxt->is_special_syscall(nr_syscall))
			restore_rest(target->task, (struct pt_regs *)regs, &note_regs);

		/*
		 * See FIXUP_TOP_OF_STACK in arch/x86/kernel/entry_64.S.
		 */
		regs->ss = __USER_DS;
		regs->cs = __USER_CS;
		regs->cx = (ulong)-1;
		regs->flags = regs->r11;

		restore_segment_registers(target->task, regs);

	} else {
		const int vector = (int)~regs->orig_ax;

		if (vector < 0 || vector > 255) {
			error(WARNING, "unexpected IRQ number: %d.\n", vector);
		}

                /* Exceptions and NMI */
		else if (vector < 20) {
			restore_rest(target->task, (struct pt_regs *)regs,
				     &note_regs);
			restore_segment_registers(target->task, regs);
		}

                /* reserved by Intel */
		else if (vector < 32) {
			error(WARNING, "IRQ number %d is reserved by Intel\n",
			      vector);
		}

		/* system call invocation by int 0x80 */
		else if (vector == 0x80 && is_ia32_syscall_enabled()) {
			const int nr_syscall = regs->ax;

			if (!gxt->is_special_ia32_syscall(nr_syscall))
				restore_rest(target->task,
					     (struct pt_regs *)regs,
					     &note_regs);
			restore_segment_registers(target->task, regs);
		}

                /* Muskable Interrupts */
		else if (vector < 256) {
			restore_rest(target->task, (struct pt_regs *)regs,
				     &note_regs);
			restore_segment_registers(target->task, regs);
		}

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
}
#endif

static void gcore_x86_table_register_get_thread_struct_fpu(void)
{
	if (MEMBER_EXISTS("thread_struct", "fpu")) {
		gxt->get_thread_struct_fpu =
			gcore_x86_get_thread_struct_fpu_thread_xstate;
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
	if (GCORE_VALID_MEMBER(task_struct_used_math))
		gxt->tsk_used_math = tsk_used_math_v0;
	else
		gxt->tsk_used_math = tsk_used_math_v11;

}

#ifdef X86_64
void gcore_x86_table_init(void)
{
	gcore_x86_table_register_get_old_rsp();
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
		.name = "LINUX",
		.size = sizeof(struct user_i387_struct),
		.active = xfpregs_active,
		.get = xfpregs_get,
                .callback = xfpregs_callback
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
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
}

#endif /* X86_64 */

#ifdef X86
static int genregs_get32(struct task_context *target,
			 const struct user_regset *regset,
			 unsigned int size, void *buf)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;
	char *pt_regs_buf;
	ulonglong pt_regs_addr;

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

static struct user_regset x86_32_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.get = genregs_get32,
		.size = sizeof(struct user_regs_struct),
	},
	[REGSET_FP] = {
		.core_note_type = NT_FPREGSET,
		.name = "LINUX",
		.size = sizeof(struct user_i387_ia32_struct),
		.active = fpregs_active, .get = fpregs_get,
                .callback = xfpregs_callback,
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
		.name = "CORE",
		.active = xstateregs_active, .get = xstateregs_get,
	},
	[REGSET_XFP] = {
		.core_note_type = NT_PRXFPREG,
		.name = "CORE",
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
#endif

const struct user_regset_view *
task_user_regset_view(void)
{
#ifdef X86_64
	return &x86_64_regset_view;
#elif X86
	return &x86_32_regset_view;
#endif
}

#ifdef GCORE_TEST

#ifdef X86_64
static char *gcore_x86_64_test(void)
{
	int test_rsp, test_fpu, test_syscall, test_math;

	if (gcore_is_rhel4()) {
		test_rsp = gxt->get_old_rsp == gcore_x86_64_get_cpu_pda_oldrsp;
		test_fpu = gxt->get_thread_struct_fpu == gcore_x86_get_thread_struct_i387;
		test_syscall = gxt->is_special_syscall == is_special_syscall_v0;
		test_math = gxt->tsk_used_math == tsk_used_math_v0;
	} else if (gcore_is_rhel5()) {
		test_rsp = gxt->get_old_rsp == gcore_x86_64_get_cpu__pda_oldrsp;
		test_fpu = gxt->get_thread_struct_fpu == gcore_x86_get_thread_struct_i387;
		test_syscall = gxt->is_special_syscall == is_special_syscall_v0;
		test_math = gxt->tsk_used_math == tsk_used_math_v11;
	} else if (gcore_is_rhel6()) {
		test_rsp = gxt->get_old_rsp == gcore_x86_64_get_per_cpu__old_rsp;
		test_fpu = gxt->get_thread_struct_fpu == gcore_x86_get_thread_struct_thread_xstate;
		test_syscall = gxt->is_special_syscall == is_special_syscall_v26;
		test_math = gxt->tsk_used_math == tsk_used_math_v11;
	} else if (THIS_KERNEL_VERSION == LINUX(2,6,36)) {
		test_rsp = gxt->get_old_rsp == gcore_x86_64_get_old_rsp;
		test_fpu = gxt->get_thread_struct_fpu == gcore_x86_get_thread_struct_fpu_thread_xstate;
		test_syscall = gxt->is_special_syscall == is_special_syscall_v26;
		test_math = gxt->tsk_used_math == tsk_used_math_v11;
	}

	mu_assert("gxt->get_old_rsp has wrongly been registered", test_rsp);
	mu_assert("gxt->get_thread_struct_fpu has wrongly been registered", test_fpu);
	mu_assert("gxt->is_special_syscall has wrongly been registered", test_syscall);
	mu_assert("gxt->tsk_used_math has wrongly been registered", test_math);

	return NULL;
}
#endif

#ifdef X86
static char *gcore_x86_32_test(void)
{
	return NULL;
}
#endif

char *gcore_x86_test(void)
{
#ifdef X86_64
	return gcore_x86_64_test();
#else
	return gcore_x86_32_test();
#endif
}

#endif

#endif /* defined(X86) || defined(X86_64) */
