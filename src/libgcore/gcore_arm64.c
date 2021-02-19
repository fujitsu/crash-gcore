/* gcore_arm64.c
 *
 * Copyright (C) 2014 Red Hat, Inc. All rights reserved
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

#ifdef ARM64

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>

static int gpr_get(struct task_context *target,
		   const struct user_regset *regset,
		   unsigned int size, void *buf)
{
	struct user_pt_regs *regs = (struct user_pt_regs *)buf;

	BZERO(regs, sizeof(*regs));

	readmem(machdep->get_stacktop(target->task) -
		machdep->machspec->user_eframe_offset, KVADDR,
		regs, sizeof(struct user_pt_regs), "gpr_get: user_pt_regs",
		gcore_verbose_error_handle());

	return 0;
}

static int fpr_get(struct task_context *target,
		   const struct user_regset *regset,
		   unsigned int size, void *buf)
{
	struct user_fpsimd_state *fpr = (struct user_fpsimd_state *)buf;

	BZERO(fpr, sizeof(*fpr));
	readmem(target->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_fpsimd_state),
		KVADDR, fpr, sizeof(struct user_fpsimd_state),
		"fpr_get: user_fpsimd_state",
		gcore_verbose_error_handle());
	return 0;
}

static int tls_get(struct task_context *target,
		   const struct user_regset *regset,
		   unsigned int size, void *buf)
{
	void *tls = (void *)buf;

	BZERO(tls, size);
	readmem(target->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_tp_value),
		KVADDR, tls, sizeof(void *),
		"tls_get: tp_value",
		gcore_verbose_error_handle());
	return 0;
}

enum gcore_regset {
	REGSET_GPR,
	REGSET_FPR,
	REGSET_TLS,
};

static struct user_regset arm64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = sizeof(struct elf_prstatus),
		.get = gpr_get,
	},
	[REGSET_FPR] = {
		.core_note_type = NT_FPREGSET,
		.name = "CORE",
		.size = sizeof(struct user_fpsimd_state),
		.get = fpr_get,
	},
	[REGSET_TLS] = {
		.core_note_type = NT_ARM_TLS,
		.name = "CORE",
		.size = sizeof(void *),
		.get = tls_get,
	},
};
#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const struct user_regset_view arm64_regset_view = {
	.name = "arm64",
	.regsets = arm64_regsets,
	.n = ARRAY_SIZE(arm64_regsets),
	.e_machine = EM_AARCH64,
};

#ifdef GCORE_ARCH_COMPAT
enum compat_regset {
	REGSET_COMPAT_GPR,
	REGSET_COMPAT_VFP,
};

struct pt_regs {
	struct user_pt_regs user_regs;
	unsigned long orig_x0;
	unsigned long syscallno;
};

static int compat_gpr_get(struct task_context *target,
			  const struct user_regset *regset,
			  unsigned int size, void *buf)
{
	struct pt_regs pt_regs;
	struct user_regs_struct32 *regs = (struct user_regs_struct32 *)buf;

	BZERO(&pt_regs, sizeof(pt_regs));
	BZERO(regs, sizeof(*regs));

	readmem(machdep->get_stacktop(target->task) -
		machdep->machspec->user_eframe_offset, KVADDR,
		&pt_regs, sizeof(struct pt_regs), "compat_gpr_get: pt_regs",
		gcore_verbose_error_handle());

	regs->r0 = pt_regs.user_regs.regs[0];
	regs->r1 = pt_regs.user_regs.regs[1];
	regs->r2 = pt_regs.user_regs.regs[2];
	regs->r3 = pt_regs.user_regs.regs[3];
	regs->r4 = pt_regs.user_regs.regs[4];
	regs->r5 = pt_regs.user_regs.regs[5];
	regs->r6 = pt_regs.user_regs.regs[6];
	regs->r7 = pt_regs.user_regs.regs[7];
	regs->r8 = pt_regs.user_regs.regs[8];
	regs->r9 = pt_regs.user_regs.regs[9];
	regs->r10 = pt_regs.user_regs.regs[10];
	regs->fp = pt_regs.user_regs.regs[11];
	regs->ip = pt_regs.user_regs.regs[12];
	regs->sp = pt_regs.user_regs.regs[13];
	regs->lr = pt_regs.user_regs.regs[14];
	regs->pc = pt_regs.user_regs.pc;
	regs->cpsr = pt_regs.user_regs.pstate;
	regs->ORIG_r0 = pt_regs.orig_x0;

	return 0;
}

static int compat_vfp_get(struct task_context *target,
			  const struct user_regset *regset,
			  unsigned int size, void *buf)
{
	/*
	 * The VFP registers are packed into the fpsimd_state, so they all sit
	 * nicely together for us. We just need to create the fpscr separately.
	 */
	struct user_fpsimd_state *fpr = (struct user_fpsimd_state *)buf;
	compat_ulong_t fpscr;

	BZERO(fpr, sizeof(*fpr));
	readmem(target->task + OFFSET(task_struct_thread)
		+ GCORE_OFFSET(thread_struct_fpsimd_state),
		KVADDR, fpr, sizeof(struct user_fpsimd_state),
		"compat_fpr_get: user_fpsimd_state",
		gcore_verbose_error_handle());

	fpscr = (fpr->fpsr & VFP_FPSCR_STAT_MASK) |
		(fpr->fpcr & VFP_FPSCR_CTRL_MASK);

	fpr->fpcr = fpscr;

	return 0;
}

#define NT_ARM_VFP	0x400           /* ARM VFP/NEON registers */
static const struct user_regset aarch32_regsets[] = {
	[REGSET_COMPAT_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = sizeof(struct user_regs_struct32),
		.get = compat_gpr_get,
	},
	[REGSET_COMPAT_VFP] = {
		.core_note_type = NT_ARM_VFP,
		.name = "CORE",
		.size = VFP_STATE_SIZE,
		.get = compat_vfp_get,
	},
};

static const struct user_regset_view aarch32_regset_view = {
	.name = "aarch32",
	.e_machine = EM_ARM,
	.regsets = aarch32_regsets,
	.n = ARRAY_SIZE(aarch32_regsets)
};
#endif /* GCORE_ARCH_COMPAT */

const struct user_regset_view *
task_user_regset_view(void)
{
#ifdef GCORE_ARCH_COMPAT
	if (gcore_is_arch_32bit_emulation(CURRENT_CONTEXT()))
		return &aarch32_regset_view;
#endif /* GCORE_ARCH_COMPAT */
	return &arm64_regset_view;
}

#ifdef GCORE_ARCH_COMPAT
enum gcore_arm64_thread_info_flag
{
	TIF_32BIT = 22		/* 32bit process */
};
#endif /* GCORE_ARCH_COMPAT */

int gcore_is_arch_32bit_emulation(struct task_context *tc)
{
#ifdef GCORE_ARCH_COMPAT
	uint32_t flags;
	char *thread_info_buf;

	thread_info_buf = fill_thread_info(tc->thread_info);
	flags = ULONG(thread_info_buf + OFFSET(thread_info_flags));

	if (flags & (1UL << TIF_32BIT))
		return TRUE;
#endif /* GCORE_ARCH_COMPAT */
	return FALSE;
}

ulong gcore_arch_get_gate_vma(void)
{
	return 0UL;
}

char *gcore_arch_vma_name(ulong vma)
{
	return NULL;
}

int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
	return FALSE;
}

#endif
