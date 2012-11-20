/* gcore_arm.c -- core analysis suite
 *
 * Copyright (C) 2012 Marvell INC
 * Author: Lei Wen <leiwen@marvell.com>
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
#if defined(ARM)

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>
#include <asm/ldt.h>

static int gpr_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;

	BZERO(regs, sizeof(*regs));

	readmem(machdep->get_stacktop(target->task) - 8 - SIZE(pt_regs), KVADDR,
		regs, SIZE(pt_regs), "genregs_get: pt_regs",
		gcore_verbose_error_handle());

	return 0;
}

static int fpa_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	struct user_fp *fp = (struct user_fp*)buf;

	BZERO(fp, sizeof(*fp));
	readmem(target->task + OFFSET(task_struct_thread_info)
		+ GCORE_OFFSET(thread_info_fpstate),
		KVADDR, fp, sizeof(*fp),
		"fpa_get: fpstate",
		gcore_verbose_error_handle());
	return 0;
}

static int vfp_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	struct user_vfp *vfp = (struct user_vfp*)buf;

	BZERO(vfp, sizeof(*vfp));
	readmem(target->task + OFFSET(task_struct_thread_info)
		+ GCORE_OFFSET(thread_info_vfpstate)
		+ GCORE_OFFSET(vfp_state_hard)
		+ GCORE_OFFSET(vfp_hard_struct_fpregs),
		KVADDR, &vfp->fpregs, GCORE_SIZE(vfp_hard_struct_fpregs),
		"vfp_get: fpregs",
		gcore_verbose_error_handle());

	readmem(target->task + OFFSET(task_struct_thread_info)
		+ GCORE_OFFSET(thread_info_vfpstate)
		+ GCORE_OFFSET(vfp_state_hard)
		+ GCORE_OFFSET(vfp_hard_struct_fpscr),
		KVADDR, &vfp->fpscr, GCORE_SIZE(vfp_hard_struct_fpscr),
		"vfp_get: fpregs",
		gcore_verbose_error_handle());
	return 0;
}

static inline int
vfp_vector_active(struct task_context *target,
		  const struct user_regset *regset)
{
	return !!symbol_exists("vfp_vector");
}

enum gcore_regset {
	REGSET_GPR,
	REGSET_FPR,
	REGSET_VFP,
};

#define NT_ARM_VFP	0x400           /* ARM VFP/NEON registers */
static struct user_regset arm_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = ELF_NGREG * sizeof(unsigned int),
		.get = gpr_get,
	},
	[REGSET_FPR] = {
		.core_note_type = NT_FPREGSET,
		.name = "CORE",
		.size = sizeof(struct user_fp),
		.get = fpa_get,
	},
	[REGSET_VFP] = {
		.core_note_type = NT_ARM_VFP,
		.name = "CORE",
		.size = ARM_VFPREGS_SIZE,
		.active = vfp_vector_active,
		.get = vfp_get,
	},
};
#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const struct user_regset_view arm_regset_view = {
	.name = "arm",
	.regsets = arm_regsets,
	.n = ARRAY_SIZE(arm_regsets),
	.e_machine = EM_ARM,
};

const struct user_regset_view *
task_user_regset_view(void)
{
	return &arm_regset_view;
}

int gcore_is_arch_32bit_emulation(struct task_context *tc)
{
	return FALSE;
}

/**
 * Return an address to gate_vma.
 */
ulong gcore_arch_get_gate_vma(void)
{
	if (!symbol_exists("gate_vma"))
		return 0UL;

	return symbol_value("gate_vma");
}

char *gcore_arch_vma_name(ulong vma)
{
	return NULL;
}

int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
	return FALSE;
}

#endif /* defined(ARM) */
