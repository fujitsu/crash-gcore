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

	readmem(machdep->get_stacktop(target->task) - 16 - SIZE(pt_regs), KVADDR,
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

const struct user_regset_view *
task_user_regset_view(void)
{
	return &arm64_regset_view;
}

int gcore_is_arch_32bit_emulation(struct task_context *tc)
{
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
