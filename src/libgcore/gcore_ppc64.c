/* gcore_ppc64.c
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

#ifdef PPC64

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>

static int gpr_get(struct task_context *target,
                   const struct user_regset *regset,
                   unsigned int size, void *buf)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)buf;

	BZERO(regs, sizeof(*regs));

	readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs), KVADDR,
		regs, SIZE(pt_regs), "genregs_get: pt_regs",
		gcore_verbose_error_handle());

	return 0;
}

enum gcore_regset {
	REGSET_GPR,
};

static struct user_regset ppc64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = ELF_NGREG * sizeof(unsigned int),
		.get = gpr_get,
	},
};

static const struct user_regset_view ppc64_regset_view = {
	.name = "ppc64",
	.regsets = ppc64_regsets,
	.n = 1,
	.e_machine = EM_PPC64,
};

const struct user_regset_view *
task_user_regset_view(void)
{
	return &ppc64_regset_view;
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

#endif
