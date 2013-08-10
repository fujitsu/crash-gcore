/* regset.c -- core analysis suite
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

#include "defs.h"
#include <gcore_defs.h>
#include <elf.h>

enum gcore_default_regset {
	REGSET_GENERAL,
};

static int genregs_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size,
		       void *buf)
{
	readmem(machdep->get_stacktop(target->task) - SIZE(pt_regs), KVADDR,
		buf, size, "genregs_get: pt_regs", gcore_verbose_error_handle());

	return 0;
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static struct user_regset gcore_default_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.get = genregs_get
	},
};

static struct user_regset_view gcore_default_regset_view = {
	.name = REGSET_VIEW_NAME,
	.regsets = gcore_default_regsets,
	.n = ARRAY_SIZE(gcore_default_regsets),
	.e_machine = REGSET_VIEW_MACHINE
};

const struct user_regset_view * __attribute__((weak))
task_user_regset_view(void)
{
	return &gcore_default_regset_view;
}

void gcore_default_regsets_init(void)
{
	gcore_default_regsets[REGSET_GENERAL].size = SIZE(pt_regs);
}

int __attribute__((weak))
gcore_arch_get_fp_valid(struct task_context *tc)
{
	return 0;
}
