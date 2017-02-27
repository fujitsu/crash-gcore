/* gcore_mips.c -- core analysis suite
 *
 * Copyright (C) 2016 Axis Communications
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
#if defined(MIPS)

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>
#include <asm/ldt.h>

#define MIPS32_EF_R0		6
#define MIPS32_EF_R1		7
#define MIPS32_EF_R26		32
#define MIPS32_EF_R27		33
#define MIPS32_EF_R31		37
#define MIPS32_EF_LO		38
#define MIPS32_EF_HI		39
#define MIPS32_EF_CP0_EPC	40
#define MIPS32_EF_CP0_BADVADDR	41
#define MIPS32_EF_CP0_STATUS	42
#define MIPS32_EF_CP0_CAUSE	43

static int gpr_get(struct task_context *target,
		       const struct user_regset *regset,
		       unsigned int size, void *buf)
{
	static int once;
	struct user_regs_struct *regs = buf;
	struct mips_pt_regs_main *mains;
	struct mips_pt_regs_cp0 *cp0;
	char pt_regs[SIZE(pt_regs)];
	int i;

	/*
	 * All registers are saved in thread_info.regs only on certain types of
	 * entries to the kernel (such as abort handling).  For other types of
	 * entries (such as system calls), only a subset of the registers are
	 * saved on entry and the rest are saved on the stack according to the
	 * ABI's calling conventions.  To always get the full register set we
	 * would have to unwind the stack and find where the registers are by
	 * using DWARF information.  We don't have an implementation for this
	 * right now so warn to avoid misleading the user.  Only warn since
	 * this function is called multiple times even for a single invocation
	 * of the gcore command.
	 */
	if (!once) {
		once = 1;
		error(WARNING, "WARNING: Current register values may be inaccurate\n");
	}

	readmem(machdep->get_stacktop(target->task) - 32 - SIZE(pt_regs),
		KVADDR, pt_regs, SIZE(pt_regs), "genregs_get: pt_regs",
		gcore_verbose_error_handle());

	mains = (struct mips_pt_regs_main *) (pt_regs + OFFSET(pt_regs_regs));
	cp0 = (struct mips_pt_regs_cp0 *) \
	      (pt_regs + OFFSET(pt_regs_cp0_badvaddr));

	BZERO(regs, sizeof(*regs));

	for (i = MIPS32_EF_R1; i <= MIPS32_EF_R31; i++) {
		/* k0/k1 are copied as zero. */
		if (i == MIPS32_EF_R26 || i == MIPS32_EF_R27)
			continue;

		regs->gregs[i] = mains->regs[i - MIPS32_EF_R0];
	}

	regs->gregs[MIPS32_EF_LO] = mains->lo;
	regs->gregs[MIPS32_EF_HI] = mains->hi;
	regs->gregs[MIPS32_EF_CP0_EPC] = cp0->cp0_epc;
	regs->gregs[MIPS32_EF_CP0_BADVADDR] = cp0->cp0_badvaddr;
	regs->gregs[MIPS32_EF_CP0_STATUS] = mains->cp0_status;
	regs->gregs[MIPS32_EF_CP0_CAUSE] = cp0->cp0_cause;

	return 0;
}

enum gcore_regset {
	REGSET_GPR,
};

static struct user_regset mips_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = ELF_NGREG * sizeof(unsigned int),
		.get = gpr_get,
	},
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const struct user_regset_view mips_regset_view = {
	.name = "mips",
	.regsets = mips_regsets,
	.n = ARRAY_SIZE(mips_regsets),
	.e_machine = EM_MIPS,
};

const struct user_regset_view *
task_user_regset_view(void)
{
	return &mips_regset_view;
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
	ulong mm, vm_start, vdso;

	readmem(vma + OFFSET(vm_area_struct_vm_mm), KVADDR, &mm, sizeof(mm),
		"gcore_arch_vma_name: vma->vm_mm",
		gcore_verbose_error_handle());

	readmem(vma + OFFSET(vm_area_struct_vm_start), KVADDR, &vm_start,
		sizeof(vm_start), "gcore_arch_vma_name: vma->vm_start",
		gcore_verbose_error_handle());

	readmem(mm + GCORE_OFFSET(mm_struct_context) +
		GCORE_OFFSET(mm_context_t_vdso), KVADDR, &vdso,
		sizeof(vdso), "gcore_arch_vma_name: mm->context.vdso",
		gcore_verbose_error_handle());

	if (mm && vm_start == vdso)
		return "[vdso]";

	return NULL;
}

int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
	return FALSE;
}

#endif /* defined(MIPS) */
