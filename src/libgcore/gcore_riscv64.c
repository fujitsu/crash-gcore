/* gcore_riscv64.c -- core analysis suite
 *
 * Copyright (C) 2025 Mobileye INC
 * Author: Pnina Feder <pnina.feder@mobileye.com>
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
#if defined(RISCV64)

#include "defs.h"
#include <gcore_defs.h>
#include <stdint.h>
#include <elf.h>

static int gpr_get(struct task_context *target,
                           const struct user_regset *regset,
                           unsigned int size, void *buf)
{
    struct user_regs_struct *regs = buf;
    char pt_regs_buf[SIZE(pt_regs)];
    struct riscv64_register *r;
    ulong stacktop;

    BZERO(regs, sizeof(*regs));

    stacktop = machdep->get_stacktop(target->task);
    readmem(stacktop - SIZE(pt_regs), KVADDR, pt_regs_buf, SIZE(pt_regs),
            "riscv64_gpr_get: pt_regs", gcore_verbose_error_handle());

    r = (struct riscv64_register *)pt_regs_buf;

    for (int i = 0; i < 32; i++) {
        regs->gregs[i] = r->regs[i];
    }

    return 0;
}

static int fpr_get(struct task_context *target,
                   const struct user_regset *regset,
                   unsigned int size, void *buf)
{
    struct __riscv_d_ext_state *fpr = (struct __riscv_d_ext_state *)buf;

    BZERO(fpr, sizeof(*fpr));
    readmem(target->task + OFFSET(task_struct_thread)
            + GCORE_OFFSET(thread_struct_fstate),
            KVADDR, fpr, sizeof(struct __riscv_d_ext_state),
            "fpr_get: user_struct_fstate",
            gcore_verbose_error_handle());

    return 0;
}

enum gcore_regset {
	REGSET_GPR,
    REGSET_FPR,
};

static const struct user_regset riscv64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = ELF_NGREG * sizeof(uint64_t),
		.get = gpr_get,
	},
    [REGSET_FPR] = {
        .core_note_type = NT_FPREGSET,
        .name = "CORE",
        .size = sizeof(struct __riscv_d_ext_state),
        .get = fpr_get,
    },
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const struct user_regset_view riscv64_regset_view = {
    .name = "riscv64",
    .regsets = riscv64_regsets,
    .n = ARRAY_SIZE(riscv64_regsets),
    .e_machine = EM_RISCV,
};

const struct user_regset_view *task_user_regset_view(void)
{
    return &riscv64_regset_view;
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
    // No architecture-specific VMA labels are currently defined for RISC-V.
    return NULL;
}

int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
	return FALSE;
}
#endif /* defined(RISCV64) */