/* Minimal LoongArch64 backend for crash-gcore-command
 *
 * This file provides the arch hooks referenced by the core dumper so that
 * the extension can load without undefined symbols on __loongarch64.
 *
 * Keep behavior aligned with other minimal backends (e.g. riscv64):
 *  - no special VMA naming
 *  - no forced alwaysdump for vsyscall
 *  - no 32-bit emulation
 *  - no 32-bit emulation
 */
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

	readmem(machdep->get_stacktop(target->task) -
		SIZE(pt_regs), KVADDR,
		regs, SIZE(pt_regs), "gpr_get: pt_regs",
		gcore_verbose_error_handle());

	return 0;
}

enum gcore_regset {
	REGSET_GPR,
};

static struct user_regset loongarch64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.name = "CORE",
		.size = ELF_NGREG * sizeof(unsigned long),
		.get = gpr_get,
	},
};

static const struct user_regset_view loongarch64_regset_view = {
	.name = "loongarch64",
	.regsets = loongarch64_regsets,
	.n = 1,
	.e_machine = EM_LOONGARCH,
};

const struct user_regset_view *
task_user_regset_view(void)
{
	return &loongarch64_regset_view;
}

int gcore_is_arch_32bit_emulation(struct task_context *tc)
{
    /* loongarch64: no 32-bit compat emulation in this context */
    (void)tc;
    return FALSE;
}

ulong gcore_arch_get_gate_vma(void)
{
    /*
     * Follow other arches' convention: if kernel exports a symbol marking
     * VDSO/vsyscall gate, return its address; otherwise 0 (not used).
     */
    if (symbol_exists("gate_vma"))
        return symbol_value("gate_vma");
    return 0;
}

char *gcore_arch_vma_name(ulong vma)
{
    /*
     * Minimal implementation: do not name VMAs specially.
     * Returning NULL makes the generic logic fall back to defaults.
     */
    (void)vma;
    return NULL;
}

int gcore_arch_vsyscall_has_vm_alwaysdump_flag(void)
{
    /*
     * Minimal implementation: do not force alwaysdump for vsyscall.
     * The generic dumpfilter logic will decide based on flags.
     */
    return FALSE;
}
