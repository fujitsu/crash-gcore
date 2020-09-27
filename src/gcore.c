/* gcore.c -- core analysis suite
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
#include <stdint.h>
#include <elf.h>

static void gcore_offset_table_init(void);
static void gcore_size_table_init(void);
static void gcore_machdep_init(void);

static void do_gcore(char *arg);
static void print_version(void);

static struct command_table_entry command_table[] = {
	{ "gcore", cmd_gcore, help_gcore, 0 },
	{ (char *)NULL }                               
};

int 
_init(void) /* Register the command set. */
{
	gcore_offset_table_init();
	gcore_size_table_init();
	gcore_coredump_table_init();
	gcore_arch_table_init();
	gcore_arch_regsets_init();
	gcore_machdep_init();
        register_extension(command_table);
	return 1;
}
 
int 
_fini(void) 
{ 
	return 1;
}

char *help_gcore[] = {
"gcore",
"gcore - retrieve a process image as a core dump",
"\n"
"  gcore [-v vlevel] [-f filter] [pid | taskp]*\n"
"  This command retrieves a process image as a core dump.",
"  ",
"    -v Display verbose information according to vlevel:",
"  ",
"           progress  library error  page fault",
"       ---------------------------------------",
"         0",
"         1    x",
"         2                  x",
"         4                                x    (default)",
"         7    x             x             x",
"  ",
"    -f Specify kinds of memory to be written into core dumps according to",
"       the filter flag in bitwise:",
"  ",
"           AP  AS  FP  FS  ELF HP  HS  DD",
"       ----------------------------------",
"         0",
"         1  x",
"         2      x",
"         4          x",
"         8              x",
"        16          x       x",
"        32                      x",
"        64                          x",
"       128                              x",
"       255  x   x   x   x   x   x   x   x",
" ",
"        AP  Anonymous Private Memory",
"        AS  Anonymous Shared Memory",
"        FP  File-Backed Private Memory",
"        FS  File-Backed Shared Memory",
"        ELF ELF header pages in file-backed private memory areas",
"        HP  Hugetlb Private Memory",
"        HS  Hugetlb Shared Memory",
"        DD  Memory advised using madvise with MADV_DONTDUMP flag",
" ",
"    -V Display version information",
"  ",
"  If no pid or taskp is specified, gcore tries to retrieve the process image",
"  of the current task context.",
"  ",
"  The file name of a generated core dump is core.<pid> where pid is PID of",
"  the specified process.",
"  ",
"  For a multi-thread process, gcore generates a core dump containing",
"  information for all threads, which is similar to a behaviour of the ELF",
"  core dumper in Linux kernel.",
"  ",
"  Notice the difference of PID on between crash and linux that ps command in",
"  crash utility displays LWP, while ps command in Linux thread group tid,",
"  precisely PID of the thread group leader.",
"  ",
"  gcore provides core dump filtering facility to allow users to select what",
"  kinds of memory maps to be included in the resulting core dump. There are",
"  7 kinds memory maps in total, and you can set it up with set command.",
"  For more detailed information, please see a help command message.",
"  ",
"EXAMPLES",
"  Specify the process you want to retrieve as a core dump. Here assume the",
"  process with PID 12345.",
"  ",
"    crash> gcore 12345",
"    Saved core.12345",
"    crash>",
"  ",
"  Next, specify by TASK. Here assume the process placing at the address",
"  f9d7000 with PID 32323.",
"  ",
"    crash> gcore f9d78000",
"    Saved core.32323",
"    crash>",
"  ",
"  If multiple arguments are given, gcore performs dumping process in the",
"  order the arguments are given.",
"  ",
"    crash> gcore 5217 ffff880136d72040 23299 24459 ffff880136420040",
"    Saved core.5217",
"    Saved core.1130",
"    Saved core.1130",
"    Saved core.24459",
"    Saved core.30102",
"    crash>",
"  ",
"  If no argument is given, gcore tries to retrieve the process of the current",
"  task context.",
"  ",
"    crash> set",
"         PID: 54321",
"     COMMAND: \"bash\"",
"        TASK: e0000040f80c0000",
"         CPU: 0",
"       STATE: TASK_INTERRUPTIBLE",
"    crash> gcore",
"    Saved core.54321",
"  ",
"  When a multi-thread process is specified, the generated core file name has",
"  the thread leader's PID; here it is assumed to be 12340.",
"  ",
"    crash> gcore 12345",
"    Saved core.12340",
"  ",
"  It is not allowed to specify two same options at the same time.",
"  ",
"    crash> gcore -v 1 1234 -v 1",
"    Usage: gcore",
"      gcore [-v vlevel] [-f filter] [pid | taskp]*",
"      gcore -d",
"    Enter \"help gcore\" for details.",
"  ",
"  It is allowed to specify -v and -f options in a different order.",
"  ",
"    crash> gcore -v 2 5201 -f 21 ffff880126ff9520 5205",
"    Saved core.5174",
"    Saved core.5217",
"    Saved core.5167",
"    crash> gcore 5201 ffff880126ff9520 -f 21 5205 -v 2",
"    Saved core.5174",
"    Saved core.5217",
"    Saved core.5167",
"  ",
NULL,
};

void
cmd_gcore(void)
{
	char *foptarg, *voptarg;
	int c, optversion;

	if (ACTIVE())
		error(FATAL, "no support on live kernel\n");

	gcore_dumpfilter_set_default();
	gcore_verbose_set_default();

	foptarg = voptarg = NULL;
	optversion = FALSE;

	while ((c = getopt(argcnt, args, "f:v:V")) != EOF) {
		switch (c) {
		case 'V':
			optversion = TRUE;
			break;
		case 'f':
			if (foptarg)
				goto argerr;
			foptarg = optarg;
			break;
		case 'v':
			if (voptarg)
				goto argerr;
			voptarg = optarg;
			break;
		default:
		argerr:
			argerrs++;
			break;
		}
	}

	if (argerrs) {
		cmd_usage(pc->curcmd, SYNOPSIS);
	}

	if (optversion) {
		print_version();
		return;
	}

	if (foptarg) {
		ulong value;

		if (!decimal(foptarg, 0))
			error(FATAL, "filter must be a decimal: %s.\n",
			      foptarg);

		value = stol(foptarg, gcore_verbose_error_handle(), NULL);
		if (!gcore_dumpfilter_set(value))
			error(FATAL, "invalid filter value: %s.\n", foptarg);
	}

	if (voptarg) {
		ulong value;

		if (!decimal(voptarg, 0))
			error(FATAL, "vlevel must be a decimal: %s.\n",
			      voptarg);

		value = stol(voptarg, gcore_verbose_error_handle(), NULL);
		if (!gcore_verbose_set(value))
			error(FATAL, "invalid vlevel: %s.\n", voptarg);

	}

	if (!args[optind]) {
		do_gcore(NULL);
		return;
	}

	for (; args[optind]; optind++) {
		do_gcore(args[optind]);
		free_all_bufs();
	}

}

/**
 * do_gcore - do process core dump for a given task
 *
 * @arg string that refers to PID or task context's address
 *
 * Given the string, arg, refering to PID or task context's address,
 * do_gcore tries to do process coredump for the corresponding
 * task. If the string given is NULL, do_gcore does the process dump
 * for the current task context.
 *
 * Here is the unique exception point in gcore sub-command. Any fatal
 * action during gcore sub-command will come back here. Look carefully
 * at how IN_FOREACH is used here.
 *
 * Dynamic allocation in gcore sub-command fully depends on buffer
 * mechanism provided by crash utility. do_gcore() never makes freeing
 * operation. Thus, it is necessary to call free_all_bufs() each time
 * calling do_gcore(). See the end of cmd_gcore().
 */
static void do_gcore(char *arg)
{
	if (!setjmp(pc->foreach_loop_env)) {
		struct task_context *tc;
		ulong dummy;

		BZERO(gcore, sizeof(struct gcore_one_session_data));

		pc->flags |= IN_FOREACH;

		if (arg) {
			if (!IS_A_NUMBER(arg))
				error(FATAL, "neither pid nor taskp: %s\n",
				      args[optind]);

			if (STR_INVALID == str_to_context(arg, &dummy, &tc))
				error(FATAL, "invalid task or pid: %s\n",
				      args[optind]);
		} else
			tc = CURRENT_CONTEXT();

		if (is_kernel_thread(tc->task))
			error(FATAL, "The specified task is a kernel thread.\n");

		if (tc != CURRENT_CONTEXT()) {
			gcore->orig_task = CURRENT_TASK();
			(void) set_context(tc->task, NO_PID);
		}

		snprintf(gcore->corename, CORENAME_MAX_SIZE + 1, "core.%lu.%s",
			 task_tgid(CURRENT_TASK()), CURRENT_COMM());

		gcore_elf_init(gcore);

		gcore_coredump();
	}

	pc->flags &= ~IN_FOREACH;

	if (gcore->fp != NULL) {
		if (fflush(gcore->fp) == EOF) {
			error(FATAL, "%s: flush %s\n", gcore->corename,
			      strerror(errno));
		}
		if (fclose(gcore->fp) == EOF) {
			gcore->fp = NULL;
			error(FATAL, "%s: close %s\n", gcore->corename,
			      strerror(errno));
		}
		gcore->fp = NULL;
	}

	if (gcore->flags & GCF_UNDER_COREDUMP) {
		if (gcore->flags & GCF_SUCCESS)
			fprintf(fp, "Saved %s\n", gcore->corename);
		else
			fprintf(fp, "Failed.\n");
	}

	if (gcore->orig_task)
		(void)set_context(gcore->orig_task, NO_PID);

}

static void print_version(void)
{
	fprintf(fp, "crash gcore command: version " VERSION " (released on "
		RELEASE_DATE ")\n");
	fprintf(fp, "Copyright (C) " PERIOD "  Fujitsu Limited\n");
}

static void gcore_offset_table_init(void)
{
	GCORE_MEMBER_OFFSET_INIT(cpuinfo_x86_x86_capability, "cpuinfo_x86", "x86_capability");
	GCORE_MEMBER_OFFSET_INIT(cred_gid, "cred", "gid");
	GCORE_MEMBER_OFFSET_INIT(cred_uid, "cred", "uid");
	GCORE_MEMBER_OFFSET_INIT(desc_struct_base0, "desc_struct", "base0");
	GCORE_MEMBER_OFFSET_INIT(desc_struct_base1, "desc_struct", "base1");
	GCORE_MEMBER_OFFSET_INIT(desc_struct_base2, "desc_struct", "base2");
	GCORE_MEMBER_OFFSET_INIT(fpu_state, "fpu", "state");
	GCORE_MEMBER_OFFSET_INIT(inode_i_nlink, "inode", "i_nlink");
	if (GCORE_INVALID_MEMBER(inode_i_nlink))
		GCORE_ANON_MEMBER_OFFSET_INIT(inode_i_nlink, "inode", "i_nlink");
	GCORE_MEMBER_OFFSET_INIT(nsproxy_pid_ns, "nsproxy", "pid_ns");
	if (GCORE_INVALID_MEMBER(nsproxy_pid_ns))
		GCORE_MEMBER_OFFSET_INIT(nsproxy_pid_ns, "nsproxy", "pid_ns_for_children");
	GCORE_MEMBER_OFFSET_INIT(mm_context_t_vdso, "mm_context_t", "vdso");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_arg_start, "mm_struct", "arg_start");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_arg_end, "mm_struct", "arg_end");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_map_count, "mm_struct", "map_count");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_reserved_vm, "mm_struct", "reserved_vm");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_saved_files, "mm_struct", "saved_files");
	GCORE_MEMBER_OFFSET_INIT(mm_struct_context, "mm_struct", "context");
	GCORE_MEMBER_OFFSET_INIT(pid_level, "pid", "level");
	GCORE_MEMBER_OFFSET_INIT(pid_namespace_level, "pid_namespace", "level");
        if (MEMBER_EXISTS("pt_regs", "ax"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ax, "pt_regs", "ax");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ax, "pt_regs", "eax");
        if (MEMBER_EXISTS("pt_regs", "bp"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_bp, "pt_regs", "bp");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_bp, "pt_regs", "ebp");
        if (MEMBER_EXISTS("pt_regs", "bx"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_bx, "pt_regs", "bx");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_bx, "pt_regs", "ebx");
        if (MEMBER_EXISTS("pt_regs", "cs"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_cs, "pt_regs", "cs");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_cs, "pt_regs", "xcs");
        if (MEMBER_EXISTS("pt_regs", "cx"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_cx, "pt_regs", "cx");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_cx, "pt_regs", "ecx");
        if (MEMBER_EXISTS("pt_regs", "di"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_di, "pt_regs", "di");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_di, "pt_regs", "edi");
        if (MEMBER_EXISTS("pt_regs", "ds"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ds, "pt_regs", "ds");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ds, "pt_regs", "xds");
        if (MEMBER_EXISTS("pt_regs", "dx"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_dx, "pt_regs", "dx");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_dx, "pt_regs", "edx");
        if (MEMBER_EXISTS("pt_regs", "es"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_es, "pt_regs", "es");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_es, "pt_regs", "xes");
        if (MEMBER_EXISTS("pt_regs", "flags"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_flags, "pt_regs", "flags");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_flags, "pt_regs", "eflags");
	GCORE_MEMBER_OFFSET_INIT(pt_regs_fs, "pt_regs", "fs");
	GCORE_MEMBER_OFFSET_INIT(pt_regs_gs, "pt_regs", "gs");
        if (MEMBER_EXISTS("pt_regs", "ip"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ip, "pt_regs", "ip");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ip, "pt_regs", "eip");
        if (MEMBER_EXISTS("pt_regs", "orig_eax"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_orig_ax, "pt_regs", "orig_eax");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_orig_ax, "pt_regs", "orig_ax");
        if (MEMBER_EXISTS("pt_regs", "si"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_si, "pt_regs", "si");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_si, "pt_regs", "esi");
        if (MEMBER_EXISTS("pt_regs", "sp"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_sp, "pt_regs", "sp");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_sp, "pt_regs", "esp");
        if (MEMBER_EXISTS("pt_regs", "ss"))
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ss, "pt_regs", "ss");
        else
	  GCORE_MEMBER_OFFSET_INIT(pt_regs_ss, "pt_regs", "xss");
	GCORE_MEMBER_OFFSET_INIT(pt_regs_xfs, "pt_regs", "xfs");
	GCORE_MEMBER_OFFSET_INIT(pt_regs_xgs, "pt_regs", "xgs");
	GCORE_MEMBER_OFFSET_INIT(sched_entity_sum_exec_runtime, "sched_entity", "sum_exec_runtime");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_cutime, "signal_struct", "cutime");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_pgrp, "signal_struct", "pgrp");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_session, "signal_struct", "session");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_stime, "signal_struct", "stime");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_sum_sched_runtime, "signal_struct", "sum_sched_runtime");
	GCORE_MEMBER_OFFSET_INIT(signal_struct_utime, "signal_struct", "utime");
	GCORE_MEMBER_OFFSET_INIT(task_struct_cred, "task_struct", "cred");
	GCORE_MEMBER_OFFSET_INIT(task_struct_gid, "task_struct", "gid");
	GCORE_MEMBER_OFFSET_INIT(task_struct_group_leader, "task_struct", "group_leader");
	GCORE_MEMBER_OFFSET_INIT(task_struct_real_cred, "task_struct", "real_cred");
	if (MEMBER_EXISTS("task_struct", "real_parent"))
		GCORE_MEMBER_OFFSET_INIT(task_struct_real_parent, "task_struct", "real_parent");
	else if (MEMBER_EXISTS("task_struct", "parent"))
		GCORE_MEMBER_OFFSET_INIT(task_struct_real_parent, "task_struct", "parent");
	GCORE_MEMBER_OFFSET_INIT(task_struct_se, "task_struct", "se");
	GCORE_MEMBER_OFFSET_INIT(task_struct_static_prio, "task_struct", "static_prio");
	GCORE_MEMBER_OFFSET_INIT(task_struct_uid, "task_struct", "uid");
	GCORE_MEMBER_OFFSET_INIT(task_struct_used_math, "task_struct", "used_math");
	GCORE_MEMBER_OFFSET_INIT(thread_info_status, "thread_info", "status");
	GCORE_MEMBER_OFFSET_INIT(thread_info_fpstate, "thread_info", "fpstate");
	GCORE_MEMBER_OFFSET_INIT(thread_info_vfpstate, "thread_info", "vfpstate");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_ds, "thread_struct", "ds");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_es, "thread_struct", "es");
	if (MEMBER_EXISTS("thread_struct", "fs"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_fs, "thread_struct", "fs");
	else
		GCORE_MEMBER_OFFSET_INIT(thread_struct_fs, "thread_struct", "fsbase");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_fsindex, "thread_struct", "fsindex");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_fpu, "thread_struct", "fpu");
	if (MEMBER_EXISTS("thread_struct", "gs"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_gs, "thread_struct", "gs");
	else
		GCORE_MEMBER_OFFSET_INIT(thread_struct_gs, "thread_struct", "gsbase");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_gsindex, "thread_struct", "gsindex");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_i387, "thread_struct", "i387");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_tls_array, "thread_struct", "tls_array");
	if (MEMBER_EXISTS("thread_struct", "usersp"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_usersp, "thread_struct", "usersp");
	else if (MEMBER_EXISTS("thread_struct", "userrsp"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_usersp, "thread_struct", "userrsp");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_sp0, "thread_struct", "sp0");
	if (MEMBER_EXISTS("thread_struct", "xstate"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_xstate, "thread_struct", "xstate");
	else if (MEMBER_EXISTS("thread_struct", "i387"))
		GCORE_MEMBER_OFFSET_INIT(thread_struct_xstate, "thread_struct", "i387");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_io_bitmap_max, "thread_struct", "io_bitmap_max");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_io_bitmap_ptr, "thread_struct", "io_bitmap_ptr");
	if (GCORE_INVALID_MEMBER(thread_struct_io_bitmap_max)) {
		GCORE_MEMBER_OFFSET_INIT(thread_struct_io_bitmap_max, "io_bitmap", "max");
		GCORE_MEMBER_OFFSET_INIT(thread_struct_io_bitmap_ptr, "io_bitmap", "bitmap");
	}
	GCORE_MEMBER_OFFSET_INIT(user_regset_n, "user_regset", "n");
	GCORE_MEMBER_OFFSET_INIT(vm_area_struct_anon_vma, "vm_area_struct", "anon_vma");
	GCORE_MEMBER_OFFSET_INIT(vm_area_struct_vm_ops, "vm_area_struct", "vm_ops");
	GCORE_MEMBER_OFFSET_INIT(vm_area_struct_vm_private_data, "vm_area_struct", "vm_private_data");
	GCORE_MEMBER_OFFSET_INIT(vm_operations_struct_name, "vm_operations_struct", "name");
	GCORE_MEMBER_OFFSET_INIT(vm_special_mapping_name, "vm_special_mapping", "name");

	if (symbol_exists("_cpu_pda"))
		GCORE_MEMBER_OFFSET_INIT(x8664_pda_oldrsp, "x8664_pda", "oldrsp");
	GCORE_MEMBER_OFFSET_INIT(vfp_state_hard, "vfp_state", "hard");
	GCORE_MEMBER_OFFSET_INIT(vfp_hard_struct_fpregs, "vfp_hard_struct", "fpregs");
	GCORE_MEMBER_OFFSET_INIT(vfp_hard_struct_fpscr, "vfp_hard_struct", "fpscr");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_fpsimd_state, "thread_struct", "fpsimd_state");
	GCORE_MEMBER_OFFSET_INIT(thread_struct_tp_value, "thread_struct", "tp_value");
	if (GCORE_INVALID_MEMBER(thread_struct_fpsimd_state)) {
		GCORE_ANON_MEMBER_OFFSET_INIT(thread_struct_fpsimd_state, "thread_struct", "uw.fpsimd_state");
		GCORE_ANON_MEMBER_OFFSET_INIT(thread_struct_tp_value, "thread_struct", "uw.tp_value");
	}
	if (MEMBER_EXISTS("task_struct", "thread_pid"))
		GCORE_MEMBER_OFFSET_INIT(task_struct_thread_pid, "task_struct", "thread_pid");
	if (MEMBER_EXISTS("signal_struct", "pids"))
		GCORE_MEMBER_OFFSET_INIT(signal_struct_pids, "signal_struct", "pids");
}

static void gcore_size_table_init(void)
{
	GCORE_STRUCT_SIZE_INIT(i387_union, "i387_union");
	GCORE_STRUCT_SIZE_INIT(mm_context_t, "mm_context_t");
	GCORE_MEMBER_SIZE_INIT(mm_struct_saved_auxv, "mm_struct", "saved_auxv");
	GCORE_MEMBER_SIZE_INIT(mm_struct_saved_files, "mm_struct", "saved_files");
	GCORE_MEMBER_SIZE_INIT(thread_struct_ds, "thread_struct", "ds");
	GCORE_MEMBER_SIZE_INIT(thread_struct_es, "thread_struct", "es");
	if (MEMBER_EXISTS("thread_struct", "fs"))
		GCORE_MEMBER_SIZE_INIT(thread_struct_fs, "thread_struct", "fs");
	else
		GCORE_MEMBER_SIZE_INIT(thread_struct_fs, "thread_struct", "fsbase");
	GCORE_MEMBER_SIZE_INIT(thread_struct_fsindex, "thread_struct", "fsindex");
	if (MEMBER_EXISTS("thread_struct", "gs"))
		GCORE_MEMBER_SIZE_INIT(thread_struct_gs, "thread_struct", "gs");
	else
		GCORE_MEMBER_SIZE_INIT(thread_struct_gs, "thread_struct", "gsbase");
	GCORE_MEMBER_SIZE_INIT(thread_struct_gsindex, "thread_struct", "gsindex");
	GCORE_MEMBER_SIZE_INIT(thread_struct_tls_array, "thread_struct", "tls_array");
	GCORE_STRUCT_SIZE_INIT(thread_xstate, "thread_xstate");
	GCORE_MEMBER_SIZE_INIT(vm_area_struct_anon_vma, "vm_area_struct", "anon_vma");
	GCORE_MEMBER_SIZE_INIT(vfp_hard_struct_fpregs, "vfp_hard_struct", "fpregs");
	GCORE_MEMBER_SIZE_INIT(vfp_hard_struct_fpscr, "vfp_hard_struct", "fpscr");

}

static void gcore_machdep_init(void)
{
	if (STRUCT_EXISTS("fault_data") || STRUCT_EXISTS("vm_fault"))
		gcore_machdep->vm_alwaysdump = 0x04000000;
	else
		gcore_machdep->vm_alwaysdump = 0x08000000;

	if (!gcore_arch_vsyscall_has_vm_alwaysdump_flag())
		gcore_machdep->vm_alwaysdump = 0x00000000;
}
