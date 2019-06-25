/* gcore_coredump_table.c -- core analysis suite
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

#include <defs.h>
#include <gcore_defs.h>

static unsigned int get_inode_i_nlink_v0(ulong file);
static unsigned int get_inode_i_nlink_v19(ulong file);
static pid_t pid_nr_ns(ulong pid, ulong ns);
static int pid_alive(ulong task);
static int __task_pid_nr_ns(ulong task, enum pid_type type);
static inline pid_t task_pid(ulong task);
static inline pid_t process_group(ulong task);
static inline pid_t task_session(ulong task);
static inline pid_t task_pid_vnr(ulong task);
static inline pid_t task_pgrp_vnr(ulong task);
static inline pid_t task_session_vnr(ulong task);
static void
thread_group_cputime_v0(ulong task, struct task_cputime *cputime);
static void
thread_group_cputime_v22(ulong task, struct task_cputime *cputime);
static inline __kernel_uid_t task_uid_v0(ulong task);
static inline __kernel_uid_t task_uid_v28(ulong task);
static inline __kernel_gid_t task_gid_v0(ulong task);
static inline __kernel_gid_t task_gid_v28(ulong task);

void gcore_coredump_table_init(void)
{
	/*
         * struct path was introduced at v2.6.19, where f_dentry
         * member of struct file was replaced by f_path member.
	 *
	 * See vfs_init() to know why this condition is chosen.
	 *
	 * See commit 0f7fc9e4d03987fe29f6dd4aa67e4c56eb7ecb05.
	 */
	if (VALID_MEMBER(file_f_path))
		ggt->get_inode_i_nlink = get_inode_i_nlink_v19;
	else
		ggt->get_inode_i_nlink = get_inode_i_nlink_v0;

	/*
	 * task_pid_vnr() and relevant helpers were introduced at
	 * v2.6.23, while pid_namespace itself was introduced prior to
	 * that at v2.6.19.
	 *
	 * We've choosed here the former commit because implemented
	 * enough to provide pid facility was the period when the
	 * former patches were committed.
	 *
	 * We've chosen symbol ``pid_nr_ns'' because it is just a
	 * unique function that is not defined as static inline.
	 *
	 * See commit 7af5729474b5b8ad385adadab78d6e723e7655a3.
	 */
	if (symbol_exists("pid_nr_ns")) {
		ggt->task_pid = task_pid_vnr;
		ggt->task_pgrp = task_pgrp_vnr;
		ggt->task_session = task_session_vnr;
	} else {
		ggt->task_pid = task_pid;
		ggt->task_pgrp = process_group;
		ggt->task_session = task_session;
	}

	/*
	 * The way of tracking cputime changed when CFS was introduced
	 * at v2.6.23, which can be distinguished by checking whether
	 * se member of task_struct structure exist or not.
	 *
	 * See commit 20b8a59f2461e1be911dce2cfafefab9d22e4eee.
	 */
	if (GCORE_VALID_MEMBER(task_struct_se))
		ggt->thread_group_cputime = thread_group_cputime_v22;
	else
		ggt->thread_group_cputime = thread_group_cputime_v0;

        /*
	 * Credidentials feature was introduced at v2.6.28 where uid
	 * and gid members were moved into cred member of struct
	 * task_struct that was newly introduced.
	 *
         * See commit b6dff3ec5e116e3af6f537d4caedcad6b9e5082a.
	 */
	if (GCORE_VALID_MEMBER(task_struct_cred)) {
		ggt->task_uid = task_uid_v28;
		ggt->task_gid = task_gid_v28;
	} else {
		ggt->task_uid = task_uid_v0;
		ggt->task_gid = task_gid_v0;
	}

}

static unsigned int get_inode_i_nlink_v0(ulong file)
{
	ulong d_entry, d_inode;
	unsigned int i_nlink;

	readmem(file + OFFSET(file_f_dentry), KVADDR, &d_entry, sizeof(d_entry),
		"get_inode_i_nlink_v0: d_entry", gcore_verbose_error_handle());

	readmem(d_entry + OFFSET(dentry_d_inode), KVADDR, &d_inode,
		sizeof(d_inode), "get_inode_i_nlink_v0: d_inode",
		gcore_verbose_error_handle());

	readmem(d_inode + GCORE_OFFSET(inode_i_nlink), KVADDR, &i_nlink,
		sizeof(i_nlink), "get_inode_i_nlink_v0: i_nlink",
		gcore_verbose_error_handle());

	return i_nlink;
}

static unsigned int get_inode_i_nlink_v19(ulong file)
{
	ulong d_entry, d_inode;
	unsigned int i_nlink;

	readmem(file + OFFSET(file_f_path) + OFFSET(path_dentry), KVADDR,
		&d_entry, sizeof(d_entry), "get_inode_i_nlink_v19: d_entry",
		gcore_verbose_error_handle());

	readmem(d_entry + OFFSET(dentry_d_inode), KVADDR, &d_inode, sizeof(d_inode),
		"get_inode_i_nlink_v19: d_inode", gcore_verbose_error_handle());

	readmem(d_inode + GCORE_OFFSET(inode_i_nlink), KVADDR, &i_nlink,
		sizeof(i_nlink), "get_inode_i_nlink_v19: i_nlink",
		gcore_verbose_error_handle());

	return i_nlink;
}

static inline pid_t
task_pid(ulong task)
{
	return task_to_context(task)->pid;
}

static inline pid_t
process_group(ulong task)
{
	ulong signal;
	pid_t pgrp;

	readmem(task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "process_group: signal", gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_pgrp), KVADDR, &pgrp,
		sizeof(pgrp), "process_group: pgrp", gcore_verbose_error_handle());

	return pgrp;
}

static inline pid_t
task_session(ulong task)
{
	ulong signal;
	pid_t session;

	readmem(task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "process_group: signal", gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_session), KVADDR,
		&session, sizeof(session), "task_session: session",
		gcore_verbose_error_handle());

	return session;
}

static pid_t
pid_nr_ns(ulong pid, ulong ns)
{
	ulong upid;
	unsigned int ns_level, pid_level;
	pid_t nr = 0;

	readmem(ns + GCORE_OFFSET(pid_namespace_level), KVADDR, &ns_level,
		sizeof(ns_level), "pid_nr_ns: ns_level", gcore_verbose_error_handle());

	readmem(pid + GCORE_OFFSET(pid_level), KVADDR, &pid_level,
		sizeof(pid_level), "pid_nr_ns: pid_level", gcore_verbose_error_handle());

        if (pid && ns_level <= pid_level) {
		ulong upid_ns;

		upid = pid + OFFSET(pid_numbers) + SIZE(upid) * ns_level;

		readmem(upid + OFFSET(upid_ns), KVADDR, &upid_ns,
			sizeof(upid_ns), "pid_nr_ns: upid_ns",
			gcore_verbose_error_handle());

		if (upid_ns == ns)
			readmem(upid + OFFSET(upid_nr), KVADDR, &nr,
				sizeof(ulong), "pid_nr_ns: upid_nr",
				gcore_verbose_error_handle());
        }

        return nr;
}

static int
__task_pid_nr_ns(ulong task, enum pid_type type)
{
	ulong nsproxy, ns;
	int nr = 0;

	readmem(task + OFFSET(task_struct_nsproxy), KVADDR, &nsproxy,
		sizeof(nsproxy), "__task_pid_nr_ns: nsproxy",
		gcore_verbose_error_handle());

	readmem(nsproxy + GCORE_OFFSET(nsproxy_pid_ns), KVADDR, &ns,
		sizeof(ns), "__task_pid_nr_ns: ns", gcore_verbose_error_handle());

	if (pid_alive(task)) {
		ulong pids_type_pid, signal;

                if (type != PIDTYPE_PID)
			readmem(task + MEMBER_OFFSET("task_struct",
						     "group_leader"),
				KVADDR, &task, sizeof(ulong),
				"__task_pid_nr_ns: group_leader",
				gcore_verbose_error_handle());

		if (VALID_MEMBER(task_struct_pids))
			readmem(task + OFFSET(task_struct_pids) +
				type * SIZE(pid_link) + OFFSET(pid_link_pid),
				KVADDR, &pids_type_pid,
				sizeof(pids_type_pid),
				"__task_pid_nr_ns: pids_type_pid",
				gcore_verbose_error_handle());
		else
			if (type == PIDTYPE_PID)
				readmem(task + GCORE_OFFSET(task_struct_thread_pid),
					KVADDR, &pids_type_pid,
					sizeof(pids_type_pid),
					"__task_pid_nr_ns: pids_type_pid",
					gcore_verbose_error_handle());
			else {
				readmem(task + OFFSET(task_struct_signal),
					KVADDR, &signal,
					sizeof(signal),
					"__task_pid_nr_ns: signal",
					gcore_verbose_error_handle());

				readmem(signal + GCORE_OFFSET(signal_struct_pids) +
					type * sizeof(void *),
					KVADDR, &pids_type_pid,
					sizeof(pids_type_pid),
					"__task_pid_nr_ns: pids_type_pid",
					gcore_verbose_error_handle());
			}

		nr = pid_nr_ns(pids_type_pid, ns);
        }

        return nr;
}

static inline pid_t
task_pid_vnr(ulong task)
{
	return __task_pid_nr_ns(task, PIDTYPE_PID);
}

static inline pid_t
task_pgrp_vnr(ulong task)
{
        return __task_pid_nr_ns(task, PIDTYPE_PGID);
}

static inline pid_t
task_session_vnr(ulong task)
{
        return __task_pid_nr_ns(task, PIDTYPE_SID);
}

static void
thread_group_cputime_v0(ulong task, struct task_cputime *cputime)
{
	ulong signal;
	ulong utime, signal_utime, stime, signal_stime;

	readmem(task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "thread_group_cputime_v0: signal",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_utime), KVADDR, &utime,
		sizeof(utime), "thread_group_cputime_v0: utime",
		gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_utime), KVADDR,
		&signal_utime, sizeof(signal_utime),
		"thread_group_cputime_v0: signal_utime",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_stime), KVADDR, &stime,
		sizeof(stime), "thread_group_cputime_v0: stime",
		gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_stime), KVADDR,
		&signal_stime, sizeof(signal_stime),
		"thread_group_cputime_v0: signal_stime",
		gcore_verbose_error_handle());

	cputime->utime = utime + signal_utime;
	cputime->stime = stime + signal_stime;
	cputime->sum_exec_runtime = 0;

}

static void
thread_group_cputime_v22(ulong task, struct task_cputime *times)
{
	struct task_context *tc;
	ulong sighand, signal, signal_utime, signal_stime;
	uint64_t sum_sched_runtime;

	*times = INIT_CPUTIME;

	readmem(task + OFFSET(task_struct_sighand), KVADDR, &sighand,
		sizeof(sighand), "thread_group_cputime_v22: sighand",
		gcore_verbose_error_handle());

	if (!sighand)
		goto out;

	readmem(task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "thread_group_cputime_v22: signal",
		gcore_verbose_error_handle());

	FOR_EACH_TASK_IN_THREAD_GROUP(task_tgid(CURRENT_TASK()), tc) {
		ulong utime, stime;
		uint64_t sum_exec_runtime;

		readmem(tc->task + OFFSET(task_struct_utime), KVADDR,
			&utime,	sizeof(utime),
			"thread_group_cputime_v22: utime",
			gcore_verbose_error_handle());

		readmem(tc->task + OFFSET(task_struct_stime), KVADDR,
			&stime, sizeof(stime),
			"thread_group_cputime_v22: stime",
			gcore_verbose_error_handle());

		readmem(tc->task + GCORE_OFFSET(task_struct_se) +
			GCORE_OFFSET(sched_entity_sum_exec_runtime),
			KVADDR,	&sum_exec_runtime,
			sizeof(sum_exec_runtime),
			"thread_group_cputime_v22: sum_exec_runtime",
			gcore_verbose_error_handle());

		times->utime = cputime_add(times->utime, utime);
		times->stime = cputime_add(times->stime, stime);
		times->sum_exec_runtime += sum_exec_runtime;
	}

	readmem(signal + GCORE_OFFSET(signal_struct_utime), KVADDR,
		&signal_utime, sizeof(signal_utime),
		"thread_group_cputime_v22: signal_utime", gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_stime), KVADDR,
		&signal_stime, sizeof(signal_stime),
		"thread_group_cputime_v22: signal_stime", gcore_verbose_error_handle());

	readmem(signal + GCORE_OFFSET(signal_struct_sum_sched_runtime),
		KVADDR, &sum_sched_runtime, sizeof(sum_sched_runtime),
		"thread_group_cputime_v22: sum_sched_runtime",
		gcore_verbose_error_handle());

	times->utime = cputime_add(times->utime, signal_utime);
	times->stime = cputime_add(times->stime, signal_stime);
	times->sum_exec_runtime += sum_sched_runtime;

out:
	return;
}

static inline __kernel_uid_t
task_uid_v0(ulong task)
{
	__kernel_uid_t uid;

	readmem(task + GCORE_OFFSET(task_struct_uid), KVADDR, &uid,
		sizeof(uid), "task_uid_v0: uid", gcore_verbose_error_handle());

	return uid;
}

static inline __kernel_uid_t
task_uid_v28(ulong task)
{
	ulong cred;
	__kernel_uid_t uid;

	readmem(task + GCORE_OFFSET(task_struct_real_cred), KVADDR, &cred,
		sizeof(cred), "task_uid_v28: real_cred", gcore_verbose_error_handle());

	readmem(cred + GCORE_OFFSET(cred_uid), KVADDR, &uid, sizeof(uid),
		"task_uid_v28: uid", gcore_verbose_error_handle());

	return uid;
}

static inline __kernel_gid_t
task_gid_v0(ulong task)
{
	__kernel_gid_t gid;

	readmem(task + GCORE_OFFSET(task_struct_gid), KVADDR, &gid,
		sizeof(gid), "task_gid_v0: gid", gcore_verbose_error_handle());

	return gid;
}

static inline __kernel_gid_t
task_gid_v28(ulong task)
{
	ulong cred;
	__kernel_gid_t gid;

	readmem(task + GCORE_OFFSET(task_struct_real_cred), KVADDR, &cred,
		sizeof(cred), "task_gid_v28: real_cred", gcore_verbose_error_handle());

	readmem(cred + GCORE_OFFSET(cred_gid), KVADDR, &gid, sizeof(gid),
		"task_gid_v28: gid", gcore_verbose_error_handle());

	return gid;
}

static int
pid_alive(ulong task)
{
	pid_t pid;

	if (VALID_MEMBER(task_struct_pids))
		readmem(task + OFFSET(task_struct_pids) +
			PIDTYPE_PID * SIZE(pid_link) + OFFSET(pid_link_pid),
			KVADDR, &pid, sizeof(pid),
			"pid_alive",
			gcore_verbose_error_handle());
	else
		readmem(task + GCORE_OFFSET(task_struct_thread_pid),
			KVADDR, &pid, sizeof(pid),
			"task_struct.thread_pid",
			gcore_verbose_error_handle());

        return !!pid;
}
