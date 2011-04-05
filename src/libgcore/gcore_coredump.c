/* gcore_coredump.c -- core analysis suite
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

static struct elf_note_info *elf_note_info_init(void);

static void fill_prstatus_note(struct elf_note_info *info,
			       struct elf_thread_core_info *t,
			       const struct thread_group_list *tglist,
			       void *pr_reg);
static void fill_psinfo_note(struct elf_note_info *info, ulong task);
static void fill_auxv_note(struct elf_note_info *info, ulong task);

#ifdef GCORE_ARCH_COMPAT
static void compat_fill_prstatus_note(struct elf_note_info *info,
				      struct elf_thread_core_info *t,
				      const struct thread_group_list *tglist,
				      void *pr_reg);
static void compat_fill_psinfo_note(struct elf_note_info *info, ulong task);
static void compat_fill_auxv_note(struct elf_note_info *info, ulong task);
#endif

static int fill_thread_group(struct thread_group_list **tglist);
static void fill_thread_core_info(struct elf_thread_core_info *t,
				  struct elf_note_info *info,
				  const struct user_regset_view *view,
				  size_t *total,
				  struct thread_group_list *tglist);
static int fill_note_info(struct elf_note_info *info,
			  struct thread_group_list *tglist, int phnum);
static void fill_note(struct memelfnote *note, const char *name, int type,
		      unsigned int sz, void *data);

static int notesize(struct memelfnote *en);
static void alignfile(int fd, off_t *foffset);
static void writenote(struct memelfnote *men, int fd, off_t *foffset);
static void write_note_info(int fd, struct elf_note_info *info, off_t *foffset);
static size_t get_note_info_size(struct elf_note_info *info);
static ulong first_vma(ulong mmap, ulong gate_vma);
static ulong next_vma(ulong this_vma, ulong gate_vma);

static inline int thread_group_leader(ulong task);

void gcore_coredump(void)
{
	struct thread_group_list *tglist = NULL;
	struct elf_note_info *info;
	int map_count, phnum;
	ulong vma, index, mmap;
	off_t offset, foffset, dataoff;
	char *mm_cache, *buffer = NULL;
	ulong gate_vma;

	gcore->flags |= GCF_UNDER_COREDUMP;

	mm_cache = fill_mm_struct(task_mm(CURRENT_TASK(), TRUE));
	if (!mm_cache)
		error(FATAL, "The user memory space does not exist.\n");

	mmap = ULONG(mm_cache + OFFSET(mm_struct_mmap));
	map_count = INT(mm_cache + GCORE_OFFSET(mm_struct_map_count));

	progressf("Restoring the thread group ... \n");
	fill_thread_group(&tglist);
	progressf("done.\n");

	phnum = map_count;
	phnum++; /* for note information */
	gate_vma = gcore_arch_get_gate_vma();
	if (gate_vma)
		phnum++;

	info = elf_note_info_init();

	progressf("Retrieving note information ... \n");
	fill_note_info(info, tglist, phnum);
	progressf("done.\n");

	progressf("Opening file %s ... \n", gcore->corename);
	gcore->fd = open(gcore->corename, O_WRONLY|O_TRUNC|O_CREAT,
			 S_IRUSR|S_IWUSR);
	if (gcore->fd < 0)
		error(FATAL, "%s: open: %s\n", gcore->corename,
		      strerror(errno));
	progressf("done.\n");

	progressf("Writing ELF header ... \n");
	if (!gcore->elf->ops->write_elf_header(gcore->elf, gcore->fd))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));
	progressf(" done.\n");

	if (gcore->elf->ops->get_e_shoff(gcore->elf)) {
		progressf("Writing section header table ... \n");
		if (!gcore->elf->ops->write_section_header(gcore->elf,
							   gcore->fd))
			error(FATAL, "%s: gcore: %s\n", gcore->corename,
			      strerror(errno));
		progressf("done.\n");
	}

	offset = gcore->elf->ops->calc_segment_offset(gcore->elf);
	foffset = offset;

	progressf("Writing PT_NOTE program header ... \n");
	gcore->elf->ops->fill_program_header(gcore->elf, PT_NOTE, 0, offset, 0,
					     get_note_info_size(info), 0, 0);
	offset += get_note_info_size(info);
	if (!gcore->elf->ops->write_program_header(gcore->elf, gcore->fd))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));
	progressf("done.\n");

	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	progressf("Writing PT_LOAD program headers ... \n");
	FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
		char *vma_cache;
		ulong vm_start, vm_end, vm_flags;
		uint64_t p_offset, p_filesz;
		uint32_t p_flags;

		vma_cache = fill_vma_cache(vma);
		vm_start = ULONG(vma_cache + OFFSET(vm_area_struct_vm_start));
		vm_end   = ULONG(vma_cache + OFFSET(vm_area_struct_vm_end));
		vm_flags = ULONG(vma_cache + OFFSET(vm_area_struct_vm_flags));

		p_flags = 0;
		if (vm_flags & VM_READ)
			p_flags |= PF_R;
		if (vm_flags & VM_WRITE)
			p_flags |= PF_W;
		if (vm_flags & VM_EXEC)
			p_flags |= PF_X;

		p_offset = offset;
		p_filesz = gcore_dumpfilter_vma_dump_size(vma);

		offset += p_filesz;

		gcore->elf->ops->fill_program_header(gcore->elf, PT_LOAD,
						     p_flags, p_offset,
						     vm_start, p_filesz,
						     vm_end - vm_start,
						     ELF_EXEC_PAGESIZE);

		if (!gcore->elf->ops->write_program_header(gcore->elf,
							   gcore->fd))
			error(FATAL, "%s: write, %s\n", gcore->corename,
			      strerror(errno));
	}
	progressf("done.\n");

	progressf("Writing PT_NOTE segment ... \n");
	write_note_info(gcore->fd, info, &foffset);
	progressf("done.\n");

	buffer = GETBUF(PAGE_SIZE);
	BZERO(buffer, PAGE_SIZE);

	{
		size_t len;

		len = dataoff - foffset;
		if ((size_t)write(gcore->fd, buffer, len) != len)
			error(FATAL, "%s: write: %s\n", gcore->corename,
			      strerror(errno));
	}

	progressf("Writing PT_LOAD segment ... \n");
	FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
		ulong addr, end, vm_start;

		vm_start = ULONG(fill_vma_cache(vma) +
				 OFFSET(vm_area_struct_vm_start));

		end = vm_start + gcore_dumpfilter_vma_dump_size(vma);

		progressf("PT_LOAD[%lu]: %lx - %lx\n", index, vm_start, end);

		for (addr = vm_start; addr < end; addr += PAGE_SIZE) {
			physaddr_t paddr;

			if (uvtop(CURRENT_CONTEXT(), addr, &paddr, FALSE)) {
				readmem(paddr, PHYSADDR, buffer, PAGE_SIZE,
					"readmem vma list",
					gcore_verbose_error_handle());
			} else {
				pagefaultf("page fault at %lx\n", addr);
				BZERO(buffer, PAGE_SIZE);
			}

			if (write(gcore->fd, buffer, PAGE_SIZE) != PAGE_SIZE)
				error(FATAL, "%s: write: %s\n", gcore->corename,
				      strerror(errno));

		}
	}
	progressf("done.\n");

	gcore->flags |= GCF_SUCCESS;

}

static inline int
thread_group_leader(ulong task)
{
	ulong group_leader;

	readmem(task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"thread_group_leader: group_leader",
		gcore_verbose_error_handle());

	return task == group_leader;
}

static int
fill_thread_group(struct thread_group_list **tglist)
{
	ulong i;
	struct task_context *tc;
	struct thread_group_list *l;
	const uint tgid = task_tgid(CURRENT_TASK());
	const ulong lead_pid = CURRENT_PID();

	tc = FIRST_CONTEXT();
	l = NULL;
	for (i = 0; i < RUNNING_TASKS(); i++, tc++) {
		if (task_tgid(tc->task) == tgid) {
			struct thread_group_list *new;

			new = (struct thread_group_list *)
				GETBUF(sizeof(struct thread_group_list));
			new->task = tc->task;
			if (tc->pid == lead_pid || !l) {
				new->next = l;
				l = new;
			} else if (l) {
				new->next = l->next;
				l->next = new;
			}
		}
	}
	*tglist = l;

	return 1;
}

static int
task_nice(ulong task)
{
	int static_prio;

	readmem(task + GCORE_OFFSET(task_struct_static_prio), KVADDR,
		&static_prio, sizeof(static_prio), "task_nice: static_prio",
		gcore_verbose_error_handle());

	return PRIO_TO_NICE(static_prio);
}

static void
fill_psinfo_note(struct elf_note_info *info, ulong task)
{
	struct elf_prpsinfo *psinfo;
	ulong arg_start, arg_end, parent;
	physaddr_t paddr;
	long state, uid, gid;
        unsigned int i, len;
	char *mm_cache;

	psinfo = (struct elf_prpsinfo *)GETBUF(sizeof(struct elf_prpsinfo));
        fill_note(&info->psinfo, "CORE", NT_PRPSINFO,
		  sizeof(struct elf_prpsinfo), psinfo);

        /* first copy the parameters from user space */
	BZERO(psinfo, sizeof(struct elf_prpsinfo));

	mm_cache = fill_mm_struct(task_mm(task, FALSE));

	arg_start = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_start));
	arg_end = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_end));

        len = arg_end - arg_start;
        if (len >= ELF_PRARGSZ)
                len = ELF_PRARGSZ-1;
	if (uvtop(CURRENT_CONTEXT(), arg_start, &paddr, FALSE)) {
		readmem(paddr, PHYSADDR, &psinfo->pr_psargs, len,
			"fill_psinfo: pr_psargs", gcore_verbose_error_handle());
	} else {
		pagefaultf("page fault at %lx\n", arg_start);
	}
        for(i = 0; i < len; i++)
                if (psinfo->pr_psargs[i] == 0)
                        psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;

	readmem(task + GCORE_OFFSET(task_struct_real_parent), KVADDR,
		&parent, sizeof(parent), "fill_psinfo: real_parent",
		gcore_verbose_error_handle());

	psinfo->pr_ppid = ggt->task_pid(parent);
	psinfo->pr_pid = ggt->task_pid(task);
	psinfo->pr_pgrp = ggt->task_pgrp(task);
	psinfo->pr_sid = ggt->task_session(task);

	readmem(task + OFFSET(task_struct_state), KVADDR, &state, sizeof(state),
		"fill_psinfo: state", gcore_verbose_error_handle());

        i = state ? ffz(~state) + 1 : 0;
        psinfo->pr_state = i;
        psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
        psinfo->pr_zomb = psinfo->pr_sname == 'Z';

	psinfo->pr_nice = task_nice(task);

	readmem(task + OFFSET(task_struct_flags), KVADDR, &psinfo->pr_flag,
		sizeof(psinfo->pr_flag), "fill_psinfo: flags",
		gcore_verbose_error_handle());

	uid = ggt->task_uid(task);
	gid = ggt->task_gid(task);

	SET_UID(psinfo->pr_uid, (uid_t)uid);
	SET_GID(psinfo->pr_gid, (gid_t)gid);

	readmem(task + OFFSET(task_struct_comm), KVADDR, &psinfo->pr_fname,
		TASK_COMM_LEN, "fill_psinfo: comm",
		gcore_verbose_error_handle());

}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_psinfo_note(struct elf_note_info *info, ulong task)
{
	struct compat_elf_prpsinfo *psinfo;
	ulong arg_start, arg_end, parent;
	physaddr_t paddr;
	long state, uid, gid;
        unsigned int i, len;
	char *mm_cache;

	psinfo = (struct compat_elf_prpsinfo *)GETBUF(sizeof(*psinfo));
        fill_note(&info->psinfo, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);

        /* first copy the parameters from user space */
	BZERO(psinfo, sizeof(struct elf_prpsinfo));

	mm_cache = fill_mm_struct(task_mm(task, FALSE));

	arg_start = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_start));
	arg_end = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_end));

        len = arg_end - arg_start;
        if (len >= ELF_PRARGSZ)
                len = ELF_PRARGSZ-1;
	if (uvtop(CURRENT_CONTEXT(), arg_start, &paddr, FALSE)) {
		readmem(paddr, PHYSADDR, &psinfo->pr_psargs, len,
			"fill_psinfo: pr_psargs", gcore_verbose_error_handle());
	} else {
		pagefaultf("page fault at %lx\n", arg_start);
	}
        for(i = 0; i < len; i++)
                if (psinfo->pr_psargs[i] == 0)
                        psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;

	readmem(task + GCORE_OFFSET(task_struct_real_parent), KVADDR,
		&parent, sizeof(parent), "fill_psinfo: real_parent",
		gcore_verbose_error_handle());

	psinfo->pr_ppid = ggt->task_pid(parent);
	psinfo->pr_pid = ggt->task_pid(task);
	psinfo->pr_pgrp = ggt->task_pgrp(task);
	psinfo->pr_sid = ggt->task_session(task);

	readmem(task + OFFSET(task_struct_state), KVADDR, &state, sizeof(state),
		"fill_psinfo: state", gcore_verbose_error_handle());

        i = state ? ffz(~state) + 1 : 0;
        psinfo->pr_state = i;
        psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
        psinfo->pr_zomb = psinfo->pr_sname == 'Z';

	psinfo->pr_nice = task_nice(task);

	readmem(task + OFFSET(task_struct_flags), KVADDR, &psinfo->pr_flag,
		sizeof(psinfo->pr_flag), "fill_psinfo: flags",
		gcore_verbose_error_handle());

	uid = ggt->task_uid(task);
	gid = ggt->task_gid(task);

	SET_UID(psinfo->pr_uid, (__compat_uid_t)uid);
	SET_GID(psinfo->pr_gid, (__compat_gid_t)gid);

	readmem(task + OFFSET(task_struct_comm), KVADDR, &psinfo->pr_fname,
		TASK_COMM_LEN, "fill_psinfo: comm",
		gcore_verbose_error_handle());

}

#endif /* GCORE_ARCH_COMPAT */

static void
fill_thread_core_info(struct elf_thread_core_info *t,
		      struct elf_note_info *info,
		      const struct user_regset_view *view, size_t *total,
		      struct thread_group_list *tglist)
{
	unsigned int i;
	char *pr_reg_buf;

	/* NT_PRSTATUS is the one special case, because the regset data
	 * goes into the pr_reg field inside the note contents, rather
         * than being the whole note contents.  We fill the reset in here.
         * We assume that regset 0 is NT_PRSTATUS.
         */
	pr_reg_buf = GETBUF(view->regsets[0].size);
	view->regsets[0].get(task_to_context(t->task), &view->regsets[0],
			     view->regsets[0].size, pr_reg_buf);
	info->fill_prstatus_note(info, t, tglist, pr_reg_buf);
        *total += notesize(&t->notes[0]);

	if (view->regsets[0].writeback)
		view->regsets[0].writeback(task_to_context(t->task),
					   &view->regsets[0], 1);

	for (i = 1; i < view->n; ++i) {
		const struct user_regset *regset = &view->regsets[i];
		void *data;

		if (regset->writeback)
			regset->writeback(task_to_context(t->task), regset, 1);
		if (!regset->core_note_type)
			continue;
		if (regset->active &&
		    !regset->active(task_to_context(t->task), regset))
			continue;
		data = (void *)GETBUF(regset->size);
		if (!regset->get(task_to_context(t->task), regset, regset->size,
				 data))
			continue;
		if (regset->callback)
			regset->callback(t, regset);

		fill_note(&t->notes[i], regset->name, regset->core_note_type,
			  regset->size, data);
		*total += notesize(&t->notes[i]);
	}

}

static struct elf_note_info *elf_note_info_init(void)
{
	struct elf_note_info *info;

	info = (struct elf_note_info *)GETBUF(sizeof(*info));

#ifdef GCORE_ARCH_COMPAT
	if (gcore_is_arch_32bit_emulation(CURRENT_CONTEXT())) {
		info->fill_prstatus_note = compat_fill_prstatus_note;
		info->fill_psinfo_note = compat_fill_psinfo_note;
		info->fill_auxv_note = compat_fill_auxv_note;
		return info;
	}
#endif

	info->fill_prstatus_note = fill_prstatus_note;
	info->fill_psinfo_note = fill_psinfo_note;
	info->fill_auxv_note = fill_auxv_note;

	return info;
}

static int
fill_note_info(struct elf_note_info *info, struct thread_group_list *tglist,
	       int phnum)
{
	const struct user_regset_view *view = task_user_regset_view();
	struct thread_group_list *l;
	struct elf_thread_core_info *t;
	ulong dump_task;
	unsigned int i;

	info->size = 0;
	info->thread = NULL;

	info->thread_notes = 0;
	for (i = 0; i < view->n; i++)
		if (view->regsets[i].core_note_type != 0)
			++info->thread_notes;

	/* Sanity check.  We rely on regset 0 being in NT_PRSTATUS,
         * since it is our one special case.
         */
	if (info->thread_notes == 0 ||
	    view->regsets[0].core_note_type != NT_PRSTATUS)
		error(FATAL, "regset 0 is _not_ NT_PRSTATUS\n");

	gcore->elf->ops->fill_elf_header(gcore->elf,
					 phnum < PN_XNUM ? phnum : PN_XNUM,
					 view->e_machine, view->e_flags,
					 view->ei_osabi);

	if (gcore->elf->ops->get_e_shoff(gcore->elf))
		gcore->elf->ops->fill_section_header(gcore->elf, phnum);

	/* head task is always a dump target */
	dump_task = tglist->task;

	for (l = tglist; l; l = l->next) {
		struct elf_thread_core_info *new;
		size_t entry_size;

		entry_size = offsetof(struct elf_thread_core_info,
				      notes[info->thread_notes]);
		new = (struct elf_thread_core_info *)GETBUF(entry_size);
		BZERO(new, entry_size);
		new->task = l->task;
		if (!info->thread || l->task == dump_task) {
			new->next = info->thread;
			info->thread = new;
		} else {
			/* keep dump_task in the head position */
			new->next = info->thread->next;
			info->thread->next = new;
		}
	}

	for (t = info->thread; t; t = t->next)
		fill_thread_core_info(t, info, view, &info->size, tglist);

        /*
	 * Fill in the two process-wide notes.
         */
        info->fill_psinfo_note(info, dump_task);
        info->size += notesize(&info->psinfo);

	info->fill_auxv_note(info, dump_task);
	info->size += notesize(&info->auxv);

	return 0;
}

static int
notesize(struct memelfnote *en)
{
        int sz;

        sz = gcore->elf->ops->get_note_header_size(gcore->elf);
        sz += roundup(strlen(en->name) + 1, 4);
        sz += roundup(en->datasz, 4);

        return sz;
}

static void
fill_note(struct memelfnote *note, const char *name, int type, unsigned int sz,
	  void *data)
{
        note->name = name;
        note->type = type;
	note->datasz = sz;
        note->data = data;
        return;
}

static void
alignfile(int fd, off_t *foffset)
{
        static const char buffer[4] = {};
	const size_t len = roundup(*foffset, 4) - *foffset;

	if ((size_t)write(fd, buffer, len) != len)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += (off_t)len;
}

static void
writenote(struct memelfnote *men, int fd, off_t *foffset)
{
	uint32_t n_namesz, n_descsz, n_type;

	n_namesz = strlen(men->name) + 1;
	n_descsz = men->datasz;
	n_type = men->type;

	gcore->elf->ops->fill_note_header(gcore->elf, n_namesz, n_descsz,
					  n_type);

	if (!gcore->elf->ops->write_note_header(gcore->elf, fd, foffset))
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));

	if (write(fd, men->name, n_namesz) != n_namesz)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += n_namesz;

        alignfile(fd, foffset);

	if (write(fd, men->data, men->datasz) != men->datasz)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += men->datasz;

        alignfile(fd, foffset);

}

static void
write_note_info(int fd, struct elf_note_info *info, off_t *foffset)
{
        int first = 1;
        struct elf_thread_core_info *t = info->thread;

        do {
                int i;

                writenote(&t->notes[0], fd, foffset);

                if (first) {
			writenote(&info->psinfo, fd, foffset);
			writenote(&info->auxv, fd, foffset);
		}

                for (i = 1; i < info->thread_notes; ++i)
                        if (t->notes[i].data)
				writenote(&t->notes[i], fd, foffset);

                first = 0;
                t = t->next;
        } while (t);

}

static size_t
get_note_info_size(struct elf_note_info *info)
{
	return info->size;
}

static ulong first_vma(ulong mmap, ulong gate_vma)
{
	return mmap ? mmap : gate_vma;
}

static ulong next_vma(ulong this_vma, ulong gate_vma)
{
	ulong next;

	next = ULONG(fill_vma_cache(this_vma) + OFFSET(vm_area_struct_vm_next));
	if (next)
		return next;
	if (this_vma == gate_vma)
		return 0UL;
	return gate_vma;
}

static void
fill_prstatus_note(struct elf_note_info *info, struct elf_thread_core_info *t,
		   const struct thread_group_list *tglist, void *pr_reg)
{
	ulong pending_signal_sig0, blocked_sig0, real_parent, group_leader,
		signal, cutime,	cstime;

	memcpy(&t->prstatus.native.pr_reg, pr_reg, sizeof(t->prstatus.native.pr_reg));

        fill_note(&t->notes[0], "CORE", NT_PRSTATUS, sizeof(t->prstatus.native),
		  &t->prstatus.native);

        /* The type of (sig[0]) is unsigned long. */
	readmem(t->task + OFFSET(task_struct_pending) + OFFSET(sigpending_signal),
		KVADDR, &pending_signal_sig0, sizeof(unsigned long),
		"fill_prstatus: sigpending_signal_sig",
		gcore_verbose_error_handle());

	readmem(t->task + OFFSET(task_struct_blocked), KVADDR, &blocked_sig0,
		sizeof(unsigned long), "fill_prstatus: blocked_sig0",
		gcore_verbose_error_handle());

	readmem(t->task + OFFSET(task_struct_parent), KVADDR, &real_parent,
		sizeof(real_parent), "fill_prstatus: real_parent",
		gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"fill_prstatus: group_leader", gcore_verbose_error_handle());

	t->prstatus.native.pr_info.si_signo = t->prstatus.native.pr_cursig = 0;
        t->prstatus.native.pr_sigpend = pending_signal_sig0;
        t->prstatus.native.pr_sighold = blocked_sig0;
        t->prstatus.native.pr_ppid = ggt->task_pid(real_parent);
        t->prstatus.native.pr_pid = ggt->task_pid(t->task);
        t->prstatus.native.pr_pgrp = ggt->task_pgrp(t->task);
        t->prstatus.native.pr_sid = ggt->task_session(t->task);
        if (thread_group_leader(t->task)) {
                struct task_cputime cputime;

                /*
                 * This is the record for the group leader.  It shows the
                 * group-wide total, not its individual thread total.
                 */
                ggt->thread_group_cputime(t->task, tglist, &cputime);
                cputime_to_timeval(cputime.utime, &t->prstatus.native.pr_utime);
                cputime_to_timeval(cputime.stime, &t->prstatus.native.pr_stime);
        } else {
		cputime_t utime, stime;

		readmem(t->task + OFFSET(task_struct_utime), KVADDR, &utime,
			sizeof(utime), "task_struct utime",
			gcore_verbose_error_handle());

		readmem(t->task + OFFSET(task_struct_stime), KVADDR, &stime,
			sizeof(stime), "task_struct stime",
			gcore_verbose_error_handle());

                cputime_to_timeval(utime, &t->prstatus.native.pr_utime);
                cputime_to_timeval(stime, &t->prstatus.native.pr_stime);
        }

	readmem(t->task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "task_struct signal", gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cutime, sizeof(cutime), "signal_struct cutime",
		gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cstime, sizeof(cstime), "signal_struct cstime",
		gcore_verbose_error_handle());

        cputime_to_timeval(cutime, &t->prstatus.native.pr_cutime);
        cputime_to_timeval(cstime, &t->prstatus.native.pr_cstime);

}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_prstatus_note(struct elf_note_info *info,
			  struct elf_thread_core_info *t,
			  const struct thread_group_list *tglist,
			  void *pr_reg)
{
	ulong pending_signal_sig0, blocked_sig0, real_parent, group_leader,
		signal, cutime,	cstime;

	memcpy(&t->prstatus.compat.pr_reg, pr_reg, sizeof(t->prstatus.compat.pr_reg));

        fill_note(&t->notes[0], "CORE", NT_PRSTATUS,
                  sizeof(t->prstatus.compat), &t->prstatus.compat);

        /* The type of (sig[0]) is unsigned long. */
	readmem(t->task + OFFSET(task_struct_pending) + OFFSET(sigpending_signal),
		KVADDR, &pending_signal_sig0, sizeof(unsigned long),
		"fill_prstatus: sigpending_signal_sig",
		gcore_verbose_error_handle());

	readmem(t->task + OFFSET(task_struct_blocked), KVADDR, &blocked_sig0,
		sizeof(unsigned long), "fill_prstatus: blocked_sig0",
		gcore_verbose_error_handle());

	readmem(t->task + OFFSET(task_struct_parent), KVADDR, &real_parent,
		sizeof(real_parent), "fill_prstatus: real_parent",
		gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"fill_prstatus: group_leader", gcore_verbose_error_handle());

	t->prstatus.compat.pr_info.si_signo = t->prstatus.compat.pr_cursig = 0;
        t->prstatus.compat.pr_sigpend = pending_signal_sig0;
        t->prstatus.compat.pr_sighold = blocked_sig0;
        t->prstatus.compat.pr_ppid = ggt->task_pid(real_parent);
        t->prstatus.compat.pr_pid = ggt->task_pid(t->task);
        t->prstatus.compat.pr_pgrp = ggt->task_pgrp(t->task);
        t->prstatus.compat.pr_sid = ggt->task_session(t->task);
        if (thread_group_leader(t->task)) {
                struct task_cputime cputime;

                /*
                 * This is the record for the group leader.  It shows the
                 * group-wide total, not its individual thread total.
                 */
                ggt->thread_group_cputime(t->task, tglist, &cputime);
                cputime_to_compat_timeval(cputime.utime, &t->prstatus.compat.pr_utime);
                cputime_to_compat_timeval(cputime.stime, &t->prstatus.compat.pr_stime);
        } else {
		cputime_t utime, stime;

		readmem(t->task + OFFSET(task_struct_utime), KVADDR, &utime,
			sizeof(utime), "task_struct utime",
			gcore_verbose_error_handle());

		readmem(t->task + OFFSET(task_struct_stime), KVADDR, &stime,
			sizeof(stime), "task_struct stime",
			gcore_verbose_error_handle());

                cputime_to_compat_timeval(utime, &t->prstatus.compat.pr_utime);
                cputime_to_compat_timeval(stime, &t->prstatus.compat.pr_stime);
        }

	readmem(t->task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "task_struct signal",
		gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cutime, sizeof(cutime), "signal_struct cutime",
		gcore_verbose_error_handle());

	readmem(t->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cstime, sizeof(cstime), "signal_struct cstime",
		gcore_verbose_error_handle());

        cputime_to_compat_timeval(cutime, &t->prstatus.compat.pr_cutime);
        cputime_to_compat_timeval(cstime, &t->prstatus.compat.pr_cstime);

}

#endif /* GCORE_ARCH_COMPAT */

static void
fill_auxv_note(struct elf_note_info *info, ulong task)
{
	struct memelfnote *note = &info->auxv;
	ulong *auxv;
	int i;

	auxv = (ulong *)GETBUF(GCORE_SIZE(mm_struct_saved_auxv));

	readmem(task_mm(task, FALSE) +
		GCORE_OFFSET(mm_struct_saved_auxv), KVADDR, auxv,
		GCORE_SIZE(mm_struct_saved_auxv), "fill_auxv_note",
		gcore_verbose_error_handle());

	i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);

	fill_note(note, "CORE", NT_AUXV, i * sizeof(ulong), auxv);

}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_auxv_note(struct elf_note_info *info, ulong task)
{
	struct memelfnote *note = &info->auxv;
	uint32_t *auxv;
	int i;

	auxv = (uint32_t *)GETBUF(GCORE_SIZE(mm_struct_saved_auxv));

	readmem(task_mm(task, FALSE) +
		GCORE_OFFSET(mm_struct_saved_auxv), KVADDR, auxv,
		GCORE_SIZE(mm_struct_saved_auxv), "fill_auxv_note32",
		gcore_verbose_error_handle());

	i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);

	fill_note(note, "CORE", NT_AUXV, i * sizeof(uint32_t), auxv);
}

#endif /* GCORE_ARCH_COMPAT */
