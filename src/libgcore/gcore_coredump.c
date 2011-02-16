/* gcore_coredump.c -- core analysis suite
 *
 * Copyright (C) 2010 FUJITSU LIMITED
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

static void fill_prstatus(struct elf_prstatus *prstatus, ulong task,
			  const struct thread_group_list *tglist);
static void fill_psinfo(struct elf_prpsinfo *psinfo, ulong task);
static void fill_auxv_note(struct memelfnote *note, ulong task);
static int fill_thread_group(struct thread_group_list **tglist);
static void fill_headers(Elf_Ehdr *elf, Elf_Shdr *shdr0, int phnum,
			 uint16_t e_machine, uint32_t e_flags,
			 uint8_t ei_osabi);
static void fill_thread_core_info(struct elf_thread_core_info *t,
				  const struct user_regset_view *view,
				  size_t *total,
				  struct thread_group_list *tglist);
static int fill_note_info(struct elf_note_info *info,
			  struct thread_group_list *tglist, Elf_Ehdr *elf,
			  Elf_Shdr *shdr0, int phnum);
static void fill_note(struct memelfnote *note, const char *name, int type,
		      unsigned int sz, void *data);

static int notesize(struct memelfnote *en);
static void alignfile(int fd, off_t *foffset);
static void write_elf_note_phdr(int fd, size_t size, off_t *offset);
static void writenote(struct memelfnote *men, int fd, off_t *foffset);
static void write_note_info(int fd, struct elf_note_info *info, off_t *foffset);
static size_t get_note_info_size(struct elf_note_info *info);
static ulong next_vma(ulong this_vma);

static inline int thread_group_leader(ulong task);

void gcore_coredump(void)
{
	struct thread_group_list *tglist = NULL;
	struct elf_note_info info;
	Elf_Ehdr elf;
	Elf_Shdr shdr0;
	int map_count, phnum;
	ulong vma, index, mmap;
	off_t offset, foffset, dataoff;
	char *mm_cache, *buffer = NULL;

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

	progressf("Retrieving note information ... \n");
	fill_note_info(&info, tglist, &elf, &shdr0, phnum);
	progressf("done.\n");

	progressf("Opening file %s ... \n", gcore->corename);
	gcore->fd = open(gcore->corename, O_WRONLY|O_TRUNC|O_CREAT,
			 S_IRUSR|S_IWUSR);
	if (gcore->fd < 0)
		error(FATAL, "%s: open: %s\n", gcore->corename,
		      strerror(errno));
	progressf("done.\n");

	progressf("Writing ELF header ... \n");
	if (write(gcore->fd, &elf, sizeof(elf)) != sizeof(elf))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));
	progressf(" done.\n");

	if (elf.e_shoff) {
		progressf("Writing section header table ... \n");
		if (write(gcore->fd, &shdr0, sizeof(shdr0)) != sizeof(shdr0))
			error(FATAL, "%s: gcore: %s\n", gcore->corename,
			      strerror(errno));
		progressf("done.\n");
	}

	offset = elf.e_ehsize +
		(elf.e_phnum == PN_XNUM ? elf.e_shnum * elf.e_shentsize : 0) +
		phnum * elf.e_phentsize;
	foffset = offset;

	progressf("Writing PT_NOTE program header ... \n");
	write_elf_note_phdr(gcore->fd, get_note_info_size(&info), &offset);
	progressf("done.\n");

	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);

	progressf("Writing PT_LOAD program headers ... \n");
	FOR_EACH_VMA_OBJECT(vma, index, mmap) {
		char *vma_cache;
		ulong vm_start, vm_end, vm_flags;
		Elf_Phdr phdr;

		vma_cache = fill_vma_cache(vma);
		vm_start = ULONG(vma_cache + OFFSET(vm_area_struct_vm_start));
		vm_end   = ULONG(vma_cache + OFFSET(vm_area_struct_vm_end));
		vm_flags = ULONG(vma_cache + OFFSET(vm_area_struct_vm_flags));

		phdr.p_type = PT_LOAD;
		phdr.p_offset = offset;
		phdr.p_vaddr = vm_start;
		phdr.p_paddr = 0;
		phdr.p_filesz = gcore_dumpfilter_vma_dump_size(vma);
		phdr.p_memsz = vm_end - vm_start;
		phdr.p_flags = vm_flags & VM_READ ? PF_R : 0;
		if (vm_flags & VM_WRITE)
			phdr.p_flags |= PF_W;
		if (vm_flags & VM_EXEC)
			phdr.p_flags |= PF_X;
		phdr.p_align = ELF_EXEC_PAGESIZE;

		offset += phdr.p_filesz;

		if (write(gcore->fd, &phdr, sizeof(phdr)) != sizeof(phdr))
			error(FATAL, "%s: write, %s\n", gcore->corename,
			      strerror(errno));
	}
	progressf("done.\n");

	progressf("Writing PT_NOTE segment ... \n");
	write_note_info(gcore->fd, &info, &foffset);
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
	FOR_EACH_VMA_OBJECT(vma, index, mmap) {
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
fill_psinfo(struct elf_prpsinfo *psinfo, ulong task)
{
	ulong arg_start, arg_end, parent;
	physaddr_t paddr;
	long state, uid, gid;
        unsigned int i, len;
	char *mm_cache;

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

static void
fill_headers(Elf_Ehdr *elf, Elf_Shdr *shdr0, int phnum, uint16_t e_machine,
	     uint32_t e_flags, uint8_t ei_osabi)
{
	BZERO(elf, sizeof(Elf_Ehdr));
	BCOPY(ELFMAG, elf->e_ident, SELFMAG);
	elf->e_ident[EI_CLASS] = ELF_CLASS;
	elf->e_ident[EI_DATA] = ELF_DATA;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ei_osabi;
	elf->e_ehsize = sizeof(Elf_Ehdr);
	elf->e_phentsize = sizeof(Elf_Phdr);
	elf->e_phnum = phnum >= PN_XNUM ? PN_XNUM : phnum;
	if (elf->e_phnum == PN_XNUM) {
		elf->e_shoff = elf->e_ehsize;
		elf->e_shentsize = sizeof(Elf_Shdr);
		elf->e_shnum = 1;
		elf->e_shstrndx = SHN_UNDEF;
	}
	elf->e_type = ET_CORE;
	elf->e_machine = e_machine;
	elf->e_version = EV_CURRENT;
	elf->e_phoff = sizeof(Elf_Ehdr) + elf->e_shentsize * elf->e_shnum;
	elf->e_flags = e_flags;

	if (elf->e_phnum == PN_XNUM) {
		BZERO(shdr0, sizeof(Elf_Shdr));
		shdr0->sh_type = SHT_NULL;
		shdr0->sh_size = elf->e_shnum;
		shdr0->sh_link = elf->e_shstrndx;
		shdr0->sh_info = phnum;
	}

}

static void
fill_thread_core_info(struct elf_thread_core_info *t,
		      const struct user_regset_view *view, size_t *total,
		      struct thread_group_list *tglist)
{
	unsigned int i;

	/* NT_PRSTATUS is the one special case, because the regset data
	 * goes into the pr_reg field inside the note contents, rather
         * than being the whole note contents.  We fill the reset in here.
         * We assume that regset 0 is NT_PRSTATUS.
         */
	fill_prstatus(&t->prstatus, t->task, tglist);
        view->regsets[0].get(task_to_context(t->task), &view->regsets[0],
			     sizeof(t->prstatus.pr_reg), &t->prstatus.pr_reg);

        fill_note(&t->notes[0], "CORE", NT_PRSTATUS,
                  sizeof(t->prstatus), &t->prstatus);
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

static int
fill_note_info(struct elf_note_info *info, struct thread_group_list *tglist,
	       Elf_Ehdr *elf, Elf_Shdr *shdr0, int phnum)
{
	const struct user_regset_view *view = task_user_regset_view();
	struct thread_group_list *l;
	struct elf_thread_core_info *t;
	struct elf_prpsinfo *psinfo = NULL;
	ulong dump_task;
	unsigned int i;

	info->size = 0;
	info->thread = NULL;

	psinfo = (struct elf_prpsinfo *)GETBUF(sizeof(struct elf_prpsinfo));
        fill_note(&info->psinfo, "CORE", NT_PRPSINFO,
		  sizeof(struct elf_prpsinfo), psinfo);

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

	fill_headers(elf, shdr0, phnum, view->e_machine, view->e_flags,
		     view->ei_osabi);

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
		fill_thread_core_info(t, view, &info->size, tglist);

        /*
	 * Fill in the two process-wide notes.
         */
        fill_psinfo(psinfo, dump_task);
        info->size += notesize(&info->psinfo);

	fill_auxv_note(&info->auxv, dump_task);
	info->size += notesize(&info->auxv);

	return 0;
}

static int
notesize(struct memelfnote *en)
{
        int sz;

        sz = sizeof(Elf_Nhdr);
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
        const Elf_Nhdr en = {
		.n_namesz = strlen(men->name) + 1,
		.n_descsz = men->datasz,
		.n_type   = men->type,
	};

	if (write(fd, &en, sizeof(en)) != sizeof(en))
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += sizeof(en);

	if (write(fd, men->name, en.n_namesz) != en.n_namesz)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += en.n_namesz;

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

static ulong next_vma(ulong this_vma)
{
	return ULONG(fill_vma_cache(this_vma) + OFFSET(vm_area_struct_vm_next));
}

static void
write_elf_note_phdr(int fd, size_t size, off_t *offset)
{
	Elf_Phdr phdr;

	BZERO(&phdr, sizeof(phdr));

        phdr.p_type = PT_NOTE;
        phdr.p_offset = *offset;
        phdr.p_filesz = size;

	*offset += size;

	if (write(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));

}

static void
fill_prstatus(struct elf_prstatus *prstatus, ulong task,
	      const struct thread_group_list *tglist)
{
	ulong pending_signal_sig0, blocked_sig0, real_parent, group_leader,
		signal, cutime,	cstime;

        /* The type of (sig[0]) is unsigned long. */
	readmem(task + OFFSET(task_struct_pending) + OFFSET(sigpending_signal),
		KVADDR, &pending_signal_sig0, sizeof(unsigned long),
		"fill_prstatus: sigpending_signal_sig",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_blocked), KVADDR, &blocked_sig0,
		sizeof(unsigned long), "fill_prstatus: blocked_sig0",
		gcore_verbose_error_handle());

	readmem(task + OFFSET(task_struct_parent), KVADDR, &real_parent,
		sizeof(real_parent), "fill_prstatus: real_parent",
		gcore_verbose_error_handle());

	readmem(task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"fill_prstatus: group_leader", gcore_verbose_error_handle());

	prstatus->pr_info.si_signo = prstatus->pr_cursig = 0;
        prstatus->pr_sigpend = pending_signal_sig0;
        prstatus->pr_sighold = blocked_sig0;
        prstatus->pr_ppid = ggt->task_pid(real_parent);
        prstatus->pr_pid = ggt->task_pid(task);
        prstatus->pr_pgrp = ggt->task_pgrp(task);
        prstatus->pr_sid = ggt->task_session(task);
        if (thread_group_leader(task)) {
                struct task_cputime cputime;

                /*
                 * This is the record for the group leader.  It shows the
                 * group-wide total, not its individual thread total.
                 */
                ggt->thread_group_cputime(task, tglist, &cputime);
                cputime_to_timeval(cputime.utime, &prstatus->pr_utime);
                cputime_to_timeval(cputime.stime, &prstatus->pr_stime);
        } else {
		cputime_t utime, stime;

		readmem(task + OFFSET(task_struct_utime), KVADDR, &utime,
			sizeof(utime), "task_struct utime", gcore_verbose_error_handle());

		readmem(task + OFFSET(task_struct_stime), KVADDR, &stime,
			sizeof(stime), "task_struct stime", gcore_verbose_error_handle());

                cputime_to_timeval(utime, &prstatus->pr_utime);
                cputime_to_timeval(stime, &prstatus->pr_stime);
        }

	readmem(task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "task_struct signal", gcore_verbose_error_handle());

	readmem(task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cutime, sizeof(cutime), "signal_struct cutime",
		gcore_verbose_error_handle());

	readmem(task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cstime, sizeof(cstime), "signal_struct cstime",
		gcore_verbose_error_handle());

        cputime_to_timeval(cutime, &prstatus->pr_cutime);
        cputime_to_timeval(cstime, &prstatus->pr_cstime);

}

static void
fill_auxv_note(struct memelfnote *note, ulong task)
{
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
	while (auxv[i] != AT_NULL);

	fill_note(note, "CORE", NT_AUXV, i * sizeof(ulong), auxv);

}
