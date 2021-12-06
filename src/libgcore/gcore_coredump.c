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
			       struct task_context *tc,
			       struct memelfnote *memnote);
static void fill_psinfo_note(struct elf_note_info *info,
			     struct task_context *tc,
			     struct memelfnote *memnote);
static void fill_auxv_note(struct elf_note_info *info,
			   struct task_context *tc,
			   struct memelfnote *memnote);
static int fill_files_note(struct elf_note_info *info,
			   struct task_context *tc,
			   struct memelfnote *memnote);

#ifdef GCORE_ARCH_COMPAT
static void compat_fill_prstatus_note(struct elf_note_info *info,
				      struct task_context *tc,
				      struct memelfnote *memnote);
static void compat_fill_psinfo_note(struct elf_note_info *info,
				    struct task_context *tc,
				    struct memelfnote *memnote);
static void compat_fill_auxv_note(struct elf_note_info *info,
				  struct task_context *tc,
				  struct memelfnote *memnote);
static int compat_fill_files_note(struct elf_note_info *info,
				  struct task_context *tc,
				  struct memelfnote *memnote);
#endif

static void fill_elf_header(int phnum);
static void fill_write_thread_core_info(FILE *fp, struct task_context *tc,
					struct task_context *dump_tc,
					struct elf_note_info *info,
					const struct user_regset_view *view,
					loff_t *offset, size_t *total);
static int fill_write_note_info(FILE *fp, struct elf_note_info *info, int phnum,
				loff_t *offset);
static void fill_note(struct memelfnote *note, const char *name, int type,
		      unsigned int sz, void *data);

static int notesize(struct memelfnote *en);
static void alignfile(FILE *fp, loff_t *foffset);
static void writenote(struct memelfnote *men, FILE *fp, loff_t *foffset);
static size_t get_note_info_size(struct elf_note_info *info);

static inline int thread_group_leader(ulong task);

static int uvtop_quiet(ulong vaddr, physaddr_t *paddr);

ulong __attribute__((weak))
readswap(ulonglong pte_val, char *buf, ulong len, ulonglong vaddr)
{
	return 0;
}

void gcore_readmem_user(ulong addr, void *buf, long size, char *type)
{
	ulong paddr, cnt;
	char *bufptr = buf;

	while (size > 0) {
		if (!uvtop_quiet(addr, &paddr)) {

			cnt = PAGESIZE() - PAGEOFFSET(addr);
			if (cnt > size)
				cnt = size;

			if (!(paddr &&
			      (cnt = readswap(paddr,
					      bufptr,
					      cnt,
					      addr)))) {
				memset(bufptr, ' ', cnt);
				pagefaultf("page fault at %lx\n", addr);
			}

			bufptr += cnt;
			addr += cnt;
			size -= cnt;

			continue;
		}

		cnt = PAGESIZE() - PAGEOFFSET(paddr);
		if (cnt > size)
			cnt = size;

		if (!readmem(paddr,
			     PHYSADDR,
			     bufptr,
			     cnt,
			     type,
			     gcore_verbose_error_handle_user())) {
			memset(bufptr, ' ', cnt);
			pagefaultf("page fault at %lx\n", addr);
		}

		bufptr += cnt;
		addr += cnt;
		size -= cnt;
	}
}

void gcore_coredump(void)
{
	struct elf_note_info *info;
	int map_count, phnum;
	ulong vma, index, mmap;
	loff_t offset;
	char *mm_cache, *buffer = NULL;
	ulong gate_vma;

	gcore->flags |= GCF_UNDER_COREDUMP;

	mm_cache = fill_mm_struct(task_mm(CURRENT_TASK(), TRUE));
	if (!mm_cache)
		error(FATAL, "The user memory space does not exist.\n");

	mmap = ULONG(mm_cache + OFFSET(mm_struct_mmap));
	map_count = INT(mm_cache + GCORE_OFFSET(mm_struct_map_count));

	phnum = map_count;
	phnum++; /* for note information */
	gate_vma = gcore_arch_get_gate_vma();
	if (gate_vma)
		phnum++;

	info = elf_note_info_init();

	fill_elf_header(phnum);

	progressf("Opening file %s ... \n", gcore->corename);
	gcore->fp = fopen(gcore->corename, "w");
	if (!gcore->fp)
		error(FATAL, "%s: open: %s\n", gcore->corename,
		      strerror(errno));
	progressf("done.\n");

	progressf("Writing ELF header ... \n");
	if (!gcore->elf->ops->write_elf_header(gcore->elf, gcore->fp))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));
	progressf(" done.\n");

	offset = gcore->elf->ops->calc_segment_offset(gcore->elf);

	if (fseek(gcore->fp, offset, SEEK_SET) < 0) {
		error(FATAL, "%s: fseek: %s\n", gcore->corename,
		      strerror(errno));
	}

	progressf("Retrieving and writing note information ... \n");
	fill_write_note_info(gcore->fp, info, phnum, &offset);
	progressf("done.\n");

	if (gcore->elf->ops->get_e_shoff(gcore->elf)) {
		if (fseek(gcore->fp, gcore->elf->ops->get_e_shoff(gcore->elf),
			  SEEK_SET) < 0) {
			error(FATAL, "%s: fseek: %s\n", gcore->corename,
			      strerror(errno));
		}
		progressf("Writing section header table ... \n");
		if (!gcore->elf->ops->write_section_header(gcore->elf,
							   gcore->fp))
			error(FATAL, "%s: gcore: %s\n", gcore->corename,
			      strerror(errno));
		progressf("done.\n");
	}

	progressf("Writing PT_NOTE program header ... \n");
	if (fseek(gcore->fp, gcore->elf->ops->get_e_phoff(gcore->elf),
		  SEEK_SET) < 0) {
		error(FATAL, "%s: fseek: %s\n", gcore->corename,
		      strerror(errno));
	}
	offset = gcore->elf->ops->calc_segment_offset(gcore->elf);
	gcore->elf->ops->fill_program_header(gcore->elf, PT_NOTE, 0, offset, 0,
					     get_note_info_size(info), 0, 0);
	if (!gcore->elf->ops->write_program_header(gcore->elf, gcore->fp))
		error(FATAL, "%s: write: %s\n", gcore->corename,
		      strerror(errno));
	progressf("done.\n");

	offset =
		gcore->elf->ops->calc_segment_offset(gcore->elf)
		+ get_note_info_size(info);
	offset = roundup(offset, ELF_EXEC_PAGESIZE);

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
							   gcore->fp))
			error(FATAL, "%s: write, %s\n", gcore->corename,
			      strerror(errno));
	}
	progressf("done.\n");

	/* Align to page. Segment needs to begin with offset multiple
	 * of block size, typically multiple of 512 bytes, in order to
	 * make skipped page-faulted pages as holes. See the
	 * page-fault code below. */
	offset =
		gcore->elf->ops->calc_segment_offset(gcore->elf)
		+ get_note_info_size(info);
	offset = roundup(offset, ELF_EXEC_PAGESIZE);

	if (fseek(gcore->fp, offset, SEEK_SET) < 0) {
		error(FATAL, "%s: fseek: %s\n", gcore->corename,
		      strerror(errno));
	}

	buffer = GETBUF(PAGE_SIZE);
	BZERO(buffer, PAGE_SIZE);

	progressf("Writing PT_LOAD segment ... \n");
	FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
		ulong addr, end, vm_start;

		vm_start = ULONG(fill_vma_cache(vma) +
				 OFFSET(vm_area_struct_vm_start));

		end = vm_start + gcore_dumpfilter_vma_dump_size(vma);

		progressf("PT_LOAD[%lu]: %lx - %lx\n", index, vm_start, end);

		for (addr = vm_start; addr < end; addr += PAGE_SIZE) {
			physaddr_t paddr;

			if (uvtop_quiet(addr, &paddr)
			    ? readmem(paddr,
				      PHYSADDR,
				      buffer,
				      PAGE_SIZE,
				      "readmem vma list",
				      gcore_verbose_error_handle_user())
			    : paddr && readswap(paddr,
						buffer,
						PAGE_SIZE,
						addr) == PAGE_SIZE) {
				if (fwrite(buffer, PAGE_SIZE, 1, gcore->fp)
				    != 1)
					error(FATAL, "%s: write: %s\n",
					      gcore->corename,
					      strerror(errno));
			} else {
				pagefaultf("page fault at %lx\n", addr);

				/* Fill unavailable page-faulted pages
				 * with 0 for ease of implementation;
				 * to be honest, I want to avoid
				 * restructuring program header table.
				 *
				 * Also, we do skip these pages by
				 * fseek(). Recent filesystems support
				 * sparse file that doesn't allocate
				 * actual blocks if there are no
				 * corresponding write; such part is
				 * called hole. Hence, the skip works
				 * just like a filter for page-faulted
				 * pages.
				 *
				 * Note, however, that we don't reedit
				 * program headers and these pages are
				 * logically present on corefile as
				 * zero-filled pages. If copying the
				 * corefile on system that doesn't
				 * support sparse file, resulting
				 * corefile can be much larger than
				 * original size.
				 */
				if (fseek(gcore->fp, PAGE_SIZE, SEEK_CUR) < 0) {
					error(FATAL, "%s: fseek: %s\n",
					      gcore->corename,
					      strerror(errno));
				}
			}
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
task_nice(ulong task)
{
	int static_prio;

	readmem(task + GCORE_OFFSET(task_struct_static_prio), KVADDR,
		&static_prio, sizeof(static_prio), "task_nice: static_prio",
		gcore_verbose_error_handle());

	return PRIO_TO_NICE(static_prio);
}

static void
fill_psinfo_note(struct elf_note_info *info, struct task_context *tc,
		 struct memelfnote *memnote)
{
	struct elf_prpsinfo *psinfo;
	ulong arg_start, arg_end, parent;
	long state, uid, gid;
        unsigned int i, len;
	char *mm_cache;

	psinfo = (struct elf_prpsinfo *)GETBUF(sizeof(struct elf_prpsinfo));
        fill_note(memnote, "CORE", NT_PRPSINFO, sizeof(struct elf_prpsinfo),
		  psinfo);

        /* first copy the parameters from user space */
	BZERO(psinfo, sizeof(struct elf_prpsinfo));

	mm_cache = fill_mm_struct(task_mm(tc->task, FALSE));

	arg_start = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_start));
	arg_end = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_end));

        len = arg_end - arg_start;
        if (len >= ELF_PRARGSZ)
                len = ELF_PRARGSZ-1;
	gcore_readmem_user(arg_start,
			   &psinfo->pr_psargs,
			   len,
			   "fill_psinfo: pr_psargs");
        for(i = 0; i < len; i++)
                if (psinfo->pr_psargs[i] == 0)
                        psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;

	readmem(tc->task + GCORE_OFFSET(task_struct_real_parent), KVADDR,
		&parent, sizeof(parent), "fill_psinfo: real_parent",
		gcore_verbose_error_handle());

	psinfo->pr_ppid = ggt->task_pid(parent);
	psinfo->pr_pid = ggt->task_pid(tc->task);
	psinfo->pr_pgrp = ggt->task_pgrp(tc->task);
	psinfo->pr_sid = ggt->task_session(tc->task);

	readmem(tc->task + OFFSET(task_struct_state), KVADDR, &state, sizeof(state),
		"fill_psinfo: state", gcore_verbose_error_handle());

        i = state ? ffz(~state) + 1 : 0;
        psinfo->pr_state = i;
        psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
        psinfo->pr_zomb = psinfo->pr_sname == 'Z';

	psinfo->pr_nice = task_nice(tc->task);

	readmem(tc->task + OFFSET(task_struct_flags), KVADDR, &psinfo->pr_flag,
		sizeof(psinfo->pr_flag), "fill_psinfo: flags",
		gcore_verbose_error_handle());

	uid = ggt->task_uid(tc->task);
	gid = ggt->task_gid(tc->task);

	SET_UID(psinfo->pr_uid, (uid_t)uid);
	SET_GID(psinfo->pr_gid, (gid_t)gid);

	readmem(tc->task + OFFSET(task_struct_comm), KVADDR, &psinfo->pr_fname,
		TASK_COMM_LEN, "fill_psinfo: comm",
		gcore_verbose_error_handle());

}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_psinfo_note(struct elf_note_info *info,
			struct task_context *tc,
			struct memelfnote *memnote)
{
	struct compat_elf_prpsinfo *psinfo;
	ulong arg_start, arg_end, parent;
	long state, uid, gid;
        unsigned int i, len;
	char *mm_cache;

	psinfo = (struct compat_elf_prpsinfo *)GETBUF(sizeof(*psinfo));
        fill_note(memnote, "CORE", NT_PRPSINFO, sizeof(*psinfo), psinfo);

        /* first copy the parameters from user space */
	BZERO(psinfo, sizeof(struct elf_prpsinfo));

	mm_cache = fill_mm_struct(task_mm(tc->task, FALSE));

	arg_start = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_start));
	arg_end = ULONG(mm_cache + GCORE_OFFSET(mm_struct_arg_end));

        len = arg_end - arg_start;
        if (len >= ELF_PRARGSZ)
                len = ELF_PRARGSZ-1;
	gcore_readmem_user(arg_start,
			   &psinfo->pr_psargs,
			   len,
			   "fill_psinfo: pr_psargs");
        for(i = 0; i < len; i++)
                if (psinfo->pr_psargs[i] == 0)
                        psinfo->pr_psargs[i] = ' ';
        psinfo->pr_psargs[len] = 0;

	readmem(tc->task + GCORE_OFFSET(task_struct_real_parent), KVADDR,
		&parent, sizeof(parent), "fill_psinfo: real_parent",
		gcore_verbose_error_handle());

	psinfo->pr_ppid = ggt->task_pid(parent);
	psinfo->pr_pid = ggt->task_pid(tc->task);
	psinfo->pr_pgrp = ggt->task_pgrp(tc->task);
	psinfo->pr_sid = ggt->task_session(tc->task);

	readmem(tc->task + OFFSET(task_struct_state), KVADDR, &state, sizeof(state),
		"fill_psinfo: state", gcore_verbose_error_handle());

        i = state ? ffz(~state) + 1 : 0;
        psinfo->pr_state = i;
        psinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
        psinfo->pr_zomb = psinfo->pr_sname == 'Z';

	psinfo->pr_nice = task_nice(tc->task);

	readmem(tc->task + OFFSET(task_struct_flags), KVADDR, &psinfo->pr_flag,
		sizeof(psinfo->pr_flag), "fill_psinfo: flags",
		gcore_verbose_error_handle());

	uid = ggt->task_uid(tc->task);
	gid = ggt->task_gid(tc->task);

	SET_UID(psinfo->pr_uid, (__compat_uid_t)uid);
	SET_GID(psinfo->pr_gid, (__compat_gid_t)gid);

	readmem(tc->task + OFFSET(task_struct_comm), KVADDR, &psinfo->pr_fname,
		TASK_COMM_LEN, "fill_psinfo: comm",
		gcore_verbose_error_handle());

}

#endif /* GCORE_ARCH_COMPAT */

static void fill_elf_header(int phnum)
{
	const struct user_regset_view *view = task_user_regset_view();

	gcore->elf->ops->fill_elf_header(gcore->elf,
					 phnum < PN_XNUM ? phnum : PN_XNUM,
					 view->e_machine, view->e_flags,
					 view->ei_osabi);

	if (gcore->elf->ops->get_e_shoff(gcore->elf))
		gcore->elf->ops->fill_section_header(gcore->elf, phnum);
}

static void
fill_write_thread_core_info(FILE *fp, struct task_context *tc,
			    struct task_context *dump_tc,
			    struct elf_note_info *info,
			    const struct user_regset_view *view,
			    loff_t *offset, size_t *total)
{
	unsigned int i;
	char *buf;
	struct memelfnote memnote;

	/* NT_PRSTATUS is the one special case, because the regset data
	 * goes into the pr_reg field inside the note contents, rather
         * than being the whole note contents.  We fill the reset in here.
         * We assume that regset 0 is NT_PRSTATUS.
         */
	buf = GETBUF(view->regsets[0].size);
	view->regsets[0].get(tc, &view->regsets[0],
			     view->regsets[0].size, buf);
	/* We pass actual object in case of prstatus. We don't do this
	 * in other cases. */
	memnote.data = buf;
	info->fill_prstatus_note(info, tc, &memnote);
        *total += notesize(&memnote);
	writenote(&memnote, fp, offset);
	FREEBUF(buf);
	FREEBUF(memnote.data);

        /*
	 * Fill in the two process-wide notes.
         */
	if (tc == dump_tc) {
		info->fill_psinfo_note(info, dump_tc, &memnote);
		info->size += notesize(&memnote);
		writenote(&memnote, fp, offset);
		FREEBUF(memnote.data);

		info->fill_auxv_note(info, dump_tc, &memnote);
		info->size += notesize(&memnote);
		writenote(&memnote, fp, offset);
		FREEBUF(memnote.data);

		if (info->fill_files_note(info, dump_tc, &memnote)) {
			info->size += notesize(&memnote);
			writenote(&memnote, fp, offset);
			FREEBUF(memnote.data);
		}
	}

	for (i = 1; i < view->n; ++i) {
		const struct user_regset *regset = &view->regsets[i];

		if (!regset->core_note_type)
			continue;
		if (regset->active &&
		    !regset->active(tc, regset))
			continue;
		buf = GETBUF(regset->size);
		if (regset->get(tc, regset, regset->size, buf))
			goto fail;

		fill_note(&memnote, regset->name, regset->core_note_type,
			  regset->size, buf);
		*total += notesize(&memnote);
		writenote(&memnote, fp, offset);
	fail:
		FREEBUF(buf);
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
		info->fill_files_note = compat_fill_files_note;
		return info;
	}
#endif

	info->fill_prstatus_note = fill_prstatus_note;
	info->fill_psinfo_note = fill_psinfo_note;
	info->fill_auxv_note = fill_auxv_note;
	info->fill_files_note = fill_files_note;

	return info;
}

static int
fill_write_note_info(FILE *fp, struct elf_note_info *info, int phnum,
		     loff_t *offset)
{
	const struct user_regset_view *view = task_user_regset_view();
	struct task_context *tc;
	struct task_context *dump_tc = CURRENT_CONTEXT();
	ulong i;

	info->size = 0;

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

	/*
	 * Put dump task note information first. This is a common
	 * convension we can see in core dump generated by linux
	 * process core dumper and gdb gcore.
	 */
	fill_write_thread_core_info(fp, dump_tc, dump_tc, info, view,
				    offset, &info->size);
	FOR_EACH_TASK_IN_THREAD_GROUP(task_tgid(dump_tc->task), tc) {
		if (tc != dump_tc) {
			fill_write_thread_core_info(fp, tc, dump_tc, info,
						    view, offset, &info->size);
		}
	}

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
alignfile(FILE *fp, loff_t *foffset)
{
        static const char buffer[4] = {};
	const size_t len = roundup(*foffset, 4) - *foffset;

	if (len > 0) {
		if (fwrite(buffer, len, 1, fp) != 1)
			error(FATAL, "%s: write %s\n", gcore->corename,
			      strerror(errno));
		*foffset += (loff_t)len;
	}
}

static void
writenote(struct memelfnote *men, FILE *fp, loff_t *foffset)
{
	uint32_t n_namesz, n_descsz, n_type;

	n_namesz = strlen(men->name) + 1;
	n_descsz = men->datasz;
	n_type = men->type;

	gcore->elf->ops->fill_note_header(gcore->elf, n_namesz, n_descsz,
					  n_type);

	if (!gcore->elf->ops->write_note_header(gcore->elf, fp, foffset))
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));

	if (fwrite(men->name, n_namesz, 1, fp) != 1)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += n_namesz;

        alignfile(fp, foffset);

	if (fwrite(men->data, men->datasz, 1, fp) != 1)
		error(FATAL, "%s: write %s\n", gcore->corename,
		      strerror(errno));
	*foffset += men->datasz;

        alignfile(fp, foffset);

}

static size_t
get_note_info_size(struct elf_note_info *info)
{
	return info->size;
}

ulong first_vma(ulong mmap, ulong gate_vma)
{
	return mmap ? mmap : gate_vma;
}

ulong next_vma(ulong this_vma, ulong gate_vma)
{
	ulong next;

	next = ULONG(fill_vma_cache(this_vma) + OFFSET(vm_area_struct_vm_next));
	if (next)
		return next;
	if (this_vma == gate_vma)
		return 0UL;
	return gate_vma;
}

struct task_context *next_task_context(ulong tgid, struct task_context *tc)
{
	const struct task_context * const end = FIRST_CONTEXT() + RUNNING_TASKS();

	for (++tc; tc < end; ++tc)
		if (task_tgid(tc->task) == tgid)
			return tc;

	return NULL;
}

static void
fill_prstatus_note(struct elf_note_info *info, struct task_context *tc,
		   struct memelfnote *memnote)
{
	struct elf_prstatus *prstatus;
#if defined(X86) || defined(X86_64) || defined(ARM) || defined(MIPS) || defined(PPC64)
	struct user_regs_struct *regs = (struct user_regs_struct *)memnote->data;
#endif
#ifdef ARM64
	struct user_pt_regs *regs = (struct user_pt_regs *)memnote->data;
#endif
	ulong pending_signal_sig0, blocked_sig0, real_parent, group_leader,
		signal, cutime,	cstime;

	prstatus = (struct elf_prstatus *)GETBUF(sizeof(*prstatus));
	memcpy(&prstatus->pr_reg, regs, sizeof(*regs));

        fill_note(memnote, "CORE", NT_PRSTATUS, sizeof(*prstatus), prstatus);

        /* The type of (sig[0]) is unsigned long. */
	readmem(tc->task + OFFSET(task_struct_pending) + OFFSET(sigpending_signal),
		KVADDR, &pending_signal_sig0, sizeof(unsigned long),
		"fill_prstatus: sigpending_signal_sig",
		gcore_verbose_error_handle());

	readmem(tc->task + OFFSET(task_struct_blocked), KVADDR, &blocked_sig0,
		sizeof(unsigned long), "fill_prstatus: blocked_sig0",
		gcore_verbose_error_handle());

	readmem(tc->task + OFFSET(task_struct_parent), KVADDR, &real_parent,
		sizeof(real_parent), "fill_prstatus: real_parent",
		gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"fill_prstatus: group_leader", gcore_verbose_error_handle());

	prstatus->pr_info.si_signo = prstatus->pr_cursig = 0;
        prstatus->pr_sigpend = pending_signal_sig0;
        prstatus->pr_sighold = blocked_sig0;
        prstatus->pr_ppid = ggt->task_pid(real_parent);
        prstatus->pr_pid = ggt->task_pid(tc->task);
        prstatus->pr_pgrp = ggt->task_pgrp(tc->task);
        prstatus->pr_sid = ggt->task_session(tc->task);

        if (thread_group_leader(tc->task)) {
                struct task_cputime cputime;

                /*
                 * This is the record for the group leader.  It shows the
                 * group-wide total, not its individual thread total.
                 */
                ggt->thread_group_cputime(tc->task, &cputime);
                cputime_to_timeval(cputime.utime, &prstatus->pr_utime);
                cputime_to_timeval(cputime.stime, &prstatus->pr_stime);
        } else {
		cputime_t utime, stime;

		readmem(tc->task + OFFSET(task_struct_utime), KVADDR, &utime,
			sizeof(utime), "task_struct utime",
			gcore_verbose_error_handle());

		readmem(tc->task + OFFSET(task_struct_stime), KVADDR, &stime,
			sizeof(stime), "task_struct stime",
			gcore_verbose_error_handle());

                cputime_to_timeval(utime, &prstatus->pr_utime);
                cputime_to_timeval(stime, &prstatus->pr_stime);
        }

	readmem(tc->task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "task_struct signal", gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cutime, sizeof(cutime), "signal_struct cutime",
		gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cstime, sizeof(cstime), "signal_struct cstime",
		gcore_verbose_error_handle());

        cputime_to_timeval(cutime, &prstatus->pr_cutime);
        cputime_to_timeval(cstime, &prstatus->pr_cstime);

	prstatus->pr_fpvalid = gcore_arch_get_fp_valid(tc);
}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_prstatus_note(struct elf_note_info *info,
			  struct task_context *tc,
			  struct memelfnote *memnote)
{
	struct compat_elf_prstatus *prstatus;
	compat_elf_gregset_t *regs =
		(compat_elf_gregset_t *)memnote->data;
	ulong pending_signal_sig0, blocked_sig0, real_parent, group_leader,
		signal, cutime,	cstime;

	prstatus = (struct compat_elf_prstatus *)GETBUF(sizeof(*prstatus));
	memcpy(&prstatus->pr_reg, regs, sizeof(*regs));

        fill_note(memnote, "CORE", NT_PRSTATUS, sizeof(*prstatus), prstatus);

        /* The type of (sig[0]) is unsigned long. */
	readmem(tc->task + OFFSET(task_struct_pending) + OFFSET(sigpending_signal),
		KVADDR, &pending_signal_sig0, sizeof(unsigned long),
		"fill_prstatus: sigpending_signal_sig",
		gcore_verbose_error_handle());

	readmem(tc->task + OFFSET(task_struct_blocked), KVADDR, &blocked_sig0,
		sizeof(unsigned long), "fill_prstatus: blocked_sig0",
		gcore_verbose_error_handle());

	readmem(tc->task + OFFSET(task_struct_parent), KVADDR, &real_parent,
		sizeof(real_parent), "fill_prstatus: real_parent",
		gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(task_struct_group_leader), KVADDR,
		&group_leader, sizeof(group_leader),
		"fill_prstatus: group_leader", gcore_verbose_error_handle());

	prstatus->pr_info.si_signo = prstatus->pr_cursig = 0;
        prstatus->pr_sigpend = pending_signal_sig0;
        prstatus->pr_sighold = blocked_sig0;
        prstatus->pr_ppid = ggt->task_pid(real_parent);
        prstatus->pr_pid = ggt->task_pid(tc->task);
        prstatus->pr_pgrp = ggt->task_pgrp(tc->task);
        prstatus->pr_sid = ggt->task_session(tc->task);

        if (thread_group_leader(tc->task)) {
                struct task_cputime cputime;

                /*
                 * This is the record for the group leader.  It shows the
                 * group-wide total, not its individual thread total.
                 */
                ggt->thread_group_cputime(tc->task, &cputime);
                cputime_to_compat_timeval(cputime.utime, &prstatus->pr_utime);
                cputime_to_compat_timeval(cputime.stime, &prstatus->pr_stime);
        } else {
		cputime_t utime, stime;

		readmem(tc->task + OFFSET(task_struct_utime), KVADDR, &utime,
			sizeof(utime), "task_struct utime",
			gcore_verbose_error_handle());

		readmem(tc->task + OFFSET(task_struct_stime), KVADDR, &stime,
			sizeof(stime), "task_struct stime",
			gcore_verbose_error_handle());

                cputime_to_compat_timeval(utime, &prstatus->pr_utime);
                cputime_to_compat_timeval(stime, &prstatus->pr_stime);
        }

	readmem(tc->task + OFFSET(task_struct_signal), KVADDR, &signal,
		sizeof(signal), "task_struct signal",
		gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cutime, sizeof(cutime), "signal_struct cutime",
		gcore_verbose_error_handle());

	readmem(tc->task + GCORE_OFFSET(signal_struct_cutime), KVADDR,
		&cstime, sizeof(cstime), "signal_struct cstime",
		gcore_verbose_error_handle());

        cputime_to_compat_timeval(cutime, &prstatus->pr_cutime);
        cputime_to_compat_timeval(cstime, &prstatus->pr_cstime);

	prstatus->pr_fpvalid = gcore_arch_get_fp_valid(tc);
}

#endif /* GCORE_ARCH_COMPAT */

static void
fill_auxv_note(struct elf_note_info *info, struct task_context *tc,
	       struct memelfnote *memnote)
{
	ulong *auxv;
	int i;

	auxv = (ulong *)GETBUF(GCORE_SIZE(mm_struct_saved_auxv));

	readmem(task_mm(tc->task, FALSE) +
		GCORE_OFFSET(mm_struct_saved_auxv), KVADDR, auxv,
		GCORE_SIZE(mm_struct_saved_auxv), "fill_auxv_note",
		gcore_verbose_error_handle());

	i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);

	fill_note(memnote, "CORE", NT_AUXV, i * sizeof(ulong), auxv);

}

#ifdef GCORE_ARCH_COMPAT

static void
compat_fill_auxv_note(struct elf_note_info *info,
		      struct task_context *tc,
		      struct memelfnote *memnote)
{
	uint32_t *auxv;
	int i;

	auxv = (uint32_t *)GETBUF(GCORE_SIZE(mm_struct_saved_auxv));

	readmem(task_mm(tc->task, FALSE) +
		GCORE_OFFSET(mm_struct_saved_auxv), KVADDR, auxv,
		GCORE_SIZE(mm_struct_saved_auxv), "fill_auxv_note32",
		gcore_verbose_error_handle());

	i = 0;
	do
		i += 2;
	while (auxv[i - 2] != AT_NULL);

	fill_note(memnote, "CORE", NT_AUXV, i * sizeof(uint32_t), auxv);
}

#endif /* GCORE_ARCH_COMPAT */

static int
fill_files_note(struct elf_note_info *info, struct task_context *tc,
	       struct memelfnote *memnote)
{
	ulong mmap, gate_vma, vma, vm_start, vm_end, vm_file, vm_pgoff, dentry, vfsmnt;
	unsigned count, map_count, size, names_ofs, remaining, n, index;
	ulong *data, *start_end_ofs;
	char *name_base, *name_curpos, *file_buf, *mm_cache;
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);

	mm_cache = fill_mm_struct(task_mm(CURRENT_TASK(), TRUE));
	if (!mm_cache) {
		error(WARNING, "The user memory space does not exist.\n");
		return FALSE;
	}

	mmap = ULONG(mm_cache + OFFSET(mm_struct_mmap));
	gate_vma = gcore_arch_get_gate_vma();

	/* *Estimated* file count and total data size needed */
	map_count = count = INT(mm_cache + GCORE_OFFSET(mm_struct_map_count));
	if (count > UINT_MAX / 64) {
		error(WARNING, "Map count too big.\n");
		return FALSE;
	}
	size = count * 64;
	names_ofs = (2 + 3 * count) * sizeof(data[0]);

	/* paranoia check */
	if (size >= ELF_EXEC_PAGESIZE * 1024) {
		error(WARNING, "Size required for file_note is too big.\n");
		return FALSE;
	}
	size = PAGE_ALIGN(size);
	data = (ulong *)GETBUF(size);
	BZERO(data, size);

	start_end_ofs = data + 2;
	name_base = name_curpos = ((char *)data) + names_ofs;
	remaining = size - names_ofs;
	count = 0;

	FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
		char *vma_cache;

		if (!IS_KVADDR(vma))
			continue;

		vma_cache = fill_vma_cache(vma);
		vm_start = ULONG(vma_cache + OFFSET(vm_area_struct_vm_start));
		vm_end = ULONG(vma_cache + OFFSET(vm_area_struct_vm_end));
		vm_file = ULONG(vma_cache + OFFSET(vm_area_struct_vm_file));
		vm_pgoff = ULONG(vma_cache + OFFSET(vm_area_struct_vm_pgoff));

		if (!vm_file)
			continue;

		file_buf = fill_file_cache(vm_file);
		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
		if (dentry) {
			fill_dentry_cache(dentry);
			if (VALID_MEMBER(file_f_vfsmnt)) {
				vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
				get_pathname(dentry, buf, BUFSIZE, 1, vfsmnt);
			} else {
				get_pathname(dentry, buf, BUFSIZE, 1, 0);
			}
		}

		/* get_pathname() fills at the end, move name down */
		n = strlen(buf)*sizeof(char) + 1;
		remaining -= n;
		memmove(name_curpos, buf, n);
		progressf("FILE %s\n", name_curpos);
		name_curpos += n;

		*start_end_ofs++ = vm_start;
		*start_end_ofs++ = vm_end;
		*start_end_ofs++ = vm_pgoff;
		count++;
	}

	/* Now we know exact count of files, can store it */
	data[0] = count;
	data[1] = size;

	/*
	 * Count usually is less than map_count,
	 * we need to move filenames down.
	 */
	n = map_count - count;
	if (n != 0) {
		unsigned shift_bytes = n * 3 * sizeof(data[0]);
		memmove(name_base - shift_bytes, name_base,
			name_curpos - name_base);
		name_curpos -= shift_bytes;
	}

	size = name_curpos - (char *)data;
	fill_note(memnote, "CORE", NT_FILE, size, data);

	return TRUE;
}

#ifdef GCORE_ARCH_COMPAT
static int
compat_fill_files_note(struct elf_note_info *info, struct task_context *tc,
		       struct memelfnote *memnote)
{
	ulong mmap, gate_vma, vma, vm_start, vm_end, vm_file, vm_pgoff, dentry, vfsmnt;
	unsigned count, map_count, size, names_ofs, remaining, n, index;
	unsigned int *data, *start_end_ofs;
	char *name_base, *name_curpos, *file_buf, *mm_cache;
	char buf[BUFSIZE];

	BZERO(buf, BUFSIZE);

	mm_cache = fill_mm_struct(task_mm(CURRENT_TASK(), TRUE));
	if (!mm_cache) {
		error(WARNING, "The user memory space does not exist.\n");
		return FALSE;
	}

	mmap = ULONG(mm_cache + OFFSET(mm_struct_mmap));
	gate_vma = gcore_arch_get_gate_vma();

	/* *Estimated* file count and total data size needed */
	map_count = count = INT(mm_cache + GCORE_OFFSET(mm_struct_map_count));
	if (count > UINT_MAX / 64) {
		error(WARNING, "Map count too big.\n");
		return FALSE;
	}
	size = count * 64;
	names_ofs = (2 + 3 * count) * sizeof(data[0]);

	/* paranoia check */
	if (size >= ELF_EXEC_PAGESIZE * 1024) {
		error(WARNING, "Size required for file_note is too big.\n");
		return FALSE;
	}
	size = PAGE_ALIGN(size);
	data = (unsigned int *)GETBUF(size);
	BZERO(data, size);

	start_end_ofs = data + 2;
	name_base = name_curpos = ((char *)data) + names_ofs;
	remaining = size - names_ofs;
	count = 0;

	FOR_EACH_VMA_OBJECT(vma, index, mmap, gate_vma) {
		char *vma_cache;

		if (!IS_KVADDR(vma))
			continue;

		vma_cache = fill_vma_cache(vma);
		vm_start = ULONG(vma_cache + OFFSET(vm_area_struct_vm_start));
		vm_end = ULONG(vma_cache + OFFSET(vm_area_struct_vm_end));
		vm_file = ULONG(vma_cache + OFFSET(vm_area_struct_vm_file));
		vm_pgoff = ULONG(vma_cache + OFFSET(vm_area_struct_vm_pgoff));

		if (!vm_file)
			continue;

		file_buf = fill_file_cache(vm_file);
		dentry = ULONG(file_buf + OFFSET(file_f_dentry));
		if (dentry) {
			fill_dentry_cache(dentry);
			if (VALID_MEMBER(file_f_vfsmnt)) {
				vfsmnt = ULONG(file_buf + OFFSET(file_f_vfsmnt));
				get_pathname(dentry, buf, BUFSIZE, 1, vfsmnt);
			} else {
				get_pathname(dentry, buf, BUFSIZE, 1, 0);
			}
		}

		/* get_pathname() fills at the end, move name down */
		n = strlen(buf)*sizeof(char) + 1;
		remaining -= n;
		memmove(name_curpos, buf, n);
		progressf("FILE %s\n", name_curpos);
		name_curpos += n;

		*start_end_ofs++ = vm_start;
		*start_end_ofs++ = vm_end;
		*start_end_ofs++ = vm_pgoff;
		count++;
	}

	/* Now we know exact count of files, can store it */
	data[0] = count;
	data[1] = size;

	/*
	 * Count usually is less than map_count,
	 * we need to move filenames down.
	 */
	n = map_count - count;
	if (n != 0) {
		unsigned shift_bytes = n * 3 * sizeof(data[0]);
		memmove(name_base - shift_bytes, name_base,
			name_curpos - name_base);
		name_curpos -= shift_bytes;
	}

	size = name_curpos - (char *)data;
	fill_note(memnote, "CORE", NT_FILE, size, data);

	return TRUE;
}
#endif /* GCORE_ARCH_COMPAT */

static int uvtop_quiet(ulong vaddr, physaddr_t *paddr)
{
	FILE *saved_fp = fp;
	int page_present;

	/* uvtop() with verbose FALSE returns wrong physical address
	 * for gate_vma. The problem is that kvtop() wrongly thinks of
	 * the fixed address 0xffffffffff600000 as the one that
	 * belongs to direct mapping region and calculates the result
	 * by substracting offset of direct-mapping space from the
	 * fixed address. However, it's necessary to do paging to get
	 * correct physical address.
	 *
	 * uvtop() does paging if verbose == TRUE. Then, it retuns
	 * correct physical address.
	 *
	 * Next output of vtop clarifies this bug, where the first
	 * PHYSICAL showing 0x7f600000 is wrong one and the PHYSICAL
	 * in the last line showing 0x1c08000 is correct one.
	 *
	 * crash> vtop 0xffffffffff600000
	 * VIRTUAL           PHYSICAL        
	 * ffffffffff600000  7f600000        
	 *
	 * PML4 DIRECTORY: ffffffff81a85000
	 * PAGE DIRECTORY: 1a87067
	 *    PUD: 1a87ff8 => 1a88067
	 *    PMD: 1a88fd8 => 28049067
	 *    PTE: 28049000 => 1c08165
	 *   PAGE: 1c08000
	 *
	 *   PTE    PHYSICAL  FLAGS
	 * 1c08165   1c08000  (PRESENT|USER|ACCESSED|DIRTY|GLOBAL)
	 *
	 *       PAGE        PHYSICAL      MAPPING       INDEX CNT FLAGS
	 * ffffea00000621c0   1c08000                0        0  1 20000000000400
	 *
	 * The remaining problem is that if specifying TRUE to
	 * verbose, same information is displayed during gcore
	 * processing. To avoid this, we assign the file pointer to
	 * /dev/null to fp during call of uvtop().
	 */
	fp = pc->nullfp;
	page_present = uvtop(CURRENT_CONTEXT(), vaddr, paddr, TRUE);
	fp = saved_fp;

	return page_present;
}
