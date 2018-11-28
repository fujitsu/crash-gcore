/* gcore_dumpfilter.c -- core analysis suite
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
#include <elf.h>

static ulong dumpfilter = GCORE_DUMPFILTER_DEFAULT;

static int special_mapping_name(ulong vma)
{
	ulong vm_private_data, name_p;

	readmem(vma + GCORE_OFFSET(vm_area_struct_vm_private_data),
		KVADDR,
		&vm_private_data,
		sizeof(vm_private_data),
		"always_dump_vma: vma->vm_private_data",
		gcore_verbose_error_handle());

	readmem(vm_private_data +
		GCORE_OFFSET(vm_special_mapping_name),
		KVADDR,
		&name_p,
		sizeof(name_p),
		"always_dump_vma: ((struct vm_special_mapping *)vma->vm_private_data)->name",
		gcore_verbose_error_handle());

	return name_p ? TRUE : FALSE;
}

static int always_dump_vma(ulong vma)
{
	if (vma == gcore_arch_get_gate_vma())
		return TRUE;

	if (GCORE_VALID_MEMBER(vm_special_mapping_name)) {
		ulong vm_ops, name;

		readmem(vma + GCORE_OFFSET(vm_area_struct_vm_ops),
			KVADDR,
			&vm_ops,
			sizeof(vm_ops),
			"always_dump_vma: vma->vm_ops",
			gcore_verbose_error_handle());

		if (!vm_ops)
			goto out;

		readmem(vm_ops + GCORE_OFFSET(vm_operations_struct_name),
			KVADDR,
			&name,
			sizeof(name),
			"always_dump_vma: vma->vm_ops->name",
			gcore_verbose_error_handle());

		if (!name)
			goto out;

		if (name == symbol_value("special_mapping_name"))
			return special_mapping_name(vma);
	}
out:

	if (gcore_arch_vma_name(vma))
		return TRUE;
	return FALSE;
}

/**
 * Set a given filter value to the current state
 * @filter a filter value given from command line
 *
 * Precondition:
 *
 *   - Nothing.
 *
 * Postcondition:
 *
 *   - If @filter > GCORE_DUMPFILTER_MAX_LEVEL, then the Precondition remains.
 *
 *   - Otherwise, dumpfilter == @filter.
 *
 * Return Value:
 *
 *   - If @filter > GCORE_DUMPFILTER_MAX_LEVEL, return FALSE.
 *   - Otherwise, return TRUE>
 */
int gcore_dumpfilter_set(ulong filter)
{
	if (filter > GCORE_DUMPFILTER_MAX_LEVEL)
		return FALSE;

	dumpfilter = filter;

	return TRUE;
}

void gcore_dumpfilter_set_default(void)
{
	dumpfilter = GCORE_DUMPFILTER_DEFAULT;
}

ulong gcore_dumpfilter_get(void)
{
	return dumpfilter;
}

static inline int is_filtered(int bit)
{
	return !!(dumpfilter & bit);
}

ulong gcore_dumpfilter_vma_dump_size(ulong vma)
{
	char *vma_cache;
	physaddr_t paddr;
	ulong vm_start, vm_end, vm_flags, vm_file, vm_pgoff, anon_vma;

	vma_cache = fill_vma_cache(vma);
	vm_start = ULONG(vma_cache + OFFSET(vm_area_struct_vm_start));
	vm_end = ULONG(vma_cache + OFFSET(vm_area_struct_vm_end));
	vm_flags = ULONG(vma_cache + OFFSET(vm_area_struct_vm_flags));
	vm_file = ULONG(vma_cache + OFFSET(vm_area_struct_vm_file));
	vm_pgoff = ULONG(vma_cache + OFFSET(vm_area_struct_vm_pgoff));
	anon_vma = ULONG(vma_cache + GCORE_OFFSET(vm_area_struct_anon_vma));

        /* always dump the vdso and vsyscall sections */
	if (always_dump_vma(vma))
		goto whole;

	if (!gcore_machdep->vm_alwaysdump && (vm_flags & VM_DONTDUMP) &&
	    !is_filtered(GCORE_DUMPFILTER_DONTDUMP))
		goto nothing;

        /* Hugetlb memory check */
	if (vm_flags & VM_HUGETLB) {
		if ((vm_flags & VM_SHARED)
		    ? is_filtered(GCORE_DUMPFILTER_HUGETLB_SHARED)
		    : is_filtered(GCORE_DUMPFILTER_HUGETLB_PRIVATE))
			goto whole;

		/* Hugepage memory filtering was introduced at the
		 * time where VM_NODUMP or VM_DONTDUMP flag was not
		 * introduced yet, so there was still VM_RESERVED
		 * flag. At that time, vmas with VM_HUGETLB flag
		 * always had VM_RESERVED flag, too. This means that
		 * if the vma had VM_HUGETLB flag and it was not
		 * filtered by neither of two filtering types,
		 * GCORE_DUMPFILTER_HUGETLB_{SHARED, PRIVATE}, then
		 * the memory was always filtered by VM_RESEARVED
		 * check below. However, after VM_NODUMP or
		 * VM_DONTDUMP was introduced, VM_RESERVED flag was
		 * removed and the check to see if VM_RESERVED flag
		 * was set, was also removed. This goto nothing is
		 * needed instead of checking the VM_RESERVED flag. */
		goto nothing;
	}

        /* Do not dump I/O mapped devices */
        if (vm_flags & VM_IO)
		goto nothing;

	/* Do not dump special mappings */
	if (GCORE_VALID_MEMBER(mm_struct_reserved_vm)
	    && (vm_flags & VM_RESERVED))
		goto nothing;

        /* By default, dump shared memory if mapped from an anonymous file. */
        if (vm_flags & VM_SHARED) {

		if (ggt->get_inode_i_nlink(vm_file)
		    ? is_filtered(GCORE_DUMPFILTER_MAPPED_SHARED)
		    : is_filtered(GCORE_DUMPFILTER_ANON_SHARED))
			goto whole;

		goto nothing;
        }

        /* Dump segments that have been written to.  */
        if (anon_vma && is_filtered(GCORE_DUMPFILTER_ANON_PRIVATE))
                goto whole;
        if (!vm_file)
		goto nothing;

        if (is_filtered(GCORE_DUMPFILTER_MAPPED_PRIVATE))
                goto whole;

        /*
         * If this looks like the beginning of a DSO or executable mapping,
         * check for an ELF header.  If we find one, dump the first page to
         * aid in determining what was mapped here.
         */
        if (is_filtered(GCORE_DUMPFILTER_ELF_HEADERS) &&
            vm_pgoff == 0 && (vm_flags & VM_READ)) {
		ulong header = vm_start;
		uint32_t word = 0;
                /*
                 * Doing it this way gets the constant folded by GCC.
                 */
                union {
                        uint32_t cmp;
                        char elfmag[SELFMAG];
                } magic;
                magic.elfmag[EI_MAG0] = ELFMAG0;
                magic.elfmag[EI_MAG1] = ELFMAG1;
                magic.elfmag[EI_MAG2] = ELFMAG2;
                magic.elfmag[EI_MAG3] = ELFMAG3;
		if (uvtop(CURRENT_CONTEXT(), header, &paddr, FALSE)) {
			readmem(paddr, PHYSADDR, &word, sizeof(magic.elfmag),
				"read ELF page", gcore_verbose_error_handle());
		} else {
			pagefaultf("page fault at %lx\n", header);
		}
                if (word == magic.cmp)
			goto pagesize;
        }

nothing:
        return 0;

whole:
        return vm_end - vm_start;

pagesize:
	return PAGE_SIZE;
}
