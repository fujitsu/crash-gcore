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

        /* The vma can be set up to tell us the answer directly.  */
        if (vm_flags & VM_ALWAYSDUMP)
                goto whole;

        /* Hugetlb memory check */
	if (vm_flags & VM_HUGETLB)
		if ((vm_flags & VM_SHARED)
		    ? is_filtered(GCORE_DUMPFILTER_HUGETLB_SHARED)
		    : is_filtered(GCORE_DUMPFILTER_HUGETLB_PRIVATE))
			goto whole;

        /* Do not dump I/O mapped devices or special mappings */
        if (vm_flags & (VM_IO | VM_RESERVED))
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

#ifdef GCORE_TEST

char *gcore_dumpfilter_test(void)
{
	dumpfilter = 0UL;
	mu_assert("given filter level is too large",
		  !gcore_dumpfilter_set(GCORE_DUMPFILTER_MAX_LEVEL + 1));
	mu_assert("dumpfilter was updated given an invalid argument",
		  dumpfilter == 0UL);

	dumpfilter = 0UL;
	mu_assert("didn't return TRUE even if a valid argument was given",
		  gcore_dumpfilter_set(GCORE_DUMPFILTER_MAX_LEVEL));
	mu_assert("not set given valid argument",
		  dumpfilter == GCORE_DUMPFILTER_MAX_LEVEL);
	dumpfilter = GCORE_DUMPFILTER_DEFAULT;

	return NULL;
}

#endif
