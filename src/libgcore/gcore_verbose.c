/* gcore_verbose.c -- core analysis suite
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

struct gcore_verbose_data
{
	ulong level;
	ulong error_handle;
};

static struct gcore_verbose_data gcore_verbose_data = { 0 };
static struct gcore_verbose_data *gvd = &gcore_verbose_data;

/**
 * set current verbose state to the default
 *
 * Precondition:
 *
 *   Nothing.
 *
 * Postcondition:
 *
 *   - gcore_verbose_get() == VERBOSE_DEFAULT_LEVEL
 *   - gcore_verbose_error_handle() == VERBOSE_DEFAULT_ERROR_HANDLE
 *
 * Return Value:
 *
 *   Nothing.
 */
void gcore_verbose_set_default(void)
{
	gvd->level = VERBOSE_DEFAULT_LEVEL;
	gvd->error_handle = VERBOSE_DEFAULT_ERROR_HANDLE;
}

/**
 * set current verbose state to the one corresponding to a given level
 *
 * @level verbose level to be set
 *
 * Precondition:
 *
 *   Nothing.
 *
 * Postcondition:
 *
 *   If 0 <= @level <= VERBOSE_MAX_LEVEL, gcore_verbose_get() ==
 *   @level. If VERBOSE_NONQUIET is set to @level, QUIET is unset to
 *   gcore_verbose_error_handle(). If VERBOSE_NONQUIET is set, QUIET
 *   is set conversely. If @level > VERBOSE_MAX_LEVEL, the state
 *   remains the same.
 *
 * Return Value:
 *
 *   If 0 <= @level <= VERBOSE_MAX_LEVEL, return TRUE. Otherwise,
 *   return FALSE.
 */
int gcore_verbose_set(ulong level)
{
	if (level > VERBOSE_MAX_LEVEL)
		return FALSE;
	gvd->level = level;
	if (gvd->level & VERBOSE_NONQUIET)
		gvd->error_handle &= ~QUIET;
	else
		gvd->error_handle |= QUIET;
	return TRUE;
}

ulong gcore_verbose_get(void)
{
	return gvd->level;
}

ulong gcore_verbose_error_handle(void)
{
	return gvd->error_handle;
}

#ifdef GCORE_TEST

char *gcore_verbose_test(void)
{
	int test;

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_PROGRESS);
	mu_assert("failed to set VERBOSE_PROGRESS", test);
	test = !!(gcore_verbose_get() & VERBOSE_PROGRESS);
	mu_assert("VERBOSE_PROGRESS is not set even after set operation", test);
	test = !!(gcore_verbose_error_handle() & QUIET);
	mu_assert("error_handle is not set to QUIET", test);

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_NONQUIET);
	mu_assert("failed to set VERBOSE_NONQUIET", test);
	test = !!(gcore_verbose_get() & VERBOSE_NONQUIET);
	mu_assert("VERBOSE_NONQUIET is not set even after set operation", test);
	test = !!(gcore_verbose_error_handle() & QUIET);
	mu_assert("error_handle is set to QUIET even if VERBOSE_NONQUIET is set", !test);

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_PAGEFAULT);
	mu_assert("failed to set VERBOSE_PAGEFAULT", test);
	test = !!(gcore_verbose_get() & VERBOSE_PAGEFAULT);
	mu_assert("VERBOSE_PAGEFAULT is not set even after set operation", test);
	test = !!(gcore_verbose_error_handle() & QUIET);
	mu_assert("error_handle is not set to QUIET", test);

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_PAGEFAULT | VERBOSE_NONQUIET);
	mu_assert("failed to set VERBOSE_PAGEFAULT | VERBOSE_NONQUIET", test);
	test = !!(gcore_verbose_get() & (VERBOSE_PAGEFAULT | VERBOSE_NONQUIET));
	mu_assert("VERBOSE_PAGEFAULT is not set even after set operation", test);
	test = !!(gcore_verbose_error_handle() & QUIET);
	mu_assert("error_handle is not set to QUIET", !test);

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_MAX_LEVEL);
	mu_assert("VERBOSE_MAX_LEVEL should be valid, but here thought of as invalid.", test);

	gcore_verbose_set_default();
	test = gcore_verbose_set(VERBOSE_MAX_LEVEL+1);
	mu_assert("(VERBOSE_MAX_LEVEL+1) should be invalid, but somehow accepted.", !test);

	return NULL;
}

#endif /* GCORE_TEST */

