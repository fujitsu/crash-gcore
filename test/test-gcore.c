/* test-gcore.c -- core analysis suite
 *
 * Copyright (C) 2011 FUJITSU LIMITED
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
#include <test-gcore.h>

static char *help_test_gcore_verbose[];
static void cmd_test_gcore_verbose(void);

static void gcore_tc_gcore_verbose_set_default(struct gcore_test_result *);
static void gcore_tc_gcore_verbose_set(struct gcore_test_result *);

static struct command_table_entry command_table[] = {
	{ "test_gcore_verbose", cmd_test_gcore_verbose, help_test_gcore_verbose, 0 },
	{ (char *)NULL }                               
};

int 
_init(void) /* Register the command set. */
{
	register_extension(command_table);
	return 1;
}
 
int 
_fini(void) 
{ 
	return 1;
}

static char *help_test_gcore_verbose[] = {
"test_gcore_verbose",
"test_gcore_verbose - test verbose feature of gcore extension module",
"  ",
"  Execute a set of testcases and then display their results.",
"  ",
NULL,
};

static void cmd_test_gcore_verbose(void)
{
	struct gcore_test_result res;

	gcore_reset_result(&res);

	fprintf(fp, "SUITE: gcore_verbose.c\n");

	gcore_reset_result(&res);
	fprintf(fp, "TEST: gcore_verbose_set_default()\n");
	gcore_tc_gcore_verbose_set_default(&res);
	gcore_print_result(&res);

	fprintf(fp, "\n");

	gcore_reset_result(&res);
	fprintf(fp, "TEST: gcore_verbose_set()\n");
	gcore_tc_gcore_verbose_set(&res);
	gcore_print_result(&res);
}

static void gcore_tc_gcore_verbose_set_default(struct gcore_test_result *res)
{
	gcore_verbose_set_default();

	gcore_assert(gcore_verbose_get() == VERBOSE_DEFAULT_LEVEL
		     && gcore_verbose_error_handle() == VERBOSE_DEFAULT_ERROR_HANDLE,
		     "verbose default value mismatch",
		     res);
}

static void gcore_tc_gcore_verbose_set(struct gcore_test_result *res)
{
	ulong prev_level, prev_error_handle;

	/* negative case */
	prev_level = gcore_verbose_get();
	prev_error_handle = gcore_verbose_error_handle();
	gcore_assert(gcore_verbose_set(VERBOSE_MAX_LEVEL+1) == FALSE,
		     "succeeded even if a value larger than VERBOSE_MAX_LEVEL is given",
		     res);
	gcore_assert(prev_level == gcore_verbose_get()
		     && prev_error_handle == gcore_verbose_error_handle(),
		     "gcore_verbose_set(VERBOSE_MAX_LEVEL+1) doesn't preserve the state",
		     res);

	/* positive case */
	gcore_assert(gcore_verbose_set(VERBOSE_MAX_LEVEL) && gcore_verbose_set(0),
		     "failed even if valid input is given",
		     res);

	gcore_assert(gcore_verbose_set(VERBOSE_PROGRESS),
		     "setting VERBOSE_PROGRESS failed",
		     res);
	gcore_assert(gcore_verbose_error_handle() & QUIET,
		     "somehow QUIET has not been set in case of VERBOSE_PROGRESS",
		     res);

	gcore_assert(gcore_verbose_set(VERBOSE_NONQUIET),
		     "setting VERBOSE_NONQUIET failed",
		     res);
	gcore_assert(!(gcore_verbose_error_handle() & QUIET),
		     "somehow QUIET has been unset in case of VERBOSE_NONQUIET",
		     res);

	gcore_assert(gcore_verbose_set(VERBOSE_PAGEFAULT),
		     "setting VERBOSE_PAGEFAULT failed",
		     res);
	gcore_assert(gcore_verbose_error_handle() & QUIET,
		     "somehow QUIET has not been set in case of VERBOSE_PAGEFAULT",
		     res);
}
