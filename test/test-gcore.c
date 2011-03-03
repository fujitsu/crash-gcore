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
#include <CUnit/Basic.h>

static char *help_test_gcore[];
static void cmd_test_gcore(void);

static void gcore_tc_gcore_verbose_set_default(void);
static void gcore_tc_gcore_verbose_set(void);

static void gcore_tc_gcore_dumpfilter_set_default(void);
static void gcore_tc_gcore_dumpfilter_set(void);

static struct command_table_entry command_table[] = {
	{ "test_gcore", cmd_test_gcore, help_test_gcore, 0 },
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

static char *help_test_gcore[] = {
"test_gcore",
"test_gcore - test vmcore-independent part in gcore extension module",
"  ",
"  Execute a set of testcases and then display their results.",
"  ",
NULL,
};

static void cmd_test_gcore(void)
{
	CU_pSuite pSuite = NULL;

	if (CUE_SUCCESS != CU_initialize_registry())
		goto CU_error;

	pSuite = CU_add_suite("gcore_verbose.c", NULL, NULL);
	if (!pSuite)
		goto CU_error;

	if (!CU_add_test(pSuite, "test of gcore_verbose_set_default()",
			 gcore_tc_gcore_verbose_set_default))
		goto CU_error;

	if (!CU_add_test(pSuite, "test of gcore_verse_set()",
			 gcore_tc_gcore_verbose_set))
		goto CU_error;

	pSuite = CU_add_suite("gcore_dumpfilter.c", NULL, NULL);
	if (!pSuite)
		goto CU_error;

	if (!CU_add_test(pSuite, "test of gcore_dumpfilter_set_default()",
			 gcore_tc_gcore_dumpfilter_set_default))
		goto CU_error;

	if (!CU_add_test(pSuite, "test of gcore_dumpfilter_set()",
			 gcore_tc_gcore_dumpfilter_set))
		goto CU_error;

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();

	return;

CU_error:
	error(FATAL, "%s\n", CU_get_error_msg());
	CU_cleanup_registry();
}

static void gcore_tc_gcore_verbose_set_default(void)
{
	gcore_verbose_set_default();

	CU_ASSERT(gcore_verbose_get() == VERBOSE_DEFAULT_LEVEL &&
		  gcore_verbose_error_handle() == VERBOSE_DEFAULT_ERROR_HANDLE);
}

static void gcore_tc_gcore_verbose_set(void)
{
	ulong prev_level, prev_error_handle;

	/* negative case */
	prev_level = gcore_verbose_get();
	prev_error_handle = gcore_verbose_error_handle();

	CU_ASSERT_FALSE(gcore_verbose_set(VERBOSE_MAX_LEVEL+1));
	CU_ASSERT(prev_level == gcore_verbose_get() &&
		  prev_error_handle == gcore_verbose_error_handle());

	/* positive case */
	CU_ASSERT(gcore_verbose_set(VERBOSE_MAX_LEVEL) == TRUE
		  && gcore_verbose_set(0) == TRUE);
	CU_ASSERT_TRUE(gcore_verbose_set(VERBOSE_PROGRESS));
	CU_ASSERT(gcore_verbose_error_handle() & QUIET);
	CU_ASSERT_TRUE(gcore_verbose_set(VERBOSE_NONQUIET));
	CU_ASSERT(!(gcore_verbose_error_handle() & QUIET));
	CU_ASSERT_TRUE(gcore_verbose_set(VERBOSE_PAGEFAULT));
	CU_ASSERT(gcore_verbose_error_handle() & QUIET);
}

static void gcore_tc_gcore_dumpfilter_set_default(void)
{
	CU_FAIL("Not implemented yet");
}

static void gcore_tc_gcore_dumpfilter_set(void)
{
	CU_FAIL("Not implemented yet");
}
