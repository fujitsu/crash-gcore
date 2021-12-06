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
	ulong error_handle_user;
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
	gvd->error_handle_user = VERBOSE_DEFAULT_ERROR_HANDLE_USER;
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
	if (gvd->level & VERBOSE_NONQUIET) {
		gvd->error_handle &= ~QUIET;
		gvd->error_handle_user &= ~QUIET;
	} else {
		gvd->error_handle |= QUIET;
		gvd->error_handle_user |= QUIET;
	}
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

ulong gcore_verbose_error_handle_user(void)
{
	return gvd->error_handle_user;
}
