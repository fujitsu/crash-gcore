/* gcore_global_data.c -- core analysis suite
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

static struct gcore_one_session_data gcore_one_session_data = {0, };
struct gcore_one_session_data *gcore = &gcore_one_session_data;

static struct gcore_coredump_table gcore_coredump_table = {0, };
struct gcore_coredump_table *ggt = &gcore_coredump_table;

struct gcore_offset_table gcore_offset_table = {0, };
struct gcore_size_table gcore_size_table = {0, };

struct gcore_machdep_table gcore_machdep_table;
struct gcore_machdep_table *gcore_machdep = &gcore_machdep_table;
