/* test-gcore.h -- core analysis suite
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
#ifndef TEST_GCORE_H_
#define TEST_GCORE_H_

struct gcore_test_result
{
	int total;
	int failures;
};

static inline void gcore_reset_result(struct gcore_test_result *res)
{
	res->total = res->failures = 0;
}

static inline void gcore_print_result(struct gcore_test_result *res)
{
	fprintf(fp, "[%s] total: %d failures: %d\n",
		(res->failures > 0 ? "FAILED" : "OK"),
		res->total,
		res->failures);
}

static inline void gcore_assert(int condition, char *description,
				   struct gcore_test_result *res)
{
	if (!condition) {
		fprintf(fp, "[%d] %s\n", res->total, description);
		res->failures++;
	}
	res->total++;
}

#endif /* TEST_GCORE_H_ */
