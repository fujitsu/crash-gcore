/* gcore_compat_x86.h -- core analysis suite
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
#ifndef GCORE_COMPAT_X86_H_
#define GCORE_COMPAT_X86_H_
#include <stdint.h>

typedef int32_t compat_time_t;
typedef int32_t compat_pid_t;
typedef uint16_t __compat_uid_t;
typedef uint16_t __compat_gid_t;
typedef int32_t compat_int_t;
typedef uint32_t compat_ulong_t;

struct compat_timeval {
	compat_time_t	tv_sec;
	int32_t	tv_usec;
};

#ifdef X86_64
typedef struct user_regs_struct32 compat_elf_gregset_t;
#else
typedef struct user_regs_struct compat_elf_gregset_t;
#endif

#endif /* GCORE_COMPAT_X86_H_ */
