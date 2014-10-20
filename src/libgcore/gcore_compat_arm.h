/* gcore_compat_arm.h -- core analysis suite
 *
 * Copyright (C) 2014 Marvell. Inc
 * author: Wei Shu <weishu@marvell.com>
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
#ifndef GCORE_COMPAT_ARM_H_
#define GCORE_COMPAT_ARM_H_
#include <stdint.h>

typedef int32_t compat_time_t;
typedef int32_t compat_pid_t;
typedef uint32_t __compat_uid_t;
typedef uint32_t __compat_gid_t;
typedef int32_t compat_int_t;
typedef uint32_t compat_ulong_t;

struct compat_timeval {
	compat_time_t	tv_sec;
	int32_t	tv_usec;
};

typedef struct user_regs_struct32 compat_elf_gregset_t;

/* Masks for extracting the FPSR and FPCR from the FPSCR */
#define VFP_FPSCR_STAT_MASK	0xf800009f
#define VFP_FPSCR_CTRL_MASK	0x07f79f00
/*
 * The VFP state has 32x64-bit registers and a single 32-bit
 * control/status register.
 */
#define VFP_STATE_SIZE		((32 * 8) + 4)

#endif /* GCORE_COMPAT_ARM_H_ */
