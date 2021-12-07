#
# Copyright (C) 2010 FUJITSU LIMITED
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

VERSION=1.6.3
DATE=7 Dec 2021
PERIOD=2010, 2011, 2012, 2013, 2014, 2016, 2017, 2018, 2019, 2020, 2021

ARCH=UNSUPPORTED

ifeq ($(shell arch), i686)
  TARGET=X86
  TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), arm)
  TARGET=ARM
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), aarch64)
  TARGET=ARM64
  ARCH_CFLAGS=-D_SYS_UCONTEXT_H=1
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), mips)
  TARGET=MIPS
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), ppc64)
  TARGET=PPC64
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell arch), ppc64le)
  TARGET=PPC64
  TARGET_CFLAGS=
  ARCH=SUPPORTED
endif

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif

GCORE_CFILES = \
	libgcore/gcore_coredump.c \
	libgcore/gcore_coredump_table.c \
	libgcore/gcore_dumpfilter.c \
	libgcore/gcore_elf_struct.c \
	libgcore/gcore_global_data.c \
	libgcore/gcore_regset.c \
	libgcore/gcore_verbose.c

ifneq (,$(findstring $(TARGET), X86 X86_64))
GCORE_CFILES += libgcore/gcore_x86.c
endif

ifneq (,$(findstring $(TARGET), ARM))
GCORE_CFILES += libgcore/gcore_arm.c
endif

ifneq (,$(findstring $(TARGET), ARM64))
GCORE_CFILES += libgcore/gcore_arm64.c
endif

ifneq (,$(findstring $(TARGET), MIPS))
GCORE_CFILES += libgcore/gcore_mips.c
endif

ifneq (,$(findstring $(TARGET), PPC64))
GCORE_CFILES += libgcore/gcore_ppc64.c
endif

GCORE_OFILES = $(patsubst %.c,%.o,$(GCORE_CFILES))

COMMON_CFLAGS=-Wall -I$(INCDIR) -I./libgcore -fPIC -D$(TARGET) \
	-DVERSION='"$(VERSION)"' -DRELEASE_DATE='"$(DATE)"' \
	-DPERIOD='"$(PERIOD)"'

all: gcore.so

gcore.so: gcore.c $(INCDIR)/defs.h
	@if [ $(ARCH) = "UNSUPPORTED"  ]; then \
		echo "gcore: architecture not supported"; \
	else \
		make -f gcore.mk $(GCORE_OFILES) && \
		gcc $(RPM_OPT_FLAGS) $(CFLAGS) $(TARGET_CFLAGS) $(COMMON_CFLAGS) $(ARCH_CFLAGS) -nostartfiles -shared -rdynamic $(GCORE_OFILES) -Wl,-soname,$@ -o $@ $< ; \
	fi;

%.o: %.c $(INCDIR)/defs.h
	gcc $(RPM_OPT_FLAGS) $(CFLAGS) $(TARGET_CFLAGS) $(COMMON_CFLAGS) $(ARCH_CFLAGS) -c -o $@ $<

clean:
	rm -f gcore.so
	rm -f libgcore/gcore_*.o
