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

ifeq ($(shell arch), i686)
  TARGET=X86
  TARGET_CFLAGS=-D_FILE_OFFSET_BITS=64
endif

ifeq ($(shell arch), x86_64)
  TARGET=X86_64
  TARGET_CFLAGS=
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
	libgcore/gcore_global_data.c \
	libgcore/gcore_regset.c \
	libgcore/gcore_verbose.c

ifneq (,$(findstring $(TARGET), X86 X86_64))
GCORE_CFILES += libgcore/gcore_x86.c
endif

GCORE_OFILES = $(patsubst %.c,%.o,$(GCORE_CFILES))

COMMON_CFLAGS=-Wall -I$(INCDIR) -I./libgcore -fPIC -D$(TARGET)

all: gcore.so
	
gcore.so: $(INCDIR)/defs.h gcore.c $(GCORE_OFILES)
	gcc $(TARGET_CFLAGS) $(COMMON_CFLAGS) -nostartfiles -shared -rdynamic $(GCORE_OFILES) -o gcore.so gcore.c

%.o: %.c $(INCDIR)/defs.h
	gcc $(TARGET_CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<

clean:
	find ./libgcore -regex ".+\(o\|so\)" -exec rm -f {} \;

