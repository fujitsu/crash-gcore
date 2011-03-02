#
# Copyright (C) 2011 FUJITSU LIMITED
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

ifeq ($(shell /bin/ls /usr/include/crash/defs.h 2>/dev/null), /usr/include/crash/defs.h)
  INCDIR=/usr/include/crash
endif
ifeq ($(shell /bin/ls ./defs.h 2> /dev/null), ./defs.h)
  INCDIR=.
endif
ifeq ($(shell /bin/ls ../defs.h 2> /dev/null), ../defs.h)
  INCDIR=..
endif

TEST_GCORE_CFILES = \
	test-gcore.c

TEST_GCORE_HFILES = \
	test-gcore.h

TEST_GCORE_OFILES = $(patsubst %.c,%.o,$(TEST_GCORE_CFILES))

COMMON_CFLAGS=-Wall -I$(INCDIR) -I./libgcore -fPIC -D$(TARGET)

all: test-gcore.so

test-gcore.so: $(INCDIR)/defs.h
	make -f test-gcore.mk $(TEST_GCORE_OFILES) && \
	gcc $(CFLAGS) $(TARGET_CFLAGS) $(COMMON_CFLAGS) -nostartfiles -shared -rdynamic $(TEST_GCORE_OFILES) -o $@ $<

%.o: %.c $(INCDIR)/defs.h
	gcc $(CFLAGS) $(TARGET_CFLAGS) $(COMMON_CFLAGS) -c -o $@ $<
