
.PHONY: check_crash all default tarball test

all: test

default: check_crash
	@cp -r ./src/* ${CRASH}/extensions/
	@(cd ${CRASH}; make CFLAGS="-g -O0"; make CFLAGS="-g -O0" extensions)

test: check_crash
	@cp -r ./test/* ${CRASH}/extensions/
	make default

gcore_version: ./src/gcore.mk
GCORE_VERSION := $(shell egrep "VERSION=[0-9]\.[0-9]\.[0-9]" ./src/gcore.mk | head -n 1 | cut -d = -f 2)

tarball: gcore_version
	@(cd ./src; \
	git archive --format=tar HEAD ./ | bzip2 > ../gcore-${GCORE_VERSION}.tar.bz2; \
	cd ..)

check_crash:
ifndef CRASH
	@echo "Please specify CRASH=<directory>"
	@exit 1
endif

clean:
	@(rm -f gcore.tar.bz2)
ifdef CRASH
	@(cd ${CRASH}; make do_clean)
endif
