
.PHONY: check_crash all default tarball test

all: test

default: check_crash
	@cp -r ./src/* ${CRASH}/extensions/
	@(cd ${CRASH}; make CFLAGS="-g -O0"; make CFLAGS="-g -O0" extensions)

test: check_crash
	@cp -r ./test/* ${CRASH}/extensions/
	make default

gcore_version: ./src/gcore.mk
GCORE_VERSION := $(shell egrep "VERSION=[0-9]\.[0-9]" ./src/gcore.mk | head -n 1 | cut -d = -f 2)

tarball: gcore_version
	@(cp -r ./src ./crash-gcore-command-${GCORE_VERSION}; \
	cp ./COPYING ./crash-gcore-command-${GCORE_VERSION}; \
	tar zcf crash-gcore-command-${GCORE_VERSION}.tar.gz crash-gcore-command-${GCORE_VERSION}; \
	rm -rf ./crash-gcore-command-${GCORE_VERSION})

check_crash:
ifndef CRASH
	@echo "Please specify CRASH=<directory>"
	@exit 1
endif

clean:
	@(rm -f crash-gcore-command-*.tar.gz)
ifdef CRASH
	@(cd ${CRASH}; make do_clean)
endif
