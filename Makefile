
.PHONY: check_crash all default tarball test

all: test

default: check_crash
	@cp -r ./src/* ${CRASH}/extensions/
	@(cd ${CRASH}; make CFLAGS="-g -O0"; make CFLAGS="-g -O0" extensions)

test: check_crash
	@cp -r ./test/* ${CRASH}/extensions/
	make default

tarball:
	@(cd ./src; \
	git archive --format=tar HEAD ./ | bzip2 > ../gcore.tar.bz2; \
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
