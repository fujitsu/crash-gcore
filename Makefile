
.PHONY: check_crash all default test

all: test

default: check_crash
	@cp -r ./src/* ${CRASH}/extensions/
	@(cd ${CRASH}; make CFLAGS="-g -O0"; make CFLAGS="-g -O0" extensions)

test: check_crash
	@cp -r ./test/* ${CRASH}/extensions/
	make default

check_crash:
ifndef CRASH
	@echo "Please specify CRASH=<directory>"
	@exit 1
endif

clean:
	@(cd ${CRASH}; make do_clean)
