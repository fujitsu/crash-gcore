/*
 * target-dumpfilter.c
 * ===================
 *
 * This allocates all kind of memory maps at runtime, created intended for use
 * of a target program for a unit test of gcore_dumpfilter.c.
 *
 * How to use:
 *
 *   Before we get down to execute test-dumpfilter, we need to turn on hugetlb feature.
 *
 *   1. set up the environment to be able to use hugetlb feature.
 *
 *     $ echo 10 > /proc/sys/vm/nr_hugepages
 *
 *       - This operation is intended to change the number of
 *       hugepages that system can allocate from physical memory.
 *
 *       - You can check a single huge page size from /proc/meminfo
 *
 *         $ grep "Huge" /proc/meminfo
 *         HugePages_Total:   128
 *         HugePages_Free:    128
 *         HugePages_Rsvd:      0
 *         Hugepagesize:     2048 kB
 *
 *       - You need to set up the number of hugepages enough for required memory size.
 *
 *     $ mkdir -p /media/hugetlb
 *     $ mount -t hugetlbfs none /media/hugetlb -o uid=n,gid=m,mode=0777
 *     $ echo m > /proc/sys/vm/hugetlb_shm_group
 *
 *        - Both n and m are 0 for root user; so it's easy to specify this by
 *          doing as root user.
 *
 *   2. Use mmap or shmget to map hugepages via /media/hugetlb.
 *
 *     Reference
 *
 *       [1] linux-2.6/Documentation/vm/hugetlbpage.txt
 *
 */

/*
 * Each type of memory are is assigned as shown below:
 *
 *  Anon Private | user stack
 *  Anon Shared  | SysV IPC
 *  File-mapped Private | executable file
 *  File-mapped Shared | mmap()
 *  ELF | executable library/shared library/vdso
 *  Hugetlb Private | alloc using mmap()
 *  Hugetlb Shared | alloc using shm library
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>

#ifndef SHM_HUGETLB
#define SHM_HUGETLB 04000
#endif

#define SHMAT_FLAGS (0)

static void sleep_to_be_aborted(void)
{
	for (;;) sleep(100);
}

static void *alloc_mmap(const char *filename, unsigned long flags, size_t length)
{
	int fd; /* [XXX] never closed in this test case */
	void *addr;

	if (flags & MAP_ANONYMOUS) {
		fd = -1;
	} else {
		fd = open(filename, O_CREAT | O_RDWR, 0755);
		if (fd < 0) {
			perror("Open failed");
			return NULL;
		}
		char c = 'K';
		write(fd, &c, sizeof(c));
	}
        addr = mmap(0, length, PROT_READ | PROT_WRITE, flags, fd, 0);
        if (addr == MAP_FAILED) {
                perror("mmap");
                unlink(filename);
		return NULL;
        }
	return addr;
}

void print_pmapx_meminfo(void)
{
	char buf[128+1];

	snprintf(buf, 128, "pmap -x %d; cat /proc/meminfo", getpid());
	system(buf);
}

size_t get_hugepagesize(void)
{
	char buf[128];
	FILE *meminfo;
	size_t hugepagesize;

	meminfo = fopen("/proc/meminfo", "r");
	if (!meminfo)
		return 0;

	for (;;) {
		fgets(buf, sizeof(buf), meminfo);
		if (ferror(meminfo))
			return 0;
		if (strstr(buf, "Hugepagesize:"))
			break;
		if (feof(meminfo))
			return 0;
	}

	fclose(meminfo);

	sscanf(buf, "Hugepagesize: %lu kB", &hugepagesize);
	hugepagesize *= 1024; /* kB */

	return hugepagesize;
}

int main(void)
{
	size_t HUGEPAGE_SIZE;
        char *addr;
        int shmid;
        char *shmaddr;

	if (!(HUGEPAGE_SIZE = get_hugepagesize()))
		exit(1);

	printf("Hugepagesize: %lu\n", HUGEPAGE_SIZE);

	puts("Mapped Shared (mmap):");
	addr = alloc_mmap("Mapped_Shared.txt", MAP_SHARED, 4092);
	strncpy(addr, "Mapped Shared (mmap)", 21);
	if (addr == NULL)
		exit(1);
	printf("Returned address is %p\n", addr);

	puts("Mapped Shared (SysV IPC):");
        if ((shmid = shmget(2, 4096, IPC_CREAT | SHM_R | SHM_W)) < 0) {
                perror("shmget");
                exit(1);
        }
        printf("shmid: 0x%x\n", shmid);
        shmaddr = shmat(shmid, 0, SHMAT_FLAGS);
        if (shmaddr == (char *)-1) {
                perror("Shared memory attach failure");
                shmctl(shmid, IPC_RMID, NULL);
                exit(2);
        }
        printf("shmaddr: %p\n", shmaddr);
	strncpy(shmaddr, "Mapped Shared (SysV IPC)", 25);

	puts("Anon Shared (mmap):\n");
	addr = alloc_mmap(NULL, MAP_SHARED|MAP_ANONYMOUS, 4092);
	if (addr == NULL)
		exit(1);
	printf("Returned address is %p\n", addr);
	strncpy(addr, "Anon Shared (mmap)", 19);

	fflush(stdout);

	print_pmapx_meminfo();

	puts("Hugetlb Private (mmap):");
	addr = alloc_mmap("/media/hugetlb/test-dumpfilter", MAP_PRIVATE,
			  HUGEPAGE_SIZE);
	if (addr == NULL)
		exit(1);
        printf("Returned address is %p\n", addr);
	strncpy(addr, "Hugetlb Private (mmap)", 23);

	print_pmapx_meminfo();

	puts("Hugetlb Shared (mmap):");
	addr = alloc_mmap("/media/hugetlb/test-dumpfilter", MAP_SHARED,
			  HUGEPAGE_SIZE);
	if (addr == NULL)
		exit(1);
        printf("Returned address is %p\n", addr);
	strncpy(addr, "Hugetlb Shared (mmap)", 22);

	print_pmapx_meminfo();

	sleep_to_be_aborted();

        return 0;
}
