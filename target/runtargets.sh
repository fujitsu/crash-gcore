#! /bin/sh

if [ x$UID != x0 ]; then
    echo "This operation need root permission"
    exit 1
fi

function setup_hugepage () {
    local NR_HUGEPAGE=2
    local ROOT_UID=0
    local ROOT_GID=0

    echo ${NR_HUGEPAGE} > /proc/sys/vm/nr_hugepages
    mkdir -p /media/hugetlb
    mount -t hugetlbfs none /media/hugetlb -o uid=${ROOT_UID},gid=${ROOT_GID},mode=0777
    echo ${ROOT_GID} > /proc/sys/vm/hugetlb_shm_group
}

setup_hugepage

./target-gcore_dumpfilter &
