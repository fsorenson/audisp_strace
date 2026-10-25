#!/bin/bash
# setup_audit_rules.sh
# Configures auditctl rules to capture all syscalls monitored by audisp-strace.
# Usage: sudo ./setup_audit_rules.sh [-d|--delete]

KEY="audisp_strace_test"

if [ "$1" == "-d" ] || [ "$1" == "--delete" ]; then
    echo "Removing audit rules with key: $KEY"
    auditctl -D -k "$KEY" 2>/dev/null
    exit 0
fi

sessionid=$(cat /proc/$$/sessionid)

echo "Adding audit rules with key: $KEY"

# Exclude the current session to prevent runaway feedback loops
auditctl -a never,exit -F sessionid=$sessionid

# Permissions & Ownership
auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,setfsuid,setfsgid -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S getuid,getgid,geteuid,getegid,getresuid,getresgid,getgroups,setgroups -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S getpid,getppid,getpgrp,gettid -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S capget,capset,prctl -F key="$KEY"

# File Creation, Open, Close & Directories
auditctl -a always,exit -F arch=b64 -S creat,open,openat,openat2,close -F key="$KEY"

# Links, Unlink, Rename & Directories
auditctl -a always,exit -F arch=b64 -S mkdir,mkdirat,rmdir -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S link,linkat,symlink,symlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S unlink,unlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S rename,renameat,renameat2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S readlink,readlinkat -F key="$KEY"

# File Metadata, Attributes & Access
auditctl -a always,exit -F arch=b64 -S stat,lstat,fstat,newfstatat,statx,statfs,fstatfs,ustat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S access,faccessat,faccessat2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S truncate,ftruncate,fallocate -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S utime,utimes,futimesat,utimensat -F key="$KEY"

# Filesystem, Mount, Swap, Quota & Watch Operations
auditctl -a always,exit -F arch=b64 -S chdir,chroot,getcwd,acct,inotify_add_watch,quotactl -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S mount,umount2,pivot_root,swapon,swapoff -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S name_to_handle_at,open_tree,move_mount,fsconfig,fspick,mount_setattr -F key="$KEY"

# Extended Attributes (xattr)
auditctl -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,getxattr,lgetxattr,fgetxattr -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S listxattr,llistxattr,flistxattr,removexattr,lremovexattr,fremovexattr -F key="$KEY"

# Special Files & Descriptors
auditctl -a always,exit -F arch=b64 -S mknod,mknodat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S dup,dup2,dup3,pipe,pipe2 -F key="$KEY"

# IPC: System V Shared Memory, Semaphores & Message Queues
auditctl -a always,exit -F arch=b64 -S shmget,shmctl,semget,semop,semtimedop,semctl -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S msgget,msgsnd,msgrcv,msgctl -F key="$KEY"

# Time & Clock
auditctl -a always,exit -F arch=b64 -S time,gettimeofday,settimeofday,adjtimex -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S clock_gettime,clock_settime,clock_getres,clock_adjtime -F key="$KEY"

# Memory Management
auditctl -a always,exit -F arch=b64 -S mmap,munmap,mprotect,madvise,brk,mremap,msync,mincore -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S shmat,shmdt,mlock,munlock,mlockall,munlockall,mlock2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S pkey_mprotect,remap_file_pages,mbind,set_mempolicy,get_mempolicy,migrate_pages,move_pages -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S mseal,map_shadow_stack,set_mempolicy_home_node -F key="$KEY"

# Sockets & Networking
auditctl -a always,exit -F arch=b64 -S socket,socketpair,bind,listen,accept,accept4 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S connect,getsockname,getpeername,shutdown -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S sendto,recvfrom,sendmsg,recvmsg,setsockopt,getsockopt,sendmmsg,recvmmsg -F key="$KEY"

# Read, Write & I/O Operations
auditctl -a always,exit -F arch=b64 -S read,write,readv,writev -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S pread,pwrite,preadv,pwritev,preadv2,pwritev2,sendfile -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S io_uring_setup,io_uring_enter,io_uring_register -F key="$KEY"

# Descriptor Control
auditctl -a always,exit -F arch=b64 -S fcntl,ioctl -F key="$KEY"

# Descriptor Manipulation & Event Descriptors (%desc)
auditctl -a always,exit -F arch=b64 -S lseek,flock,fsync,fdatasync,syncfs,fchdir,fchroot -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S eventfd,eventfd2,epoll_create,epoll_create1,epoll_ctl,epoll_wait,epoll_pwait,epoll_pwait2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S inotify_init,inotify_init1,inotify_rm_watch -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S timerfd_create,timerfd_settime,timerfd_gettime -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S memfd_create,memfd_secret,userfaultfd,pidfd_open,pidfd_getfd -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S poll,ppoll,select,pselect6,copy_file_range,splice,tee,vmsplice,readahead,fadvise64 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S fanotify_init,fsmount,fsopen,finit_module,kexec_file_load,bpf -F key="$KEY"

# Process Lifecycle & Signals
auditctl -a always,exit -F arch=b64 -S clone,clone3,fork,vfork,execve,execveat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S kill,tkill,tgkill,wait4,waitid -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S pause,rt_sigaction,rt_sigpending,rt_sigprocmask,rt_sigqueueinfo,rt_tgsigqueueinfo,sigaltstack,signalfd,signalfd4 -F key="$KEY"

# Process Control, Scheduling & Resource Limits
auditctl -a always,exit -F arch=b64 -S sched_yield,sched_setparam,sched_getparam,sched_setscheduler,sched_getscheduler -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S sched_get_priority_max,sched_get_priority_min,sched_rr_get_interval,sched_setaffinity,sched_getaffinity -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S sched_setattr,sched_getattr,getcpu,setpgid,getpgid,setsid,getsid,getpriority,setpriority -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S umask,personality,getrlimit,setrlimit,prlimit64,getrusage,unshare,set_tid_address,rseq,vhangup,restart_syscall -F key="$KEY"

# Time, Timers & Clocks (non-%clock)
auditctl -a always,exit -F arch=b64 -S nanosleep,clock_nanosleep,alarm,getitimer,setitimer,times -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S timer_create,timer_settime,timer_gettime,timer_getoverrun,timer_delete -F key="$KEY"

# System Info, Hostname & Administration
auditctl -a always,exit -F arch=b64 -S uname,sysinfo,syslog,sethostname,setdomainname,sync,reboot -F key="$KEY"

# Keys, Security, Seccomp & Random
auditctl -a always,exit -F arch=b64 -S add_key,request_key,keyctl,seccomp,getrandom,membarrier -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S ptrace,kcmp,process_vm_readv,process_vm_writev,ioprio_set,ioprio_get -F key="$KEY"

# Futex, Robust Lists, Memory Keys & Async I/O
auditctl -a always,exit -F arch=b64 -S futex,set_robust_list,get_robust_list,pkey_alloc,pkey_free -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S io_submit,io_cancel,io_getevents,io_pgetevents -F key="$KEY"

# Kernel Modules, Architecture-specific & Legacy
auditctl -a always,exit -F arch=b64 -S init_module,delete_module,create_module,get_kernel_syms,query_module,kexec_load,mq_unlink -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S arch_prctl,modify_ldt,iopl,ioperm,set_thread_area,get_thread_area,lookup_dcookie -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S _sysctl,sysfs,epoll_ctl_old,epoll_wait_old,security,nfsservctl,afs_syscall,tuxcall,vserver -F key="$KEY"

# Modern Unclassed Syscalls (syscallent-common.h)
auditctl -a always,exit -F arch=b64 -S close_range,futex_waitv,futex_wake,futex_wait,futex_requeue,statmount,listmount -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S lsm_get_self_attr,lsm_set_self_attr,lsm_list_modules,listns,rseq_slice_yield -F key="$KEY"

echo "Current active rules with key $KEY:"
auditctl -l | grep "$KEY"
