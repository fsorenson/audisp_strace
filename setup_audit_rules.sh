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

echo "Adding audit rules with key: $KEY"

# Exclude logging daemons and monitoring pipeline to prevent runaway feedback loops
auditctl -a never,exit -F exe=/usr/sbin/auditd -k "$KEY"
auditctl -a never,exit -F comm=sshd-session -k "$KEY"
auditctl -a never,exit -F comm=tail -k "$KEY"
auditctl -a never,exit -F comm=tee -k "$KEY"
auditctl -a never,exit -F comm=tclsh -k "$KEY"
auditctl -a never,exit -F comm=python3 -k "$KEY"

# Permissions & Ownership
auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S setuid,setgid -F key="$KEY"

# File Creation, Open, Close & Directories
auditctl -a always,exit -F arch=b64 -S creat,open,openat,openat2,close -F key="$KEY"

# Links, Unlink, Rename & Directories
auditctl -a always,exit -F arch=b64 -S mkdir,mkdirat,rmdir -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S link,linkat,symlink,symlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S unlink,unlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S rename,renameat,renameat2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S readlink,readlinkat -F key="$KEY"

# File Metadata, Attributes & Access
auditctl -a always,exit -F arch=b64 -S stat,lstat,fstat,newfstatat,statx,statfs,fstatfs -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S access,faccessat,faccessat2 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S truncate,ftruncate,fallocate -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S utime,utimes,futimesat,utimensat -F key="$KEY"

# Extended Attributes (xattr)
auditctl -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,getxattr,lgetxattr,fgetxattr -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S listxattr,llistxattr,flistxattr,removexattr,lremovexattr,fremovexattr -F key="$KEY"

# Special Files & Descriptors
auditctl -a always,exit -F arch=b64 -S mknod,mknodat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S dup,dup2,dup3,pipe,pipe2 -F key="$KEY"

# Memory Management
auditctl -a always,exit -F arch=b64 -S mmap,munmap,mprotect,madvise,brk -F key="$KEY"

# Sockets & Networking
auditctl -a always,exit -F arch=b64 -S socket,socketpair,bind,listen,accept,accept4 -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S connect,getsockname,getpeername,shutdown -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S sendto,recvfrom,sendmsg,recvmsg -F key="$KEY"

# Read, Write & I/O Operations
auditctl -a always,exit -F arch=b64 -S read,write,readv,writev -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S pread,pwrite,preadv,pwritev,preadv2,pwritev2,sendfile -F key="$KEY"

# Descriptor Control
auditctl -a always,exit -F arch=b64 -S fcntl,ioctl -F key="$KEY"

# Process Lifecycle (for ancestry tracking)
auditctl -a always,exit -F arch=b64 -S clone,clone3,fork,vfork,execve,execveat -F key="$KEY"

echo "Current active rules with key $KEY:"
auditctl -l | grep "$KEY"
