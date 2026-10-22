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

# Permissions & Ownership
auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S setuid,setgid -F key="$KEY"

# File Creation, Open, Close & Directories
auditctl -a always,exit -F arch=b64 -S creat,open,openat,close -F key="$KEY"
# openat2 is syscall 437 on x86_64
auditctl -a always,exit -F arch=b64 -S 437 -F key="$KEY" 2>/dev/null || true

# Links, Unlink, Rename & Directories
auditctl -a always,exit -F arch=b64 -S mkdir,mkdirat,rmdir -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S link,linkat,symlink,symlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S unlink,unlinkat -F key="$KEY"
auditctl -a always,exit -F arch=b64 -S rename,renameat,renameat2 -F key="$KEY"

# Process Lifecycle (for ancestry tracking)
auditctl -a always,exit -F arch=b64 -S clone,clone3,fork,vfork,execve,execveat -F key="$KEY"

echo "Current active rules with key $KEY:"
auditctl -l | grep "$KEY"
