# PROJECT: audisp-strace

## Overview
`audisp-strace` is a Linux audit event consumer and `audisp` plugin written in Python using `auparse`. It parses raw Linux audit records for system calls and outputs formatted, readable traces resembling `strace` output, augmented with:
- Full process ancestry tracking (`1 (systemd) -> ... -> parent (comm) -> child (comm)`)
- Comprehensive process credentials (`uid`, `gid`, `auid`, `agid`, `euid`, `egid`, `suid`, `sgid`, `fsuid`, `fsgid`)
- Syscall arguments, resolved file paths, and return values
- Support for both live execution (audisp plugin or `tail -F` pipe with `/proc` enrichment) and offline replay of historical audit logs

Supported Syscalls:
- **Ownership & Permissions / Credentials**: `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `fchownat`, `lchown`, `setuid`, `setgid`, `getuid`, `getgid`, `geteuid`, `getegid`, `setreuid`, `setregid`, `setresuid`, `setresgid`, `getresuid`, `getresgid`, `setfsuid`, `setfsgid`, `getgroups`, `setgroups`, `capget`, `capset`, `prctl`
- **File & Directory Management**: `creat`, `open`, `openat`, `openat2`, `close`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`, `mkdir`, `mkdirat`, `rmdir`, `link`, `linkat`, `symlink`, `symlinkat`, `readlink`, `readlinkat`, `chdir`, `chroot`, `getcwd`, `acct`, `inotify_add_watch`, `uselib`
- **File Metadata, Inspection, Mounts & Quota**: `stat`, `lstat`, `fstat`, `newfstatat` (`fstatat`), `statx`, `statfs`, `fstatfs`, `access`, `faccessat`, `faccessat2`, `fchmodat2`, `mount`, `umount2`, `pivot_root`, `swapon`, `swapoff`, `quotactl`, `name_to_handle_at`, `open_tree`, `open_tree_attr`, `move_mount`, `fsconfig`, `fspick`, `mount_setattr`, `file_getattr`, `file_setattr`
- **File Manipulation, Descriptors & Sizing**: `dup`, `dup2`, `dup3`, `truncate`, `ftruncate`, `fallocate`
- **Extended Attributes**: `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat`
- **Special Files, IPC & Timestamps**: `mknod`, `mknodat`, `pipe`, `pipe2`, `utime`, `utimes`, `futimesat`, `utimensat`, `time`, `gettimeofday`, `settimeofday`, `adjtimex`, `clock_gettime`, `clock_settime`, `clock_getres`, `clock_adjtime`, `shmget`, `shmctl`, `semget`, `semop`, `semtimedop`, `semctl`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`
- **Memory Management**: `mmap`, `munmap`, `mprotect`, `madvise`, `brk`, `mremap`, `msync`, `mincore`, `shmat`, `shmdt`, `mlock`, `munlock`, `mlock2`, `mlockall`, `munlockall`, `pkey_mprotect`, `io_setup`, `io_destroy`, `remap_file_pages`, `mbind`, `set_mempolicy`, `get_mempolicy`, `migrate_pages`, `move_pages`
- **Sockets & Networking**: `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, `setsockopt`, `getsockopt`, `sendmmsg`, `recvmmsg`, `getpmsg`, `putpmsg`
- **Read, Write & I/O Operations**: `read`, `write`, `readv`, `writev`, `pread` / `pread64`, `pwrite` / `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendfile` / `sendfile64`
- **Descriptor Control**: `fcntl`, `ioctl`
- **Process Lifecycle, Signals & Tracking**: `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `exit`, `exit_group`, `kill`, `tkill`, `tgkill`, `pidfd_send_signal`, `wait4`, `waitid`, `waitpid`

---

## Target Output Format

Sample 3-line format per monitored event:
```text
<pid><comm> HH:MM:SS.mmm <syscall>(<args>) = <result>
    uid=<uid> (<user>), gid=<gid> (<group>), auid=<auid> (<user>), agid=<agid> (<group>), ...
    1 (systemd)->...-><ppid> (<ppexe>)-><pid> (<exe>)
```

---

## Design Decisions
1. **Language & Libraries**: Python 3 with `auparse` (C bindings for Linux audit parsing).
2. **Execution Modes**:
   - `audisp` plugin (standard input stream from `auditd`/`audispd`). Automatically detected if parent process is `auditd` or `audispd`.
   - Live stream pipe (e.g., `unbuffer tail -n0 -F /var/log/audit/audit.log | audisp-strace --live`).
   - Offline batch mode (reading past audit logs via stdin or file arguments).
3. **Filtering Controls**:
   - `-s`, `--syscalls`: Comma-separated list of syscalls or `%CLASS` shorthands to display (e.g. `-s %creds,%net,openat`).
   - `-x`, `-X`, `--exclude`: Comma-separated list of syscalls or `%CLASS shorthands to omit (e.g. `-X %desc,openat`).
   - Supports 18 strace-compatible `%CLASS` shorthand selectors:
     - `%desc`: File descriptor-related syscalls
     - `%file`: File-related syscalls
     - `%memory`: Memory mapping & NUMA syscalls
     - `%process`: Process lifecycle and management syscalls
     - `%creds`: Process credentials and capability syscalls
     - `%signal`: Signal-related syscalls
     - `%ipc`: System V IPC (shm, sem, msg) syscalls
     - `%net` / `%network`: Socket and network-related syscalls
     - `%stat`: `stat` syscall
     - `%lstat`: `lstat` syscall
     - `%fstat`: `fstat`, `newfstatat`, `statx` syscalls
     - `%%stat`: All stat-like syscalls (`stat`, `lstat`, `fstat`, `newfstatat`, `statx`)
     - `%statfs`: `statfs` syscall
     - `%fstatfs`: `fstatfs` syscall
     - `%%statfs`: All statfs-like syscalls (`statfs`, `fstatfs`, `ustat`)
     - `%pure`: Zero-argument getter syscalls (`getuid`, `getgid`, `geteuid`, `getegid`, etc.)
     - `%clock`: Clock and system time syscalls
     - Syscalls in any class not yet implemented in `audisp-strace` are maintained commented out in `SYSCALL_CLASSES` sets for easy activation as handlers are added.
   - `-a`, `--all`: Display all captured syscalls.
   - `-p`, `--pid`: Comma-separated or repeatable process ID filter (e.g. `-p 1234` or `-p 1234,5678`).
   - `--exclude-pid`: Comma-separated or repeatable process ID exclusion list.
   - `-f`, `--follow-fork`: When filtering by PID, automatically trace child processes created by `clone`, `clone3`, `fork`, `vfork`.
   - `-u`, `--user`, `--uid`: Comma-separated or repeatable username or numeric UID filter (e.g. `-u root`, `-u 1000`, `-u root,pcp`).
   - `--exclude-user`, `--exclude-uid`: Comma-separated or repeatable username or numeric UID exclusion filter (e.g. `--exclude-user root` or `--exclude-uid 0`).
   - `--auid`: Comma-separated or repeatable audit login UID or username filter.
   - `-Z`, `--failed-only`: Display only syscalls that returned an error code (like `strace -Z`).
   - `-z`, `--successful-only`: Display only syscalls that returned without an error code (like `strace -z`).
   - `-C`, `-1`, `--compact [{summary,strace}]`: Compact 1-line output per event (`summary` [default] with `[uid]` `[ppid]`, or `strace` for pure syscall line).
   - `-t`, `--timestamp-format`: Select `time` (default: `HH:MM:SS.mmm`), `datetime` (`YYYY-MM-DD HH:MM:SS.mmm [tz]`), or `epoch`.
4. **Architecture**:
   - Single executable script [`audisp-strace`](file:///home/sorenson/projects/audisp_strace/audisp-strace) with modular classes:
     - **`ProcResolver`**: Inspects `/proc` for file descriptor target paths, executable links, and process status when running in live mode.
     - **`ProcessTracker`**: Maintains in-memory PID state (ppid, exe, comm, cmdline, session, ancestry). Dynamically walks ancestry chains with cycle detection.
     - **`AuditEvent`**: Normalizes multi-record events (`SYSCALL`, `CWD`, `PATH`, `EXECVE`, `PROCTITLE`) and safely handles hex decoding, quote stripping, and unescaped characters.
     - **`TraceFormatter`**: Formats credentials (with uppercase interpreted field precedence and local passwd/group resolution) and timestamps (`time`, `datetime`, `epoch`).
     - **`SyscallHandler`**: Dispatches specific formatting for all supported syscalls.
     - **`AudispStraceApp`**: Stream line un-wrapper, `auparse` feed manager, and signal lifecycle coordinator.
5. **Testing & Audit Event Generation**:
   - **`test_syscalls.c` / `test_syscalls`**: C test generator that exercises every handled syscall across AT_FDCWD, dir_fd, relative paths, and absolute paths, creating a full parent->child->execve process tree.
   - **`setup_audit_rules.sh`**: Helper script to configure `auditctl` rules for capturing the generated events on a test system. Automatically discovers and excludes the monitoring login session (`auditctl -a never,exit -F sessionid=$sessionid`) to prevent audit storm feedback loops between `tail`, `tee`, `sshd`, and `audisp-strace` during live stream pipe monitoring.

---

## Status & Progress

### Done
- [x] Initial review of `project.txt`, `watch_audit.py`, and sample logs in `examples/`.
- [x] Verified `auparse` availability and environment capabilities.
- [x] Initialized and maintained `PROJECT.md` tracking document.
- [x] Implemented modular `audisp-strace` executable:
  - [x] CLI argument parsing (`--live`, `--offline`, `-t/--timestamp-format`, `-s/--syscalls`, `-x/--exclude`, `-a/--all`, files/stdin).
  - [x] Auto-detection of live mode (parent inspection for `auditd` / `audispd`).
  - [x] Signal handling (`SIGTERM`, `SIGHUP`, `SIGINT`, `SIGPIPE`).
  - [x] PID and ancestry tracking engine (`ProcessTracker`).
  - [x] `/proc` fallback resolver for live mode (`/proc/<pid>/fd/*`, `/proc/<pid>/exe`, `/proc/<pid>/stat`).
  - [x] Formatter matching the target strace-like 3-line structure.
  - [x] Syscall handlers for permission, ownership & credentials:
    - [x] `chmod`, `fchmod`, `fchmodat`
    - [x] `chown`, `fchown`, `fchownat`, `lchown`
    - [x] `setuid`, `setgid`, `getuid`, `getgid`, `geteuid`, `getegid`
    - [x] `setreuid`, `setregid`, `setresuid`, `setresgid`, `getresuid`, `getresgid`
    - [x] `setfsuid`, `setfsgid`, `getgroups`, `setgroups`
    - [x] `capget`, `capset`, `prctl` (with PRCTL options interpretation)
  - [x] Syscall handlers for file & directory lifecycle:
    - [x] `creat`, `open`, `openat`, `openat2`, `close`
    - [x] `unlink`, `unlinkat`
    - [x] `rename`, `renameat`, `renameat2`
    - [x] `mkdir`, `mkdirat`, `rmdir`
    - [x] `link`, `linkat`, `symlink`, `symlinkat`, `readlink`, `readlinkat`
  - [x] Syscall handlers for file metadata, inspection & access:
    - [x] `stat`, `lstat`, `fstat`, `newfstatat` (`fstatat`), `statx`, `statfs`, `fstatfs`
    - [x] `access`, `faccessat`, `faccessat2`
  - [x] Syscall handlers for file sizing & descriptor manipulation:
    - [x] `dup`, `dup2`, `dup3`
    - [x] `truncate`, `ftruncate`, `fallocate`
  - [x] Syscall handlers for extended attributes:
    - [x] `setxattr`, `lsetxattr`, `fsetxattr`
    - [x] `getxattr`, `lgetxattr`, `fgetxattr`
    - [x] `listxattr`, `llistxattr`, `flistxattr`
    - [x] `removexattr`, `lremovexattr`, `fremovexattr`
  - [x] Syscall handlers for special files, IPC & timestamps:
    - [x] `mknod`, `mknodat`, `pipe`, `pipe2`
    - [x] `utime`, `utimes`, `futimesat`, `utimensat`
    - [x] `time`, `gettimeofday`, `settimeofday`, `adjtimex`
    - [x] `clock_gettime`, `clock_settime`, `clock_getres`, `clock_adjtime` (with CLOCK ID interpretation)
    - [x] System V IPC: `shmget`, `shmctl`, `semget`, `semop`, `semtimedop`, `semctl`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`
  - [x] Syscall handlers for memory management:
    - [x] `mmap`, `munmap`, `mprotect`, `madvise`, `brk`
    - [x] `mremap`, `msync`, `mincore`, `shmat`, `shmdt`
    - [x] `mlock`, `munlock`, `mlock2`, `mlockall`, `munlockall`, `pkey_mprotect`
    - [x] `io_setup`, `io_destroy`, `remap_file_pages`
    - [x] NUMA memory policies: `mbind`, `set_mempolicy`, `get_mempolicy`, `migrate_pages`, `move_pages`
  - [x] Syscall handlers for sockets & networking:
    - [x] `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`
    - [x] `connect`, `getsockname`, `getpeername`, `shutdown`
    - [x] `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
    - [x] `setsockopt`, `getsockopt`, `sendmmsg`, `recvmmsg`, `getpmsg`, `putpmsg`
    - [x] Socket address (`SOCKADDR`) interpretation for `inet`, `inet6`, `local/unix`, and `netlink`.
    - [x] Socket options formatting (`SOL_SOCKET`, `IPPROTO_TCP`, options flags).
  - [x] Syscall handlers for read, write & I/O:
    - [x] `read`, `write`, `readv`, `writev`
    - [x] `pread` / `pread64`, `pwrite` / `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`
    - [x] `sendfile` / `sendfile64`
  - [x] Syscall handlers for descriptor control:
    - [x] `fcntl` (command decoding, flag interpretation, and `F_DUPFD`/`F_SETFD` FD tracking)
    - [x] `ioctl` (decoding common tty/socket ioctls e.g. `TCGETS`, `TIOCGWINSZ`, `FIONREAD`, with hex fallback)
  - [x] Syscall handlers for process tracking, signals & wait:
    - [x] `clone`, `clone3`, `fork`, `vfork`
    - [x] `execve`, `execveat`
    - [x] `exit`, `exit_group`
    - [x] `kill`, `tkill`, `tgkill`, `pidfd_send_signal`
    - [x] `wait4`, `waitid`, `waitpid` (with wait options decoding)
  - [x] String unescaping & hex-decoding for command line arguments (`argv`, `proctitle`).
  - [x] Full in-memory file descriptor lifecycle tracking (`ProcessTracker`):
    - [x] Tracks descriptors opened by `open`, `openat`, `openat2`, `creat` (with relative-to-cwd and relative-to-dirfd resolution).
    - [x] Tracks descriptor duplication via `dup`, `dup2`, `dup3`, and `fcntl(F_DUPFD)`.
    - [x] Tracks socket descriptors from `socket`, `socketpair`, `accept`, `accept4`.
    - [x] Tracks `FD_PAIR` records from `pipe`, `pipe2`, `socketpair`.
    - [x] In-flight resolution for `fstat`, `fchmod`, `fchown`, `ftruncate`, `fallocate`, `f*xattr`, directory descriptors in `*at` syscalls, read/write, sockets, fcntl/ioctl, and `close(fd<path>)`.
    - [x] Inherits open descriptors across `fork`/`clone`, handles `O_CLOEXEC` closure on `execve`, and cleans up on `exit`.
- [x] Refactored `SyscallHandler` dispatch from an $O(N)$ `if/elif` chain to an $O(1)$ dictionary method dispatch table (`self._handlers`), unifying handler method signatures (`handle_*(self, event)`) and validating zero output regressions across all test logs.
- [x] Implemented strace-compatible `%CLASS` shorthand selectors for `-s` and `-x`/`-X`:
  - Added support for all 18 classes: `%desc`, `%file`, `%memory`, `%process`, `%creds`, `%signal`, `%ipc`, `%net`, `%network`, `%stat`, `%lstat`, `%fstat`, `%%stat`, `%statfs`, `%fstatfs`, `%%statfs`, `%pure`, `%clock`.
  - Added `-X` flag alias for `--exclude` alongside `-x`.
  - Included unimplemented syscalls commented out inside `SYSCALL_CLASSES` dictionary definitions for easy future enablement.
  - Verified class selection and exclusion behavior across `examples/audit-log-v10.out` and validated zero regressions against `out-v6.txt`.
- [x] Implemented all remaining `%file` syscalls (bringing `%file` to 100% complete with 75 active handlers):
  - Standard & watch: `chdir`, `chroot`, `getcwd`, `acct`, `inotify_add_watch`, `uselib`
  - Mount, swap & quota: `mount`, `umount2`, `pivot_root`, `swapon`, `swapoff`, `quotactl`
  - Advanced/modern mount & file ops: `name_to_handle_at`, `open_tree`, `open_tree_attr`, `move_mount`, `fsconfig`, `fspick`, `mount_setattr`
  - Modern `*at` variants: `fchmodat2`, `file_getattr`, `file_setattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat`
  - Added exercise calls in `test_syscalls.c` (Section 16.5) and audit rules in `setup_audit_rules.sh`.
- [x] Implemented handlers for `%pure`, `ustat`, `%signal`, `%process`, and `%memory`:
  - **`%pure`** (100% complete, 8/8 active): added `getpid`, `getppid`, `getpgrp`, `gettid` mapping to `handle_get_id`.
  - **`ustat`** / **`%%statfs`** (100% complete, 3/3 active): implemented `handle_ustat` formatting `ustat(makedev(maj, min), {...}|NULL) = exit`.
  - **`%process`** (100% complete, 16/16 active): implemented `rt_sigqueueinfo` and `rt_tgsigqueueinfo`.
  - **`%signal`** (100% complete, 17/17 active): implemented `pause`, `rt_sigaction`, `rt_sigpending`, `rt_sigprocmask`, `rt_sigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`, `rt_tgsigqueueinfo`, `sigaltstack`, `signalfd`, `signalfd4`, `io_uring_enter`.
  - **`%memory`** (100% complete, 28/28 active): implemented `io_uring_register`, `map_shadow_stack`, `mseal`, `set_mempolicy_home_node`, and descriptor creator `io_uring_setup`.
  - Activated all newly implemented syscalls across `SYSCALL_CLASSES` dictionary entries (`%pure`, `%%statfs`, `%process`, `%signal`, `%memory`, `%desc`).
  - Added exercise calls in `test_syscalls.c` and updated `setup_audit_rules.sh`.
  - Verified regression-free execution against `out-v6.txt`.
- [x] Implemented all 60 remaining `%desc` handlers, reaching 100% completion across all 18 strace classes (108/108 active handlers for `%desc`):
  - Event, epoll, inotify & timer descriptors: `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `epoll_pwait2`, `eventfd`, `eventfd2`, `inotify_init`, `inotify_init1`, `inotify_rm_watch`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime`, `userfaultfd`
  - Descriptor lifecycle tracking: added tracking in `ProcessTracker` for `epoll_create`, `epoll_create1`, `eventfd`, `eventfd2`, `inotify_init`, `inotify_init1`, `timerfd_create`, `userfaultfd`, `pidfd_open`, `pidfd_getfd`, `memfd_create`, `signalfd`, `signalfd4`, and `fchdir`
  - File synchronization, positioning & advisory: `lseek`, `flock`, `fsync`, `fdatasync`, `syncfs`, `sync_file_range`, `fadvise64`, `readahead`
  - Splicing, copying & zero-copy I/O: `splice`, `vmsplice`, `tee`, `copy_file_range`
  - Polling & multiplexing: `poll`, `ppoll`, `select`, `pselect6`
  - POSIX & System V message queues: `mq_open`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`
  - Process file descriptors & memory: `pidfd_open`, `pidfd_getfd`, `memfd_create`, `memfd_secret`, `process_madvise`, `process_mrelease`
  - Advanced kernel modules, eBPF & security: `bpf`, `kexec_file_load`, `finit_module`, `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`
  - Advanced filesystem & directories: `fchdir`, `fchroot`, `fsmount`, `fsopen`, `quotactl_fd`, `cachestat`, `getdents`, `getdents64`, `open_by_handle_at`, `fanotify_init`, `perf_event_open`, `setns`
  - Added test exercises to `test_syscalls.c` (Section 16.6) and audit rules to `setup_audit_rules.sh`.
  - Verified with synthetic unit tests for all 60 handlers and regression-checked against `out-v6.txt`.
- [x] Implemented unclassed Batch 1: Process Control, Scheduling & Resource Limits (30 syscalls):
  - Scheduling: `sched_yield`, `sched_setparam`, `sched_getparam`, `sched_setscheduler`, `sched_getscheduler`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_getaffinity`, `sched_setattr`, `sched_getattr`, `getcpu`
  - Process IDs & Priority: `setpgid`, `getpgid`, `setsid`, `getsid`, `getpriority`, `setpriority`
  - Resource Limits & System Attributes: `umask`, `personality`, `getrlimit`, `setrlimit`, `prlimit64`, `getrusage`
  - Namespaces, Execution & Threading: `unshare`, `set_tid_address`, `rseq`, `vhangup`, `restart_syscall`
  - Added Section 16.7 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Implemented unclassed Batch 2: Time, Timers & Clocks (non-%clock) (11 syscalls):
  - Sleep & alarms: `nanosleep`, `clock_nanosleep`, `alarm`
  - Interval timers & process accounting: `getitimer`, `setitimer`, `times`
  - POSIX interval timers: `timer_create`, `timer_settime`, `timer_gettime`, `timer_getoverrun`, `timer_delete`
  - Added Section 16.8 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Implemented unclassed Batch 3: System Info, Hostname & Administration (7 syscalls):
  - System identification & statistics: `uname`, `sysinfo`, `syslog`
  - Host & domain naming: `sethostname`, `setdomainname`
  - Filesystem sync & reboot control: `sync`, `reboot`
  - Added Section 16.9 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Implemented unclassed Batch 4: Keys, Security, Seccomp & Random (12 syscalls):
  - Keys subsystem: `add_key`, `request_key`, `keyctl` (formatting key serial numbers, `KEY_SPEC_*`, and all keyctl subcommands)
  - Security & Sandboxing: `seccomp` (supporting `SECCOMP_SET_MODE_*`, `SECCOMP_GET_ACTION_AVAIL`, and filter flags)
  - Randomness & Memory barriers: `getrandom`, `membarrier` (supporting commands, CPU flags, and command queries)
  - Process tracing & inspection: `ptrace` (with single-arg `PTRACE_TRACEME`, 2-arg `ATTACH`/`INTERRUPT`/`KILL`/`LISTEN`, signals, and `PTRACE_O_*` options), `kcmp` (handling omitted idx args for non-file resource types, and file descriptor indexing for `KCMP_FILE`)
  - Cross-process memory transfer: `process_vm_readv`, `process_vm_writev`
  - I/O Scheduling Priority: `ioprio_set`, `ioprio_get` (formatting `IOPRIO_PRIO_VALUE(class, data)`)
  - Added Section 16.10 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
  - Added root safety guards in `test_syscalls.c` (defanged `vhangup`, `reboot`, `sethostname`/`setdomainname` via UTS namespace, and `acct`).
- [x] Implemented unclassed Batch 5: Futex, Robust Lists, Memory Keys & Async I/O (9 syscalls):
  - Fast user-space locking: `futex` (supporting all 14 futex operations, private/realtime flags, and `FUTEX_BITSET_MATCH_ANY`)
  - Robust futex lists: `set_robust_list`, `get_robust_list`
  - Memory protection keys: `pkey_alloc` (supporting `PKEY_UNRESTRICTED` and `PKEY_DISABLE_*` rights), `pkey_free`
  - Asynchronous I/O: `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`
  - Added Section 16.11 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Implemented unclassed Batch 6: Kernel Modules, Architecture-specific & Legacy (24 syscalls) — **100% of x86_64 unclassed syscalls completed (93/93)**:
  - Kernel module management: `init_module`, `delete_module`, `create_module`, `get_kernel_syms`, `query_module`
  - Boot & messaging: `kexec_load`, `mq_unlink`
  - Architecture-specific controls: `arch_prctl` (decoding `ARCH_*` subcommands and `ARCH_GET_CPUID`), `modify_ldt`, `iopl`, `ioperm`, `set_thread_area`, `get_thread_area`
  - Cookie lookup & system control: `lookup_dcookie`, `_sysctl`, `sysfs`
  - Legacy event poll & subsystems: `epoll_ctl_old`, `epoll_wait_old`, `security`, `nfsservctl`, `afs_syscall`, `tuxcall`, `vserver`
  - Kernel trampoline: `uretprobe`
  - Added Section 16.12 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Implemented unclassed Batch 7: Generic & Recent Syscalls from `syscallent-common.h` (12 syscalls):
  - File descriptors: `close_range` (with in-memory descriptor lifecycle tracking in `ProcessTracker` for single FDs and ranges)
  - Futex2 subsystem: `futex_waitv`, `futex_wake`, `futex_wait`, `futex_requeue` (decoding futex2 size flags `FUTEX2_SIZE_*`, `FUTEX2_PRIVATE`, and `FUTEX2_NUMA`)
  - Mount inspection: `statmount`, `listmount`
  - Linux Security Modules (LSM): `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` (decoding `LSM_ATTR_*`)
  - Namespaces & Concurrency: `listns`, `rseq_slice_yield`
  - Added Section 16.13 in `test_syscalls.c` exercising these syscalls, and updated `setup_audit_rules.sh`.
- [x] Verified and completed full test & audit coverage for all 37 classed syscalls from `syscallent-common.h`:
  - Verified 100% handler registration in `audisp-strace` and membership across `%desc`, `%file`, `%memory`, `%process`, `%signal`.
  - Added Section 16.14 to `test_syscalls.c` covering the remaining 29 classed syscalls safely.
  - Added audit rules for all remaining classed syscalls in `setup_audit_rules.sh`.
- [x] Verified against all reference cases:
  - [x] `examples/fchmodat-v1`
  - [x] `examples/fchmodat-v2`
  - [x] `examples/clone`
  - [x] `examples/execve`
  - [x] `examples/audit-log.out`
  - [x] `examples/audit-log-v2.out`
  - [x] `examples/audit-log-v3.out`
  - [x] `examples/audit-log-v4.out`
  - [x] `examples/audit-log-v5.out`
  - [x] `examples/audit-log-v6.out` (verified complete run across 75+ syscalls, memory, sockets, I/O, fcntl, ioctl, and FD tracking)
  - [x] `examples/audit-log-v7.out` & `examples/audit-log-v7-trace.out` (investigated audit buffer exhaustion under live pipe monitoring)
  - [x] `examples/audit-log-v8.out` & `examples/audit-log-v8-trace.out` (verified live capture with session exclusion; confirmed root and user1 UID/GID decoding, deep ancestry tracking, and file descriptor lifecycle)
  - [x] `examples/audit-log-v9.out` & `examples/audit-log-v9-trace.out` (verified new process signals/wait4/waitid, socket options/mmsg, and extended memory/shared memory operations across both test_syscalls and system services)
  - [x] `examples/audit-log-v10.out` & `examples/audit-log-v10-trace.out` (verified System V IPC shm/sem/msg queues, credentials get/set identity variations, prctl options, and time/clock syscalls)
  - [x] `examples/audit-log-v11.out` & `examples/audit-log-v11-trace.out` (verified 17 additional %file syscalls across test_syscalls and system daemons: chdir, getcwd, inotify_add_watch, name_to_handle_at, chroot, mount, umount2, pivot_root, swapon, swapoff, acct, quotactl, open_tree, move_mount, fspick, fsconfig, mount_setattr)
  - [x] `examples/audit-log-v12.out` & `examples/audit-log-v12-trace.out` (verified %pure, ustat, %signal, %process, and %memory syscalls: getpid, getppid, getpgrp, gettid, ustat, sigaltstack, signalfd4, pause, mseal, rt_sigprocmask, rt_sigpending; confirmed 150+ distinct syscalls properly formatted)
  - [x] `examples/audit-log-v13.out` & `examples/audit-log-v13-trace.out` (verified complete run across 176 distinct syscalls including all %desc syscalls: epoll_create1, epoll_ctl, epoll_wait, epoll_pwait2, eventfd2, inotify_init1, inotify_rm_watch, timerfd_create, timerfd_settime, timerfd_gettime, memfd_create, pidfd_open, copy_file_range, fadvise64, readahead, poll, ppoll, select, pselect6, pipe2, dup3, syncfs, msync; validated live vs. offline parity across 112,504 trace lines)
  - [x] `examples/audit-log-v14.out` & `examples/audit-log-v14-trace.out` (verified unclassed batches 1-5 syscalls across scheduling, time/clocks, system info, keys, futexes, and async I/O)
  - [x] `examples/audit-log-v15.out` & `examples/audit-log-v15-trace.out` (verified complete run across 286 distinct syscalls and 53,204 events; validated 100% event count parity [212,816 lines] between live and offline replay across Group 6, Group 7, and `syscallent-common.h` classed syscalls including `close_range`, `futex2`, `statmount`, `listmount`, `io_uring_*`, `memfd_secret`, `landlock_*`, `process_madvise`, `process_mrelease`, and `set_mempolicy_home_node`)
- [x] Implemented strace-compatible exit status filtering (`-Z` / `--failed-only` and `-z` / `--successful-only`). Verified exact mathematical partition (`50,431` successful + `2,773` failed = `53,204` total events) against `examples/audit-log-v15.out`.
- [x] Implemented compact 1-line output mode (`-C` / `-1` / `--compact` with `summary` [default] and `strace` variants). Enables dense, single-line terminal streaming and easy piping into `grep`/`awk`/`wc`.
- [x] Implemented PID and User/UID filtering:
  - `-p` / `--pid` accepting comma-separated lists and repeatable arguments.
  - `--exclude-pid` to omit specific process IDs.
  - `-f` / `--follow-fork` to automatically follow and trace child processes spawned by traced PIDs via `clone`, `clone3`, `fork`, `vfork`.
  - `-u` / `--user` / `--uid` accepting usernames or numeric UIDs (comma-separated or repeatable) matching both real and effective identities.
  - `--exclude-user` / `--exclude-uid` to filter out background noise (e.g. `--exclude-user root` or `--exclude-uid 0`).
  - `--auid` to filter by audit login UID or login username.
- [x] Implemented binary hex `sockaddr` decoding for network syscalls (`connect`, `bind`, `accept`, `accept4`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`):
  - Decodes raw `SOCKADDR` audit records (`saddr=<hex>`) directly matching `strace` output:
    - `AF_UNIX`: Filesystem paths (`sun_path="/path"`), abstract namespace sockets (`sun_path=@"name"`), and unnamed/anonymous sockets (`{sa_family=AF_UNIX}`).
    - `AF_INET`: Port and IPv4 address (`{sa_family=AF_INET, sin_port=htons(port), sin_addr=inet_addr("IP")}`).
    - `AF_INET6`: Port, flowinfo, IPv6 address, and scope ID (`{sa_family=AF_INET6, sin6_port=htons(port), sin6_flowinfo=htonl(flowinfo), inet_pton(AF_INET6, "IPv6", &sin6_addr), sin6_scope_id=scope_id}`).
    - `AF_NETLINK`: Port ID and multicast groups (`{sa_family=AF_NETLINK, nl_pid=..., nl_groups=...}`).
    - `AF_PACKET`: Protocol, interface index, hardware type, packet type, and hardware address (`{sa_family=AF_PACKET, sll_protocol=htons(...), sll_ifindex=..., sll_hatype=..., sll_pkttype=..., sll_halen=...}`).
    - `AF_VSOCK`: CID, port, and flags (`{sa_family=AF_VSOCK, svm_cid=..., svm_port=...}`).
    - Corrected Linux socket family numeric constants in `SOCKET_DOMAINS` (`AF_BLUETOOTH`=31, `AF_VSOCK`=40, `AF_ALG`=38, `AF_XDP`=44, etc.).
    - Updated `handle_sendmsg_recvmsg` to display `{msg_name=<sockaddr>, ...}` when a `SOCKADDR` record accompanies `sendmsg`/`recvmsg`.
    - Handled `sendto` and `recvfrom` with `NULL` addresses and accurate sockaddr lengths.
- [x] Fixed `handle_fchown` dispatch method in `SyscallHandler`.
- [x] Fixed `renameat2` and `unlinkat` flag parsing from audit records.
- [x] Created C test generator `test_syscalls.c` and `Makefile` exercising 75+ syscalls across memory, I/O, sockets, descriptors, permissions, and process management.
- [x] Created `setup_audit_rules.sh` to configure `auditctl` rules for all tested syscalls.
- [x] Created audisp plugin configuration file `audisp-strace.conf`.

### Next Steps / Ideas
- [ ] Potential to-do: Add direct `syscall(SYS_open, ...)` and `syscall(SYS_stat, ...)` to `test_syscalls.c` if explicit audit verification of legacy syscall numbers is desired on x86_64.
- [ ] Live integration test on test VM with auditd daemon active.
