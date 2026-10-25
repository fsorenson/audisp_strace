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
- [x] Fixed `handle_fchown` dispatch method in `SyscallHandler`.
- [x] Fixed `renameat2` and `unlinkat` flag parsing from audit records.
- [x] Created C test generator `test_syscalls.c` and `Makefile` exercising 75+ syscalls across memory, I/O, sockets, descriptors, permissions, and process management.
- [x] Created `setup_audit_rules.sh` to configure `auditctl` rules for all tested syscalls.
- [x] Created audisp plugin configuration file `audisp-strace.conf`.

### Next Steps / Ideas
- [ ] Potential to-do: Add direct `syscall(SYS_open, ...)` and `syscall(SYS_stat, ...)` to `test_syscalls.c` if explicit audit verification of legacy syscall numbers is desired on x86_64.
- [ ] Live integration test on test VM with auditd daemon active.
