# PROJECT: audisp-strace

## Overview
`audisp-strace` is a Linux audit event consumer and `audisp` plugin written in Python using `auparse`. It parses raw Linux audit records for system calls and outputs formatted, readable traces resembling `strace` output, augmented with:
- Full process ancestry tracking (`1 (systemd) -> ... -> parent (comm) -> child (comm)`)
- Comprehensive process credentials (`uid`, `gid`, `auid`, `agid`, `euid`, `egid`, `suid`, `sgid`, `fsuid`, `fsgid`)
- Syscall arguments, resolved file paths, and return values
- Support for both live execution (audisp plugin or `tail -F` pipe with `/proc` enrichment) and offline replay of historical audit logs

Supported Syscalls:
- **Ownership & Permissions / Credentials**: `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `fchownat`, `lchown`, `setuid`, `setgid`
- **File & Directory Management**: `creat`, `open`, `openat`, `openat2`, `close`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`, `mkdir`, `mkdirat`, `rmdir`, `link`, `linkat`, `symlink`, `symlinkat`, `readlink`, `readlinkat`
- **File Metadata, Inspection & Access**: `stat`, `lstat`, `fstat`, `newfstatat` (`fstatat`), `statx`, `statfs`, `fstatfs`, `access`, `faccessat`, `faccessat2`
- **File Manipulation, Descriptors & Sizing**: `dup`, `dup2`, `dup3`, `truncate`, `ftruncate`, `fallocate`
- **Extended Attributes**: `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr`
- **Special Files, IPC & Timestamps**: `mknod`, `mknodat`, `pipe`, `pipe2`, `utime`, `utimes`, `futimesat`, `utimensat`
- **Memory Management**: `mmap`, `munmap`, `mprotect`, `madvise`, `brk`
- **Sockets & Networking**: `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`
- **Read, Write & I/O Operations**: `read`, `write`, `readv`, `writev`, `pread` / `pread64`, `pwrite` / `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendfile` / `sendfile64`
- **Descriptor Control**: `fcntl`, `ioctl`
- **Process Lifecycle & Tracking**: `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `exit`, `exit_group`

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
   - `-s`, `--syscalls`: Comma-separated list of syscalls to display (e.g. `--syscalls chown,rename,unlink,setuid`).
   - `-x`, `--exclude`: Comma-separated list of syscalls to omit (e.g. `--exclude close,openat`).
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
   - **`setup_audit_rules.sh`**: Helper script to configure `auditctl` rules for capturing the generated events on a test system. Includes `-a never,exit` exclusion rules for `auditd`, `sshd-session`, `tail`, `tee`, and `python3` to prevent runaway audit feedback loops during live pipe monitoring.

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
    - [x] `setuid`, `setgid`
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
    - [x] `mknod`, `mknodat`
    - [x] `pipe`, `pipe2`
    - [x] `utime`, `utimes`, `futimesat`, `utimensat`
  - [x] Syscall handlers for memory management:
    - [x] `mmap`, `munmap`, `mprotect`, `madvise`, `brk`
  - [x] Syscall handlers for sockets & networking:
    - [x] `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`
    - [x] `connect`, `getsockname`, `getpeername`, `shutdown`
    - [x] `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
    - [x] Socket address (`SOCKADDR`) interpretation for `inet`, `inet6`, `local/unix`, and `netlink`.
  - [x] Syscall handlers for read, write & I/O:
    - [x] `read`, `write`, `readv`, `writev`
    - [x] `pread` / `pread64`, `pwrite` / `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`
    - [x] `sendfile` / `sendfile64`
  - [x] Syscall handlers for descriptor control:
    - [x] `fcntl` (command decoding, flag interpretation, and `F_DUPFD`/`F_SETFD` FD tracking)
    - [x] `ioctl` (decoding common tty/socket ioctls e.g. `TCGETS`, `TIOCGWINSZ`, `FIONREAD`, with hex fallback)
  - [x] Syscall handlers for process tracking:
    - [x] `clone`, `clone3`, `fork`, `vfork`
    - [x] `execve`, `execveat`
    - [x] `exit`, `exit_group`
  - [x] String unescaping & hex-decoding for command line arguments (`argv`, `proctitle`).
  - [x] Full in-memory file descriptor lifecycle tracking (`ProcessTracker`):
    - [x] Tracks descriptors opened by `open`, `openat`, `openat2`, `creat` (with relative-to-cwd and relative-to-dirfd resolution).
    - [x] Tracks descriptor duplication via `dup`, `dup2`, `dup3`, and `fcntl(F_DUPFD)`.
    - [x] Tracks socket descriptors from `socket`, `socketpair`, `accept`, `accept4`.
    - [x] Tracks `FD_PAIR` records from `pipe`, `pipe2`, `socketpair`.
    - [x] In-flight resolution for `fstat`, `fchmod`, `fchown`, `ftruncate`, `fallocate`, `f*xattr`, directory descriptors in `*at` syscalls, read/write, sockets, fcntl/ioctl, and `close(fd<path>)`.
    - [x] Inherits open descriptors across `fork`/`clone`, handles `O_CLOEXEC` closure on `execve`, and cleans up on `exit`.
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
- [x] Fixed `handle_fchown` dispatch method in `SyscallHandler`.
- [x] Fixed `renameat2` and `unlinkat` flag parsing from audit records.
- [x] Created C test generator `test_syscalls.c` and `Makefile` exercising 75+ syscalls across memory, I/O, sockets, descriptors, permissions, and process management.
- [x] Created `setup_audit_rules.sh` to configure `auditctl` rules for all tested syscalls.
- [x] Created audisp plugin configuration file `audisp-strace.conf`.

### Next Steps / Ideas
- [ ] Potential to-do: Add direct `syscall(SYS_open, ...)` and `syscall(SYS_stat, ...)` to `test_syscalls.c` if explicit audit verification of legacy syscall numbers is desired on x86_64.
- [ ] Live integration test on test VM with auditd daemon active.
