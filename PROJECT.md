# PROJECT: audisp-strace

## Overview
`audisp-strace` is a Linux audit event consumer and `audisp` plugin written in Python using `auparse`. It parses raw Linux audit records for system calls and outputs formatted, readable traces resembling `strace` output, augmented with:
- Full process ancestry tracking (`1 (systemd) -> ... -> parent (comm) -> child (comm)`)
- Comprehensive process credentials (`uid`, `gid`, `auid`, `agid`, `euid`, `egid`, `suid`, `sgid`, `fsuid`, `fsgid`)
- Syscall arguments, resolved file paths, and return values
- Support for both live execution (audisp plugin or `tail -F` pipe with `/proc` enrichment) and offline replay of historical audit logs

Supported Syscalls:
- **Ownership & Permissions / Credentials**: `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `fchownat`, `lchown`, `setuid`, `setgid`
- **File & Directory Management**: `creat`, `open`, `openat`, `openat2`, `close`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`, `mkdir`, `mkdirat`, `rmdir`, `link`, `linkat`, `symlink`, `symlinkat`
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
   - **`setup_audit_rules.sh`**: Helper script to configure `auditctl` rules for capturing the generated events on a test system.

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
    - [x] `link`, `linkat`, `symlink`, `symlinkat`
  - [x] Syscall handlers for process tracking:
    - [x] `clone`, `clone3`, `fork`, `vfork`
    - [x] `execve`, `execveat`
    - [x] `exit`, `exit_group`
  - [x] String unescaping & hex-decoding for command line arguments (`argv`, `proctitle`).
- [x] Verified against all reference cases:
  - [x] `examples/fchmodat-v1`
  - [x] `examples/fchmodat-v2`
  - [x] `examples/clone`
  - [x] `examples/execve`
  - [x] `examples/audit-log.out`
  - [x] `examples/audit-log-v2.out`
  - [x] `examples/audit-log-v3.out`
- [x] Created C test generator `test_syscalls.c` and `Makefile`.
- [x] Created `setup_audit_rules.sh` to configure `auditctl` rules for all tested syscalls.
- [x] Created audisp plugin configuration file `audisp-strace.conf`.

### Next Steps / Ideas
- [ ] Live integration test on test VM with auditd daemon active.
- [ ] Add support for additional syscalls as needed.
