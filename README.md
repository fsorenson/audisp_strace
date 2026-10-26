# audisp-strace

**Linux Audit Event Consumer & `strace`-like Trace Formatter**

`audisp-strace` translates raw Linux audit records into clear, human-readable system call traces modeled after [`strace`](https://strace.io/), enriched with **full process ancestry trees** and **comprehensive process credentials**.

It operates as an **`audisp` plugin**, as a **live stream monitor** on `/var/log/audit/audit.log`, or as an **offline forensic tool** for analyzing past audit logs.

```text
29381<test_syscalls> 14:23:01.123 openat(AT_FDCWD</tmp>, "config.json", O_RDONLY|O_CLOEXEC) = 3</tmp/config.json>
    uid=1000 (sorenson), gid=1000 (sorenson), auid=1000 (sorenson), agid=1000 (sorenson), euid=1000 (sorenson), egid=1000 (sorenson)
    1 (systemd) -> 29380 (bash) -> 29381 (test_syscalls)
```

---

## Why audisp-strace?

Standard Linux audit records (`/var/log/audit/audit.log`) capture system activity system-wide with near-zero overhead, but reading them raw is notoriously difficult:
- A single system call is split across multiple separate records (`SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, `EXECVE`, `SOCKADDR`).
- File paths and command lines are often hex-encoded (`74657374...`).
- Process information only records `<pid>` and immediate `<ppid>`, offering no insight into whether a process was spawned by a cron job, a shell session, an SSH login, or a system daemon.
- Standard `strace` cannot run in production 24/7 without severe `ptrace` latency and cannot capture short-lived processes retroactively.

`audisp-strace` bridges this gap: it correlates audit records in real time, tracks process state and file descriptors across `clone`, `fork`, `execve`, and `close`, and formats output like `strace` while exposing the security context of every call.

---

## Features

- **Rich 3-Line Output**:
  - **Line 1 (Trace)**: `<pid><comm> timestamp syscall(args) = result`
  - **Line 2 (Credentials)**: Process identities (`uid`, `gid`, `auid`, `agid`, `euid`, `egid`, `suid`, `sgid`, `fsuid`, `fsgid`) with username and group resolution.
  - **Line 3 (Ancestry)**: Full process hierarchy walk (`1 (systemd) -> ... -> parent (comm) -> child (comm)`).
- **Compact 1-Line Mode (`-C` / `--compact`)**:
  - Single-line format per event with inline `[uid=...]` and `[ppid:...]` tags for high-throughput terminal monitoring or piping to `grep`/`awk`.
- **Structured JSON Lines Output (`--json` / `--jsonl`)**:
  - Output each audit event as a machine-readable JSON object containing full syscall details, errno, resolved paths, credential dictionary, and process ancestry array for SIEM and log ingestion (`jq`, Vector, Loki, Elasticsearch).
- **Extensive Syscall Coverage (285+ syscalls)**:
  - File I/O, lifecycle, descriptors, permissions, attributes, and ownership.
  - Sockets & networking with binary hex `SOCKADDR` decoding (IPv4, IPv6, UNIX sockets [filesystem, abstract `@`, unnamed], Netlink, Packet, VSOCK).
  - Modern Linux syscalls: `openat2`, `close_range`, `statx`, `statmount`, `listmount`, `futex_waitv`, `pidfd_*`, `io_uring_*`, `landlock_*`, `process_madvise`, and more.
- **`strace`-Compatible `%CLASS` Selectors**:
  - Filter using 18 standard syscall categories: `%desc`, `%file`, `%net`, `%creds`, `%process`, `%memory`, `%signal`, `%ipc`, `%clock`, `%stat`, `%fstat`, `%%stat`, `%statfs`, `%fstatfs`, `%%statfs`, `%pure`.
- **Granular Filtering**:
  - Filter by PID (`-p`, `--exclude-pid`) with child process tracking (`-f` / `--follow-fork`).
  - Filter by User or UID (`-u`, `--exclude-user`) matching real and effective identities.
  - Filter by Audit Login UID (`--auid`).
  - Filter by Exit Status: failed only (`-Z`) or successful only (`-z`).
- **Syscall Statistics & Summary (`-c` / `--summary-only`, `--summary`, `-S`)**:
  - Aggregates call counts, error counts, and error percentages per syscall.
  - Sortable by `calls`, `errors`, `error%`, or `name`.
- **ANSI Terminal Colorization (`--color=auto|always|never`)**:
  - Auto-detects TTY and respects `NO_COLOR`.
  - Color-codes PIDs, commands, timestamps, string literals, resolved FD paths, green success codes, and bold red errors.
- **String Length Limits (`-L` / `--string-limit` / `--strsize`)**:
  - Modeled after `strace -s strsize` (default: 32 characters, use 0 for unlimited) to prevent unwieldy multi-line string or argument dumps while keeping full pathnames intact.
- **Flexible Stream Redirection (`-o` / `--output`, `-A` / `--append`)**:
  - Route traces directly to a file with safe atomic flushing on `Ctrl-C`.

---

## Installation & Requirements

### Prerequisites
- Python 3.8+
- Python `auparse` bindings (Audit parsing library)

**On Fedora / RHEL / Rocky / CentOS**:
```bash
sudo dnf install audit-libs-python3 python3-audit
```

**On Debian / Ubuntu**:
```bash
sudo apt-get install python3-audit
```

### Installation
Clone the repository and install the script:
```bash
git clone https://github.com/username/audisp_strace.git
cd audisp_strace
chmod +x audisp-strace
sudo cp audisp-strace /usr/local/bin/
```

---

## Usage

```text
usage: audisp-strace [-h] [-l] [--offline] [-t {time,datetime,epoch}]
                     [-s SYSCALLS] [-x EXCLUDE] [-a] [-Z | -z]
                     [-C [{summary,strace}]] [-p PIDS] [--exclude-pid EXCLUDE_PIDS]
                     [-f] [-u USERS] [--exclude-user EXCLUDE_USERS] [--auid AUIDS]
                     [--color [{auto,always,never}]] [-o OUTPUT] [-A]
                     [-c] [--summary] [-S {calls,errors,error%,name}] [--json]
                     [-L STRING_LIMIT]
                     [files ...]
```

### 1. Offline Audit Log Analysis

Analyze an existing audit log file:
```bash
audisp-strace --offline /var/log/audit/audit.log
```

Trace only permission, credential, and ownership changes:
```bash
audisp-strace --offline audit.log -s %creds
```

Display only failed system calls (`-Z`):
```bash
audisp-strace --offline audit.log -Z
```

### 2. Live Monitoring via Pipe

Monitor audit events as they occur in real time using `tail`:
```bash
sudo unbuffer tail -n0 -F /var/log/audit/audit.log | audisp-strace --live
```

Trace activity for a specific user and follow child processes:
```bash
sudo tail -n0 -F /var/log/audit/audit.log | audisp-strace --live -u user1 -f
```

Exclude background root noise:
```bash
sudo tail -n0 -F /var/log/audit/audit.log | audisp-strace --live --exclude-user root
```

### 3. As an `audisp` Plugin

`audisp-strace` can be configured directly inside auditd's dispatcher:

1. Copy the configuration file to the audit plugins directory:
   ```bash
   sudo cp audisp-strace.conf /etc/audit/plugins.d/
   ```
2. Restart `auditd`:
   ```bash
   sudo service auditd restart
   ```

When audit events are dispatched, `audisp-strace` automatically detects that its parent is `auditd`/`audispd` and enables live `/proc` lookups.

---

## Syscall Statistics & Summary (`-c`)

Modeled after `strace -c`, the summary mode aggregates syscall call counts, failed attempts, and error rates:

```bash
audisp-strace --offline audit.log -c
```

Output:
```text
% calls      calls     errors   error%  syscall
-------  ---------  ---------  -------  ----------------
  29.94      12418         79     0.6%  read
  22.65       9396       1204    12.8%  openat
  20.83       8639          8     0.1%  close
   6.26       2598                      fstat
   5.58       2316                      write
   1.90        789        661    83.8%  ioctl
   1.71        710        112    15.8%  recvfrom
   0.96        398         79    19.8%  newfstatat
   0.36        148        132    89.2%  readlink
   0.32        131         91    69.5%  access
   0.19         78         24    30.8%  connect
-------  ---------  ---------  -------  ----------------
 100.00      41475       2428     5.9%  total
```

Sort by errors or error rate to locate issues or failed access attempts immediately:
```bash
audisp-strace --offline audit.log -c -S errors
audisp-strace --offline audit.log -c -S error%
```

---

## Filtering Reference

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-s`, `--syscalls` | Comma-separated syscalls or `%CLASS` selectors to monitor | `-s %net,openat` |
| `-x`, `-X`, `--exclude` | Syscalls or `%CLASS` selectors to omit | `-X %desc,close` |
| `-a`, `--all` | Display all captured syscalls (overrides default filter) | `-a` |
| `-Z`, `--failed-only` | Display only syscalls returning an error | `-Z` |
| `-z`, `--successful-only` | Display only syscalls returning success | `-z` |
| `-p`, `--pid` | Filter by PID (repeatable or comma-separated) | `-p 1234,5678` |
| `--exclude-pid` | Exclude specific PIDs | `--exclude-pid 1` |
| `-f`, `--follow-fork` | Trace child processes created by `clone`/`fork` | `-p 1234 -f` |
| `-u`, `--user`, `--uid` | Filter by username or numeric UID | `-u apache,1001` |
| `--exclude-user` | Exclude specific username or numeric UID | `--exclude-user root` |
| `--auid` | Filter by audit login identity | `--auid 1000` |
| `-C`, `--compact` | Compact 1-line mode (`summary` or `strace`) | `-C summary` |
| `--json`, `--jsonl` | Output events as JSON Lines (NDJSON) | `--json` |
| `--color` | ANSI color output (`auto`, `always`, `never`) | `--color=always` |
| `-o`, `--output` | Write trace output to file | `-o /var/log/trace.log` |
| `-A`, `--append` | Append to output file instead of overwriting | `-o trace.log -A` |
| `-c`, `--summary-only` | Print counts and error table on exit | `-c` |
| `--summary` | Print traces and summary table on exit | `--summary` |
| `-S`, `--sort-by` | Sort summary table (`calls`, `errors`, `error%`, `name`) | `-S errors` |
| `-L`, `--string-limit`, `--strsize` | Limit maximum string length for arguments (default: 32, 0 for unlimited) | `-L 64`, `-L 0` |

---

## Setting Up Audit Rules

To monitor syscalls with `audisp-strace`, the Linux kernel must be instructed to log syscall events using `auditctl`.

Use the provided [`setup_audit_rules.sh`](file:///home/sorenson/projects/audisp_strace/setup_audit_rules.sh) script to set up monitoring rules with session exclusion (preventing audit storm loops when tailing logs over SSH):

```bash
# Add audit rules
sudo ./setup_audit_rules.sh

# Remove test audit rules
sudo ./setup_audit_rules.sh --delete
```

Or configure custom rules manually with `auditctl`:
```bash
# Example: monitor file permission and ownership changes
sudo auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F key=perm_mod
sudo auditctl -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F key=perm_mod
```

---

## Architecture

`audisp-strace` is implemented as a single, self-contained Python executable structured into modular components:

- **`AuditEvent`**: Normalizes multi-record audit events (`SYSCALL`, `CWD`, `PATH`, `EXECVE`, `PROCTITLE`, `SOCKADDR`), cleans strings, and extracts exit codes.
- **`ProcessTracker`**: In-memory state engine tracking parent/child relationships, command lines, current working directories, and file descriptors across fork/exec/close.
- **`ProcResolver`**: Fallback inspector resolving file descriptors and process info from `/proc` during live mode.
- **`SyscallHandler`**: Decodes arguments and formats syscall calls for over 285 distinct Linux syscalls.
- **`TraceFormatter`**: Handles timestamp variations (`time`, `datetime`, `epoch`), credentials formatting, compact tags, and process ancestry trees.
- **`ColorTheme`**: High-performance ANSI styling engine using token lexing to highlight paths, strings, and errors without delimiter conflicts.
- **`AudispStraceApp`**: Orchestrates `auparse` line un-wrapping, signal lifecycle (`SIGINT`, `SIGTERM`, `SIGPIPE`), filtering, and stream output.

---

## License

This project is licensed under the MIT License.
