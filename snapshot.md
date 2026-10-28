# Context Snapshot & Continuity Guide: `audisp_strace`

This document defines the procedure for capturing and preserving critical project context prior to clearing, resetting, or compacting conversation memory. Follow these instructions whenever a session is concluding or context is about to be refreshed.

---

## 1. Documentation Roles & Structure

Context must be preserved directly in the project's repository files rather than in transient chat history. Do not duplicate information that already exists in dedicated reference files; reference existing documentation by file path.

Maintain the following three core tracking files:

1. **[`PROJECT.md`](file:///home/sorenson/projects/audisp_strace/PROJECT.md)** (Internal Architecture & Implementation Status):
   - Architectural model, component responsibilities (`ProcResolver`, `ProcessTracker`, `AuditEvent`, `TraceFormatter`, `SyscallHandler`, `AudispStraceApp`).
   - Design rationale and non-obvious implementation details (e.g., audit stream unwrapping, kernel audit record field conventions, negative exit code interpretation).
   - Authoritative list of handled syscalls grouped by subsystem.
   - Implementation checklist under `Status & Progress` -> `Done`.

2. **[`README.md`](file:///home/sorenson/projects/audisp_strace/README.md)** (User-Facing Manual & CLI Reference):
   - User documentation, deployment methods (`audispd` plugin, live follower, offline analysis).
   - CLI options and argument specifications.
   - Syscall classification selectors (`%CLASS` categories).
   - `Filtering Reference` table and usage examples.
   - Feature overviews (colorization, drop detection, summary statistics, ghost file tracking).

3. **[`todo`](file:///home/sorenson/projects/audisp_strace/todo)** (Roadmap & Work Queue):
   - `Section 1: Recently Completed Enhancements`: Concise ledger of completed features.
   - `Section 2: High-Value Enhancement Suggestions & Remaining To-Do Items`: Active and deferred items grouped by theme (Root-Cause Analysis, Forensics & Timing, Configuration Ergonomics, Packaging). Each entry documents *What it does*, *Support Value*, and any prerequisites.

---

## 2. What to Capture Before Clearing Context

Capture information that exists only in the current conversation and would otherwise be lost:

- **Architectural & Design Decisions**: Rationale for non-obvious choices ("we chose X over Y because Z", kernel audit peculiarities, performance trade-offs).
- **In-Progress or Uncommitted Changes**: Summary of files modified in the working tree, state of tests, and any half-finished features.
- **Active Next Steps**: The prioritized tasks queued for the immediate next session so work can resume cold.
- **Kernel / Audit Caveats**: Real-world audit subsystem quirks discovered during testing (e.g. feedback loops when tracing own PID, multi-core netlink packet delivery jitter, negative exit code decoding).
- **Standing Constraints**:
  - Single-file standalone executable architecture for [`audisp-strace`](file:///home/sorenson/projects/audisp_strace/audisp-strace) (no third-party dependencies outside Linux audit/auparse libraries and standard library).
  - Git commit policy: The user creates git commits; do not create commits unless explicitly directed.

---

## 3. What NOT to Capture

To prevent context bloat and stale documentation, avoid:
- Detailed code diffs, function signatures, or line numbers that can be read directly from the working tree.
- Routine bugfix history (rely on `git log`).
- Raw audit log dumps or transcripts (reference specific log files in `examples/` like `examples/audit-log-v19.out`).
- Redundant duplication across `PROJECT.md`, `README.md`, and `todo`.

---

## 4. Maintenance & Reconciliation Protocol

When updating project files during a snapshot:

1. **Reconcile `todo`**:
   - Move completed items from Section 2 into Section 1 with a brief bullet point.
   - Keep pending items ordered by priority with clear rationale.
2. **Reconcile `PROJECT.md`**:
   - Add new features and syscall additions to the `Done` checklist.
   - Update `Supported Syscalls` if new system calls were introduced or handled.
   - Update `Design Decisions` if new architectural patterns or flags were established.
3. **Reconcile `README.md`**:
   - Update the `Filtering Reference` table whenever CLI flags are added or modified.
   - Update the `%CLASS` listing if syscall groupings change.
   - Document any new CLI options in the relevant feature sections.
4. **Test Suite Alignment**:
   - Check whether [`test_syscalls.c`](file:///home/sorenson/projects/audisp_strace/test_syscalls.c) exercises newly introduced syscalls or features.
   - Verify code compiles cleanly (`python3 -m py_compile audisp-strace`).

---

## 5. Pre-Clear Snapshot Checklist

Before clearing or resetting context, verify:

- [ ] `git status -s` inspected to identify all modified and untracked files.
- [ ] `python3 -m py_compile audisp-strace` completes with zero syntax errors.
- [ ] Working tree changes verified against test logs in `examples/`.
- [ ] `PROJECT.md` updated (implementation milestones checked off).
- [ ] `README.md` updated (CLI options, filtering table, feature docs).
- [ ] `todo` updated (completed items moved to Section 1; active priorities clear).
- [ ] Brief summary of current state and recommended immediate next steps reported to the user.
