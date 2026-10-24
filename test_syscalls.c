#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <sys/timex.h>
#include <time.h>
#include <grp.h>
#include <termios.h>

#ifdef __has_include
#  if __has_include(<linux/openat2.h>)
#    include <linux/openat2.h>
#  endif
#endif

#ifndef SYS_openat2
#  if defined(__x86_64__)
#    define SYS_openat2 437
#  elif defined(__aarch64__)
#    define SYS_openat2 437
#  endif
#endif

#ifndef SYS_statx
#  if defined(__x86_64__)
#    define SYS_statx 332
#  elif defined(__aarch64__)
#    define SYS_statx 291
#  endif
#endif

#ifndef RENAME_NOREPLACE
#  define RENAME_NOREPLACE (1 << 0)
#endif

/* Stack size for clone() */
#define CLONE_STACK_SIZE (64 * 1024)

static int clone_child_func(void *arg) {
    (void)arg;
    return 0;
}

static void log_op(const char *syscall_name, const char *desc, int res) {
    if (res >= 0) {
        printf("  [OK] %-14s: %s (result: %d)\n", syscall_name, desc, res);
    } else {
        printf("  [FAIL] %-12s: %s (errno %d: %s)\n", syscall_name, desc, errno, strerror(errno));
    }
}

static void run_worker_tests(const char *base_dir) {
    char path_buf1[1024];
    char abs_sub[1024];
    char abs_file[1024];
    char xattr_buf[256];
    char link_buf[256];
    int res;
    int dir_fd = -1;
    int file_fd = -1;
    uid_t uid = getuid();
    gid_t gid = getgid();

    printf("\n=== [Worker PID %d (PPID %d)] Exercising Syscalls in: %s ===\n",
           getpid(), getppid(), base_dir);

    /* Change directory into sandbox to test relative paths & AT_FDCWD cleanly */
    if (chdir(base_dir) != 0) {
        perror("chdir base_dir");
        return;
    }

    /* -------------------------------------------------------------
     * 1. DIRECTORY OPERATIONS: mkdir, mkdirat
     * ------------------------------------------------------------- */
    printf("\n--- Directory Operations (mkdir, mkdirat) ---\n");

    /* mkdir (relative) */
    res = mkdir("subdir_rel", 0755);
    log_op("mkdir", "subdir_rel, mode 0755", res);

    /* Open directory fd for dir_fd tests */
    dir_fd = open("subdir_rel", O_RDONLY | O_DIRECTORY);
    log_op("open", "subdir_rel as dir_fd", dir_fd);

    /* mkdirat: AT_FDCWD + relative path */
    res = mkdirat(AT_FDCWD, "sub_at_fdcwd_rel", 0750);
    log_op("mkdirat", "AT_FDCWD + relative path 'sub_at_fdcwd_rel'", res);

    /* mkdirat: dir_fd + relative path (inside subdir_rel) */
    res = mkdirat(dir_fd, "nested_in_dirfd", 0750);
    log_op("mkdirat", "dir_fd + relative path 'nested_in_dirfd'", res);

    /* mkdirat: AT_FDCWD + absolute path */
    snprintf(abs_sub, sizeof(abs_sub), "%s/sub_at_fdcwd_abs", base_dir);
    res = mkdirat(AT_FDCWD, abs_sub, 0750);
    log_op("mkdirat", "AT_FDCWD + absolute path", res);

    /* mkdirat: dir_fd + absolute path */
    snprintf(path_buf1, sizeof(path_buf1), "%s/sub_dirfd_abs", base_dir);
    res = mkdirat(dir_fd, path_buf1, 0750);
    log_op("mkdirat", "dir_fd + absolute path", res);

    /* -------------------------------------------------------------
     * 2. FILE CREATION & OPEN: creat, open, openat, openat2
     * ------------------------------------------------------------- */
    printf("\n--- File Creation & Open Operations (creat, open, openat, openat2) ---\n");

    /* creat */
    file_fd = creat("creat_file.txt", 0644);
    log_op("creat", "creat_file.txt, mode 0644", file_fd);
    if (file_fd >= 0) close(file_fd);

    /* open (relative) */
    file_fd = open("open_file.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    log_op("open", "open_file.txt O_RDWR|O_CREAT", file_fd);
    if (file_fd >= 0) close(file_fd);

    /* openat: AT_FDCWD + relative path */
    file_fd = openat(AT_FDCWD, "openat_fdcwd_rel.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    log_op("openat", "AT_FDCWD + relative 'openat_fdcwd_rel.txt'", file_fd);
    if (file_fd >= 0) close(file_fd);

    /* openat: dir_fd + relative path */
    file_fd = openat(dir_fd, "openat_dirfd_rel.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    log_op("openat", "dir_fd + relative 'openat_dirfd_rel.txt'", file_fd);

    /* openat: AT_FDCWD + absolute path */
    snprintf(abs_file, sizeof(abs_file), "%s/openat_fdcwd_abs.txt", base_dir);
    res = openat(AT_FDCWD, abs_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
    log_op("openat", "AT_FDCWD + absolute path", res);
    if (res >= 0) close(res);

    /* openat: dir_fd + absolute path */
    snprintf(path_buf1, sizeof(path_buf1), "%s/openat_dirfd_abs.txt", base_dir);
    res = openat(dir_fd, path_buf1, O_RDWR | O_CREAT | O_TRUNC, 0644);
    log_op("openat", "dir_fd + absolute path", res);
    if (res >= 0) close(res);

    /* openat2 */
#ifdef SYS_openat2
    {
        struct open_how how;
        memset(&how, 0, sizeof(how));
        how.flags = O_RDWR | O_CREAT | O_TRUNC;
        how.mode = 0640;
        how.resolve = 0;
        res = syscall(SYS_openat2, dir_fd, "openat2_file.txt", &how, sizeof(how));
        log_op("openat2", "dir_fd + 'openat2_file.txt' via SYS_openat2", res);
        if (res >= 0) close(res);
    }
#endif

    /* -------------------------------------------------------------
     * 3. STAT & ACCESS FAMILY: stat, lstat, fstat, fstatat, statfs, fstatfs, statx, access, faccessat
     * ------------------------------------------------------------- */
    printf("\n--- Stat & Access Family ---\n");
    {
        struct stat st;
        res = stat("creat_file.txt", &st);
        log_op("stat", "creat_file.txt", res);

        res = lstat("creat_file.txt", &st);
        log_op("lstat", "creat_file.txt", res);

        if (file_fd >= 0) {
            res = fstat(file_fd, &st);
            log_op("fstat", "open file_fd", res);
        }

        res = fstatat(dir_fd, "openat_dirfd_rel.txt", &st, 0);
        log_op("fstatat", "dir_fd + 'openat_dirfd_rel.txt'", res);

        struct statfs stfs;
        res = statfs(base_dir, &stfs);
        log_op("statfs", base_dir, res);

        if (dir_fd >= 0) {
            res = fstatfs(dir_fd, &stfs);
            log_op("fstatfs", "dir_fd", res);
        }

#ifdef SYS_statx
        struct statx stx;
        res = syscall(SYS_statx, AT_FDCWD, "creat_file.txt", 0, STATX_ALL, &stx);
        log_op("statx", "AT_FDCWD + 'creat_file.txt'", res);
#endif

        res = access("creat_file.txt", R_OK | W_OK);
        log_op("access", "creat_file.txt, R_OK|W_OK", res);

        res = faccessat(dir_fd, "openat_dirfd_rel.txt", R_OK, 0);
        log_op("faccessat", "dir_fd + 'openat_dirfd_rel.txt', R_OK", res);

        res = faccessat(AT_FDCWD, abs_file, R_OK, AT_EACCESS);
        log_op("faccessat", "AT_FDCWD + abs_file, AT_EACCESS", res);
    }

    /* -------------------------------------------------------------
     * 4. PERMISSIONS: chmod, fchmod, fchmodat
     * ------------------------------------------------------------- */
    printf("\n--- Permission Operations (chmod, fchmod, fchmodat) ---\n");

    res = chmod("creat_file.txt", 0600);
    log_op("chmod", "creat_file.txt to 0600", res);

    if (file_fd >= 0) {
        res = fchmod(file_fd, 0660);
        log_op("fchmod", "open file_fd to 0660", res);
    }

    res = fchmodat(AT_FDCWD, "openat_fdcwd_rel.txt", 0640, 0);
    log_op("fchmodat", "AT_FDCWD + 'openat_fdcwd_rel.txt' to 0640", res);

    res = fchmodat(dir_fd, "openat_dirfd_rel.txt", 0640, 0);
    log_op("fchmodat", "dir_fd + 'openat_dirfd_rel.txt' to 0640", res);

    res = fchmodat(AT_FDCWD, abs_file, 0640, 0);
    log_op("fchmodat", "AT_FDCWD + absolute path to 0640", res);

    res = fchmodat(dir_fd, abs_file, 0644, 0);
    log_op("fchmodat", "dir_fd + absolute path to 0644", res);

    /* -------------------------------------------------------------
     * 5. OWNERSHIP: chown, fchown, lchown, fchownat
     * ------------------------------------------------------------- */
    printf("\n--- Ownership Operations (chown, fchown, lchown, fchownat) ---\n");

    res = chown("creat_file.txt", uid, gid);
    log_op("chown", "creat_file.txt to uid/gid", res);

    if (file_fd >= 0) {
        res = fchown(file_fd, uid, gid);
        log_op("fchown", "open file_fd to uid/gid", res);
    }

    res = fchownat(AT_FDCWD, "openat_fdcwd_rel.txt", uid, gid, 0);
    log_op("fchownat", "AT_FDCWD + 'openat_fdcwd_rel.txt'", res);

    res = fchownat(dir_fd, "openat_dirfd_rel.txt", uid, gid, 0);
    log_op("fchownat", "dir_fd + 'openat_dirfd_rel.txt'", res);

    res = fchownat(AT_FDCWD, abs_file, uid, gid, 0);
    log_op("fchownat", "AT_FDCWD + absolute path", res);

    /* -------------------------------------------------------------
     * 6. LINKS, SYMLINKS & READLINK: link, linkat, symlink, symlinkat, readlink, readlinkat, lchown
     * ------------------------------------------------------------- */
    printf("\n--- Links, Symlinks & Readlink ---\n");

    res = link("open_file.txt", "hardlink_open.txt");
    log_op("link", "open_file.txt -> hardlink_open.txt", res);

    res = linkat(dir_fd, "openat_dirfd_rel.txt", dir_fd, "hardlink_dirfd.txt", 0);
    log_op("linkat", "dir_fd 'openat_dirfd_rel.txt' -> dir_fd 'hardlink_dirfd.txt'", res);

    res = symlink("open_file.txt", "symlink_open.txt");
    log_op("symlink", "'open_file.txt' target -> 'symlink_open.txt'", res);

    res = lchown("symlink_open.txt", uid, gid);
    log_op("lchown", "symlink_open.txt to uid/gid", res);

    res = readlink("symlink_open.txt", link_buf, sizeof(link_buf) - 1);
    log_op("readlink", "symlink_open.txt", res);

    res = symlinkat("target_dummy.txt", dir_fd, "symlink_in_dirfd.txt");
    log_op("symlinkat", "'target_dummy.txt' target -> dir_fd 'symlink_in_dirfd.txt'", res);

    res = readlinkat(dir_fd, "symlink_in_dirfd.txt", link_buf, sizeof(link_buf) - 1);
    log_op("readlinkat", "dir_fd 'symlink_in_dirfd.txt'", res);

    res = fchownat(dir_fd, "symlink_in_dirfd.txt", uid, gid, AT_SYMLINK_NOFOLLOW);
    log_op("fchownat", "dir_fd symlink with AT_SYMLINK_NOFOLLOW", res);

    /* -------------------------------------------------------------
     * 7. DESCRIPTOR DUPLICATION, TRUNCATE & FALLOCATE: dup, dup2, dup3, truncate, ftruncate, fallocate
     * ------------------------------------------------------------- */
    printf("\n--- Descriptor Duplication, Truncate & Fallocate ---\n");
    if (file_fd >= 0) {
        int dup_fd1 = dup(file_fd);
        log_op("dup", "file_fd", dup_fd1);
        if (dup_fd1 >= 0) close(dup_fd1);

        int dup_fd2 = dup2(file_fd, 88);
        log_op("dup2", "file_fd to 88", dup_fd2);
        if (dup_fd2 >= 0) close(dup_fd2);

        int dup_fd3 = dup3(file_fd, 89, O_CLOEXEC);
        log_op("dup3", "file_fd to 89 (O_CLOEXEC)", dup_fd3);
        if (dup_fd3 >= 0) close(dup_fd3);

        res = ftruncate(file_fd, 16);
        log_op("ftruncate", "file_fd to 16 bytes", res);

        res = fallocate(file_fd, 0, 0, 1024);
        log_op("fallocate", "file_fd allocate 1024 bytes", res);
    }
    res = truncate("open_file.txt", 32);
    log_op("truncate", "open_file.txt to 32 bytes", res);

    /* -------------------------------------------------------------
     * 8. EXTENDED ATTRIBUTES: *setxattr, *getxattr, *listxattr, *removexattr
     * ------------------------------------------------------------- */
    printf("\n--- Extended Attributes (*xattr) ---\n");
    res = setxattr("open_file.txt", "user.audisp_test", "val1", 4, 0);
    log_op("setxattr", "open_file.txt 'user.audisp_test'", res);

    res = getxattr("open_file.txt", "user.audisp_test", xattr_buf, sizeof(xattr_buf));
    log_op("getxattr", "open_file.txt 'user.audisp_test'", res);

    res = listxattr("open_file.txt", xattr_buf, sizeof(xattr_buf));
    log_op("listxattr", "open_file.txt", res);

    res = removexattr("open_file.txt", "user.audisp_test");
    log_op("removexattr", "open_file.txt 'user.audisp_test'", res);

    if (file_fd >= 0) {
        res = fsetxattr(file_fd, "user.audisp_fd", "val2", 4, 0);
        log_op("fsetxattr", "file_fd 'user.audisp_fd'", res);

        res = fgetxattr(file_fd, "user.audisp_fd", xattr_buf, sizeof(xattr_buf));
        log_op("fgetxattr", "file_fd 'user.audisp_fd'", res);

        res = flistxattr(file_fd, xattr_buf, sizeof(xattr_buf));
        log_op("flistxattr", "file_fd", res);

        res = fremovexattr(file_fd, "user.audisp_fd");
        log_op("fremovexattr", "file_fd 'user.audisp_fd'", res);
    }

    res = lsetxattr("symlink_open.txt", "user.audisp_sym", "val3", 4, 0);
    log_op("lsetxattr", "symlink_open.txt 'user.audisp_sym'", res);

    res = lgetxattr("symlink_open.txt", "user.audisp_sym", xattr_buf, sizeof(xattr_buf));
    log_op("lgetxattr", "symlink_open.txt 'user.audisp_sym'", res);

    res = llistxattr("symlink_open.txt", xattr_buf, sizeof(xattr_buf));
    log_op("llistxattr", "symlink_open.txt", res);

    res = lremovexattr("symlink_open.txt", "user.audisp_sym");
    log_op("lremovexattr", "symlink_open.txt 'user.audisp_sym'", res);

    /* -------------------------------------------------------------
     * 9. SPECIAL NODES, PIPES, TIMESTAMPS: mknod, mknodat, pipe, pipe2, utime, utimes, futimesat, utimensat
     * ------------------------------------------------------------- */
    printf("\n--- Special Nodes, Pipes & Timestamps ---\n");

    res = mknod("fifo_test.pipe", S_IFIFO | 0644, 0);
    log_op("mknod", "fifo_test.pipe S_IFIFO", res);

    res = mknodat(dir_fd, "fifo_in_dirfd.pipe", S_IFIFO | 0644, 0);
    log_op("mknodat", "dir_fd + 'fifo_in_dirfd.pipe'", res);

    {
        int p_fds[2];
        res = pipe(p_fds);
        log_op("pipe", "create pipe pair", res);
        if (res >= 0) { close(p_fds[0]); close(p_fds[1]); }

        res = pipe2(p_fds, O_CLOEXEC);
        log_op("pipe2", "create pipe2 pair with O_CLOEXEC", res);
        if (res >= 0) { close(p_fds[0]); close(p_fds[1]); }
    }

    res = utime("open_file.txt", NULL);
    log_op("utime", "open_file.txt", res);

    res = utimes("open_file.txt", NULL);
    log_op("utimes", "open_file.txt", res);

    res = futimesat(dir_fd, "openat_dirfd_rel.txt", NULL);
    log_op("futimesat", "dir_fd + 'openat_dirfd_rel.txt'", res);

    res = utimensat(dir_fd, "openat_dirfd_rel.txt", NULL, 0);
    log_op("utimensat", "dir_fd + 'openat_dirfd_rel.txt'", res);

    time_t t = time(NULL);
    log_op("time", "time(NULL)", (t != (time_t)-1) ? 0 : -1);

    struct timeval tv;
    res = gettimeofday(&tv, NULL);
    log_op("gettimeofday", "gettimeofday(&tv, NULL)", res);

    struct timex tmx;
    memset(&tmx, 0, sizeof(tmx));
    res = adjtimex(&tmx);
    log_op("adjtimex", "adjtimex query state", res);

    struct timespec ts;
    res = clock_gettime(CLOCK_REALTIME, &ts);
    log_op("clock_gettime", "CLOCK_REALTIME", res);

    res = clock_gettime(CLOCK_MONOTONIC, &ts);
    log_op("clock_gettime", "CLOCK_MONOTONIC", res);

    res = clock_getres(CLOCK_MONOTONIC, &ts);
    log_op("clock_getres", "CLOCK_MONOTONIC", res);

    /* -------------------------------------------------------------
     * 10. RENAMING: rename, renameat, renameat2
     * ------------------------------------------------------------- */
    printf("\n--- Rename Operations (rename, renameat, renameat2) ---\n");

    res = rename("creat_file.txt", "creat_renamed.txt");
    log_op("rename", "creat_file.txt -> creat_renamed.txt", res);

    res = renameat(dir_fd, "openat_dirfd_rel.txt", dir_fd, "openat_renamed.txt");
    log_op("renameat", "dir_fd openat_dirfd_rel.txt -> dir_fd openat_renamed.txt", res);

    res = renameat2(dir_fd, "hardlink_dirfd.txt", dir_fd, "hardlink_renamed.txt", RENAME_NOREPLACE);
    log_op("renameat2", "dir_fd with RENAME_NOREPLACE", res);

    /* -------------------------------------------------------------
     * 11. CREDENTIALS & PROCESS CONTROL: getuid, getgid, geteuid, getegid,
     *                                   getresuid, getresgid, setreuid, setregid,
     *                                   setresuid, setresgid, setfsuid, setfsgid,
     *                                   getgroups, prctl, capget
     * ------------------------------------------------------------- */
    printf("\n--- Credential Operations ---\n");

    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    res = (int)getuid();
    log_op("getuid", "getuid()", res);

    res = (int)getgid();
    log_op("getgid", "getgid()", res);

    res = (int)geteuid();
    log_op("geteuid", "geteuid()", res);

    res = (int)getegid();
    log_op("getegid", "getegid()", res);

    res = getresuid(&ruid, &euid, &suid);
    log_op("getresuid", "getresuid(&ruid, &euid, &suid)", res);

    res = getresgid(&rgid, &egid, &sgid);
    log_op("getresgid", "getresgid(&rgid, &egid, &sgid)", res);

    res = setreuid(uid, uid);
    log_op("setreuid", "setreuid(uid, uid)", res);

    res = setregid(gid, gid);
    log_op("setregid", "setregid(gid, gid)", res);

    res = setresuid(uid, uid, uid);
    log_op("setresuid", "setresuid(uid, uid, uid)", res);

    res = setresgid(gid, gid, gid);
    log_op("setresgid", "setresgid(gid, gid, gid)", res);

    res = setfsuid(uid);
    log_op("setfsuid", "setfsuid(uid)", res);

    res = setfsgid(gid);
    log_op("setfsgid", "setfsgid(gid)", res);

    gid_t groups[16];
    res = getgroups(16, groups);
    log_op("getgroups", "getgroups(16, groups)", res);

    res = setgid(gid);
    log_op("setgid", "setgid(current_gid)", res);

    res = setuid(uid);
    log_op("setuid", "setuid(current_uid)", res);

    res = setgid(0);
    log_op("setgid", "setgid(0)", res);

    res = setuid(0);
    log_op("setuid", "setuid(0)", res);

    char comm_buf[16] = {0};
    res = prctl(PR_GET_NAME, comm_buf);
    log_op("prctl", "PR_GET_NAME", res);

    res = prctl(PR_SET_NAME, "test_syscalls");
    log_op("prctl", "PR_SET_NAME 'test_syscalls'", res);

    res = prctl(PR_GET_DUMPABLE);
    log_op("prctl", "PR_GET_DUMPABLE", res);

    /* -------------------------------------------------------------
     * 12. PROCESS LIFECYCLE & SIGNALS: clone, kill, tkill, tgkill, wait4, waitid
     * ------------------------------------------------------------- */
    printf("\n--- Process Lifecycle & Signals (clone, kill, tkill, tgkill, wait4, waitid) ---\n");
    {
        /* Signal checks with signal 0 (null signal tests process/thread existence) */
        res = kill(getpid(), 0);
        log_op("kill", "kill(getpid(), 0)", res);

        pid_t tid = (pid_t)syscall(SYS_gettid);
        res = (int)syscall(SYS_tkill, tid, 0);
        log_op("tkill", "tkill(gettid(), 0)", res);

        res = (int)syscall(SYS_tgkill, getpid(), tid, 0);
        log_op("tgkill", "tgkill(getpid(), gettid(), 0)", res);

        /* Test wait4 */
        pid_t child_w4 = fork();
        if (child_w4 == 0) {
            _exit(0);
        } else if (child_w4 > 0) {
            int wstatus = 0;
            res = (int)wait4(child_w4, &wstatus, 0, NULL);
            log_op("wait4", "wait4 on child", res);
        }

        /* Test waitid */
        pid_t child_wid = fork();
        if (child_wid == 0) {
            _exit(0);
        } else if (child_wid > 0) {
            siginfo_t si;
            memset(&si, 0, sizeof(si));
            res = waitid(P_PID, (id_t)child_wid, &si, WEXITED);
            log_op("waitid", "waitid P_PID WEXITED", res);
        }

        char *stack = malloc(CLONE_STACK_SIZE);
        if (stack) {
            pid_t clone_pid = clone(clone_child_func, stack + CLONE_STACK_SIZE, SIGCHLD, NULL);
            log_op("clone", "direct clone() invocation", clone_pid);
            if (clone_pid > 0) {
                waitpid(clone_pid, NULL, 0);
            }
            free(stack);
        }
    }

    /* -------------------------------------------------------------
     * 13. MEMORY MANAGEMENT: mmap, mprotect, madvise, munmap, brk,
     *                          mremap, msync, mincore, mlock, munlock,
     *                          mlockall, munlockall, shmat, shmdt
     * ------------------------------------------------------------- */
    printf("\n--- Memory Operations (mmap, mprotect, madvise, munmap, brk, mremap, msync, mincore, mlock, shm) ---\n");
    {
        void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        log_op("mmap", "anonymous mmap 4096 bytes", (m != MAP_FAILED) ? 0 : -1);

        if (m != MAP_FAILED) {
            res = mprotect(m, 4096, PROT_READ);
            log_op("mprotect", "change protection to PROT_READ", res);

            res = madvise(m, 4096, MADV_DONTNEED);
            log_op("madvise", "MADV_DONTNEED on mapped region", res);

            res = munmap(m, 4096);
            log_op("munmap", "unmap 4096 bytes", res);
        }

        /* mremap */
        void *mr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mr != MAP_FAILED) {
            void *mr2 = mremap(mr, 4096, 8192, MREMAP_MAYMOVE);
            log_op("mremap", "mremap 4096 -> 8192 bytes", (mr2 != MAP_FAILED) ? 0 : -1);
            if (mr2 != MAP_FAILED) {
                munmap(mr2, 8192);
            } else {
                munmap(mr, 4096);
            }
        }

        /* msync, mincore, mlock, munlock */
        void *ms = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ms != MAP_FAILED) {
            memset(ms, 0x42, 4096);
            res = msync(ms, 4096, MS_SYNC);
            log_op("msync", "msync MS_SYNC on anonymous page", res);

            unsigned char vec[2];
            res = mincore(ms, 4096, vec);
            log_op("mincore", "mincore on mapped page", res);

            res = mlock(ms, 4096);
            log_op("mlock", "mlock 4096 bytes", res);

            res = munlock(ms, 4096);
            log_op("munlock", "munlock 4096 bytes", res);

            munmap(ms, 4096);
        }

        /* mlockall / munlockall */
        res = mlockall(MCL_CURRENT);
        log_op("mlockall", "mlockall MCL_CURRENT", res);
        res = munlockall();
        log_op("munlockall", "munlockall", res);

        /* System V Shared Memory: shmget, shmat, shmdt, shmctl */
        int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
        log_op("shmget", "IPC_PRIVATE shmget 4096", shmid);
        if (shmid >= 0) {
            void *shm_addr = shmat(shmid, NULL, 0);
            log_op("shmat", "shmat attach shared memory", (shm_addr != (void *)-1) ? 0 : -1);
            if (shm_addr != (void *)-1) {
                res = shmdt(shm_addr);
                log_op("shmdt", "shmdt detach shared memory", res);
            }
            struct shmid_ds sds;
            res = shmctl(shmid, IPC_STAT, &sds);
            log_op("shmctl", "shmctl IPC_STAT", res);
            res = shmctl(shmid, IPC_RMID, NULL);
            log_op("shmctl", "shmctl IPC_RMID", res);
        }

        /* System V Semaphores: semget, semop, semtimedop, semctl */
        int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        log_op("semget", "IPC_PRIVATE semget 1 sem", semid);
        if (semid >= 0) {
            struct sembuf sb = {0, 0, IPC_NOWAIT};
            res = semop(semid, &sb, 1);
            log_op("semop", "semop zero test", res);

            struct timespec sem_to = {0, 1000};
            res = semtimedop(semid, &sb, 1, &sem_to);
            log_op("semtimedop", "semtimedop zero test", res);

            res = semctl(semid, 0, GETVAL);
            log_op("semctl", "semctl GETVAL", res);

            res = semctl(semid, 0, IPC_RMID);
            log_op("semctl", "semctl IPC_RMID", res);
        }

        /* System V Message Queues: msgget, msgsnd, msgrcv, msgctl */
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        log_op("msgget", "IPC_PRIVATE msgget", msqid);
        if (msqid >= 0) {
            struct {
                long mtype;
                char mtext[8];
            } msg_buf = {1, "test"};
            res = msgsnd(msqid, &msg_buf, sizeof(msg_buf.mtext), IPC_NOWAIT);
            log_op("msgsnd", "msgsnd test message", res);

            res = (int)msgrcv(msqid, &msg_buf, sizeof(msg_buf.mtext), 0, IPC_NOWAIT);
            log_op("msgrcv", "msgrcv test message", res);

            struct msqid_ds mds;
            res = msgctl(msqid, IPC_STAT, &mds);
            log_op("msgctl", "msgctl IPC_STAT", res);

            res = msgctl(msqid, IPC_RMID, NULL);
            log_op("msgctl", "msgctl IPC_RMID", res);
        }

        void *cur_brk = sbrk(0);
        res = brk(cur_brk);
        log_op("brk", "query/set current break", res);
    }

    /* -------------------------------------------------------------
     * 14. READ, WRITE & I/O: write, read, pwrite, pread, writev, readv, sendfile
     * ------------------------------------------------------------- */
    printf("\n--- Read & Write Operations ---\n");
    if (file_fd >= 0) {
        char io_buf[64];
        const char *msg = "audisp test data\n";
        ssize_t rw_res;

        rw_res = write(file_fd, msg, strlen(msg));
        log_op("write", "write to file_fd", (int)rw_res);

        lseek(file_fd, 0, SEEK_SET);
        rw_res = read(file_fd, io_buf, sizeof(io_buf) - 1);
        log_op("read", "read from file_fd", (int)rw_res);

        rw_res = pwrite(file_fd, "pwrite data\n", 12, 0);
        log_op("pwrite64", "pwrite to offset 0", (int)rw_res);

        rw_res = pread(file_fd, io_buf, 12, 0);
        log_op("pread64", "pread from offset 0", (int)rw_res);

        struct iovec iov[2];
        char h1[] = "hello ";
        char h2[] = "iovec\n";
        iov[0].iov_base = h1;
        iov[0].iov_len = strlen(h1);
        iov[1].iov_base = h2;
        iov[1].iov_len = strlen(h2);

        rw_res = writev(file_fd, iov, 2);
        log_op("writev", "writev 2 buffers", (int)rw_res);

        lseek(file_fd, 0, SEEK_SET);
        char in1[8], in2[8];
        iov[0].iov_base = in1;
        iov[0].iov_len = 6;
        iov[1].iov_base = in2;
        iov[1].iov_len = 6;
        rw_res = readv(file_fd, iov, 2);
        log_op("readv", "readv 2 buffers", (int)rw_res);

        /* sendfile: copy 0 bytes from file_fd to file_fd (safe test) */
        off_t s_off = 0;
        rw_res = sendfile(file_fd, file_fd, &s_off, 0);
        log_op("sendfile", "sendfile file_fd -> file_fd", (int)rw_res);
    }

    /* -------------------------------------------------------------
     * 15. DESCRIPTOR CONTROL: fcntl, ioctl
     * ------------------------------------------------------------- */
    printf("\n--- Descriptor Control (fcntl, ioctl) ---\n");
    if (file_fd >= 0) {
        res = fcntl(file_fd, F_GETFL);
        log_op("fcntl", "F_GETFL", res);

        res = fcntl(file_fd, F_SETFL, O_RDWR);
        log_op("fcntl", "F_SETFL O_RDWR", res);

        res = fcntl(file_fd, F_GETFD);
        log_op("fcntl", "F_GETFD", res);

        res = fcntl(file_fd, F_SETFD, FD_CLOEXEC);
        log_op("fcntl", "F_SETFD FD_CLOEXEC", res);

        int dup_fd1 = fcntl(file_fd, F_DUPFD, 60);
        log_op("fcntl", "F_DUPFD min 60", dup_fd1);
        if (dup_fd1 >= 0) close(dup_fd1);

        int dup_fd2 = fcntl(file_fd, F_DUPFD_CLOEXEC, 61);
        log_op("fcntl", "F_DUPFD_CLOEXEC min 61", dup_fd2);
        if (dup_fd2 >= 0) close(dup_fd2);

        struct termios t;
        res = ioctl(0, TCGETS, &t);
        log_op("ioctl", "TCGETS on stdin", res);

        int bytes_avail = 0;
        res = ioctl(file_fd, FIONREAD, &bytes_avail);
        log_op("ioctl", "FIONREAD on file_fd", res);
    }

    /* -------------------------------------------------------------
     * 16. SOCKETS & NETWORKING: socket, socketpair, bind, listen,
     *                          getsockname, getpeername, shutdown, sendto
     * ------------------------------------------------------------- */
    printf("\n--- Sockets & Networking ---\n");
    {
        int sp[2];
        res = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp);
        log_op("socketpair", "AF_UNIX SOCK_STREAM pair", res);
        if (res >= 0) {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            res = getsockname(sp[0], (struct sockaddr *)&ss, &slen);
            log_op("getsockname", "socketpair[0]", res);

            slen = sizeof(ss);
            res = getpeername(sp[0], (struct sockaddr *)&ss, &slen);
            log_op("getpeername", "socketpair[0]", res);

            res = shutdown(sp[0], SHUT_RDWR);
            log_op("shutdown", "shutdown socketpair[0]", res);

            close(sp[0]);
            close(sp[1]);
        }

        int s_unix = socket(AF_UNIX, SOCK_STREAM, 0);
        log_op("socket", "AF_UNIX SOCK_STREAM", s_unix);
        if (s_unix >= 0) {
            struct sockaddr_un sun_addr;
            memset(&sun_addr, 0, sizeof(sun_addr));
            sun_addr.sun_family = AF_UNIX;
            snprintf(sun_addr.sun_path, sizeof(sun_addr.sun_path), "%s/test_sock.s", base_dir);
            res = bind(s_unix, (struct sockaddr *)&sun_addr, sizeof(sun_addr));
            log_op("bind", "bind unix socket path", res);

            res = listen(s_unix, 5);
            log_op("listen", "listen backlog 5", res);

            close(s_unix);
            unlink(sun_addr.sun_path);
        }

        int s_udp = socket(AF_INET, SOCK_DGRAM, 0);
        log_op("socket", "AF_INET SOCK_DGRAM", s_udp);
        if (s_udp >= 0) {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = htons(9999);
            inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);

            int optval = 1;
            res = setsockopt(s_udp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
            log_op("setsockopt", "SOL_SOCKET SO_REUSEADDR", res);

            socklen_t optlen = sizeof(optval);
            res = getsockopt(s_udp, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);
            log_op("getsockopt", "SOL_SOCKET SO_REUSEADDR", res);

            res = (int)sendto(s_udp, "ping", 4, 0, (struct sockaddr *)&sin, sizeof(sin));
            log_op("sendto", "sendto 127.0.0.1:9999 UDP", res);

            /* sendmmsg */
            struct iovec iov_mmsg;
            char msg_buf[] = "mmsg ping";
            iov_mmsg.iov_base = msg_buf;
            iov_mmsg.iov_len = sizeof(msg_buf);
            struct mmsghdr msgvec[1];
            memset(msgvec, 0, sizeof(msgvec));
            msgvec[0].msg_hdr.msg_name = &sin;
            msgvec[0].msg_hdr.msg_namelen = sizeof(sin);
            msgvec[0].msg_hdr.msg_iov = &iov_mmsg;
            msgvec[0].msg_hdr.msg_iovlen = 1;
            res = sendmmsg(s_udp, msgvec, 1, 0);
            log_op("sendmmsg", "sendmmsg 1 message to 127.0.0.1:9999", res);

            close(s_udp);
        }
    }

    /* -------------------------------------------------------------
     * 17. DELETION & CLEANUP: unlink, unlinkat, rmdir, close
     * ------------------------------------------------------------- */
    printf("\n--- Deletion & Cleanup (unlink, unlinkat, rmdir, close) ---\n");

    unlink("fifo_test.pipe");
    unlinkat(dir_fd, "fifo_in_dirfd.pipe", 0);

    unlink("hardlink_open.txt");
    unlink("creat_renamed.txt");
    unlink("open_file.txt");
    unlink("symlink_open.txt");
    unlink("openat_fdcwd_rel.txt");
    unlink(abs_file);

    snprintf(path_buf1, sizeof(path_buf1), "%s/openat_dirfd_abs.txt", base_dir);
    unlink(path_buf1);

    unlinkat(dir_fd, "openat_renamed.txt", 0);
    unlinkat(dir_fd, "hardlink_renamed.txt", 0);
    unlinkat(dir_fd, "symlink_in_dirfd.txt", 0);

#ifdef SYS_openat2
    unlinkat(dir_fd, "openat2_file.txt", 0);
#endif

    if (file_fd >= 0) {
        close(file_fd);
    }
    if (dir_fd >= 0) {
        close(dir_fd);
    }

    rmdir("subdir_rel/nested_in_dirfd");
    unlinkat(AT_FDCWD, "sub_at_fdcwd_rel", AT_REMOVEDIR);
    rmdir("subdir_rel");
    rmdir(abs_sub);
    snprintf(path_buf1, sizeof(path_buf1), "%s/sub_dirfd_abs", base_dir);
    rmdir(path_buf1);

    printf("=== Worker completed all operations ===\n");
}

int main(int argc, char **argv, char **envp) {
    /* If invoked as worker, run operations directly */
    if (argc >= 3 && strcmp(argv[1], "--worker") == 0) {
        run_worker_tests(argv[2]);
        return 0;
    }

    printf("====================================================\n");
    printf(" audisp-strace Syscall Exercise & Verification Tool\n");
    printf("====================================================\n");
    printf("Parent Process PID: %d\n", getpid());

    /* Create temporary sandbox directory */
    char template_path[] = "/tmp/audisp_test_XXXXXX";
    char *sandbox = mkdtemp(template_path);
    if (!sandbox) {
        perror("mkdtemp");
        return 1;
    }
    printf("Created test sandbox: %s\n", sandbox);

    /* Fork + execve to create process tree */
    printf("\nCreating process tree via fork() + execve()...\n");
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        rmdir(sandbox);
        return 1;
    }

    if (child_pid == 0) {
        char *child_argv[] = { argv[0], "--worker", sandbox, NULL };
        execve(argv[0], child_argv, envp);
        perror("execve");
        _exit(1);
    }

    int status = 0;
    waitpid(child_pid, &status, 0);

    rmdir(sandbox);
    printf("\nTest sandbox cleaned up. Parent exiting.\n");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
