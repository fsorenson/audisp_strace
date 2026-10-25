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
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/quota.h>
#include <sys/file.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

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

#ifndef SYS_ustat
#  if defined(__x86_64__)
#    define SYS_ustat 136
#  endif
#endif

#ifndef SYS_signalfd4
#  if defined(__x86_64__)
#    define SYS_signalfd4 289
#  endif
#endif

#ifndef SYS_mseal
#  if defined(__x86_64__)
#    define SYS_mseal 462
#  endif
#endif

#ifndef SYS_memfd_create
#  if defined(__x86_64__)
#    define SYS_memfd_create 319
#  endif
#endif

#ifndef SYS_copy_file_range
#  if defined(__x86_64__)
#    define SYS_copy_file_range 326
#  endif
#endif

#ifndef SYS_pidfd_open
#  if defined(__x86_64__)
#    define SYS_pidfd_open 434
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

#ifdef SYS_ustat
        res = (int)syscall(SYS_ustat, (unsigned int)st.st_dev, NULL);
        log_op("ustat", "ustat(st_dev, NULL)", res);
#endif

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

    pid_t my_pid = getpid();
    log_op("getpid", "getpid()", my_pid);

    pid_t my_ppid = getppid();
    log_op("getppid", "getppid()", my_ppid);

    pid_t my_pgrp = getpgrp();
    log_op("getpgrp", "getpgrp()", my_pgrp);

    pid_t my_tid = (pid_t)syscall(SYS_gettid);
    log_op("gettid", "gettid()", my_tid);

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

        /* Signal mask and pending tests */
        sigset_t set, oldset;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        res = sigprocmask(SIG_BLOCK, &set, &oldset);
        log_op("rt_sigprocmask", "sigprocmask(SIG_BLOCK, [USR1], ...)", res);

        sigset_t pending;
        res = sigpending(&pending);
        log_op("rt_sigpending", "sigpending(...)", res);

        res = sigprocmask(SIG_SETMASK, &oldset, NULL);
        log_op("rt_sigprocmask", "sigprocmask(SIG_SETMASK, oldset, NULL)", res);

        /* Alternate signal stack */
        stack_t ss, old_ss;
        char sig_alt_stack[SIGSTKSZ];
        ss.ss_sp = sig_alt_stack;
        ss.ss_flags = 0;
        ss.ss_size = sizeof(sig_alt_stack);
        res = sigaltstack(&ss, &old_ss);
        log_op("sigaltstack", "sigaltstack(new, old)", res);
        res = sigaltstack(&old_ss, NULL);
        log_op("sigaltstack", "sigaltstack(restore, NULL)", res);

#ifdef SYS_signalfd4
        sigset_t sfd_mask;
        sigemptyset(&sfd_mask);
        sigaddset(&sfd_mask, SIGUSR1);
        int sfd = (int)syscall(SYS_signalfd4, -1, &sfd_mask, 8, 0x80000 /* SFD_CLOEXEC */);
        log_op("signalfd4", "signalfd4(-1, [USR1], SFD_CLOEXEC)", sfd);
        if (sfd >= 0) close(sfd);
#endif

        /* pause with sub-process */
        pid_t pause_child = fork();
        if (pause_child == 0) {
            alarm(1);
            pause();
            _exit(0);
        } else if (pause_child > 0) {
            waitpid(pause_child, NULL, 0);
        }

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

#ifdef SYS_mseal
        void *mseal_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mseal_mem != MAP_FAILED) {
            res = (int)syscall(SYS_mseal, mseal_mem, 4096, 0);
            log_op("mseal", "mseal 4096 bytes", res);
            munmap(mseal_mem, 4096);
        }
#endif

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
     * 16.5. ADDITIONAL FILE OPERATIONS: chdir, getcwd, inotify_add_watch,
     *       name_to_handle_at, chroot, mount, umount2, pivot_root, swapon,
     *       swapoff, acct, quotactl, open_tree, move_mount, fspick,
     *       fsconfig, mount_setattr
     * ------------------------------------------------------------- */
    printf("\n--- Additional File Operations (chdir, getcwd, inotify, mount, etc.) ---\n");

    /* getcwd */
    char cwd_buf[1024];
    if (getcwd(cwd_buf, sizeof(cwd_buf)) != NULL) {
        log_op("getcwd", cwd_buf, 0);
    } else {
        log_op("getcwd", "getcwd failed", -1);
    }

    /* chdir */
    res = chdir(".");
    log_op("chdir", "chdir to '.'", res);

    /* inotify_add_watch */
    int inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd >= 0) {
        int wd = inotify_add_watch(inotify_fd, "open_file.txt", IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE);
        log_op("inotify_add_watch", "watch open_file.txt", wd);
        close(inotify_fd);
    }

    /* name_to_handle_at */
    struct {
        struct file_handle fh;
        unsigned char f_handle[128];
    } handle_buf;
    handle_buf.fh.handle_bytes = 128;
    int mount_id = 0;
    res = syscall(SYS_name_to_handle_at, AT_FDCWD, "open_file.txt", &handle_buf.fh, &mount_id, 0);
    log_op("name_to_handle_at", "open_file.txt file handle", res);

    /* Privileged / administrative calls tested with dummy/nonexistent paths */
    res = chroot("/invalid_nonexistent_chroot");
    log_op("chroot", "dummy path /invalid_nonexistent_chroot", res);

    res = mount("none", "/invalid_mount_target", "tmpfs", 0, NULL);
    log_op("mount", "dummy mount", res);

    res = umount2("/invalid_mount_target", 0);
    log_op("umount2", "dummy umount", res);

#ifdef SYS_pivot_root
    res = syscall(SYS_pivot_root, "/invalid_pivot", "/invalid_pivot");
    log_op("pivot_root", "dummy pivot_root", res);
#endif

    res = swapon("/invalid_swap_file", 0);
    log_op("swapon", "dummy swap file", res);

    res = swapoff("/invalid_swap_file");
    log_op("swapoff", "dummy swap file", res);

    res = acct("/invalid_acct_file");
    log_op("acct", "dummy acct file", res);

    res = quotactl(QCMD(Q_GETINFO, USRQUOTA), "/dev/null", 0, NULL);
    log_op("quotactl", "dummy quotactl", res);

#ifdef SYS_open_tree
    res = syscall(SYS_open_tree, AT_FDCWD, "open_file.txt", 0);
    log_op("open_tree", "dummy open_tree", res);
#endif

#ifdef SYS_move_mount
    res = syscall(SYS_move_mount, AT_FDCWD, "open_file.txt", AT_FDCWD, "open_file.txt", 0);
    log_op("move_mount", "dummy move_mount", res);
#endif

#ifdef SYS_fspick
    res = syscall(SYS_fspick, AT_FDCWD, "open_file.txt", 0);
    log_op("fspick", "dummy fspick", res);
#endif

#ifdef SYS_fsconfig
    res = syscall(SYS_fsconfig, -1, 0, NULL, NULL, 0);
    log_op("fsconfig", "dummy fsconfig", res);
#endif

#ifdef SYS_mount_setattr
    res = syscall(SYS_mount_setattr, AT_FDCWD, "open_file.txt", 0, NULL, 0);
    log_op("mount_setattr", "dummy mount_setattr", res);
#endif

    /* -------------------------------------------------------------
     * 16.6. DESCRIPTOR OPERATIONS (%desc): lseek, flock, fsync,
     *       fdatasync, syncfs, fchdir, pipe2, dup3, eventfd2,
     *       timerfd_create, timerfd_settime, timerfd_gettime,
     *       epoll_create1, epoll_ctl, epoll_wait, inotify_init1,
     *       inotify_rm_watch, memfd_create, poll, select,
     *       copy_file_range, posix_fadvise
     * ------------------------------------------------------------- */
    printf("\n--- Additional Descriptor Operations (lseek, flock, fsync, epoll, timerfd, eventfd, memfd, etc.) ---\n");
    if (file_fd >= 0) {
        off_t sk = lseek(file_fd, 0, SEEK_CUR);
        log_op("lseek", "lseek SEEK_CUR", (int)sk);

        res = flock(file_fd, LOCK_SH);
        log_op("flock", "flock LOCK_SH", res);
        res = flock(file_fd, LOCK_UN);
        log_op("flock", "flock LOCK_UN", res);

        res = fsync(file_fd);
        log_op("fsync", "fsync file_fd", res);

        res = fdatasync(file_fd);
        log_op("fdatasync", "fdatasync file_fd", res);

        res = syncfs(file_fd);
        log_op("syncfs", "syncfs file_fd", res);

        res = posix_fadvise(file_fd, 0, 1024, POSIX_FADV_WILLNEED);
        log_op("fadvise64", "posix_fadvise POSIX_FADV_WILLNEED", res);

        res = (int)readahead(file_fd, 0, 1024);
        log_op("readahead", "readahead 1024 bytes", res);

        struct pollfd pfd = { file_fd, POLLIN, 0 };
        res = poll(&pfd, 1, 0);
        log_op("poll", "poll file_fd timeout 0", res);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(file_fd, &rfds);
        struct timeval tv = {0, 0};
        res = select(file_fd + 1, &rfds, NULL, NULL, &tv);
        log_op("select", "select file_fd timeout 0", res);

#ifdef SYS_copy_file_range
        loff_t off_in = 0, off_out = 0;
        res = (int)syscall(SYS_copy_file_range, file_fd, &off_in, file_fd, &off_out, 0, 0);
        log_op("copy_file_range", "copy_file_range 0 bytes", res);
#endif

        int d3 = dup3(file_fd, 75, O_CLOEXEC);
        log_op("dup3", "dup3 file_fd -> 75 O_CLOEXEC", d3);
        if (d3 >= 0) close(d3);
    }

    if (dir_fd >= 0) {
        res = fchdir(dir_fd);
        log_op("fchdir", "fchdir dir_fd", res);
        /* Restore cwd to base_dir */
        res = chdir(base_dir);
        log_op("chdir", "restore chdir base_dir", res);
    }

    int p2[2];
    res = pipe2(p2, O_CLOEXEC);
    log_op("pipe2", "pipe2 O_CLOEXEC", res);
    if (res >= 0) {
        close(p2[0]);
        close(p2[1]);
    }

    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    log_op("eventfd2", "eventfd2 EFD_CLOEXEC|EFD_NONBLOCK", efd);
    if (efd >= 0) close(efd);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    log_op("timerfd_create", "timerfd_create CLOCK_MONOTONIC TFD_CLOEXEC", tfd);
    if (tfd >= 0) {
        struct itimerspec its = { {0, 0}, {0, 1000000} };
        res = timerfd_settime(tfd, 0, &its, NULL);
        log_op("timerfd_settime", "timerfd_settime 1ms", res);
        res = timerfd_gettime(tfd, &its);
        log_op("timerfd_gettime", "timerfd_gettime", res);
        close(tfd);
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    log_op("epoll_create1", "epoll_create1 EPOLL_CLOEXEC", epfd);
    if (epfd >= 0) {
        int ep_pipe[2];
        if (pipe(ep_pipe) == 0) {
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.fd = ep_pipe[0];
            res = epoll_ctl(epfd, EPOLL_CTL_ADD, ep_pipe[0], &ev);
            log_op("epoll_ctl", "epoll_ctl EPOLL_CTL_ADD ep_pipe[0]", res);
            res = epoll_wait(epfd, &ev, 1, 0);
            log_op("epoll_wait", "epoll_wait timeout 0", res);
            close(ep_pipe[0]);
            close(ep_pipe[1]);
        }
        close(epfd);
    }

    int infd = inotify_init1(IN_CLOEXEC);
    log_op("inotify_init1", "inotify_init1 IN_CLOEXEC", infd);
    if (infd >= 0) {
        int wd = inotify_add_watch(infd, "open_file.txt", IN_MODIFY);
        if (wd >= 0) {
            res = inotify_rm_watch(infd, wd);
            log_op("inotify_rm_watch", "inotify_rm_watch open_file.txt", res);
        }
        close(infd);
    }

#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, "test_memfd", 1 /* MFD_CLOEXEC */);
    log_op("memfd_create", "memfd_create test_memfd MFD_CLOEXEC", mfd);
    if (mfd >= 0) close(mfd);
#endif

#ifdef SYS_pidfd_open
    int pfd_fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    log_op("pidfd_open", "pidfd_open self", pfd_fd);
    if (pfd_fd >= 0) close(pfd_fd);
#endif

    /* -------------------------------------------------------------
     * 16.7. PROCESS CONTROL, SCHEDULING & RESOURCE LIMITS:
     *       sched_yield, sched_getparam, sched_setparam,
     *       sched_getscheduler, sched_setscheduler,
     *       sched_get_priority_max, sched_get_priority_min,
     *       sched_rr_get_interval, sched_getaffinity, sched_setaffinity,
     *       getcpu, getpgid, setpgid, getsid, getpriority,
     *       setpriority, umask, personality, getrlimit, setrlimit,
     *       prlimit64, getrusage, set_tid_address, unshare, vhangup
     * ------------------------------------------------------------- */
    printf("\n--- Process Control, Scheduling & Resource Limits ---\n");
    res = sched_yield();
    log_op("sched_yield", "yield execution", res);

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    res = sched_getparam(0, &sp);
    log_op("sched_getparam", "get current sched param", res);

    res = sched_setparam(0, &sp);
    log_op("sched_setparam", "set current sched param", res);

    int sched_pol = sched_getscheduler(0);
    log_op("sched_getscheduler", "get current policy", sched_pol);

    if (sched_pol >= 0) {
        res = sched_setscheduler(0, sched_pol, &sp);
        log_op("sched_setscheduler", "restore current policy", res);
    }

    res = sched_get_priority_max(SCHED_OTHER);
    log_op("sched_get_priority_max", "SCHED_OTHER max priority", res);

    res = sched_get_priority_min(SCHED_OTHER);
    log_op("sched_get_priority_min", "SCHED_OTHER min priority", res);

    struct timespec rr_tp;
    res = sched_rr_get_interval(0, &rr_tp);
    log_op("sched_rr_get_interval", "get round-robin timeslice", res);

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    res = sched_getaffinity(0, sizeof(cpuset), &cpuset);
    log_op("sched_getaffinity", "get affinity mask", res);
    if (res >= 0) {
        res = sched_setaffinity(0, sizeof(cpuset), &cpuset);
        log_op("sched_setaffinity", "restore affinity mask", res);
    }

    unsigned cpu_id = 0, node_id = 0;
    res = (int)syscall(SYS_getcpu, &cpu_id, &node_id, NULL);
    log_op("getcpu", "getcpu &cpu, &node, NULL", res);

    pid_t cur_pgrp = getpgid(0);
    log_op("getpgid", "getpgid(0)", (int)cur_pgrp);

    res = setpgid(0, cur_pgrp);
    log_op("setpgid", "setpgid self to current pgrp", res);

    pid_t cur_sid = getsid(0);
    log_op("getsid", "getsid(0)", (int)cur_sid);

    res = getpriority(PRIO_PROCESS, 0);
    log_op("getpriority", "PRIO_PROCESS self", res);

    res = setpriority(PRIO_PROCESS, 0, res);
    log_op("setpriority", "restore PRIO_PROCESS priority", res);

    mode_t cur_umask = umask(022);
    log_op("umask", "umask(022)", (int)cur_umask);
    res = (int)umask(cur_umask);
    log_op("umask", "restore umask", res);

    res = personality(0xffffffff);
    log_op("personality", "query personality(0xffffffff)", res);

    struct rlimit rlim;
    res = getrlimit(RLIMIT_NOFILE, &rlim);
    log_op("getrlimit", "RLIMIT_NOFILE", res);

    if (res >= 0) {
        res = setrlimit(RLIMIT_NOFILE, &rlim);
        log_op("setrlimit", "restore RLIMIT_NOFILE", res);

        res = (int)syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &rlim);
        log_op("prlimit64", "query prlimit64 RLIMIT_NOFILE", res);
    }

    struct rusage ru;
    res = getrusage(RUSAGE_SELF, &ru);
    log_op("getrusage", "RUSAGE_SELF", res);

    int dummy_tid = 0;
    res = (int)syscall(SYS_set_tid_address, &dummy_tid);
    log_op("set_tid_address", "set_tid_address", res);

    res = (int)syscall(SYS_unshare, 0);
    log_op("unshare", "unshare(0)", res);

    if (geteuid() == 0) {
        printf("  [SKIP] %-14s: skipped when running as root to avoid terminal disconnect\n", "vhangup");
    } else {
        res = (int)syscall(SYS_vhangup);
        log_op("vhangup", "dummy vhangup", res);
    }

    /* -------------------------------------------------------------
     * 16.8. TIME, TIMERS & CLOCKS (non-%clock):
     *       nanosleep, clock_nanosleep, alarm, getitimer, setitimer,
     *       times, timer_create, timer_settime, timer_gettime,
     *       timer_getoverrun, timer_delete
     * ------------------------------------------------------------- */
    printf("\n--- Time, Timers & Clocks (non-%%clock) ---\n");
    struct timespec ns_req = {0, 1000};
    res = nanosleep(&ns_req, NULL);
    log_op("nanosleep", "nanosleep 1us", res);

    res = clock_nanosleep(CLOCK_REALTIME, 0, &ns_req, NULL);
    log_op("clock_nanosleep", "clock_nanosleep CLOCK_REALTIME 1us", res);

    unsigned int prev_alarm = alarm(0);
    log_op("alarm", "alarm(0) cancel/query", (int)prev_alarm);

    struct itimerval itv;
    res = getitimer(ITIMER_REAL, &itv);
    log_op("getitimer", "ITIMER_REAL", res);

    memset(&itv, 0, sizeof(itv));
    res = setitimer(ITIMER_REAL, &itv, NULL);
    log_op("setitimer", "ITIMER_REAL disable", res);

    struct tms tms_buf;
    clock_t tms_res = times(&tms_buf);
    log_op("times", "query process times", (tms_res != (clock_t)-1) ? 0 : -1);

    timer_t posix_tid;
    res = timer_create(CLOCK_REALTIME, NULL, &posix_tid);
    log_op("timer_create", "CLOCK_REALTIME POSIX timer", res);
    if (res == 0) {
        struct itimerspec its = { {0, 0}, {0, 1000000} };
        res = timer_settime(posix_tid, 0, &its, NULL);
        log_op("timer_settime", "timer_settime 1ms", res);

        res = timer_gettime(posix_tid, &its);
        log_op("timer_gettime", "timer_gettime", res);

        res = timer_getoverrun(posix_tid);
        log_op("timer_getoverrun", "timer_getoverrun", res);

        res = timer_delete(posix_tid);
        log_op("timer_delete", "timer_delete", res);
    }

    /* -------------------------------------------------------------
     * 16.9. SYSTEM INFO, HOSTNAME & ADMINISTRATION:
     *       uname, sysinfo, syslog, sethostname, setdomainname,
     *       sync, reboot
     * ------------------------------------------------------------- */
    printf("\n--- System Info, Hostname & Administration ---\n");
    struct utsname uts_buf;
    res = uname(&uts_buf);
    log_op("uname", "query system info (uname)", res);

    struct sysinfo si_buf;
    res = sysinfo(&si_buf);
    log_op("sysinfo", "query system statistics (sysinfo)", res);

    res = (int)syscall(SYS_syslog, 10 /* SYSLOG_ACTION_SIZE_BUFFER */, NULL, 0);
    log_op("syslog", "syslog(SYSLOG_ACTION_SIZE_BUFFER)", res);

    pid_t uts_child = fork();
    if (uts_child == 0) {
        if (unshare(CLONE_NEWUTS) == 0) {
            res = sethostname("audisp_dummy_host", 17);
            log_op("sethostname", "private UTS namespace sethostname", res);
            res = setdomainname("audisp_dummy_domain", 19);
            log_op("setdomainname", "private UTS namespace setdomainname", res);
        } else {
            res = (int)syscall(SYS_sethostname, (const char *)-1, 0);
            log_op("sethostname", "dummy sethostname", res);
            res = (int)syscall(SYS_setdomainname, (const char *)-1, 0);
            log_op("setdomainname", "dummy setdomainname", res);
        }
        _exit(0);
    } else if (uts_child > 0) {
        waitpid(uts_child, NULL, 0);
    }

    sync();
    log_op("sync", "sync filesystems", 0);

    if (geteuid() == 0) {
        printf("  [SKIP] %-14s: skipped when running as root to avoid risk\n", "reboot");
    } else {
        res = (int)syscall(SYS_reboot, 0, 0, 0, NULL);
        log_op("reboot", "reboot(0, 0, 0, NULL) safe invalid call", res);
    }

    /* -------------------------------------------------------------
     * 16.10. KEYS, SECURITY, SECCOMP & RANDOM:
     * add_key, request_key, keyctl, seccomp, getrandom, membarrier,
     * ptrace, kcmp, process_vm_readv, process_vm_writev,
     * ioprio_set, ioprio_get
     * ------------------------------------------------------------- */
    printf("\n--- Keys, Security, Seccomp & Random ---\n");

    res = (int)syscall(SYS_add_key, "user", "audisp_test_key", "payload_data", 12, -2 /* KEY_SPEC_PROCESS_KEYRING */);
    log_op("add_key", "add_key(\"user\", ...)", res);

    res = (int)syscall(SYS_request_key, "user", "audisp_nonexistent_key", NULL, -2 /* KEY_SPEC_PROCESS_KEYRING */);
    log_op("request_key", "request_key(\"user\", ...)", res);

    res = (int)syscall(SYS_keyctl, 0 /* KEYCTL_GET_KEYRING_ID */, -3 /* KEY_SPEC_SESSION_KEYRING */, 0);
    log_op("keyctl", "keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0)", res);

    unsigned int seccomp_action = 0x7fff0000U; /* SECCOMP_RET_ALLOW */
    res = (int)syscall(SYS_seccomp, 2 /* SECCOMP_GET_ACTION_AVAIL */, 0, &seccomp_action);
    log_op("seccomp", "seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action)", res);

    char rnd_buf[8] = {0};
    res = (int)syscall(SYS_getrandom, rnd_buf, sizeof(rnd_buf), 1 /* GRND_NONBLOCK */);
    log_op("getrandom", "getrandom(rnd_buf, 8, GRND_NONBLOCK)", res);

    res = (int)syscall(SYS_membarrier, 0 /* MEMBARRIER_CMD_QUERY */, 0, 0);
    log_op("membarrier", "membarrier(MEMBARRIER_CMD_QUERY, 0)", res);

    pid_t ptr_child = fork();
    if (ptr_child == 0) {
        res = (int)syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, NULL, NULL);
        log_op("ptrace", "ptrace(PTRACE_TRACEME)", res);
        _exit(0);
    } else if (ptr_child > 0) {
        waitpid(ptr_child, NULL, 0);
    }

    res = (int)syscall(SYS_kcmp, getpid(), getpid(), 0 /* KCMP_FILE */, 0, 1);
    log_op("kcmp", "kcmp(getpid(), getpid(), KCMP_FILE, 0, 1)", res);

    char vm_local_buf[16] = "audisp_vm_test";
    char vm_remote_buf[16] = {0};
    struct iovec vm_local_iov = { .iov_base = vm_remote_buf, .iov_len = sizeof(vm_remote_buf) };
    struct iovec vm_remote_iov = { .iov_base = vm_local_buf, .iov_len = sizeof(vm_local_buf) };

    res = (int)syscall(SYS_process_vm_readv, getpid(), &vm_local_iov, 1, &vm_remote_iov, 1, 0);
    log_op("process_vm_readv", "process_vm_readv self test", res);

    res = (int)syscall(SYS_process_vm_writev, getpid(), &vm_local_iov, 1, &vm_remote_iov, 1, 0);
    log_op("process_vm_writev", "process_vm_writev self test", res);

    res = (int)syscall(SYS_ioprio_get, 1 /* IOPRIO_WHO_PROCESS */, 0);
    log_op("ioprio_get", "ioprio_get(IOPRIO_WHO_PROCESS, 0)", res);

    res = (int)syscall(SYS_ioprio_set, 1 /* IOPRIO_WHO_PROCESS */, 0, (2 << 13) | 4 /* IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4) */);
    log_op("ioprio_set", "ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4))", res);

    /* -------------------------------------------------------------
     * 16.11. FUTEX, ROBUST LISTS, MEMORY KEYS & ASYNC I/O:
     * futex, set_robust_list, get_robust_list, pkey_alloc, pkey_free,
     * io_submit, io_cancel, io_getevents, io_pgetevents
     * ------------------------------------------------------------- */
    printf("\n--- Futex, Robust Lists, Memory Keys & Async I/O ---\n");

    int futex_word = 0;
    res = (int)syscall(SYS_futex, &futex_word, 1 /* FUTEX_WAKE */, 1, NULL, NULL, 0);
    log_op("futex", "futex(&futex_word, FUTEX_WAKE, 1)", res);

    void *rob_head = NULL;
    size_t rob_len = 0;
    res = (int)syscall(SYS_get_robust_list, 0, &rob_head, &rob_len);
    log_op("get_robust_list", "get_robust_list(0, &rob_head, &rob_len)", res);

    pid_t rob_child = fork();
    if (rob_child == 0) {
        res = (int)syscall(SYS_set_robust_list, (void *)-1, 0);
        log_op("set_robust_list", "set_robust_list((void *)-1, 0)", res);
        _exit(0);
    } else if (rob_child > 0) {
        waitpid(rob_child, NULL, 0);
    }

    res = (int)syscall(SYS_pkey_alloc, 0, 0 /* PKEY_UNRESTRICTED */);
    log_op("pkey_alloc", "pkey_alloc(0, PKEY_UNRESTRICTED)", res);
    if (res >= 0) {
        int free_res = (int)syscall(SYS_pkey_free, res);
        log_op("pkey_free", "pkey_free(allocated_key)", free_res);
    } else {
        res = (int)syscall(SYS_pkey_free, 0);
        log_op("pkey_free", "pkey_free(0) fallback", res);
    }

    res = (int)syscall(SYS_io_submit, 0, 0, NULL);
    log_op("io_submit", "io_submit(0, 0, NULL)", res);

    res = (int)syscall(SYS_io_cancel, 0, NULL, NULL);
    log_op("io_cancel", "io_cancel(0, NULL, NULL)", res);

    res = (int)syscall(SYS_io_getevents, 0, 0, 0, NULL, NULL);
    log_op("io_getevents", "io_getevents(0, 0, 0, NULL, NULL)", res);

    res = (int)syscall(SYS_io_pgetevents, 0, 0, 0, NULL, NULL, NULL);
    log_op("io_pgetevents", "io_pgetevents(0, 0, 0, NULL, NULL, NULL)", res);

    /* -------------------------------------------------------------
     * 16.12. KERNEL MODULES, ARCHITECTURE-SPECIFIC & LEGACY:
     * init_module, delete_module, create_module, get_kernel_syms,
     * query_module, kexec_load, mq_unlink, arch_prctl, modify_ldt,
     * iopl, ioperm, set_thread_area, get_thread_area, lookup_dcookie,
     * _sysctl, sysfs, epoll_ctl_old, epoll_wait_old, security,
     * nfsservctl, afs_syscall, tuxcall, vserver, uretprobe
     * ------------------------------------------------------------- */
    printf("\n--- Kernel Modules, Architecture-specific & Legacy ---\n");

    res = (int)syscall(SYS_init_module, NULL, 0, NULL);
    log_op("init_module", "dummy init_module", res);

    res = (int)syscall(SYS_delete_module, "nonexistent_dummy_module", 0);
    log_op("delete_module", "dummy delete_module", res);

    res = (int)syscall(SYS_create_module, NULL, 0);
    log_op("create_module", "dummy create_module", res);

    res = (int)syscall(SYS_get_kernel_syms, NULL);
    log_op("get_kernel_syms", "dummy get_kernel_syms", res);

    res = (int)syscall(SYS_query_module, NULL, 0, NULL, 0, NULL);
    log_op("query_module", "dummy query_module", res);

    res = (int)syscall(SYS_kexec_load, NULL, 0, NULL, 0);
    log_op("kexec_load", "dummy kexec_load", res);

    res = (int)syscall(SYS_mq_unlink, "/nonexistent_dummy_queue");
    log_op("mq_unlink", "dummy mq_unlink", res);

    unsigned long fs_base = 0;
    res = (int)syscall(SYS_arch_prctl, 0x1003 /* ARCH_GET_FS */, &fs_base);
    log_op("arch_prctl", "arch_prctl(ARCH_GET_FS, &fs_base)", res);

    res = (int)syscall(SYS_modify_ldt, 0 /* read */, NULL, 0);
    log_op("modify_ldt", "modify_ldt(0, NULL, 0)", res);

    res = (int)syscall(SYS_iopl, 0);
    log_op("iopl", "iopl(0)", res);

    res = (int)syscall(SYS_ioperm, 0, 0, 0);
    log_op("ioperm", "ioperm(0, 0, 0)", res);

    res = (int)syscall(SYS_set_thread_area, NULL);
    log_op("set_thread_area", "dummy set_thread_area", res);

    res = (int)syscall(SYS_get_thread_area, NULL);
    log_op("get_thread_area", "dummy get_thread_area", res);

    res = (int)syscall(SYS_lookup_dcookie, 0, NULL, 0);
    log_op("lookup_dcookie", "dummy lookup_dcookie", res);

    res = (int)syscall(SYS__sysctl, NULL);
    log_op("_sysctl", "dummy _sysctl", res);

    res = (int)syscall(SYS_sysfs, 0, 0, 0);
    log_op("sysfs", "dummy sysfs", res);

    res = (int)syscall(SYS_epoll_ctl_old, 0, 0, 0, NULL);
    log_op("epoll_ctl_old", "dummy epoll_ctl_old", res);

    res = (int)syscall(SYS_epoll_wait_old, 0, NULL, 0, 0);
    log_op("epoll_wait_old", "dummy epoll_wait_old", res);

    res = (int)syscall(SYS_security, NULL, NULL, NULL);
    log_op("security", "dummy security", res);

    res = (int)syscall(SYS_nfsservctl, 0, NULL, NULL);
    log_op("nfsservctl", "dummy nfsservctl", res);

    res = (int)syscall(SYS_afs_syscall, 0, 0, 0, 0, 0);
    log_op("afs_syscall", "dummy afs_syscall", res);

    res = (int)syscall(SYS_tuxcall, 0, 0, 0);
    log_op("tuxcall", "dummy tuxcall", res);

    res = (int)syscall(SYS_vserver, 0, 0, 0, 0, 0);
    log_op("vserver", "dummy vserver", res);

    printf("  [SKIP] %-14s: skipped (internal return trampoline; not userspace invokable)\n", "uretprobe");

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
