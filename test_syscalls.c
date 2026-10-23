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
     * 11. CREDENTIALS: setuid, setgid
     * ------------------------------------------------------------- */
    printf("\n--- Credential Operations (setuid, setgid) ---\n");

    res = setgid(gid);
    log_op("setgid", "setgid(current_gid)", res);

    res = setuid(uid);
    log_op("setuid", "setuid(current_uid)", res);

    res = setgid(0);
    log_op("setgid", "setgid(0)", res);

    res = setuid(0);
    log_op("setuid", "setuid(0)", res);

    /* -------------------------------------------------------------
     * 12. PROCESS CLONE
     * ------------------------------------------------------------- */
    printf("\n--- Process Lifecycle (clone) ---\n");
    {
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
     * 13. DELETION & CLEANUP: unlink, unlinkat, rmdir, close
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
