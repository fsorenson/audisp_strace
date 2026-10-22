#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>

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

#ifndef RENAME_NOREPLACE
#  define RENAME_NOREPLACE (1 << 0)
#endif

/* Stack size for clone() */
#define CLONE_STACK_SIZE (64 * 1024)

static int clone_child_func(void *arg) {
    (void)arg;
    /* Minimal work inside cloned child */
    return 0;
}

static void log_op(const char *syscall_name, const char *desc, int res) {
    if (res >= 0) {
        printf("  [OK] %-12s: %s (result: %d)\n", syscall_name, desc, res);
    } else {
        printf("  [FAIL] %-12s: %s (errno %d: %s)\n", syscall_name, desc, errno, strerror(errno));
    }
}

static void run_worker_tests(const char *base_dir) {
    char path_buf1[1024];
    char abs_sub[1024];
    char abs_file[1024];
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

    /* mkdirat: dir_fd + absolute path (POSIX specifies absolute path ignores dirfd) */
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

    /* Keep file_fd open for fchmod / fchown / close tests below */

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

    /* openat2 (if supported by kernel) */
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
     * 3. PERMISSIONS: chmod, fchmod, fchmodat
     * ------------------------------------------------------------- */
    printf("\n--- Permission Operations (chmod, fchmod, fchmodat) ---\n");

    /* chmod */
    res = chmod("creat_file.txt", 0600);
    log_op("chmod", "creat_file.txt to 0600", res);

    /* fchmod on open descriptor */
    if (file_fd >= 0) {
        res = fchmod(file_fd, 0660);
        log_op("fchmod", "open file_fd to 0660", res);
    }

    /* fchmodat: AT_FDCWD + relative path */
    res = fchmodat(AT_FDCWD, "openat_fdcwd_rel.txt", 0640, 0);
    log_op("fchmodat", "AT_FDCWD + 'openat_fdcwd_rel.txt' to 0640", res);

    /* fchmodat: dir_fd + relative path */
    res = fchmodat(dir_fd, "openat_dirfd_rel.txt", 0640, 0);
    log_op("fchmodat", "dir_fd + 'openat_dirfd_rel.txt' to 0640", res);

    /* fchmodat: AT_FDCWD + absolute path */
    res = fchmodat(AT_FDCWD, abs_file, 0640, 0);
    log_op("fchmodat", "AT_FDCWD + absolute path to 0640", res);

    /* fchmodat: dir_fd + absolute path */
    res = fchmodat(dir_fd, abs_file, 0644, 0);
    log_op("fchmodat", "dir_fd + absolute path to 0644", res);

    /* -------------------------------------------------------------
     * 4. OWNERSHIP: chown, fchown, lchown, fchownat
     * ------------------------------------------------------------- */
    printf("\n--- Ownership Operations (chown, fchown, lchown, fchownat) ---\n");

    /* chown */
    res = chown("creat_file.txt", uid, gid);
    log_op("chown", "creat_file.txt to uid/gid", res);

    /* fchown */
    if (file_fd >= 0) {
        res = fchown(file_fd, uid, gid);
        log_op("fchown", "open file_fd to uid/gid", res);
    }

    /* fchownat: AT_FDCWD + relative path */
    res = fchownat(AT_FDCWD, "openat_fdcwd_rel.txt", uid, gid, 0);
    log_op("fchownat", "AT_FDCWD + 'openat_fdcwd_rel.txt'", res);

    /* fchownat: dir_fd + relative path */
    res = fchownat(dir_fd, "openat_dirfd_rel.txt", uid, gid, 0);
    log_op("fchownat", "dir_fd + 'openat_dirfd_rel.txt'", res);

    /* fchownat: AT_FDCWD + absolute path */
    res = fchownat(AT_FDCWD, abs_file, uid, gid, 0);
    log_op("fchownat", "AT_FDCWD + absolute path", res);

    /* -------------------------------------------------------------
     * 5. LINKS & SYMLINKS: link, linkat, symlink, symlinkat, lchown
     * ------------------------------------------------------------- */
    printf("\n--- Links & Symlinks (link, linkat, symlink, symlinkat, lchown) ---\n");

    /* link (hardlink) */
    res = link("open_file.txt", "hardlink_open.txt");
    log_op("link", "open_file.txt -> hardlink_open.txt", res);

    /* linkat: dir_fd + relative */
    res = linkat(dir_fd, "openat_dirfd_rel.txt", dir_fd, "hardlink_dirfd.txt", 0);
    log_op("linkat", "dir_fd 'openat_dirfd_rel.txt' -> dir_fd 'hardlink_dirfd.txt'", res);

    /* symlink */
    res = symlink("open_file.txt", "symlink_open.txt");
    log_op("symlink", "'open_file.txt' target -> 'symlink_open.txt'", res);

    /* lchown on symlink */
    res = lchown("symlink_open.txt", uid, gid);
    log_op("lchown", "symlink_open.txt to uid/gid", res);

    /* symlinkat: dir_fd */
    res = symlinkat("target_dummy.txt", dir_fd, "symlink_in_dirfd.txt");
    log_op("symlinkat", "'target_dummy.txt' target -> dir_fd 'symlink_in_dirfd.txt'", res);

    /* fchownat with AT_SYMLINK_NOFOLLOW on symlink */
    res = fchownat(dir_fd, "symlink_in_dirfd.txt", uid, gid, AT_SYMLINK_NOFOLLOW);
    log_op("fchownat", "dir_fd symlink with AT_SYMLINK_NOFOLLOW", res);

    /* -------------------------------------------------------------
     * 6. RENAMING: rename, renameat, renameat2
     * ------------------------------------------------------------- */
    printf("\n--- Rename Operations (rename, renameat, renameat2) ---\n");

    /* rename */
    res = rename("creat_file.txt", "creat_renamed.txt");
    log_op("rename", "creat_file.txt -> creat_renamed.txt", res);

    /* renameat: dir_fd */
    res = renameat(dir_fd, "openat_dirfd_rel.txt", dir_fd, "openat_renamed.txt");
    log_op("renameat", "dir_fd openat_dirfd_rel.txt -> dir_fd openat_renamed.txt", res);

    /* renameat2: dir_fd with RENAME_NOREPLACE */
    res = renameat2(dir_fd, "hardlink_dirfd.txt", dir_fd, "hardlink_renamed.txt", RENAME_NOREPLACE);
    log_op("renameat2", "dir_fd with RENAME_NOREPLACE", res);

    /* -------------------------------------------------------------
     * 7. CREDENTIALS: setuid, setgid
     * ------------------------------------------------------------- */
    printf("\n--- Credential Operations (setuid, setgid) ---\n");

    /* setgid to current gid (should succeed) */
    res = setgid(gid);
    log_op("setgid", "setgid(current_gid)", res);

    /* setuid to current uid (should succeed) */
    res = setuid(uid);
    log_op("setuid", "setuid(current_uid)", res);

    /* setgid(0) - test event even if fails with EPERM */
    res = setgid(0);
    log_op("setgid", "setgid(0)", res);

    /* setuid(0) - test event even if fails with EPERM */
    res = setuid(0);
    log_op("setuid", "setuid(0)", res);

    /* -------------------------------------------------------------
     * 8. PROCESS CLONE
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
     * 9. DELETION & CLEANUP: unlink, unlinkat, rmdir, close
     * ------------------------------------------------------------- */
    printf("\n--- Deletion & Cleanup (unlink, unlinkat, rmdir, close) ---\n");

    /* unlink */
    res = unlink("hardlink_open.txt");
    log_op("unlink", "hardlink_open.txt", res);

    res = unlink("creat_renamed.txt");
    log_op("unlink", "creat_renamed.txt", res);

    res = unlink("open_file.txt");
    log_op("unlink", "open_file.txt", res);

    res = unlink("symlink_open.txt");
    log_op("unlink", "symlink_open.txt", res);

    res = unlink("openat_fdcwd_rel.txt");
    log_op("unlink", "openat_fdcwd_rel.txt", res);

    res = unlink(abs_file);
    log_op("unlink", "openat_fdcwd_abs.txt", res);

    snprintf(path_buf1, sizeof(path_buf1), "%s/openat_dirfd_abs.txt", base_dir);
    unlink(path_buf1);

    /* unlinkat: dir_fd relative */
    res = unlinkat(dir_fd, "openat_renamed.txt", 0);
    log_op("unlinkat", "dir_fd + 'openat_renamed.txt'", res);

    res = unlinkat(dir_fd, "hardlink_renamed.txt", 0);
    log_op("unlinkat", "dir_fd + 'hardlink_renamed.txt'", res);

    res = unlinkat(dir_fd, "symlink_in_dirfd.txt", 0);
    log_op("unlinkat", "dir_fd + 'symlink_in_dirfd.txt'", res);

#ifdef SYS_openat2
    unlinkat(dir_fd, "openat2_file.txt", 0);
#endif

    /* Close descriptors */
    if (file_fd >= 0) {
        res = close(file_fd);
        log_op("close", "file_fd", res);
    }
    if (dir_fd >= 0) {
        res = close(dir_fd);
        log_op("close", "dir_fd", res);
    }

    /* rmdir (nested directory inside subdir_rel) */
    res = rmdir("subdir_rel/nested_in_dirfd");
    log_op("rmdir", "subdir_rel/nested_in_dirfd", res);

    /* unlinkat with AT_REMOVEDIR */
    res = unlinkat(AT_FDCWD, "sub_at_fdcwd_rel", AT_REMOVEDIR);
    log_op("unlinkat", "AT_FDCWD + 'sub_at_fdcwd_rel' (AT_REMOVEDIR)", res);

    res = rmdir("subdir_rel");
    log_op("rmdir", "subdir_rel", res);

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

    /* 
     * Fork a child process, which will execve() this binary with --worker.
     * This establishes the full process ancestry:
     *   Parent (%d) -> Child (%d) -> execve(test_syscalls --worker ...)
     */
    printf("\nCreating process tree via fork() + execve()...\n");
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        rmdir(sandbox);
        return 1;
    }

    if (child_pid == 0) {
        /* Child process: execve() back into self with worker argument */
        char *child_argv[] = { argv[0], "--worker", sandbox, NULL };
        execve(argv[0], child_argv, envp);
        /* If execve fails */
        perror("execve");
        _exit(1);
    }

    /* Parent process: wait for child */
    int status = 0;
    waitpid(child_pid, &status, 0);

    /* Clean up sandbox */
    rmdir(sandbox);
    printf("\nTest sandbox cleaned up. Parent exiting.\n");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
