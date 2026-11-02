/*
 * test_anomalies.c - Live generator for non-syscall security anomalies & audit records.
 *
 * Exercises kernel security subsystems to generate audit events:
 *   - Seccomp sandboxing (AUDIT_SECCOMP / 1326)
 *   - Landlock LSM sandboxing (AUDIT_LANDLOCK_ACCESS / 1423, AUDIT_LANDLOCK_DOMAIN / 1424)
 *   - Process abnormal terminations / crashes (AUDIT_ANOM_ABEND / 1701)
 *   - VFS link & creation protections (AUDIT_ANOM_LINK / 1702, AUDIT_ANOM_CREAT / 1703)
 *   - Capabilities manipulation (AUDIT_CAPSET / 1322)
 *   - Fanotify access decisions (AUDIT_FANOTIFY / 1331) [requires root/CAP_SYS_ADMIN]
 *   - SELinux status changes (AUDIT_MAC_STATUS / 1404) [requires root]
 *
 * Copyright (c) 2026 Frank Sorenson <sorenson@redhat.com>
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/landlock.h>
#include <poll.h>

#ifdef __has_include
#if __has_include(<sys/fanotify.h>)
#include <sys/fanotify.h>
#define HAVE_FANOTIFY 1
#endif
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL               (1ULL << 1)
#endif

#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

static int opt_all = 0;
static int opt_seccomp = 0;
static int opt_landlock_fs = 0;
static int opt_landlock_net = 0;
static int opt_landlock_scope = 0;
static int opt_crash = 0;
static int opt_link = 0;
static int opt_fanotify = 0;
static int opt_capset = 0;
static int opt_selinux = 0;

static void print_banner(const char *name, const char *record_type) {
    printf("\n=== [%s] Expected audit type: %s ===\n", name, record_type);
}

/* -------------------------------------------------------------------------
 * 1. SECCOMP Sandboxing (AUDIT_SECCOMP / 1326)
 * ------------------------------------------------------------------------- */
static void test_seccomp(void) {
    print_banner("SECCOMP", "AUDIT_SECCOMP (1326)");
    printf("[*] Parent PID: %d\n", getpid());

    /* Subtest A: SECCOMP_RET_LOG on getpid (non-fatal, process continues) */
    printf("[+] Testing SECCOMP_RET_LOG on getpid()...\n");
    pid_t child = fork();
    if (child == 0) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            _exit(1);
        }

        struct sock_filter filter_log[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_LOG),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter_log) / sizeof(filter_log[0])),
            .filter = filter_log,
        };

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
            perror("prctl(PR_SET_SECCOMP)");
            _exit(1);
        }

        printf("    Child PID %d executing getpid() -> logged by seccomp\n", getpid());
        syscall(SYS_getpid);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);

    /* Subtest B: SECCOMP_RET_KILL_PROCESS on mkdirat */
    printf("[+] Testing SECCOMP_RET_KILL_PROCESS on mkdirat()...\n");
    child = fork();
    if (child == 0) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);

        struct sock_filter filter_kill[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdirat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter_kill) / sizeof(filter_kill[0])),
            .filter = filter_kill,
        };

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
            _exit(1);

        printf("    Child PID %d calling mkdirat(/tmp/seccomp_denied) -> killed\n", getpid());
        mkdirat(AT_FDCWD, "/tmp/seccomp_denied", 0755);
        _exit(0);
    }
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("    Child was terminated by signal: %d (%s)\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

/* -------------------------------------------------------------------------
 * 2. Landlock LSM: Filesystem Denials (AUDIT_LANDLOCK_ACCESS / 1423)
 * ------------------------------------------------------------------------- */
static void test_landlock_fs(void) {
    print_banner("Landlock FS", "AUDIT_LANDLOCK_DOMAIN (1424) + AUDIT_LANDLOCK_ACCESS (1423)");

    pid_t child = fork();
    if (child == 0) {
        int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 0) {
            printf("    Landlock not supported on this kernel (abi=%d): %s\n", abi, strerror(errno));
            _exit(0);
        }

        struct landlock_ruleset_attr attr = {
            .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
        };
        int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (ruleset_fd < 0) {
            perror("landlock_create_ruleset");
            _exit(1);
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);

        if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
            perror("landlock_restrict_self");
            close(ruleset_fd);
            _exit(1);
        }
        close(ruleset_fd);

        printf("    Landlock PID %d restricted. Attempting open(\"/etc/hosts\", O_RDONLY)...\n", getpid());
        int fd = open("/etc/hosts", O_RDONLY);
        if (fd < 0) {
            printf("    -> Denied as expected: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            close(fd);
        }
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
}

/* -------------------------------------------------------------------------
 * 3. Landlock LSM: Network Denials (AUDIT_LANDLOCK_ACCESS / 1423)
 * ------------------------------------------------------------------------- */
static void test_landlock_net(void) {
    print_banner("Landlock Net", "AUDIT_LANDLOCK_ACCESS (1423 blockers=net.connect_tcp)");

    pid_t child = fork();
    if (child == 0) {
        int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 4) {
            printf("    Landlock network rules require ABI >= 4 (current ABI: %d)\n", abi);
            _exit(0);
        }

        struct landlock_ruleset_attr attr = {
            .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP,
        };
        int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (ruleset_fd < 0) {
            perror("landlock_create_ruleset (net)");
            _exit(1);
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);

        if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
            perror("landlock_restrict_self (net)");
            close(ruleset_fd);
            _exit(1);
        }
        close(ruleset_fd);

        printf("    Landlock PID %d network restricted. Attempting connect() to 127.0.0.1:9999...\n", getpid());
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = htons(9999);
            inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);

            int ret = connect(s, (struct sockaddr *)&sin, sizeof(sin));
            if (ret < 0) {
                printf("    -> Denied as expected: %s (errno=%d)\n", strerror(errno), errno);
            }
            close(s);
        }
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
}

/* -------------------------------------------------------------------------
 * 4. Landlock LSM: Scoped Signal Denials (AUDIT_LANDLOCK_ACCESS / 1423)
 * ------------------------------------------------------------------------- */
static void test_landlock_scope(void) {
    print_banner("Landlock Scopes", "AUDIT_LANDLOCK_ACCESS (1423 blockers=scope.signal)");

    pid_t parent_pid = getpid();
    pid_t child = fork();
    if (child == 0) {
        int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
        if (abi < 5) {
            printf("    Landlock scope rules require ABI >= 5 (current ABI: %d)\n", abi);
            _exit(0);
        }

        struct landlock_ruleset_attr attr = {
            .scoped = LANDLOCK_SCOPE_SIGNAL,
        };
        int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
        if (ruleset_fd < 0) {
            perror("landlock_create_ruleset (scope)");
            _exit(1);
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            _exit(1);

        if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
            perror("landlock_restrict_self (scope)");
            close(ruleset_fd);
            _exit(1);
        }
        close(ruleset_fd);

        printf("    Landlock PID %d signal-scoped. Attempting kill(PID %d, 0)...\n",
               getpid(), parent_pid);
        int ret = kill(parent_pid, 0);
        if (ret < 0) {
            printf("    -> Scoped signal denied as expected: %s (errno=%d)\n", strerror(errno), errno);
        }
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
}

/* -------------------------------------------------------------------------
 * 5. Process Crashes & Abnormal Terminations (AUDIT_ANOM_ABEND / 1701)
 * ------------------------------------------------------------------------- */
static void test_crashes(void) {
    print_banner("Process Crashes", "AUDIT_ANOM_ABEND (1701)");

    /* Subtest A: SIGSEGV */
    printf("[+] Testing crash: SIGSEGV (Segmentation Fault)...\n");
    pid_t child = fork();
    if (child == 0) {
        printf("    Child PID %d triggering SIGSEGV...\n", getpid());
        volatile int *bad_ptr = (volatile int *)0;
        *bad_ptr = 42;
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);

    /* Subtest B: SIGABRT */
    printf("[+] Testing crash: SIGABRT (Abort)...\n");
    child = fork();
    if (child == 0) {
        printf("    Child PID %d triggering abort()...\n", getpid());
        abort();
        _exit(1);
    }
    waitpid(child, &status, 0);
}

/* -------------------------------------------------------------------------
 * 6. VFS Protected Link & Creation Violations (AUDIT_ANOM_LINK / 1702, ANOM_CREAT / 1703)
 * ------------------------------------------------------------------------- */
static void test_protected_links(void) {
    print_banner("VFS Link Protection", "AUDIT_ANOM_LINK (1702) & AUDIT_ANOM_CREAT (1703)");

    /* Subtest A: fs.protected_hardlinks (requires same filesystem) */
    printf("[+] Testing fs.protected_hardlinks...\n");
    const char *target = "/etc/passwd";
    struct stat st_src, st_tmp;
    if (stat(target, &st_src) == 0 && stat("/tmp", &st_tmp) == 0) {
        if (st_src.st_dev == st_tmp.st_dev) {
            const char *link_dst = "/tmp/test_hardlink_violation";
            unlink(link_dst);
            int ret = link(target, link_dst);
            if (ret < 0) {
                printf("    link(\"%s\", \"%s\") -> denied: %s (errno=%d)\n",
                       target, link_dst, strerror(errno), errno);
            } else {
                printf("    link() succeeded.\n");
                unlink(link_dst);
            }
        } else {
            printf("    /etc (%ld) and /tmp (%ld) are on different filesystems (cross-device).\n",
                   (long)st_src.st_dev, (long)st_tmp.st_dev);
            printf("    Testing hardlink on same filesystem...\n");
            /* Test within current directory */
            char local_src[256];
            snprintf(local_src, sizeof(local_src), "./test_anomalies");
            char local_dst[256];
            snprintf(local_dst, sizeof(local_dst), "./test_anomalies_hl");
            unlink(local_dst);
            if (link(local_src, local_dst) == 0) {
                printf("    Hardlink on same filesystem created successfully.\n");
                unlink(local_dst);
            }
        }
    }

    /* Subtest B: Sticky directory regular file / FIFO creation check (ANOM_CREAT) */
    printf("[+] Testing sticky directory creation protections (fs.protected_regular / fs.protected_fifos)...\n");
    char fifo_path[] = "/tmp/test_sticky_fifo";
    unlink(fifo_path);
    if (mkfifo(fifo_path, 0666) == 0) {
        printf("    Created FIFO %s in sticky dir /tmp.\n", fifo_path);
        unlink(fifo_path);
    }
}

/* -------------------------------------------------------------------------
 * 7. Capabilities Manipulation (AUDIT_CAPSET / 1322)
 * ------------------------------------------------------------------------- */
static void test_capabilities(void) {
    print_banner("Capabilities", "AUDIT_CAPSET (1322)");

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return;
    }
    if (pid == 0) {
        struct __user_cap_header_struct hdr = {
            .version = _LINUX_CAPABILITY_VERSION_3,
            .pid = 0,
        };
        struct __user_cap_data_struct data[2];
        memset(data, 0, sizeof(data));

        if (syscall(SYS_capget, &hdr, data) == 0) {
            printf("[+] Current process capabilities: effective=0x%x permitted=0x%x\n",
                   data[0].effective, data[0].permitted);
            /* Drop all effective capabilities in child */
            data[0].effective = 0;
            data[1].effective = 0;
            if (syscall(SYS_capset, &hdr, data) == 0) {
                printf("    capset() successfully cleared effective capabilities in child.\n");
            } else {
                perror("capset");
            }
        } else {
            perror("capget");
        }
        _exit(0);
    }
    waitpid(pid, NULL, 0);
}

/* -------------------------------------------------------------------------
 * 8. Fanotify Access Decisions (AUDIT_FANOTIFY / 1331) [Root / CAP_SYS_ADMIN]
 * ------------------------------------------------------------------------- */
#ifdef HAVE_FANOTIFY
struct fanotify_worker_arg {
    int fan_fd;
    char target_path[256];
};

static void *fanotify_responder_thread(void *arg) {
    struct fanotify_worker_arg *warg = (struct fanotify_worker_arg *)arg;
    char buf[4096];

    struct pollfd pfd = { .fd = warg->fan_fd, .events = POLLIN };
    if (poll(&pfd, 1, 5000) > 0) {
        ssize_t len = read(warg->fan_fd, buf, sizeof(buf));
        if (len > 0) {
            struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)buf;
            while (FAN_EVENT_OK(metadata, len)) {
                if (metadata->mask & FAN_OPEN_PERM) {
                    struct fanotify_response response;
                    response.fd = metadata->fd;
                    /* Reply with FAN_DENY and request kernel AUDIT record */
                    response.response = FAN_DENY | FAN_AUDIT;
                    write(warg->fan_fd, &response, sizeof(response));
                    close(metadata->fd);
                    break;
                }
                metadata = FAN_EVENT_NEXT(metadata, len);
            }
        }
    }
    return NULL;
}

static void test_fanotify(void) {
    print_banner("Fanotify Decisions", "AUDIT_FANOTIFY (1331)");

    if (geteuid() != 0) {
        printf("    [!] Skipping fanotify test: requires root (CAP_SYS_ADMIN)\n");
        return;
    }

    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_ENABLE_AUDIT | FAN_NONBLOCK, O_RDONLY);
    if (fan_fd < 0) {
        perror("fanotify_init");
        return;
    }

    char tmp_file[] = "/tmp/test_fanotify_XXXXXX";
    int tfd = mkstemp(tmp_file);
    if (tfd < 0) {
        perror("mkstemp");
        close(fan_fd);
        return;
    }
    write(tfd, "test", 4);
    close(tfd);

    if (fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, tmp_file) != 0) {
        perror("fanotify_mark");
        unlink(tmp_file);
        close(fan_fd);
        return;
    }

    struct fanotify_worker_arg warg;
    warg.fan_fd = fan_fd;
    strncpy(warg.target_path, tmp_file, sizeof(warg.target_path) - 1);

    pthread_t th;
    pthread_create(&th, NULL, fanotify_responder_thread, &warg);
    usleep(100000); /* 100ms for thread to enter read() */

    printf("    Child opening %s (monitored by fanotify)...\n", tmp_file);
    int denied_fd = open(tmp_file, O_RDONLY);
    if (denied_fd < 0) {
        printf("    -> Fanotify denial received: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    -> Open succeeded (fd=%d)\n", denied_fd);
        close(denied_fd);
    }

    pthread_join(th, NULL);
    unlink(tmp_file);
    close(fan_fd);
}
#endif

/* -------------------------------------------------------------------------
 * 9. SELinux Mode Toggle (AUDIT_MAC_STATUS / 1404) [Root]
 * ------------------------------------------------------------------------- */
static void test_selinux(void) {
    print_banner("SELinux Status", "AUDIT_MAC_STATUS (1404)");

    if (geteuid() != 0) {
        printf("    [!] Skipping SELinux mode toggle: requires root\n");
        return;
    }

    int fd = open("/sys/fs/selinux/enforce", O_RDWR);
    if (fd < 0) {
        printf("    SELinux not active or /sys/fs/selinux not mounted (%s)\n", strerror(errno));
        return;
    }

    char current_mode[4] = {0};
    read(fd, current_mode, 1);
    printf("    Current SELinux enforce mode: %c\n", current_mode[0]);

    /* Toggle mode and restore */
    char new_mode = (current_mode[0] == '1') ? '0' : '1';
    printf("    Toggling enforce mode to %c...\n", new_mode);
    lseek(fd, 0, SEEK_SET);
    write(fd, &new_mode, 1);

    usleep(50000);

    printf("    Restoring enforce mode to %c...\n", current_mode[0]);
    lseek(fd, 0, SEEK_SET);
    write(fd, &current_mode[0], 1);

    close(fd);
    printf("    -> Generated AUDIT_MAC_STATUS transitions.\n");
}

/* -------------------------------------------------------------------------
 * CLI & Main Driver
 * ------------------------------------------------------------------------- */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Generates kernel security anomaly and non-syscall audit records:\n"
        "  --all              Run all unprivileged tests (seccomp, landlock, crashes, links, caps)\n"
        "  --seccomp          Run Seccomp filter & kill tests (AUDIT_SECCOMP / 1326)\n"
        "  --landlock-fs      Run Landlock filesystem restriction test (1423 / 1424)\n"
        "  --landlock-net     Run Landlock network connect/bind restriction test (1423)\n"
        "  --landlock-scope   Run Landlock scoped signal restriction test (1423)\n"
        "  --crash            Run SIGSEGV and SIGABRT abnormal terminations (ANOM_ABEND / 1701)\n"
        "  --link             Run VFS protected hardlink/symlink test (ANOM_LINK / 1702)\n"
        "  --capset           Run capability set change test (AUDIT_CAPSET / 1322)\n"
        "  --fanotify         Run Fanotify access decision test (AUDIT_FANOTIFY / 1331) [requires root]\n"
        "  --selinux          Run SELinux enforce toggle test (AUDIT_MAC_STATUS / 1404) [requires root]\n"
        "  -h, --help         Show this help\n",
        prog);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--all")) opt_all = 1;
        else if (!strcmp(argv[i], "--seccomp")) opt_seccomp = 1;
        else if (!strcmp(argv[i], "--landlock-fs")) opt_landlock_fs = 1;
        else if (!strcmp(argv[i], "--landlock-net")) opt_landlock_net = 1;
        else if (!strcmp(argv[i], "--landlock-scope")) opt_landlock_scope = 1;
        else if (!strcmp(argv[i], "--crash")) opt_crash = 1;
        else if (!strcmp(argv[i], "--link")) opt_link = 1;
        else if (!strcmp(argv[i], "--fanotify")) opt_fanotify = 1;
        else if (!strcmp(argv[i], "--capset")) opt_capset = 1;
        else if (!strcmp(argv[i], "--selinux")) opt_selinux = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!opt_all && !opt_seccomp && !opt_landlock_fs && !opt_landlock_net &&
        !opt_landlock_scope && !opt_crash && !opt_link && !opt_fanotify &&
        !opt_capset && !opt_selinux) {
        opt_all = 1;
    }

    printf("Starting security anomaly audit generation (PID %d)...\n", getpid());

    if (opt_all || opt_seccomp) test_seccomp();
    if (opt_all || opt_landlock_fs) test_landlock_fs();
    if (opt_all || opt_landlock_net) test_landlock_net();
    if (opt_all || opt_landlock_scope) test_landlock_scope();
    if (opt_all || opt_crash) test_crashes();
    if (opt_all || opt_link) test_protected_links();
    if (opt_all || opt_capset) test_capabilities();

#ifdef HAVE_FANOTIFY
    if (opt_fanotify || (opt_all && geteuid() == 0)) test_fanotify();
#endif
    if (opt_selinux || (opt_all && geteuid() == 0)) test_selinux();

    printf("\nAll requested anomaly tests completed.\n");
    return 0;
}
