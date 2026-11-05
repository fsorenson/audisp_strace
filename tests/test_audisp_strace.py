#!/usr/bin/env python3
"""Automated regression and functional test suite for audisp-strace.

Exercises all core capabilities:
- Syscall decoding and formatting
- SELinux AVC annotations (Enforcing & Permissive)
- Ghost file (deleted) descriptor tracking
- Audit drop & gap detection
- Multi-file rotated log chronological merging
- Fast time range inspection
- Relative timestamps and compact formats
- JSON Lines output validity
- Audit rule generation
"""

import json
import os
import subprocess
import sys
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDISP_STRACE = os.path.join(PROJECT_DIR, "audisp-strace")
DATA_DIR = os.path.join(PROJECT_DIR, "tests", "data")


def run_cmd(args, stdin_data=None):
    cmd = [AUDISP_STRACE] + args
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if stdin_data else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = p.communicate(input=stdin_data)
    return p.returncode, stdout, stderr


class TestAudispStrace(unittest.TestCase):

    def test_help_messages(self):
        """Verify -h is single-screen concise and --help-all is comprehensive."""
        code, out, _ = run_cmd(["-h"])
        self.assertEqual(code, 0)
        lines = [line for line in out.strip().splitlines() if line.strip()]
        self.assertLessEqual(len(lines), 30, "Short help must fit on an 80x24 terminal screen")
        self.assertIn("Common Options:", out)
        self.assertIn("--help-all", out)

        code, out, _ = run_cmd(["--help-all"])
        self.assertEqual(code, 0)
        self.assertIn("Syscall & Error Filtering:", out)
        self.assertIn("Output Formatting & Timestamps:", out)
        self.assertIn("Statistics & Drop Detection:", out)

    def test_syscall_matrix_summary(self):
        """Verify -c aggregates syscall statistics across 300+ syscalls."""
        matrix_file = os.path.join(DATA_DIR, "syscall_matrix.log")
        code, out, err = run_cmd(["-c", matrix_file])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertIn("Time range:", out)
        self.assertIn("syscall", out)
        self.assertIn("total", out)
        self.assertIn("write", out)
        self.assertIn("unlink", out)

    def test_selinux_avc_annotations(self):
        """Verify SELinux permissive warnings and enforcing denials."""
        avc_file = os.path.join(DATA_DIR, "selinux_avc.log")
        code, out, err = run_cmd([avc_file])
        self.assertEqual(code, 0, f"Error: {err}")

        # Permissive warning: mmap with AVC path correlation
        self.assertIn("[SELinux: WOULD DENY { map }]", out)
        self.assertIn("4</etc/centrifydc/group.ignore>", out)
        self.assertIn("avc: scontext=system_u:system_r:postfix_postdrop_t", out)
        self.assertIn("permissive=1", out)

        # Permissive warning: socket bind with name_bind denial
        self.assertIn("[SELinux: WOULD DENY { name_bind }]", out)
        self.assertIn("tclass=udp_socket", out)

        # Permissive warning: flock with LOCK_MAND and lock denial
        self.assertIn("flock(15, LOCK_MAND)", out)
        self.assertIn("[SELinux: WOULD DENY { lock }]", out)

        # Permissive warning: execve with execute denial
        self.assertIn("execve(\"/var/lib/nfs/statd/ha-callout\"", out)
        self.assertIn("[SELinux: WOULD DENY { execute, execute_no_trans }]", out)

        # Permissive warning: utimensat with 64-bit sign-extended AT_FDCWD
        self.assertIn("utimensat(AT_FDCWD</home/user1>, \"testfile\", [...])", out)
        self.assertIn("[SELinux: WOULD DENY { setattr }]", out)

        # Enforcing denial: openat with capability denials
        self.assertIn("[SELinux: DENIED { perfmon, sys_admin }]", out)
        self.assertIn("scontext=system_u:system_r:pcp_pmlogger_t", out)

        # Streamlined credentials check (no redundant euid/egid duplicates)
        self.assertIn("uid=0 (root), gid=0 (root), auid=unset", out)

    def test_selinux_filtering_and_summary(self):
        """Verify --avc filter and dynamic summary column."""
        avc_file = os.path.join(DATA_DIR, "selinux_avc.log")
        code, out, _ = run_cmd(["--avc", avc_file])
        self.assertEqual(code, 0)
        self.assertIn("[SELinux:", out)

        # Summary mode should have dynamic 'avc' column
        code, out, _ = run_cmd(["-c", "-S", "avc", avc_file])
        self.assertEqual(code, 0)
        self.assertIn("avc", out)
        self.assertIn("mmap", out)
        self.assertIn("openat", out)

    def test_ghost_files_tracking(self):
        """Verify (deleted) annotation on unlinked open file descriptors."""
        ghost_file = os.path.join(DATA_DIR, "ghost_files.log")
        code, out, err = run_cmd([ghost_file])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertIn("unlinked_while_open.txt (deleted)>", out)

    def test_drop_detection(self):
        """Verify audit sequence gap and drop detection alert banner."""
        drop_file = os.path.join(DATA_DIR, "drops_and_gaps.log")
        code, out, err = run_cmd(["-g", "--drop-window", "5", drop_file])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertIn("*** AUDIT DROP DETECTED: 39 events lost", out)

    def test_multi_file_chronological_merge(self):
        """Verify -m k-way chronological event merging across rotated files."""
        f0 = os.path.join(DATA_DIR, "rotated", "audit.log")
        f1 = os.path.join(DATA_DIR, "rotated", "audit.log.1")
        f2 = os.path.join(DATA_DIR, "rotated", "audit.log.2.gz")
        code, out, err = run_cmd(["-m", f0, f1, f2])
        self.assertEqual(code, 0, f"Error: {err}")

        # Timestamps should be ordered: 10:06:50 -> 10:07:00 -> 10:07:10
        lines = [line for line in out.splitlines() if line.startswith("100<rot>")]
        self.assertEqual(len(lines), 15)
        self.assertIn("10:06:50", lines[0])
        self.assertIn("10:07:00", lines[5])
        self.assertIn("10:07:10", lines[10])

    def test_time_range_inspection(self):
        """Verify fast header/trailer inspection with --time-range."""
        f0 = os.path.join(DATA_DIR, "rotated", "audit.log")
        f1 = os.path.join(DATA_DIR, "rotated", "audit.log.1")
        code, out, err = run_cmd(["--time-range", f0, f1])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertIn("audit.log", out)
        self.assertIn("audit.log.1", out)
        self.assertIn("Total (2 files)", out)
        self.assertIn("duration:", out)

    def test_relative_timestamps(self):
        """Verify -r relative deltas and -t relative output."""
        ghost_file = os.path.join(DATA_DIR, "ghost_files.log")
        code, out, _ = run_cmd(["-r", ghost_file])
        self.assertEqual(code, 0)
        self.assertIn("(+", out)

        code, out, _ = run_cmd(["-t", "relative", ghost_file])
        self.assertEqual(code, 0)
        self.assertIn("0.000", out)

    def test_compact_modes(self):
        """Verify compact 1-line mode (-C and -C strace)."""
        avc_file = os.path.join(DATA_DIR, "selinux_avc.log")
        code, out, _ = run_cmd([avc_file, "-C"])
        self.assertEqual(code, 0)
        first_line = out.strip().splitlines()[0]
        self.assertIn("[SELinux: WOULD DENY { map }]", first_line)
        self.assertIn("[uid=root", first_line)

        code, out, _ = run_cmd([avc_file, "-C", "strace"])
        self.assertEqual(code, 0)
        first_line = out.strip().splitlines()[0]
        self.assertIn("[SELinux: WOULD DENY { map }]", first_line)
        self.assertNotIn("[uid=root", first_line)

    def test_json_lines_output(self):
        """Verify --json produces valid parseable JSON objects with all fields."""
        avc_file = os.path.join(DATA_DIR, "selinux_avc.log")
        code, out, err = run_cmd(["--json", avc_file])
        self.assertEqual(code, 0, f"Error: {err}")
        lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(lines), 0)
        for line in lines:
            obj = json.loads(line)
            self.assertIn("timestamp", obj)
            self.assertIn("credentials", obj)
            if obj.get("syscall") and obj["syscall"].get("name") == "mmap":
                self.assertIn("avc", obj)
                self.assertTrue(obj["avc"]["permissive"])
                self.assertIn("map", obj["avc"]["denied"])

    def test_audit_rule_generation(self):
        """Verify --generate-rules outputs valid auditctl commands."""
        code, out, err = run_cmd(["--generate-rules", "-s", "%perm,unlink", "-P", "/etc"])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertIn("auditctl -a never,exit -F sessionid=", out)
        self.assertIn("-F key=\"audisp_strace\"", out)
        self.assertIn("-F dir=/etc", out)
        self.assertIn("auditctl -D -k", out)

    def test_security_anomalies_and_unknown_types(self):
        """Verify unknown kernel audit record types (Landlock 1423/1424) and anomalies do not crash parser and are formatted properly."""
        anom_file = os.path.join(DATA_DIR, "security_anomalies.log")
        code, out, err = run_cmd([anom_file])
        self.assertEqual(code, 0, f"Error: {err}")
        self.assertEqual(err.strip(), "")

        # Verify crash formatting (strace style)
        self.assertIn("+++ killed by SIGSEGV (core dumped) +++", out)
        self.assertIn("+++ killed by SIGABRT (core dumped) +++", out)

        # Verify ANOM_LINK formatting
        self.assertIn("[ANOM_LINK: protected_symlink] follow_link() = -1 EACCES (Permission denied)", out)

        # Verify Landlock domain correlation and denial formatting
        self.assertIn("3415509<xz>", out)
        self.assertIn('[Landlock: DENIED { fs.read_file }] "/sys/devices/system/cpu/online" = -1 EACCES (Permission denied)', out)
        self.assertIn('landlock: domain=14abfa4b2 (mode=enforcing, blockers=fs.read_file, path="/sys/devices/system/cpu/online", dev="sysfs", ino=1165)', out)

        # Verify Seccomp logging and process termination
        self.assertIn("[SECCOMP: LOG] getpid()", out)
        self.assertIn("[SECCOMP: KILL_PROCESS] mkdirat()", out)
        self.assertIn("+++ killed by SIGSYS (core dumped) +++", out)

        # Verify Landlock network and scoped signal denials
        self.assertIn("[Landlock: DENIED { net.connect_tcp }]", out)
        self.assertIn("kill(3032733, 0) = -1 EPERM(Operation not permitted)  [Landlock: DENIED { scope.signal }]", out)

        # Verify SELinux MAC mode change
        self.assertIn("[SELinux: MODE] Enforcing -> Permissive", out)

        # Verify Fanotify access denial
        self.assertIn('[Fanotify: DENIED]', out)
        self.assertIn('fanotify: access denied (resp=2)', out)

        # Verify VFS linkat protected hardlink denial
        self.assertIn('[ANOM_LINK: protected_hardlink]', out)
        self.assertIn('vfs: protected hardlink blocked (op=linkat)', out)

        # Verify IMA appraisal denial
        self.assertIn('[IMA: DENIED { missing-hash }]', out)
        self.assertIn('ima: op=appraise_data cause=missing-hash file="/usr/local/bin/untrusted_app"', out)

        # Verify EVM metadata denial
        self.assertIn('[EVM: DENIED { invalid-signature }]', out)
        self.assertIn('evm: op=appraise_metadata cause=invalid-signature file="/etc/shadow"', out)

        # Verify AppArmor denial
        self.assertIn('[AppArmor: DENIED { r }]', out)
        self.assertIn('apparmor: profile=/usr/bin/daemon op=open name="/etc/shadow"', out)

    def test_security_anomalies_compact_and_json(self):
        """Verify anomalies format cleanly in compact and JSON modes, and are excluded from -c tally."""
        anom_file = os.path.join(DATA_DIR, "security_anomalies.log")

        # Compact strace mode
        code, out, _ = run_cmd(["-C", "strace", anom_file])
        self.assertEqual(code, 0)
        self.assertIn("+++ killed by SIGSEGV (core dumped) +++", out)
        self.assertNotIn("landlock:", out)

        # JSON mode
        code, out, _ = run_cmd(["--json", anom_file])
        self.assertEqual(code, 0)
        json_objs = [json.loads(line) for line in out.strip().splitlines() if line.strip()]
        self.assertGreater(len(json_objs), 0)
        anomaly_types = {obj.get("anomaly", {}).get("type") for obj in json_objs if "anomaly" in obj}
        self.assertIn("crash", anomaly_types)
        self.assertIn("anom_link", anomaly_types)
        self.assertIn("landlock", anomaly_types)
        self.assertIn("seccomp", anomaly_types)
        self.assertTrue(any("fanotify" in obj for obj in json_objs))
        self.assertTrue(any("ima" in obj for obj in json_objs))
        self.assertTrue(any("evm" in obj for obj in json_objs))
        self.assertTrue(any("apparmor" in obj for obj in json_objs))

        # Summary mode (-c): crashes/anomalies must NOT be tallied into syscall table
        code, out, _ = run_cmd(["-c", anom_file])
        self.assertEqual(code, 0)
        self.assertIn("total", out)
        self.assertNotIn("SIGSEGV", out)
        self.assertNotIn("landlock", out)

    def test_statx_and_statbuf_decoding(self):
        """Verify statx argument flag/mask decoding and PATH struct statx/stat field extraction."""
        statx_log = (
            'type=SYSCALL msg=audit(1793840164.463:8185748): arch=c000003e syscall=332 success=yes exit=0 '
            'a0=ffffff9c a1=7ffedf1ee4f7 a2=900 a3=fff items=1 ppid=3203484 pid=3206395 auid=0 uid=0 gid=0 '
            'comm="stat" exe="/usr/bin/stat"\n'
            'type=CWD msg=audit(1793840164.463:8185748): cwd="/tmp/secret"\n'
            'type=PATH msg=audit(1793840164.463:8185748): item=0 name="." inode=201915981 dev=fd:00 mode=040755 '
            'ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n'
            'type=PROCTITLE msg=audit(1793840164.463:8185748): proctitle=73746174002E\n'
        )
        proc = subprocess.run(
            [AUDISP_STRACE, "-"],
            input=statx_log,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        out = proc.stdout
        self.assertIn(
            'statx(AT_FDCWD</tmp/secret>, ".", AT_STATX_SYNC_AS_STAT|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_ALL, '
            '{stx_uid=0, stx_gid=0, stx_mode=S_IFDIR|0755, stx_ino=201915981, stx_rdev_major=0, stx_rdev_minor=0, '
            'stx_dev_major=253, stx_dev_minor=0, ...}) = 0',
            out,
        )

        # Verify newfstatat from existing representative matrix
        matrix_file = os.path.join(DATA_DIR, "syscall_matrix.log")
        code, matrix_out, _ = run_cmd(["-s", "newfstatat", matrix_file])
        self.assertEqual(code, 0)
        self.assertIn("st_dev=makedev(0xfd, 0x0)", matrix_out)
        self.assertIn("st_mode=S_IFREG|0644", matrix_out)
        self.assertIn("st_ino=", matrix_out)

    def test_fallocate_and_xattr_decoding(self):
        """Verify fallocate bitmask decoding and extended attribute size/flag argument decoding."""
        matrix_file = os.path.join(DATA_DIR, "syscall_matrix.log")

        # fallocate mode decoding
        code, out, _ = run_cmd(["-s", "fallocate", matrix_file])
        self.assertEqual(code, 0)
        self.assertIn("fallocate(4</tmp/audisp_test_cmK4v2/creat_file.txt>, 0, 0, 1024) = 0", out)

        # extended attributes decoding with size argument
        code, out, _ = run_cmd(["-s", "setxattr,fsetxattr,lsetxattr,getxattr,listxattr", matrix_file])
        self.assertEqual(code, 0)
        self.assertIn('setxattr("open_file.txt", ..., ..., 4, ...) = 0', out)
        self.assertIn('getxattr("open_file.txt", ..., ..., 256) = 4', out)
        self.assertIn('listxattr("open_file.txt", ..., 256) = 34', out)
        self.assertIn('fsetxattr(4</tmp/audisp_test_cmK4v2/creat_file.txt>, ..., ..., 4, ...) = 0', out)
        self.assertIn('lsetxattr("symlink_open.txt", ..., ..., 4, ...) = -1 EPERM(Operation not permitted)', out)

        # Synthetic test for composite fallocate modes
        synth_log = (
            'type=SYSCALL msg=audit(1793840164.463:101): arch=c000003e syscall=285 success=yes exit=0 '
            'a0=3 a1=11 a2=0 a3=1000 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:102): arch=c000003e syscall=285 success=yes exit=0 '
            'a0=3 a1=41 a2=0 a3=1000 items=0 comm="test" exe="/test"\n'
        )
        proc = subprocess.run([AUDISP_STRACE, "-"], input=synth_log, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("fallocate(3, FALLOC_FL_KEEP_SIZE|FALLOC_FL_ZERO_RANGE, 0, 4096)", proc.stdout)
        self.assertIn("fallocate(3, FALLOC_FL_KEEP_SIZE|FALLOC_FL_UNSHARE_RANGE, 0, 4096)", proc.stdout)

    def test_fcntl_flag_decoding(self):
        """Verify fcntl file status flags and descriptor flags decoding for F_GETFL, F_SETFL, F_GETFD, F_SETFD."""
        matrix_file = os.path.join(DATA_DIR, "syscall_matrix.log")

        # F_GETFL from actual syscall matrix
        code, out, _ = run_cmd(["-s", "fcntl", matrix_file])
        self.assertEqual(code, 0)
        self.assertIn("fcntl(4</tmp/audisp_test_cmK4v2/creat_file.txt>, F_GETFL) = 0x8002 (flags O_RDWR|O_LARGEFILE)", out)

        # Synthetic tests for F_GETFL, F_SETFL, F_GETFD, F_SETFD
        synth_log = (
            'type=SYSCALL msg=audit(1793840164.463:201): arch=c000003e syscall=72 success=yes exit=0 '
            'a0=3 a1=3 a2=0 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:202): arch=c000003e syscall=72 success=yes exit=34818 '
            'a0=3 a1=3 a2=0 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:203): arch=c000003e syscall=72 success=yes exit=0 '
            'a0=3 a1=4 a2=0 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:204): arch=c000003e syscall=72 success=yes exit=0 '
            'a0=3 a1=4 a2=802 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:205): arch=c000003e syscall=72 success=yes exit=0 '
            'a0=3 a1=1 a2=0 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:206): arch=c000003e syscall=72 success=yes exit=1 '
            'a0=3 a1=1 a2=0 a3=0 items=0 comm="test" exe="/test"\n'
            'type=SYSCALL msg=audit(1793840164.463:207): arch=c000003e syscall=72 success=yes exit=0 '
            'a0=3 a1=2 a2=1 a3=0 items=0 comm="test" exe="/test"\n'
        )
        proc = subprocess.run([AUDISP_STRACE, "-"], input=synth_log, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("fcntl(3, F_GETFL) = 0 (flags O_RDONLY)", proc.stdout)
        self.assertIn("fcntl(3, F_GETFL) = 0x8802 (flags O_RDWR|O_NONBLOCK|O_LARGEFILE)", proc.stdout)
        self.assertIn("fcntl(3, F_SETFL, O_RDONLY) = 0", proc.stdout)
        self.assertIn("fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK) = 0", proc.stdout)
        self.assertIn("fcntl(3, F_GETFD) = 0", proc.stdout)
        self.assertIn("fcntl(3, F_GETFD) = 0x1 (flags FD_CLOEXEC)", proc.stdout)
        self.assertIn("fcntl(3, F_SETFD, FD_CLOEXEC) = 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
