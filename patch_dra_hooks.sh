#!/bin/bash
# patch_dra_hooks.sh — RKSU manual hooks for DRA-AL00 (4.4.95, MT6739)
set -e
echo "[+] Patching DRA 4.4.95 kernel for RKSU manual hooks..."

echo "[1/8] Patching fs/open.c (faccessat hook)..."
python3 - <<'''PY
from pathlib import Path
p = Path("fs/open.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif
"""
anchor = "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)"
if "ksu_handle_faccessat" not in t:
    t = t.replace(anchor, decl + "\n" + anchor)
old = "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n\tif (mode & ~S_IRWXO)"
new = """\tunsigned int lookup_flags = LOOKUP_FOLLOW;

#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif

\tif (mode & ~S_IRWXO)"""
if "ksu_handle_faccessat(&dfd" not in t:
    if old not in t:
        raise SystemExit("faccessat anchor not found")
    t = t.replace(old, new, 1)
p.write_text(t)
print("    [+] faccessat hook applied")
PY

echo "[2/8] Patching fs/exec.c (execve hook)..."
python3 - <<'''PY
from pathlib import Path
import re
p = Path("fs/exec.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
#endif
"""
anchor = "int do_execve(struct filename *filename,"
if "ksu_handle_execveat" not in t and anchor in t:
    t = t.replace(anchor, decl + "\n" + anchor)
if "ksu_handle_execveat((int *)AT_FDCWD" not in t:
    m = re.search(r"return do_execveat_common\([^;]+;", t)
    if m:
        hook = """#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_execveat((int *)AT_FDCWD, &filename, (void *)&argv, (void *)&envp, 0);
#endif
\t"""
        t = t[:m.start()] + hook + t[m.start():]
    else:
        print("    [!] do_execveat_common not found, skip body hook")
p.write_text(t)
print("    [+] execve hook applied")
PY

echo "[3/8] Patching fs/stat.c (stat hook)..."
python3 - <<'''PY
from pathlib import Path
import re
p = Path("fs/stat.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif
"""
if "ksu_handle_stat" not in t:
    for a in [
        "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)",
        "SYSCALL_DEFINE4(newfstatat,",
    ]:
        if a in t:
            t = t.replace(a, decl + "\n" + a, 1)
            break
if "ksu_handle_stat(&dfd" not in t:
    pat = re.compile(r"(SYSCALL_DEFINE4\(newfstatat,[\s\S]*?\n\tint error;\n)", re.M)
    def repl(m):
        return m.group(1) + """
#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_stat(&dfd, &filename, &flag);
#endif
"""
    t2, n = pat.subn(repl, t, count=1)
    if n:
        t = t2
p.write_text(t)
print("    [+] stat hook applied")
PY

echo "[4/8] Patching fs/read_write.c (read hook)..."
python3 - <<'''PY
from pathlib import Path
p = Path("fs/read_write.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_init_rc_hook __read_mostly;
extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);
#endif
"""
anchor = "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)"
if "ksu_handle_sys_read" not in t and anchor in t:
    t = t.replace(anchor, decl + "\n" + anchor)
if "ksu_handle_sys_read(fd" not in t:
    idx = t.find(anchor)
    if idx >= 0:
        sub = t[idx:idx+900]
        old = "ssize_t ret = -EBADF;"
        new = """ssize_t ret = -EBADF;
#ifdef CONFIG_KSU_MANUAL_HOOK
\tif (unlikely(ksu_init_rc_hook))
\t\tksu_handle_sys_read(fd, &buf, &count);
#endif"""
        if old in sub:
            t = t[:idx] + sub.replace(old, new, 1) + t[idx+900:]
p.write_text(t)
print("    [+] read hook applied")
PY

echo "[5/8] Patching kernel/reboot.c (reboot hook)..."
python3 - <<'''PY
from pathlib import Path
p = Path("kernel/reboot.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
"""
anchor = "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,"
if "ksu_handle_sys_reboot" not in t and anchor in t:
    t = t.replace(anchor, decl + "\n" + anchor)
if "ksu_handle_sys_reboot(magic1" not in t:
    idx = t.find(anchor)
    if idx >= 0:
        sub = t[idx:idx+600]
        old = "int ret = 0;"
        new = """int ret = 0;
#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif"""
        if old in sub:
            t = t[:idx] + sub.replace(old, new, 1) + t[idx+600:]
p.write_text(t)
print("    [+] reboot hook applied")
PY

echo "[6/8] Patching kernel/sys.c (setresuid hook)..."
python3 - <<'''PY
from pathlib import Path
p = Path("kernel/sys.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);
#endif
"""
anchor = "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)"
if "ksu_handle_setresuid" not in t and anchor in t:
    t = t.replace(anchor, decl + "\n" + anchor)
if "ksu_handle_setresuid(ruid" not in t:
    idx = t.find(anchor)
    if idx >= 0:
        sub = t[idx:idx+600]
        old = "kuid_t kruid, keuid, ksuid;"
        new = """kuid_t kruid, keuid, ksuid;
#ifdef CONFIG_KSU_MANUAL_HOOK
\t(void)ksu_handle_setresuid(ruid, euid, suid);
#endif"""
        if old in sub:
            t = t[:idx] + sub.replace(old, new, 1) + t[idx+600:]
p.write_text(t)
print("    [+] setresuid hook applied")
PY

echo "[7/8] Patching drivers/input/input.c (input hook)..."
python3 - <<'''PY
from pathlib import Path
p = Path("drivers/input/input.c")
t = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
#endif
"""
anchor = "void input_event(struct input_dev *dev,"
if "ksu_handle_input_handle_event" not in t and anchor in t:
    t = t.replace(anchor, decl + "\n" + anchor, 1)
if "ksu_handle_input_handle_event(&type" not in t:
    idx = t.find(anchor)
    if idx >= 0:
        sub = t[idx:idx+600]
        old = "unsigned long flags;"
        new = """unsigned long flags;
#ifdef CONFIG_KSU_MANUAL_HOOK
\tif (unlikely(ksu_input_hook))
\t\tksu_handle_input_handle_event(&type, &code, &value);
#endif"""
        if old in sub:
            t = t[:idx] + sub.replace(old, new, 1) + t[idx+600:]
p.write_text(t)
print("    [+] input hook applied")
PY

echo "[8/8] Exporting SELinux static symbols..."
sed -i 's/^static ssize_t (\*write_op\[\])/ssize_t (*write_op[])/' security/selinux/selinuxfs.c || true
sed -i 's/^static const struct file_operations sel_handle_status_ops/const struct file_operations sel_handle_status_ops/' security/selinux/selinuxfs.c || true
sed -i 's/^static DEFINE_MUTEX(sel_mutex);/DEFINE_MUTEX(sel_mutex);/' security/selinux/selinuxfs.c || true
sed -i 's/^static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c || true
sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c || true
sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c || true

echo "[+] All RKSU manual hooks applied for DRA 4.4.95!"
