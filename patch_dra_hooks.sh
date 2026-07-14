#!/bin/bash
# patch_dra_hooks.sh — RKSU manual hooks for DRA-AL00 (4.4.95, MT6739)
# Only real symbols from rsuntk/KernelSU v1.0.5-83-legacy
set -e
echo "[+] Patching DRA 4.4.95 kernel for RKSU manual hooks..."

echo "[1/6] Patching fs/open.c (faccessat)..."
python3 - <<'PY'
from pathlib import Path
p = Path("fs/open.c")
lines = p.read_text().splitlines(keepends=True)
text = "".join(lines)
if "ksu_handle_faccessat" not in text:
    out = []
    in_fa = False
    inserted = False
    for line in lines:
        if line.startswith("SYSCALL_DEFINE3(faccessat,"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n")
            out.append("\t\t\t\tint *mode, int *flags);\n")
            out.append("#endif\n")
            in_fa = True
        out.append(line)
        if in_fa and (not inserted) and "unsigned int lookup_flags = LOOKUP_FOLLOW;" in line:
            out.append("\n")
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n")
            out.append("#endif\n")
            inserted = True
            in_fa = False
    if not inserted:
        raise SystemExit("faccessat lookup_flags not found")
    p.write_text("".join(out))
print("    [+] faccessat")
PY

echo "[2/6] Patching fs/exec.c (execve)..."
python3 - <<'PY'
from pathlib import Path
import re
p = Path("fs/exec.c")
t = p.read_text()
if "ksu_handle_execveat" not in t:
    a = "int do_execve(struct filename *filename,"
    if a in t:
        decl = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
            "\t\t\t\tvoid *argv, void *envp, int *flags);\n"
            "#endif\n"
        )
        t = t.replace(a, decl + a, 1)
    m = re.search(r"return do_execveat_common\([^;]+;", t)
    if m and "ksu_handle_execveat((int *)AT_FDCWD" not in t:
        hook = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            "\tksu_handle_execveat((int *)AT_FDCWD, &filename, (void *)&argv, (void *)&envp, 0);\n"
            "#endif\n\t"
        )
        t = t[:m.start()] + hook + t[m.start():]
    p.write_text(t)
print("    [+] execve")
PY

echo "[3/6] Patching fs/stat.c (newfstatat)..."
python3 - <<'PY'
from pathlib import Path
p = Path("fs/stat.c")
lines = p.read_text().splitlines(keepends=True)
text = "".join(lines)
if "ksu_handle_stat" not in text:
    out = []
    in_nf = False
    inserted = False
    for line in lines:
        if line.startswith("SYSCALL_DEFINE4(newfstatat,"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n")
            out.append("#endif\n")
            in_nf = True
        out.append(line)
        if in_nf and (not inserted) and line.strip() == "int error;":
            out.append("\n")
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("\tksu_handle_stat(&dfd, &filename, &flag);\n")
            out.append("#endif\n")
            inserted = True
            in_nf = False
    p.write_text("".join(out))
print("    [+] stat")
PY

echo "[4/6] Patching fs/read_write.c (sys_read via ksu_vfs_read_hook)..."
python3 - <<'PY'
from pathlib import Path
p = Path("fs/read_write.c")
lines = p.read_text().splitlines(keepends=True)
text = "".join(lines)
if "ksu_handle_sys_read" not in text:
    out = []
    in_rd = False
    inserted = False
    for line in lines:
        if line.startswith("SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("extern bool ksu_vfs_read_hook __read_mostly;\n")
            out.append("extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);\n")
            out.append("#endif\n")
            in_rd = True
        out.append(line)
        if in_rd and (not inserted) and "ssize_t ret = -EBADF;" in line:
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("\tif (unlikely(ksu_vfs_read_hook))\n")
            out.append("\t\tksu_handle_sys_read(fd, &buf, &count);\n")
            out.append("#endif\n")
            inserted = True
            in_rd = False
    p.write_text("".join(out))
print("    [+] read")
PY

echo "[5/6] Patching drivers/input/input.c (input)..."
python3 - <<'PY'
from pathlib import Path
p = Path("drivers/input/input.c")
lines = p.read_text().splitlines(keepends=True)
text = "".join(lines)
if "ksu_handle_input_handle_event" not in text:
    out = []
    in_ie = False
    inserted = False
    for line in lines:
        if line.startswith("void input_event(struct input_dev *dev,"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("extern bool ksu_input_hook __read_mostly;\n")
            out.append("extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);\n")
            out.append("#endif\n")
            in_ie = True
        out.append(line)
        if in_ie and (not inserted) and line.strip() == "unsigned long flags;":
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("\tif (unlikely(ksu_input_hook))\n")
            out.append("\t\tksu_handle_input_handle_event(&type, &code, &value);\n")
            out.append("#endif\n")
            inserted = True
            in_ie = False
    p.write_text("".join(out))
print("    [+] input")
PY

echo "[6/6] 4.4 compat: unstatic groups_sort + SELinux statics..."
# groups_sort is static in 4.4.95; RKSU core_hook.c needs it
if grep -q '^static void groups_sort' kernel/groups.c; then
  sed -i 's/^static void groups_sort/void groups_sort/' kernel/groups.c
  echo "    [+] groups_sort unstatic"
else
  echo "    [!] groups_sort pattern not found"
  grep -n 'groups_sort' kernel/groups.c || true
fi

# SELinux static symbol exports (may be needed by RKSU sepolicy)
sed -i 's/^static ssize_t (\*write_op\[\])/ssize_t (*write_op[])/' security/selinux/selinuxfs.c || true
sed -i 's/^static const struct file_operations sel_handle_status_ops/const struct file_operations sel_handle_status_ops/' security/selinux/selinuxfs.c || true
sed -i 's/^static DEFINE_MUTEX(sel_mutex);/DEFINE_MUTEX(sel_mutex);/' security/selinux/selinuxfs.c || true
sed -i 's/^static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c || true
sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c || true
sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c || true

echo "[+] RKSU manual hooks applied (real symbols only; no setresuid/reboot phantoms)"
