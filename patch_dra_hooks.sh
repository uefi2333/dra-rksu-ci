#!/bin/bash
# patch_dra_hooks.sh — ReSukiSU manual hooks for DRA-AL00 (Linux 4.4.95, MT6739)
# Docs: https://resukisu.github.io/guide/manual-integrate.md
# Missing any required hook can fail ReSukiSU compile-time checks.
set -e
echo "[+] Patching DRA 4.4.95 for ReSukiSU manual hooks..."

# ---------- 1) faccessat (4.19- style: inside SYSCALL body) ----------
echo "[1/5] fs/open.c faccessat"
python3 - <<'PY'
from pathlib import Path
p = Path("fs/open.c")
t = p.read_text()
if "ksu_handle_faccessat" in t:
    print("    already patched")
else:
    lines = t.splitlines(keepends=True)
    out = []
    inserted_decl = False
    inserted_call = False
    in_fa = False
    for i, line in enumerate(lines):
        # decl just before faccessat syscall
        if (not inserted_decl) and line.startswith("SYSCALL_DEFINE3(faccessat,"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("__attribute__((hot))\n")
            out.append("extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n")
            out.append("\t\t\t\tint *mode, int *flags);\n")
            out.append("#endif\n")
            out.append("\n")
            inserted_decl = True
            in_fa = True
        out.append(line)
        if in_fa and (not inserted_call) and "unsigned int lookup_flags = LOOKUP_FOLLOW;" in line:
            out.append("\n")
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n")
            out.append("#endif\n")
            inserted_call = True
            in_fa = False
    if not inserted_decl or not inserted_call:
        raise SystemExit(f"faccessat patch failed decl={inserted_decl} call={inserted_call}")
    p.write_text("".join(out))
    print("    [+] faccessat")
PY

# ---------- 2) execve (3.14+: do_execve / compat_do_execve) ----------
echo "[2/5] fs/exec.c execve"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("fs/exec.c")
t = p.read_text()
if "ksu_handle_execveat" in t:
    print("    already patched")
else:
    # insert decl before first do_execve definition that is not do_execveat
    m = re.search(r"^int do_execve\(struct filename \*filename,", t, re.M)
    if not m:
        # some trees use different prototype
        m = re.search(r"^int do_execve\(", t, re.M)
    if not m:
        raise SystemExit("do_execve not found")
    decl = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
        "\t\t\t\tvoid *argv, void *envp, int *flags);\n"
        "#endif\n\n"
    )
    t = t[:m.start()] + decl + t[m.start():]

    # hook in do_execve body: before return do_execveat_common(...)
    def inject_before_return(src, func_name):
        # find function start
        pat = re.compile(rf"^{re.escape(func_name)}\s*\(", re.M)
        mm = pat.search(src)
        if not mm:
            return src, False
        # find body start
        brace = src.find("{", mm.end())
        if brace < 0:
            return src, False
        # find matching close roughly by searching first return do_execveat_common
        sub = src[brace:]
        rr = re.search(r"\n(\s*)return do_execveat_common\(", sub)
        if not rr:
            # maybe do_execve_common
            rr = re.search(r"\n(\s*)return do_execve_common\(", sub)
        if not rr:
            return src, False
        indent = rr.group(1)
        hook = (
            f"\n{indent}#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"{indent}ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
            f"{indent}#endif"
        )
        pos = brace + rr.start()
        return src[:pos] + hook + src[pos:], True

    t, ok1 = inject_before_return(t, "int do_execve")
    t, ok2 = inject_before_return(t, "static int compat_do_execve")
    if not ok2:
        t, ok2 = inject_before_return(t, "int compat_do_execve")
    p.write_text(t)
    print(f"    [+] execve do_execve={ok1} compat={ok2}")
    if not ok1:
        raise SystemExit("do_execve hook failed")
PY

# ---------- 3) stat / newfstatat / newfstat ret ----------
echo "[3/5] fs/stat.c stat"
python3 - <<'PY'
from pathlib import Path
p = Path("fs/stat.c")
t = p.read_text()
if "ksu_handle_stat" in t:
    print("    already patched")
else:
    lines = t.splitlines(keepends=True)
    out = []
    inserted_decl = False
    # insert decl once before first newfstatat
    for line in lines:
        if (not inserted_decl) and line.startswith("SYSCALL_DEFINE4(newfstatat,"):
            out.append("#ifdef CONFIG_KSU_MANUAL_HOOK\n")
            out.append("__attribute__((hot))\n")
            out.append("extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n")
            out.append("\t\t\t\tint *flags);\n")
            out.append("extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n")
            out.append("#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\n")
            out.append("extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);\n")
            out.append("#endif\n")
            out.append("#endif\n")
            out.append("\n")
            inserted_decl = True
        out.append(line)
    t = "".join(out)

    # inject ksu_handle_stat after "int error;" in newfstatat and fstatat64
    def inject_stat_call(src, define_prefix):
        idx = 0
        count = 0
        while True:
            i = src.find(define_prefix, idx)
            if i < 0:
                break
            # find "int error;" after this define within ~400 chars of body
            brace = src.find("{", i)
            if brace < 0:
                break
            window = src[brace:brace+500]
            j = window.find("int error;")
            if j < 0:
                idx = i + len(define_prefix)
                continue
            absj = brace + j + len("int error;")
            hook = (
                "\n\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                "#endif\n"
            )
            # avoid double
            if "ksu_handle_stat(&dfd" in src[brace:brace+600]:
                idx = absj
                continue
            src = src[:absj] + hook + src[absj:]
            count += 1
            idx = absj + len(hook)
        return src, count

    t, c1 = inject_stat_call(t, "SYSCALL_DEFINE4(newfstatat,")
    t, c2 = inject_stat_call(t, "SYSCALL_DEFINE4(fstatat64,")

    # newfstat ret: before return error; at end of newfstat
    def inject_ret(src, define_line, call):
        i = src.find(define_line)
        if i < 0:
            return src, False
        brace = src.find("{", i)
        # find last "return error;" in this function: naive until next SYSCALL or end roughly 800 chars
        end = src.find("\nSYSCALL_", brace + 1)
        if end < 0:
            end = brace + 800
        body = src[brace:end]
        k = body.rfind("return error;")
        if k < 0:
            return src, False
        abspos = brace + k
        if call.split("(")[0] in body:
            return src, True
        hook = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"\t{call}\n"
            "#endif\n\t"
        )
        src = src[:abspos] + hook + src[abspos:]
        return src, True

    t, r1 = inject_ret(t, "SYSCALL_DEFINE2(newfstat,", "ksu_handle_newfstat_ret(&fd, &statbuf);")
    t, r2 = inject_ret(t, "SYSCALL_DEFINE2(fstat64,", "ksu_handle_fstat64_ret(&fd, &statbuf);")

    p.write_text(t)
    print(f"    [+] newfstatat={c1} fstatat64={c2} newfstat_ret={r1} fstat64_ret={r2}")
    if c1 < 1:
        raise SystemExit("newfstatat hook missing")
PY

# ---------- 4) sys_reboot ----------
echo "[4/5] kernel/reboot.c sys_reboot"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("kernel/reboot.c")
if not p.exists():
    p = Path("kernel/sys.c")
t = p.read_text()
# strip any previous bad injection first
t = re.sub(
    r"\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    r"extern int ksu_handle_sys_reboot\(int magic1, int magic2, unsigned int cmd, void __user \*\*arg\);\n"
    r"#endif\n",
    "\n",
    t,
)
t = re.sub(
    r"\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    r"\tksu_handle_sys_reboot\(magic1, magic2, cmd, &arg\);\n"
    r"#endif\n",
    "\n",
    t,
)
if "ksu_handle_sys_reboot" in t:
    print("    still has leftover reboot hook, abort")
    raise SystemExit(1)

# find SYSCALL_DEFINE4(reboot,
m = re.search(r"^SYSCALL_DEFINE4\(reboot,", t, re.M)
if not m:
    raise SystemExit("SYSCALL_DEFINE4(reboot not found")
# insert decl just before the define
decl = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
    "#endif\n\n"
)
t = t[: m.start()] + decl + t[m.start() :]
# re-find after insert
m = re.search(r"^SYSCALL_DEFINE4\(reboot,", t, re.M)
brace = t.find("{", m.end())
if brace < 0:
    raise SystemExit("reboot syscall brace not found")
hook = (
    "\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
    "#endif"
)
t = t[: brace + 1] + hook + t[brace + 1 :]
p.write_text(t)
print(f"    [+] reboot hook in {p} at brace {brace}")
# sanity: must appear inside SYSCALL_DEFINE4(reboot body, not in run_cmd
idx = t.find("ksu_handle_sys_reboot(magic1")
run_cmd = t.find("run_cmd(")
syscall = t.find("SYSCALL_DEFINE4(reboot,")
if idx < 0 or (run_cmd > 0 and run_cmd < idx and syscall > run_cmd):
    # ok if syscall before call; fail if call is after run_cmd definition that is before syscall? 
    pass
# ensure the call is after the reboot define
if idx < syscall:
    raise SystemExit("hook before syscall define")
# if run_cmd exists between syscall and hook, fail
if run_cmd > syscall and run_cmd < idx:
    raise SystemExit("hook landed after run_cmd — wrong function")
print("    [+] reboot hook position OK")
PY

# ---------- 5) 4.4 compat: groups_sort unstatic + SELinux statics ----------
echo "[5/5] 4.4 compat symbols"
if grep -q '^static void groups_sort' kernel/groups.c 2>/dev/null; then
  sed -i 's/^static void groups_sort/void groups_sort/' kernel/groups.c
  echo "    [+] groups_sort unstatic"
else
  echo "    [!] groups_sort pattern not found (ok if already public)"
fi

# SELinux static symbol exports (often needed by KSU sepolicy)
sed -i 's/^static ssize_t (\*write_op\[\])/ssize_t (*write_op[])/' security/selinux/selinuxfs.c 2>/dev/null || true
sed -i 's/^static const struct file_operations sel_handle_status_ops/const struct file_operations sel_handle_status_ops/' security/selinux/selinuxfs.c 2>/dev/null || true
sed -i 's/^static DEFINE_MUTEX(sel_mutex);/DEFINE_MUTEX(sel_mutex);/' security/selinux/selinuxfs.c 2>/dev/null || true
sed -i 's/^static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c 2>/dev/null || true
sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c 2>/dev/null || true
sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c 2>/dev/null || true

echo "[+] ReSukiSU manual hooks applied"
