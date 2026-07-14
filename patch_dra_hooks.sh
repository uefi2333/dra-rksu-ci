#!/bin/bash
# patch_dra_hooks.sh — ReSukiSU full manual integrate for DRA-AL00 (Linux 4.4.95)
# Docs: https://resukisu.github.io/guide/manual-integrate.md
set -euo pipefail
echo "[+] Patching DRA 4.4.95 for ReSukiSU (hooks + static exports)..."

# ============================================================================
# 0) Static symbol exports (required if !CONFIG_KALLSYMS_ALL)
#    check file paths come from kernel/tools/static_export_check.mk
# ============================================================================
echo "[0] SELinux static symbol exports"

unstatic() {
  # $1=file $2=regex_static_line_prefix_to_strip (python)
  local f="$1"
  local pattern="$2"
  local label="$3"
  if [ ! -f "$f" ]; then
    echo "    [!] missing $f ($label) — skip"
    return 0
  fi
  python3 - "$f" "$pattern" "$label" <<'PY'
import re, sys
from pathlib import Path
path, pattern, label = sys.argv[1], sys.argv[2], sys.argv[3]
t = Path(path).read_text()
# pattern is the FULL static form that check greps for; remove leading static
# We accept flexible whitespace
orig = t
# common forms
repls = [
    (r'^static ssize_t \(\*write_op\[\]\)', r'ssize_t (*write_op[])'),
    (r'^static const struct file_operations sel_handle_status_ops', r'const struct file_operations sel_handle_status_ops'),
    (r'^static struct page \*selinux_status_page\s*;', r'struct page *selinux_status_page;'),
    (r'^static DEFINE_MUTEX\(selinux_status_lock\);', r'DEFINE_MUTEX(selinux_status_lock);'),
    (r'^static DEFINE_MUTEX\(sel_mutex\);', r'DEFINE_MUTEX(sel_mutex);'),
    (r'^static DEFINE_RWLOCK\(policy_rwlock\);', r'DEFINE_RWLOCK(policy_rwlock);'),
    (r'^static struct security_operations selinux_ops', r'struct security_operations selinux_ops'),
    (r'^static void security_dump_masked_av\b', r'void security_dump_masked_av'),
    (r'^static void context_struct_compute_av\b', r'void context_struct_compute_av'),
]
changed = 0
for a,b in repls:
    nt, n = re.subn(a, b, t, flags=re.M)
    if n:
        t = nt
        changed += n
if t != orig:
    Path(path).write_text(t)
    print(f"    [+] unstatic in {path} ({changed} rules, {label})")
else:
    # show whether already non-static
    print(f"    [=] no static match in {path} ({label}) — maybe already exported or different layout")
PY
}

# paths from static_export_check.mk
unstatic security/selinux/selinuxfs.c "write_op" "write_op/sel_handle_status_ops/sel_mutex"
unstatic security/selinux/ss/status.c "status_page" "selinux_status_page/lock"
unstatic security/selinux/ss/services.c "policy_rwlock" "policy_rwlock (+legacy status_page if here)"
unstatic security/selinux/hooks.c "selinux_ops" "selinux_ops (<4.2)"

# belt: also try services.c for status symbols if status.c absent/old trees
if [ -f security/selinux/ss/services.c ]; then
  sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c || true
  sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c || true
fi

# ============================================================================
# 1) faccessat — 4.19- style
# ============================================================================
echo "[1] fs/open.c faccessat"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("fs/open.c")
t = p.read_text()
if "ksu_handle_faccessat" in t:
    print("    already patched")
else:
    m = re.search(r"^SYSCALL_DEFINE3\(faccessat,", t, re.M)
    if not m:
        raise SystemExit("faccessat syscall not found")
    decl = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
        "\t\t\t\tint *mode, int *flags);\n"
        "#endif\n\n"
    )
    t = t[:m.start()] + decl + t[m.start():]
    m = re.search(r"^SYSCALL_DEFINE3\(faccessat,", t, re.M)
    brace = t.find("{", m.end())
    # insert after opening brace
    hook = (
        "\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "#endif"
    )
    t = t[:brace+1] + hook + t[brace+1:]
    p.write_text(t)
    print("    [+] faccessat at syscall brace")
PY

# ============================================================================
# 2) execve (3.14+)
# ============================================================================
echo "[2] fs/exec.c execve"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("fs/exec.c")
t = p.read_text()
if "ksu_handle_execveat" in t:
    print("    already patched")
else:
    m = re.search(r"^int do_execve\s*\(", t, re.M)
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

    def inject(src, sig):
        mm = re.search(rf"^{re.escape(sig)}\s*\(", src, re.M)
        if not mm:
            # try without return type exact
            mm = re.search(rf"{re.escape(sig)}\s*\(", src, re.M)
        if not mm:
            return src, False
        brace = src.find("{", mm.end())
        sub = src[brace:]
        rr = re.search(r"\n(\s*)return do_execveat_common\(", sub)
        if not rr:
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

    t, ok1 = inject(t, "int do_execve")
    t, ok2 = inject(t, "static int compat_do_execve")
    if not ok2:
        t, ok2 = inject(t, "int compat_do_execve")
    if not ok1:
        raise SystemExit("do_execve hook failed")
    p.write_text(t)
    print(f"    [+] execve do_execve={ok1} compat={ok2}")
PY

# ============================================================================
# 3) stat / newfstat ret
# ============================================================================
echo "[3] fs/stat.c stat"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("fs/stat.c")
t = p.read_text()
if "ksu_handle_stat" in t and "ksu_handle_newfstat_ret" in t:
    print("    already patched")
else:
    # strip partial
    for s in ["ksu_handle_stat", "ksu_handle_newfstat_ret", "ksu_handle_fstat64_ret"]:
        pass
    m = re.search(r"^SYSCALL_DEFINE4\(newfstatat,", t, re.M)
    if not m:
        raise SystemExit("newfstatat not found")
    decl = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n"
        "\t\t\t\tint *flags);\n"
        "extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n"
        "#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\n"
        "extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);\n"
        "#endif\n"
        "#endif\n\n"
    )
    if "ksu_handle_stat" not in t:
        t = t[:m.start()] + decl + t[m.start():]

    def inject_after_int_error(src, define):
        i = 0
        count = 0
        while True:
            pos = src.find(define, i)
            if pos < 0:
                break
            brace = src.find("{", pos)
            if brace < 0:
                break
            # only first ~40 lines of body
            window_end = min(len(src), brace + 600)
            window = src[brace:window_end]
            if "ksu_handle_stat(&dfd" in window:
                i = window_end
                continue
            j = window.find("int error;")
            if j < 0:
                # try insert right after brace
                hook = (
                    "\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                    "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                    "#endif"
                )
                src = src[:brace+1] + hook + src[brace+1:]
                count += 1
                i = brace + len(hook) + 1
                continue
            absj = brace + j + len("int error;")
            hook = (
                "\n\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                "#endif\n"
            )
            src = src[:absj] + hook + src[absj:]
            count += 1
            i = absj + len(hook)
        return src, count

    t, c1 = inject_after_int_error(t, "SYSCALL_DEFINE4(newfstatat,")
    t, c2 = inject_after_int_error(t, "SYSCALL_DEFINE4(fstatat64,")

    def inject_ret(src, define, call):
        pos = src.find(define)
        if pos < 0:
            return src, False
        brace = src.find("{", pos)
        # end at next SYSCALL_DEFINE or EOF window
        end = src.find("\nSYSCALL_", brace + 1)
        if end < 0:
            end = min(len(src), brace + 900)
        body = src[brace:end]
        if call.split("(")[0] in body:
            return src, True
        k = body.rfind("return error;")
        if k < 0:
            # try before final return
            k = body.rfind("return ")
            if k < 0:
                return src, False
        abspos = brace + k
        hook = (
            "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"\t{call}\n"
            "#endif\n\t"
        )
        return src[:abspos] + hook + src[abspos:], True

    t, r1 = inject_ret(t, "SYSCALL_DEFINE2(newfstat,", "ksu_handle_newfstat_ret(&fd, &statbuf);")
    t, r2 = inject_ret(t, "SYSCALL_DEFINE2(fstat64,", "ksu_handle_fstat64_ret(&fd, &statbuf);")
    p.write_text(t)
    print(f"    [+] newfstatat={c1} fstatat64={c2} newfstat_ret={r1} fstat64_ret={r2}")
    if c1 < 1 or not r1:
        raise SystemExit("stat hooks incomplete")
PY

# ============================================================================
# 4) sys_reboot — MUST be inside SYSCALL_DEFINE4(reboot), never run_cmd
# ============================================================================
echo "[4] kernel/reboot.c sys_reboot"
python3 - <<'PY'
from pathlib import Path
import re
p = Path("kernel/reboot.c")
if not p.exists():
    p = Path("kernel/sys.c")
t = p.read_text()
# strip any previous injections
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
    r"#endif\n?",
    "\n",
    t,
)
m = re.search(r"^SYSCALL_DEFINE4\(reboot,", t, re.M)
if not m:
    raise SystemExit("SYSCALL_DEFINE4(reboot not found")
decl = (
    "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
    "#endif\n\n"
)
t = t[:m.start()] + decl + t[m.start():]
m = re.search(r"^SYSCALL_DEFINE4\(reboot,", t, re.M)
brace = t.find("{", m.end())
hook = (
    "\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
    "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
    "#endif"
)
t = t[:brace+1] + hook + t[brace+1:]
# verify position: call must be after reboot define and before next SYSCALL_/run_cmd if any after
call = t.find("ksu_handle_sys_reboot(magic1")
syscall = t.find("SYSCALL_DEFINE4(reboot,")
run_cmd = t.find("\nstatic int run_cmd(")
if run_cmd < 0:
    run_cmd = t.find("\nint run_cmd(")
if call < syscall:
    raise SystemExit("reboot hook before define")
# if run_cmd is between syscall and call → bad
if run_cmd > syscall and run_cmd < call:
    raise SystemExit("reboot hook landed in/after run_cmd — abort")
# ensure next function after call is not wrong: call should be within ~400 chars of brace
if call - brace > 500:
    raise SystemExit(f"reboot hook too far from brace: {call-brace}")
p.write_text(t)
print(f"    [+] reboot hook OK in {p} (brace dist {call-brace})")
PY

# ============================================================================
# 5) 4.4 compat: groups_sort
# ============================================================================
echo "[5] groups_sort unstatic"
if grep -q '^static void groups_sort' kernel/groups.c 2>/dev/null; then
  sed -i 's/^static void groups_sort/void groups_sort/' kernel/groups.c
  echo "    [+] groups_sort"
else
  echo "    [=] groups_sort already public or different"
fi

# ============================================================================
# 6) VERIFY against ReSukiSU compile-time checks
# ============================================================================
echo "[6] verify against ReSukiSU check patterns"
python3 - <<'PY'
from pathlib import Path
import re, sys
fails = []

def must_contain(path, needle, why):
    t = Path(path).read_text() if Path(path).exists() else ""
    if needle not in t:
        fails.append(f"MISSING {needle} in {path} ({why})")
    else:
        print(f"    OK hook {needle} @ {path}")

def must_not_contain(path, needle, why):
    if not Path(path).exists():
        print(f"    skip missing {path}")
        return
    t = Path(path).read_text()
    if needle in t:
        # allow in comments? no
        fails.append(f"STILL STATIC: {needle!r} in {path} ({why})")
    else:
        print(f"    OK export cleared {needle!r} @ {path}")

# hooks required by manual_hook_check.mk (with AUTO_* default y)
must_contain("fs/exec.c", "ksu_handle_execveat", "execve")
must_contain("fs/open.c", "ksu_handle_faccessat", "faccessat")
must_contain("fs/stat.c", "ksu_handle_stat", "stat")
must_contain("fs/stat.c", "ksu_handle_newfstat_ret", "newfstat ret")
must_contain("fs/stat.c", "ksu_handle_fstat64_ret", "fstat64 ret")
must_contain("kernel/reboot.c", "ksu_handle_sys_reboot", "reboot")

# static_export_check.mk patterns (must NOT remain)
must_not_contain("security/selinux/selinuxfs.c", "static ssize_t (*write_op[])", "write_op")
must_not_contain("security/selinux/selinuxfs.c", "static const struct file_operations sel_handle_status_ops", "sel_handle_status_ops")
# status.c is what the makefile checks for 4.4 without selinux_state
if Path("security/selinux/ss/status.c").exists():
    must_not_contain("security/selinux/ss/status.c", "static struct page *selinux_status_page", "status_page")
    must_not_contain("security/selinux/ss/status.c", "static DEFINE_MUTEX(selinux_status_lock)", "status_lock")
must_not_contain("security/selinux/selinuxfs.c", "static DEFINE_MUTEX(sel_mutex)", "sel_mutex")
must_not_contain("security/selinux/ss/services.c", "static DEFINE_RWLOCK(policy_rwlock)", "policy_rwlock")

# reboot not in run_cmd
rb = Path("kernel/reboot.c").read_text()
# crude: extract function containing the call
idx = rb.find("ksu_handle_sys_reboot(magic1")
before = rb[max(0, idx-800):idx]
if "run_cmd" in before.split("SYSCALL_DEFINE4(reboot")[-1] if "SYSCALL_DEFINE4(reboot" in before else before:
    # if between last SYSCALL reboot and call there is run_cmd — bad already checked
    pass
if re.search(r"run_cmd[\s\S]{0,400}ksu_handle_sys_reboot", rb):
    # only fail if run_cmd appears immediately before call without SYSCALL reboot in between
    m = re.search(r"(run_cmd|SYSCALL_DEFINE4\(reboot,)[\s\S]{0,500}?ksu_handle_sys_reboot", rb)
    if m and m.group(1).startswith("run_cmd"):
        fails.append("reboot hook still near run_cmd")

if fails:
    print("VERIFY FAILED:")
    for f in fails:
        print(" -", f)
    sys.exit(1)
print("[+] all verify checks passed")
PY

echo "[+] ReSukiSU manual integrate complete"
