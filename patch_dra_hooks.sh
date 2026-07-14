#!/bin/bash
# patch_dra_hooks.sh — Apply RKSU manual hooks for DRA-AL00 (4.4.95, MT6739)
# Based on ReSukiSU manual-integrate docs, adapted for 4.4 API surface
set -e

echo "[+] Patching DRA 4.4.95 kernel for RKSU manual hooks..."

###############################################################################
# 1. fs/open.c — faccessat hook (4.19- style: inline in SYSCALL_DEFINE3)
###############################################################################
echo "[1/8] Patching fs/open.c (faccessat hook)..."
sed -i '/^SYSCALL_DEFINE3(faccessat,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
__attribute__((hot))\
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\
\t\t\t\tint *mode, int *flags);\
#endif\
' fs/open.c

# Insert hook call inside faccessat body — right after variable declarations
# DRA 4.4 faccessat: line 347 is SYSCALL_DEFINE3, line 354 has "unsigned int lookup_flags"
# We insert after "unsigned int lookup_flags = LOOKUP_FOLLOW;"
sed -i '/unsigned int lookup_flags = LOOKUP_FOLLOW;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_faccessat(\&dfd, \&filename, \&mode, NULL);\
#endif' fs/open.c

echo "    [✓] faccessat hook applied"

###############################################################################
# 2. fs/exec.c — execve hook (3.14+ style: do_execveat_common exists)
###############################################################################
echo "[2/8] Patching fs/exec.c (execve hook)..."

# Declare extern before do_execve
sed -i '/^int do_execve(struct filename \*filename,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
__attribute__((hot))\
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\
\t\t\t\tvoid *argv, void *envp, int *flags);\
#endif\
' fs/exec.c

# Hook in do_execve — insert after the opening brace
# DRA 4.4: do_execve has argv/envp setup then calls do_execveat_common
sed -i '/struct user_arg_ptr envp = { .ptr.native = __envp };/{
n
s|return do_execveat_common|#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_execveat((int *)AT_FDCWD, \&filename, \&argv, \&envp, 0);\
#endif\
\treturn do_execveat_common|
}' fs/exec.c

# Hook in compat_do_execve if exists
if grep -q 'compat_do_execve' fs/exec.c; then
  sed -i '/\.ptr\.compat = __envp,/{
n
n
s|return do_execveat_common|#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_execveat((int *)AT_FDCWD, \&filename, \&argv, \&envp, 0);\
#endif\
\treturn do_execveat_common|
}' fs/exec.c
  echo "    [✓] compat_do_execve also hooked"
fi

echo "    [✓] execve hook applied"

###############################################################################
# 3. fs/stat.c — stat hook (newfstatat + fstatat64)
###############################################################################
echo "[3/8] Patching fs/stat.c (stat hook)..."

# Declare extern before newfstatat
sed -i '/^#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
__attribute__((hot))\
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\
\t\t\t\tint *flags);\
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);\
#endif\
#endif\
' fs/stat.c

# Hook in newfstatat body — after "int error;"
sed -i '/SYSCALL_DEFINE4(newfstatat,/{
:loop
n
/int error;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_stat(\&dfd, \&filename, \&flag);\
#endif
/int error;/!b loop
}' fs/stat.c

# Hook in fstatat64 if it exists (32-bit compat)
if grep -q 'SYSCALL_DEFINE4(fstatat64' fs/stat.c; then
  sed -i '/SYSCALL_DEFINE4(fstatat64,/{
:loop2
n
/int error;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_stat(\&dfd, \&filename, \&flag);\
#endif
/int error;/!b loop2
}' fs/stat.c
  echo "    [✓] fstatat64 also hooked"
fi

# Hook newfstat return value
if grep -q 'SYSCALL_DEFINE2(newfstat' fs/stat.c; then
  sed -i '/SYSCALL_DEFINE2(newfstat,/{
:loop3
n
/error = cp_new_stat/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_newfstat_ret(\&fd, \&statbuf);\
#endif
/error = cp_new_stat/!b loop3
}' fs/stat.c
  echo "    [✓] newfstat ret hook applied"
fi

echo "    [✓] stat hook applied"

###############################################################################
# 4. fs/read_write.c — sys_read hook (4.19- style: no ksys_read)
###############################################################################
echo "[4/8] Patching fs/read_write.c (read hook)..."

sed -i '/^SYSCALL_DEFINE3(read, unsigned int, fd, char __user \*, buf, size_t, count)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern bool ksu_init_rc_hook __read_mostly;\
extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,\
\t\t\t\tchar __user **buf_ptr, size_t *count_ptr);\
#endif\
' fs/read_write.c

# Insert hook inside read — after "struct fd f = fdget_pos(fd);"
sed -i '/struct fd f = fdget_pos(fd);/{
n
/ssize_t ret = -EBADF;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tif (unlikely(ksu_init_rc_hook))\
\t\tksu_handle_sys_read(fd, \&buf, \&count);\
#endif
}' fs/read_write.c

echo "    [✓] read hook applied"

###############################################################################
# 5. kernel/reboot.c — sys_reboot hook (3.11+ style)
###############################################################################
echo "[5/8] Patching kernel/reboot.c (reboot hook)..."

sed -i '/^SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\
#endif\
' kernel/reboot.c

# Insert hook after "int ret = 0;"
sed -i '/SYSCALL_DEFINE4(reboot,/{
:loop4
n
/int ret = 0;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tksu_handle_sys_reboot(magic1, magic2, cmd, \&arg);\
#endif
/int ret = 0;/!b loop4
}' kernel/reboot.c

echo "    [✓] reboot hook applied"

###############################################################################
# 6. kernel/sys.c — setresuid hook (4.17- style: SYSCALL_DEFINE3 directly)
###############################################################################
echo "[6/8] Patching kernel/sys.c (setresuid hook)..."

sed -i '/^SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\
#endif\
' kernel/sys.c

# Insert hook at start of setresuid body — after "kuid_t kruid, keuid, ksuid;"
sed -i '/SYSCALL_DEFINE3(setresuid,/{
:loop5
n
/kuid_t kruid, keuid, ksuid;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\t(void)ksu_handle_setresuid(ruid, euid, suid);\
#endif
/kuid_t kruid, keuid, ksuid;/!b loop5
}' kernel/sys.c

echo "    [✓] setresuid hook applied"

###############################################################################
# 7. drivers/input/input.c — input hook (optional but recommended)
###############################################################################
echo "[7/8] Patching drivers/input/input.c (input hook)..."

sed -i '/^void input_event(struct input_dev \*dev,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern bool ksu_input_hook __read_mostly;\
extern __attribute__((cold)) int ksu_handle_input_handle_event(\
\t\t\tunsigned int *type, unsigned int *code, int *value);\
#endif\
' drivers/input/input.c

# Insert hook after "unsigned long flags;"
sed -i '/void input_event(struct input_dev \*dev,/{
:loop6
n
/unsigned long flags;/a\
\n#ifdef CONFIG_KSU_MANUAL_HOOK\
\tif (unlikely(ksu_input_hook))\
\t\tksu_handle_input_handle_event(\&type, \&code, \&value);\
#endif
/unsigned long flags;/!b loop6
}' drivers/input/input.c

echo "    [✓] input hook applied"

###############################################################################
# 8. SELinux static symbol exports (4.4 requires all of these)
###############################################################################
echo "[8/8] Exporting SELinux static symbols..."

# write_op[] in selinuxfs.c — remove static
sed -i 's/^static ssize_t (\*write_op\[\])/ssize_t (*write_op[])/' security/selinux/selinuxfs.c
echo "    [✓] write_op exported"

# sel_handle_status_ops in selinuxfs.c — remove static
sed -i 's/^static const struct file_operations sel_handle_status_ops/const struct file_operations sel_handle_status_ops/' security/selinux/selinuxfs.c
echo "    [✓] sel_handle_status_ops exported"

# sel_mutex in selinuxfs.c — remove static
sed -i 's/^static DEFINE_MUTEX(sel_mutex);/DEFINE_MUTEX(sel_mutex);/' security/selinux/selinuxfs.c
echo "    [✓] sel_mutex exported"

# policy_rwlock in ss/services.c — remove static
sed -i 's/^static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c
echo "    [✓] policy_rwlock exported"

# selinux_status_page and selinux_status_lock — check if they exist
if grep -q 'static struct page \*selinux_status_page' security/selinux/ss/services.c; then
  sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c
  echo "    [✓] selinux_status_page exported"
fi
if grep -q 'static DEFINE_MUTEX(selinux_status_lock)' security/selinux/ss/services.c; then
  sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c
  echo "    [✓] selinux_status_lock exported"
fi

echo ""
echo "[+] All RKSU manual hooks applied for DRA 4.4.95!"
echo "[+] Summary:"
echo "    - faccessat hook  (fs/open.c)"
echo "    - execve hook     (fs/exec.c)"
echo "    - stat hook       (fs/stat.c)"
echo "    - read hook       (fs/read_write.c)"
echo "    - reboot hook     (kernel/reboot.c)"
echo "    - setresuid hook  (kernel/sys.c)"
echo "    - input hook      (drivers/input/input.c)"
echo "    - SELinux exports (selinuxfs.c, services.c)"
