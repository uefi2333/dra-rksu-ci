#!/bin/bash
# patch_dra_hooks.sh — Apply RKSU manual hooks for DRA-AL00 (4.4.95, MT6739)
set -e

echo "[+] Patching DRA 4.4.95 kernel for RKSU manual hooks..."

###############################################################################
# Helper: insert-after-first-match (sed with line number to avoid ambiguity)
###############################################################################

###############################################################################
# 1. fs/open.c — faccessat hook
###############################################################################
echo "[1/8] Patching fs/open.c (faccessat hook)..."

# Declare extern before SYSCALL_DEFINE3(faccessat
sed -i '/^SYSCALL_DEFINE3(faccessat,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\
				int *mode, int *flags);\
#endif\
' fs/open.c

# Insert hook after "int res;" inside faccessat (unique anchor in this file)
sed -i '/SYSCALL_DEFINE3(faccessat,/,/^}/{
/int res;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	ksu_handle_faccessat(\&dfd, \&filename, \&mode, NULL);\
#endif
}' fs/open.c

echo "    [✓] faccessat hook applied"

###############################################################################
# 2. fs/exec.c — execve hook
###############################################################################
echo "[2/8] Patching fs/exec.c (execve hook)..."

# Declare extern before do_execve
sed -i '/^int do_execve(struct filename \*filename,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\
				void *argv, void *envp, int *flags);\
#endif\
' fs/exec.c

# Hook in do_execve — insert before "return do_execveat_common"
sed -i '/do_execve(struct filename \*filename,/,/^}/{
/return do_execveat_common/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	ksu_handle_execveat((int *)AT_FDCWD, \&filename, (void *)&argv, (void *)&envp, 0);\
#endif
}' fs/exec.c

echo "    [✓] execve hook applied"

###############################################################################
# 3. fs/stat.c — stat hook
###############################################################################
echo "[3/8] Patching fs/stat.c (stat hook)..."

# Declare extern before newfstatat
sed -i '/^#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\
				int *flags);\
#endif\
' fs/stat.c

# Hook in newfstatat — after "int error;"
sed -i '/SYSCALL_DEFINE4(newfstatat,/,/^}/{
/int error;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	ksu_handle_stat(\&dfd, \&filename, \&flag);\
#endif
}' fs/stat.c

echo "    [✓] stat hook applied"

###############################################################################
# 4. fs/read_write.c — sys_read hook
###############################################################################
echo "[4/8] Patching fs/read_write.c (read hook)..."

sed -i '/^SYSCALL_DEFINE3(read, unsigned int, fd, char __user \*, buf, size_t, count)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern bool ksu_init_rc_hook __read_mostly;\
extern int ksu_handle_sys_read(unsigned int fd,\
				char __user **buf_ptr, size_t *count_ptr);\
#endif\
' fs/read_write.c

# Hook inside read — after "ssize_t ret = -EBADF;"
sed -i '/SYSCALL_DEFINE3(read,/,/^}/{
/ssize_t ret = -EBADF;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	if (unlikely(ksu_init_rc_hook))\
		ksu_handle_sys_read(fd, \&buf, \&count);\
#endif
}' fs/read_write.c

echo "    [✓] read hook applied"

###############################################################################
# 5. kernel/reboot.c — sys_reboot hook
###############################################################################
echo "[5/8] Patching kernel/reboot.c (reboot hook)..."

sed -i '/^SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\
#endif\
' kernel/reboot.c

sed -i '/SYSCALL_DEFINE4(reboot,/,/^}/{
/int ret = 0;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	ksu_handle_sys_reboot(magic1, magic2, cmd, \&arg);\
#endif
}' kernel/reboot.c

echo "    [✓] reboot hook applied"

###############################################################################
# 6. kernel/sys.c — setresuid hook
###############################################################################
echo "[6/8] Patching kernel/sys.c (setresuid hook)..."

sed -i '/^SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\
#endif\
' kernel/sys.c

sed -i '/SYSCALL_DEFINE3(setresuid,/,/^}/{
/kuid_t kruid, keuid, ksuid;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	(void)ksu_handle_setresuid(ruid, euid, suid);\
#endif
}' kernel/sys.c

echo "    [✓] setresuid hook applied"

###############################################################################
# 7. drivers/input/input.c — input hook
###############################################################################
echo "[7/8] Patching drivers/input/input.c (input hook)..."

sed -i '/^void input_event(struct input_dev \*dev,/i\
#ifdef CONFIG_KSU_MANUAL_HOOK\
extern bool ksu_input_hook __read_mostly;\
extern int ksu_handle_input_handle_event(\
			unsigned int *type, unsigned int *code, int *value);\
#endif\
' drivers/input/input.c

sed -i '/void input_event(struct input_dev \*dev,/,/^}/{
/unsigned long flags;/a\
\
#ifdef CONFIG_KSU_MANUAL_HOOK\
	if (unlikely(ksu_input_hook))\
		ksu_handle_input_handle_event(\&type, \&code, \&value);\
#endif
}' drivers/input/input.c

echo "    [✓] input hook applied"

###############################################################################
# 8. SELinux static symbol exports (4.4 requires all of these)
###############################################################################
echo "[8/8] Exporting SELinux static symbols..."

sed -i 's/^static ssize_t (\*write_op\[\])/ssize_t (*write_op[])/' security/selinux/selinuxfs.c
sed -i 's/^static const struct file_operations sel_handle_status_ops/const struct file_operations sel_handle_status_ops/' security/selinux/selinuxfs.c
sed -i 's/^static DEFINE_MUTEX(sel_mutex);/DEFINE_MUTEX(sel_mutex);/' security/selinux/selinuxfs.c
sed -i 's/^static DEFINE_RWLOCK(policy_rwlock);/DEFINE_RWLOCK(policy_rwlock);/' security/selinux/ss/services.c

if grep -q 'static struct page \*selinux_status_page' security/selinux/ss/services.c; then
  sed -i 's/^static struct page \*selinux_status_page;/struct page *selinux_status_page;/' security/selinux/ss/services.c
fi
if grep -q 'static DEFINE_MUTEX(selinux_status_lock)' security/selinux/ss/services.c; then
  sed -i 's/^static DEFINE_MUTEX(selinux_status_lock);/DEFINE_MUTEX(selinux_status_lock);/' security/selinux/ss/services.c
fi

echo ""
echo "[+] All RKSU manual hooks applied for DRA 4.4.95!"
