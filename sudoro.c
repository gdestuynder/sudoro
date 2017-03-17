/*
sudoro is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

sudoro is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sudoro.  If not, see <http://www.gnu.org/licenses/>.

Copyright 2017 Guillaume Destuynder (:kang) <kang@insecure.ws>

What is sudoro?
---------------
sudoro is a setuid program that provides a "read-only" root-shell.
This means it won't be able modify the system state (in theory), for example,
it won't be able to write files, kill processes, change hostname, etc.

It is provided as a convenience tool for admins, to ensure they do
not shoot themselves in the foot while troubleshooting and is not tested
as a security tool (though if you test it, let me know how that goes!).
TLDR: Use with caution!

Example usage
-------------
~/tmp/sudoro ⚡ make && ./sudoro
gcc sudoro.c -o sudoro -lmount
sudo chown root:root sudoro
sudo chmod ug+s sudoro
[root@xps13 sudoro]# kill -9 $BASHPID
[root@xps13 sudoro]# touch aaa /tmp/aaa
touch: cannot touch 'aaa': Read-only file system
touch: cannot touch '/tmp/aaa': Read-only file system
[root@xps13 sudoro]# su
su: cannot set groups: Operation not permitted
*/

#define _GNU_SOURCE
#define SHELL "/bin/bash"
#define PATH_PROC_MOUNTINFO "/proc/self/mountinfo"
#define MOUNT_FLAGS MS_REC|MS_PRIVATE|MS_RDONLY|MS_BIND|MS_NOSUID|MS_REMOUNT
#define MOUNT_FLAGS_RW MS_NOSUID|MS_NODEV|MS_NOATIME

/* Old sched.h */
#ifndef CLONE_NEWCGROUP
#define UNSHARE_FLAGS CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID
#else
#define UNSHARE_FLAGS CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWCGROUP
#endif

#if LIBMOUNT_MAJOR_VERSION <= 2 && LIBMOUNT_MINOR_VERSION <= 29 && LIBMOUNT_PATCH_VERSION < 273
#define OLD_LIBMOUNT 1
#endif

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <libmount/libmount.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <seccomp.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "syscalls.h"

static struct libmnt_cache *tb_cache;

#ifndef OLD_LIBMOUNT
static int uniq_fs_target_cmp(
		struct libmnt_table *tb __attribute__((__unused__)),
		struct libmnt_fs *a,
		struct libmnt_fs *b)
{
	return !mnt_fs_match_target(a, mnt_fs_get_target(b), tb_cache);
}
#endif

int remount_all_fs_ro(void)
{
	int rc;
	struct libmnt_table *tb = NULL;
	struct libmnt_fs *chld = NULL;
	struct libmnt_iter *itr = NULL;
	struct libmnt_fs *fs = NULL;
	const char *sfs = NULL;

	tb = mnt_new_table();
	if (!tb) {
		return errno;
	}
	rc = mnt_table_parse_file(tb, PATH_PROC_MOUNTINFO);
	if (rc !=0 ) {
		return errno;
	}
	tb_cache = mnt_new_cache();
	if (!tb_cache) {
		return errno;
	}

	mnt_table_set_cache(tb, tb_cache);
#ifndef OLD_LIBMOUNT
	mnt_table_uniq_fs(tb, MNT_UNIQ_KEEPTREE, uniq_fs_target_cmp);
#endif
	itr = mnt_new_iter(MNT_ITER_FORWARD);
	if (mnt_table_get_root_fs(tb, &fs) != 0)
		return errno;

	while (mnt_table_next_fs(tb, itr, &fs) == 0) {
		sfs = mnt_fs_get_target(fs);
		if (mount(sfs, sfs, NULL, MOUNT_FLAGS, NULL) != 0) {
			perror("mount read-only failed");
			return errno;
		}
	}
	mnt_free_iter(itr);
#ifndef OLD_LIBMOUNT
	mnt_unref_table(tb);
#endif
	return 0;
}

int install_seccomp_filter(void)
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL) {
		return errno;
	}

	/* Yes, it's a blacklist - most operations need to be performed/allowed
	 * in this case,so we just forbid potentially bad stuff */
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syscall), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(adjtimex), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clock_settime), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(settimeofday), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(create_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(seccomp), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setns), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shutdown), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioperm), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(iopl), 0);
	/* If you speak to unix sockets such as dbus, you can escape easily */
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmsg), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(send), 0);
#ifndef ALLOW_TMP_WRITE
	/* disallow write fd > stderr */
	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_GT, 2));
#endif

	/* Also required for drop_caps */
	prctl(PR_SET_NO_NEW_PRIVS, 1);
	prctl(PR_SET_DUMPABLE, 0);
	return seccomp_load(ctx);
}

int drop_caps(void)
{
	cap_t caps;
	/* Don't really need anything else */
	static cap_value_t cap_values[] = { CAP_DAC_READ_SEARCH, CAP_NET_RAW };
	int cap_size = 2;

	caps = cap_init();
	if (caps == NULL) {
		return errno;
	}

	if (cap_set_flag(caps, CAP_PERMITTED, cap_size, cap_values, CAP_SET) == -1) {
		perror("cap_set_flag permitted");
		return errno;
	}
	if (cap_set_flag(caps, CAP_EFFECTIVE, cap_size, cap_values, CAP_SET) == -1) {
		perror("cap_set_flag effective");
		return errno;
	}
	if (cap_set_flag(caps, CAP_INHERITABLE, cap_size, cap_values, CAP_SET) == -1) {
		perror("cap_set_flag inherited");
		return errno;
	}
	if (cap_set_proc(caps) == -1) {
		perror("cap_set_proc");
		return errno;
	}
	cap_free(caps);

}

void usage(char *argv[])
{
	printf("USAGE %s [EXECUTABLE]\n", argv[0]);
	printf("\nThis program executes a binary with limited privileges, akin to a 'read-only' root-user.\n\
Since this allow for exfiltration of any data on the file-system, this program is not meant\
as a secure container (though it attempts to forcefully deny all dangerous operations).\n");
}

int shell_exec(int argc, char *argv[])
{
	/* Some basic defaults */
	char *menvp[] = {"TERM=xterm-256color",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		NULL};
	char *margv[argc];
	int i;

	if (argc > 1) {
		for (i=1;i<argc;i++) {
			margv[i-1] = argv[i];
		}
		margv[argc-1] = NULL;
	} else {
		margv[0] = SHELL;
		margv[1] = NULL;
	}

	if (access(margv[0], X_OK)) {
		printf("Cannot execute binary file: %s\n\n", margv[0]);
		usage(argv);
		return 1;
	}
	return execve(margv[0], margv, menvp);
}

int check_permissions(char *argv[])
{
	struct stat sb;
	gid_t *group;
	long i, gnr;
	long ngroups_max;

	if (stat(argv[0], &sb) == -1) {
		perror("stat");
		return errno;
	}

	if (sb.st_gid == getgid()) {
		return 0;
	}

	ngroups_max = sysconf(_SC_NGROUPS_MAX) + 1;
	group = (gid_t *)malloc(ngroups_max *sizeof(gid_t));
	gnr = getgroups(ngroups_max, group);

	for (i=0;i<gnr;i++) {
		if (group[i] == sb.st_gid) {
			return 0;
		}
	}
	printf("You are not in the authorized execution group (%u). This incident will be reported.\n", sb.st_gid);
	openlog("sudoro", LOG_PID, LOG_AUTH);
	syslog(LOG_NOTICE, "Unauthorized sudoro execution by user id %u", getuid());
	closelog();
	return 1;
}

int main(int argc, char *argv[], char **envp)
{
	int status;

	pid_t parent = getpid();
	pid_t child;

	/* Are you allowed to run this? */
	if (check_permissions(argv)) exit(EXIT_FAILURE);

	/* Get root */
	if (setgid(getegid())) perror("setegid");
	if (setuid(geteuid())) perror("seteuid");
	if (setgroups(0, NULL)) perror("setgroups");

	/* That's all it takes to enter namespaces */
	if (-1 == unshare(UNSHARE_FLAGS)) {
		perror("unshare failed");
		return errno;
	}

	/* Forking is required for CLONE_NEWPID to work in particular */
	child = fork();

	if (child == -1) {
		perror("fork failed");

	}

	if (child == 0) {
		/* Ensure mount propagates to MS_PRIVATE|MS_REC so that the mount namespace
		 * is really separated/we don't touch the host mount namespace */
		if (mount("/", "/", NULL, MOUNT_FLAGS, NULL) != 0) {
			perror("mount read-only failed");
			return errno;
		}
		/* Remount everything read-only */
		if (remount_all_fs_ro() != 0) {
			perror("remount all read-only failed");
			return errno;
		}

#ifdef ALLOW_TMP_WRITE
		/* Mount fresh/new tmp directories that are writable */
		if (mount("none", "/tmp", "tmpfs", MOUNT_FLAGS_RW, NULL) != 0) {
			perror("tmp mount read-write failed");
			return errno;
		}
#endif

		/* Drop all un-needed capabilities */
		if (drop_caps() != 0) {
			perror("could not drop capabilities");
			return errno;
		}

		/* Reduce kernel attack surface, just in case */
		if (install_seccomp_filter() != 0) {
			perror("seccomp setup failed");
			return errno;
		}

		return shell_exec(argc, argv);
	} else {
		return waitpid(child, &status, 0);
	}
	return errno;
}
