#define _BSD_SOURCE /* realpath() */
#define _GNU_SOURCE /* getline() */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>

static void print_status(pid_t pid, int status) {
	printf("[%d] ", pid);
	if (WIFEXITED(status)) {
		printf("exited %d\n", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))  {
		printf("terminated by signal %d (%s) %s\n",
				WTERMSIG(status), strsignal(WTERMSIG(status)),
				(WCOREDUMP(status)) ? "(core dumped)" : "");
	} else if (WIFSTOPPED(status)) {
		printf("stopped by signal %d (%s)\n", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
	} else if (WIFCONTINUED(status)) {
		printf("continued\n");
	} else {
		printf("unknown status %d\n", status);
	}
}

static void* libc_base(pid_t target) {
	char maps_path[32];
	FILE *fmaps;
	void *base = NULL;
	char *line = NULL;
	size_t len = 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", target);

	fmaps = fopen(maps_path, "r");
	if (!fmaps) {
		fprintf(stderr, "Failed to open: %s (%s)\n", maps_path, strerror(errno));
		return NULL;
	}

	while (getline(&line, &len, fmaps) != -1) {
		size_t start;
		size_t end;
		char perms[5] = "";
		char *file;

		file = alloca(strlen(line));
		file[0] = 0;

		if (sscanf(line, "%zx-%zx %4s %*x %*s %*u %s", &start, &end, perms, file) == 4) {
			if (strlen(file) && !strstr(file, "/lib/libc-"))
				continue;
			base = (void*)start;
			break;
		}
	}

	fclose(fmaps);

	return base;
}

static void* libc_dlopen_addr(pid_t target) {
	void *base;
	void *dlopen_sym;
	void *target_base;
	void *target_dlopen_sym;

	base = libc_base(getpid());
	if (!base) {
		fprintf(stderr, "can't find libc base\n");
		return 0;
	}
	target_base = libc_base(target);
	if (!target_base) {
		fprintf(stderr, "can't find target libc base\n");
		return 0;
	}

	dlopen_sym = dlsym(NULL, "__libc_dlopen_mode");
	target_dlopen_sym = (void*)((size_t)dlopen_sym - (size_t)base + (size_t)target_base);

	printf("base: %p dlopen: %p\n", base, dlopen_sym);
	printf("remote_base: %p\n", target_base);
	printf("target_dlopen: %p\n", target_dlopen_sym);
	return target_dlopen_sym;
}

static int ptrace_peek(pid_t target, char *addr, char *data, size_t len) {
	size_t n = 0;
	size_t w;

	assert((size_t)addr % sizeof(size_t) == 0);
	assert(len % sizeof(size_t) == 0);

	while (n < len) {
		errno = 0;
		w = ptrace(PTRACE_PEEKTEXT, target, addr + n, NULL);
		if (errno != 0)
			return -1;

		memcpy(data + n, &w, sizeof(w));
		n += sizeof(w);
	}

	return 0;
}

static int ptrace_poke(pid_t target, char *addr, char *data, size_t len) {
	size_t n = 0;
	size_t w;

	assert((size_t)addr % sizeof(size_t) == 0);
	assert(len % sizeof(size_t) == 0);

	while (n < len) {
		int r;

		memcpy(&w, data + n, sizeof(w));
		r = ptrace(PTRACE_POKETEXT, target, addr + n, w);
		if (r == -1)
			return r;

		n += sizeof(w);
	}

	return 0;
}

static uintptr_t get_sp(struct user_regs_struct* regs) {
#ifdef __x86_64__
	return regs->rsp;
#else /* x86 */
	return regs->esp;
#endif
}

static uintptr_t get_ip(struct user_regs_struct* regs) {
#ifdef __x86_64__
	return regs->rip;
#else /* x86 */
	return regs->eip;
#endif
}

/* call dlopen(filename, flags) in target */
static bool remote_dlopen(pid_t target, const char *filename, int flags) {
	void *dlopen_addr;
	struct user_regs_struct saved_regs, regs;
	char saved_stack[4096], stack[4096];
	int status;
	bool ret = false;

	dlopen_addr = libc_dlopen_addr(target);
	if (!dlopen_addr) {
		return false;
	}

	/* attach */
	if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
		perror("ptrace attach");
		return false;
	}

	do {
		if (waitpid(target, &status, 0) == -1) {
			perror("waitpid");
			goto out;
		}
		print_status(target, status);
	} while (!WIFSTOPPED(status));

	printf("attached %u\n", target);

	/* save registers */
	if (ptrace(PTRACE_GETREGS, target, NULL, &saved_regs) == -1) {
		perror("ptrace getregs");
		goto out;
	}

	/* backup stack */
	if (ptrace_peek(target, (char*) get_sp(&saved_regs), saved_stack, sizeof(saved_stack)) == -1) {
		perror("ptrace_peek");
		goto out;
	}

	memcpy(&regs, &saved_regs, sizeof(regs));

	/* setup call */
	size_t w;

	/* return address */
	w = 0;
	memcpy(stack, &w, sizeof(w));
	assert((strlen(filename) + 1) < ((sizeof(stack) - 512)));
	memcpy(stack + 512, filename, strlen(filename) + 1);


	/* pass arguments */
#ifdef __x86_64__
	regs.rsi = flags;
	regs.rdi = regs.rsp + 512;
	regs.rip = (size_t)dlopen_addr + 2;
#else /* x86 */
	w = regs.esp + 512;
	memcpy(stack + sizeof(size_t), &w, sizeof(w));
	w = flags;
	memcpy(stack + (sizeof(size_t) * 2), &w, sizeof(w));
	regs.eip = (size_t)dlopen_addr + 2;
#endif

	if (ptrace_poke(target, (char*) get_sp(&saved_regs), stack, sizeof(stack)) == -1) {
		perror("ptrace_poke");
		goto out;
	}

	if (ptrace(PTRACE_SETREGS, target, NULL, &regs) == -1) {
		perror("ptrace setregs");
		goto out;
	}

	/* call dlopen */
	if (ptrace(PTRACE_CONT, target, NULL, NULL) == -1) {
		perror("ptrace cont");
		goto out;
	}

	do {
		if (waitpid(target, &status, 0) == -1) {
			perror("waitpid");
			goto out;
		}
		print_status(target, status);
	} while (!WIFSTOPPED(status));

	if(ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1) {
		perror("ptrace getregs");
		goto out;
	}
	printf("ip: %tx\n", get_ip(&regs));

	/* restore stack */
	if (ptrace_poke(target, (char*)get_sp(&saved_regs), saved_stack, sizeof(saved_stack)) == -1) {
		perror("ptrace_poke");
		goto out;
	}

	/* restore registers */
	if (ptrace(PTRACE_SETREGS, target, NULL, &saved_regs) == -1) {
		perror("ptrace setregs");
		goto out;
	}

	ret = true;

out:
	ptrace(PTRACE_DETACH, target, NULL, NULL);
	return ret;
}

static void usage(const char *cmd) {
	printf("usage: %s <pid> <.so>\n", cmd);
	exit(1);
}

int main(int argc, char *argv[]) {

	pid_t pid;
	char *so;

	if (argc < 3)
		usage(argv[0]);

	pid = atoi(argv[1]);
	so = realpath(argv[2], NULL);

	printf("%d %s\n", pid, so);

	if (remote_dlopen(pid, so, RTLD_NOW))
		puts("OK");
	else
		puts("FAILED");

	free(so);
	return 0;
}
