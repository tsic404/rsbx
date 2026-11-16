/*
 * native-proof — the native substrate fixture for real.sh.
 *
 * This is NOT an agent CLI and proves nothing about Multica, OMP, Codex or
 * Claude. It is a small statically linked program used as an exact local
 * executable snapshot, so the sandbox boundary itself can be measured from
 * inside a session:
 *
 *   identity                         print "init=<PID 1 comm> argv0=<argv[0]>"
 *   bytes                            project executable and .so bytes keep
 *                                    their daemon source when read locally
 *   writecfg <local-dir> <id>        write a file into the local config tree
 *                                    and a different one into the project tree
 *   argv0                            exec the project executable with a custom
 *                                    argv[0]; the daemon must still run it
 *   gitflow <id>                     remote git clone, then read the fetched
 *                                    file back through the sandbox
 *   exists <path>                    exit 0 if <path> exists; run it from the
 *                                    project tree to ask the daemon
 *   fd                               execveat a named remote descriptor
 *   deleted                          execveat a deleted descriptor, which must
 *                                    be refused
 *   install <dst> <octal-mode>       copy this executable's exact bytes to a
 *                                    path (local program, remote write)
 *   put <dst> <octal-mode> <text>    write literal bytes to a path
 *   spawn <ready-file> <nonce>       start a detached local child that leaves
 *                                    the entry's process group; the session
 *                                    must clean it up
 *   detached <ready-file> <nonce>    the detached child itself
 *   hold <nonce>                     sleep, ignoring termination signals, so
 *                                    session cancellation has something to own
 *
 * The program is statically linked so it needs no runtime library resolution
 * of its own; the four real CLIs in real.sh exercise that separately. Expected
 * init names come from the caller (CLIENT_INIT/DAEMON_INIT) because the kernel
 * records whatever the deployment actually runs as PID 1.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char *argv0 = "native-proof";

__attribute__((noreturn, format(printf, 1, 2)))
static void die(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "native-proof: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static void check_true(int cond, const char *fmt, ...) {
	if (cond)
		return;
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "native-proof: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static const char *project(void) {
	const char *p = getenv("PROJ");
	return (p && *p) ? p : "/proj";
}

static const char *expect(const char *name, const char *def) {
	const char *v = getenv(name);
	return (v && *v) ? v : def;
}

/* slurp returns the exact file bytes and always appends a NUL terminator that
 * is NOT counted in *len. Callers that compare text can then use strcmp on
 * content known to have no embedded NUL; callers that compare bytes must use
 * *len, so a read that ends early is never mistaken for a short match and a
 * buffer without a terminator is never handed to a string function. */
static char *slurp(const char *path, size_t *len) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	size_t cap = 1 << 16, n = 0;
	char *buf = malloc(cap + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	for (;;) {
		if (n == cap) {
			cap *= 2;
			char *grown = realloc(buf, cap + 1);
			if (!grown) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = grown;
		}
		ssize_t r = read(fd, buf + n, cap - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return NULL;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	buf[n] = '\0';
	*len = n;
	return buf;
}

static int write_all(const char *path, const char *data, size_t len, unsigned mode) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -1;
	while (len) {
		ssize_t w = write(fd, data, len);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		data += w;
		len -= (size_t)w;
	}
	if (fchmod(fd, mode) != 0) {
		close(fd);
		return -1;
	}
	return close(fd);
}

static char *init_comm(void) {
	size_t n = 0;
	char *raw = slurp("/proc/1/comm", &n);
	if (!raw)
		die("read /proc/1/comm: %s", strerror(errno));
	while (n && (raw[n - 1] == '\n' || raw[n - 1] == '\r'))
		raw[--n] = '\0';
	return raw;
}

/* run_capture execs path (never argv[0]) with argv, capturing stdout+stderr.
 * Returns the exit status, or 128+signal. */
static int run_capture(const char *path, char *const argv[], const char *cwd, char **out) {
	int pipefd[2];
	if (pipe(pipefd) != 0)
		return -1;
	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0 || dup2(pipefd[1], STDERR_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		if (cwd && chdir(cwd) != 0)
			_exit(127);
		execv(path, argv);
		_exit(127);
	}
	close(pipefd[1]);
	size_t cap = 4096, n = 0;
	char *buf = malloc(cap);
	if (!buf) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return -1;
	}
	for (;;) {
		if (n == cap) {
			cap *= 2;
			char *grown = realloc(buf, cap);
			if (!grown) {
				free(buf);
				close(pipefd[0]);
				waitpid(pid, NULL, 0);
				return -1;
			}
			buf = grown;
		}
		ssize_t r = read(pipefd[0], buf + n, cap - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(pipefd[0]);
			waitpid(pid, NULL, 0);
			return -1;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(pipefd[0]);
	char *grown = realloc(buf, n + 1);
	if (!grown) {
		free(buf);
		waitpid(pid, NULL, 0);
		return -1;
	}
	buf = grown;
	buf[n] = '\0';
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		free(buf);
		return -1;
	}
	*out = buf;
	if (!WIFEXITED(status))
		return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
	return WEXITSTATUS(status);
}

static void trim(char *s) {
	size_t n = strlen(s);
	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
		s[--n] = '\0';
}

static char *run_expect(const char *path, char *const argv[], const char *cwd, const char *what) {
	char *out = NULL;
	int st = run_capture(path, argv, cwd, &out);
	if (st != 0)
		die("%s failed (status %d): %s", what, st, out ? out : "(no output)");
	trim(out);
	return out;
}

static int mode_identity(void) {
	char *init = init_comm();
	printf("init=%s argv0=%s\n", init, argv0);
	free(init);
	return 0;
}

static int mode_bytes(void) {
	const char *proj = project();
	char path[4096];
	size_t self_len = 0, remote_len = 0;
	char *self = slurp("/proc/self/exe", &self_len);
	if (!self)
		die("/proc/self/exe: %s", strerror(errno));
	snprintf(path, sizeof path, "%s/remote-native", proj);
	char *remote = slurp(path, &remote_len);
	if (!remote)
		die("read %s: %s", path, strerror(errno));
	check_true(self_len == remote_len && memcmp(self, remote, self_len) == 0,
		   "project executable bytes changed (local %zu, remote %zu)", self_len, remote_len);
	free(self);
	free(remote);

	snprintf(path, sizeof path, "%s/project-lib.so", proj);
	size_t so_len = 0;
	char *so = slurp(path, &so_len);
	if (!so)
		die("read %s: %s", path, strerror(errno));
	/* Compare the complete file, not a prefix: the expected content is the
	 * exact bytes real.sh seeds, including its trailing newline. A short read,
	 * an embedded NUL, or a substituted local asset all fail here. */
	static const char so_want[] = "remote shared-object data\n";
	check_true(so_len == sizeof so_want - 1 &&
			   memcmp(so, so_want, sizeof so_want - 1) == 0,
		   "project .so resolved to the wrong source (%zu bytes): [%s]",
		   so_len, so);
	free(so);
	printf("bytes preserved executable=%zu\n", self_len);
	return 0;
}

static int mode_writecfg(const char *local_dir, const char *id) {
	const char *proj = project();
	const char *client_init = expect("CLIENT_INIT", "rsbx");
	char path[4096];
	char *init = init_comm();
	check_true(strcmp(init, client_init) == 0,
		   "local program sees init %q, expected %s", init, client_init);
	free(init);

	snprintf(path, sizeof path, "%s/cfg-%s", local_dir, id);
	check_true(write_all(path, "local configuration\n", strlen("local configuration\n"), 0600) == 0,
		   "write local config %s: %s", path, strerror(errno));
	printf("local=%s\n", path);

	snprintf(path, sizeof path, "%s/artifact-%s", proj, id);
	check_true(write_all(path, "remote artifact\n", strlen("remote artifact\n"), 0644) == 0,
		   "write remote artifact %s: %s", path, strerror(errno));
	printf("remote=%s\n", path);
	return 0;
}

static int mode_argv0(void) {
	const char *proj = project();
	const char *daemon_init = expect("DAEMON_INIT", "rsbxd");
	char path[4096], want[4096];
	snprintf(path, sizeof path, "%s/remote-native", proj);
	char *identity_argv[] = {"custom-remote-name", "identity", NULL};
	snprintf(want, sizeof want, "init=%s argv0=custom-remote-name", daemon_init);
	char *out = run_expect(path, identity_argv, NULL, "custom argv[0] project exec");
	check_true(strcmp(out, want) == 0, "custom argv[0] exec: got [%s], want [%s]", out, want);
	free(out);
	printf("%s\n", want);
	return 0;
}

static int mode_gitflow(const char *id) {
	const char *proj = project();
	char path[4096], want[4096];
	snprintf(want, sizeof want, "%s/clone-%s", proj, id);
	char *clone_argv[] = {"git", "clone", "-q", "origin.git", want, NULL};
	char *out = run_expect("/usr/bin/git", clone_argv, proj, "remote git clone");
	free(out);
	snprintf(path, sizeof path, "%s/clone-%s/lib.c", proj, id);
	size_t len = 0;
	char *lib = slurp(path, &len);
	check_true(lib && strcmp(lib, "lib code\n") == 0,
		   "git-fetched file not visible to the local program: [%s]", lib ? lib : "(missing)");
	free(lib);
	printf("clone=%s\n", want);
	return 0;
}

static int mode_exists(const char *path) {
	struct stat st;
	if (stat(path, &st) != 0)
		return 1;
	return 0;
}

static int mode_fd(void) {
	const char *proj = project();
	char path[4096];
	snprintf(path, sizeof path, "%s/remote-native", proj);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	char *argv[] = {"fd-name", "identity", NULL};
	/* A named descriptor resolves to its stable daemon pathname, so the
	 * router must treat it as the remote executable it names. */
	syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);
	die("execveat named fd: %s (expected init=%s argv0=fd-name)", strerror(errno),
	    expect("DAEMON_INIT", "rsbxd"));
}

static int mode_deleted(void) {
	const char *proj = project();
	char path[4096];
	size_t len = 0;
	char *self = slurp("/proc/self/exe", &len);
	if (!self)
		die("/proc/self/exe: %s", strerror(errno));
	snprintf(path, sizeof path, "%s/deleted-exec-%d", proj, (int)getpid());
	if (write_all(path, self, len, 0700) != 0)
		die("write %s: %s", path, strerror(errno));
	free(self);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	if (unlink(path) != 0)
		die("unlink %s: %s", path, strerror(errno));
	char *argv[] = {"deleted-name", "identity", NULL};
	syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);
	/* No stable daemon pathname exists, so the router must refuse instead of
	 * uploading local bytes or running them here. */
	int err = errno;
	check_true(err == ENOENT || err == EACCES || err == EPERM || err == ENOTDIR,
		   "deleted descriptor was not refused (errno %d)", err);
	printf("refused errno=%d\n", err);
	return 0;
}

static void write_ready(const char *ready) {
	char buf[64];
	int n = snprintf(buf, sizeof buf, "%d\n", (int)getpid());
	if (write_all(ready, buf, (size_t)n, 0600) != 0)
		die("write ready file %s: %s", ready, strerror(errno));
}

/* mode_spawn starts a detached child. The child calls setsid, so it leaves the
 * entry's process group; it ignores the signals the session forwards and
 * sleeps until the session owner kills it. The parent returns only once the
 * child has recorded that it started, so a session that never ran the child
 * cannot look like a successful cleanup.
 *
 * The nonce is carried in the child's argv so the harness can find it from the
 * host afterwards by reading /proc. It is never used to kill anything: cleanup
 * is the session's job, and the check only observes whether a process
 * survived. */
static int mode_spawn(const char *ready, const char *nonce) {
	unlink(ready);
	pid_t pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		if (setsid() < 0)
			_exit(127);
		execl("/proc/self/exe", "native-proof", "detached", ready, nonce, NULL);
		_exit(127);
	}
	for (int i = 0; i < 500; i++) {
		struct stat st;
		if (stat(ready, &st) == 0) {
			printf("detached child started\n");
			return 0;
		}
		usleep(10000);
	}
	die("detached child did not start");
}

static int mode_detached(const char *ready, const char *nonce) {
	(void)nonce;
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	write_ready(ready);
	for (;;) {
		pause();
		return 0;
	}
}

static int mode_hold(const char *nonce) {
	(void)nonce;
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	for (;;) {
		sleep(60);
		return 0;
	}
}

/* find <nonce>: exit 0 and print the pid when a process whose command line
 * carries this nonce as a whole argument exists. Run on the host outside the
 * sandbox; it only observes, it never signals or kills another process.
 *
 * The finder process itself and all of its ancestors are excluded: the shell
 * that invoked `timeout ... find <nonce>` legitimately carries the nonce in
 * its own command line, and that must never count as a live child. */
static int mode_find(const char *nonce) {
	/* ancestors[0] is this process; the chain ends at pid 1. */
	int ancestors[64];
	int nanc = 0, cur = (int)getpid();
	ancestors[nanc++] = cur;
	while (nanc < 64) {
		char path[64];
		snprintf(path, sizeof path, "/proc/%d/stat", cur);
		size_t len = 0;
		char *buf = slurp(path, &len);
		if (!buf)
			break;
		/* Field 4 is ppid; field 2 (comm) may contain spaces, so parse
		 * after the closing parenthesis. */
		char *rest = strrchr(buf, ')');
		int ppid = 0;
		if (rest && sscanf(rest + 1, " %*c %d", &ppid) == 1 && ppid > 0 && ppid != cur) {
			cur = ppid;
			ancestors[nanc++] = cur;
		}
		free(buf);
		if (cur <= 1)
			break;
	}

	DIR *d = opendir("/proc");
	if (!d)
		die("opendir /proc: %s", strerror(errno));
	struct dirent *e;
	int found = 1;
	size_t want = strlen(nonce);
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		int pid = atoi(e->d_name);
		int skip = 0;
		for (int i = 0; i < nanc; i++)
			if (ancestors[i] == pid)
				skip = 1;
		if (skip)
			continue;
		char path[320];
		snprintf(path, sizeof path, "/proc/%s/cmdline", e->d_name);
		size_t len = 0;
		char *buf = slurp(path, &len);
		if (!buf)
			continue;
		int match = 0;
		for (size_t i = 0; i < len && !match;) {
			/* Compare whole NUL-separated arguments: a shell quoting or
			 * grep line that merely mentions the nonce must not match. */
			size_t n = strnlen(buf + i, len - i);
			if (n == want && memcmp(buf + i, nonce, want) == 0)
				match = 1;
			i += n + 1;
		}
		free(buf);
		if (match) {
			printf("%s\n", e->d_name);
			found = 0;
			break;
		}
	}
	closedir(d);
	return found;
}

static int mode_install(const char *dst, const char *octal) {
	size_t len = 0;
	char *self = slurp("/proc/self/exe", &len);
	if (!self)
		die("/proc/self/exe: %s", strerror(errno));
	unsigned mode = (unsigned)strtoul(octal, NULL, 8);
	if (write_all(dst, self, len, mode) != 0)
		die("write %s: %s", dst, strerror(errno));
	free(self);
	printf("installed %s\n", dst);
	return 0;
}

/* put writes exactly the text plus one trailing newline, in one open/write
 * sequence, so the bytes the harness seeds are the bytes mode_bytes expects.
 * The argument is never shell-expanded or re-parsed here. */
static int mode_put(const char *dst, const char *octal, const char *text) {
	unsigned mode = (unsigned)strtoul(octal, NULL, 8);
	size_t len = strlen(text);
	char *buf = malloc(len + 2);
	if (!buf)
		die("alloc %s: %s", dst, strerror(errno));
	memcpy(buf, text, len);
	buf[len] = '\n';
	if (write_all(dst, buf, len + 1, mode) != 0)
		die("write %s: %s", dst, strerror(errno));
	free(buf);
	printf("put %s (%zu bytes)\n", dst, len + 1);
	return 0;
}

int main(int argc, char **argv) {
	if (argc > 0 && argv[0] && *argv[0])
		argv0 = argv[0];
	if (argc < 2) {
		fprintf(stderr, "native-proof: missing mode\n");
		return 2;
	}
	const char *m = argv[1];
	if (strcmp(m, "identity") == 0)
		return mode_identity();
	if (strcmp(m, "bytes") == 0)
		return mode_bytes();
	if (strcmp(m, "writecfg") == 0 && argc == 4)
		return mode_writecfg(argv[2], argv[3]);
	if (strcmp(m, "argv0") == 0)
		return mode_argv0();
	if (strcmp(m, "gitflow") == 0 && argc == 3)
		return mode_gitflow(argv[2]);
	if (strcmp(m, "exists") == 0 && argc == 3)
		return mode_exists(argv[2]);
	if (strcmp(m, "fd") == 0)
		return mode_fd();
	if (strcmp(m, "deleted") == 0)
		return mode_deleted();
	if (strcmp(m, "install") == 0 && argc == 4)
		return mode_install(argv[2], argv[3]);
	if (strcmp(m, "put") == 0 && argc == 5)
		return mode_put(argv[2], argv[3], argv[4]);
	if (strcmp(m, "spawn") == 0 && argc >= 3)
		return mode_spawn(argv[2], argc > 3 ? argv[3] : "");
	if (strcmp(m, "detached") == 0 && argc >= 3)
		return mode_detached(argv[2], argc > 3 ? argv[3] : "");
	if (strcmp(m, "find") == 0 && argc == 3)
		return mode_find(argv[2]);
	if (strcmp(m, "hold") == 0)
		return mode_hold(argc > 2 ? argv[2] : "");
	fprintf(stderr, "native-proof: bad invocation\n");
	return 2;
}
