/* Linux amd64, single-threaded final exec boundary supervised by Go PID1. */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ENTRY "/.agentguard/bootstrap"
#define LABEL "agentguard-launcher//workload (enforce)"
#define CONFIG_FD 3
#define MAX_CONFIG (64 * 1024)
#define MAX_STRINGS 256

struct config {
    char data[MAX_CONFIG];
    char *cwd;
    char *argv[MAX_STRINGS + 1];
    char *env[MAX_STRINGS + 1];
};

/* Fixed diagnostics never disclose workload arguments/environment. No success
 * channel: only PID1's kernel exec observer may produce READY. */
_Noreturn static void fail(const char *stage)
{
    const char prefix[] = "agentguard-bootstrap: ";
    ssize_t ignored = write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
    ignored = write(STDERR_FILENO, stage, strlen(stage));
    ignored = write(STDERR_FILENO, "\n", 1);
    (void)ignored;
    _exit(125);
}

static void require(int ok, const char *stage)
{
    if (!ok) fail(stage);
}

static int clean_path(const char *path)
{
    if (path[0] != '/' || strlen(path) >= PATH_MAX) return 0;
    if (path[1] == '\0') return 1;
    for (const char *p = path + 1; ; ) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n == 0 || (n == 1 && p[0] == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.')) return 0;
        if (!end) return 1;
        p = end + 1;
    }
}

static uint32_t be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static char *take_string(char **cursor, const char *end)
{
    char *start = *cursor;
    char *nul = memchr(start, 0, (size_t)(end - start));
    require(nul != NULL, "config string");
    *cursor = nul + 1;
    return start;
}

static void parse_config(struct config *c, size_t n)
{
    const unsigned char magic[8] = {'A', 'G', 'B', 'O', 'O', 'T', 0, 1};
    const unsigned char *header = (const unsigned char *)c->data;
    require(n >= 20 && n <= MAX_CONFIG && memcmp(header, magic, 8) == 0,
            "config header");
    uint32_t argc = be32(header + 12), envc = be32(header + 16);
    require(be32(header + 8) == n - 20 && argc > 0 &&
            argc <= MAX_STRINGS && envc <= MAX_STRINGS, "config bounds");
    char *cursor = c->data + 20;
    const char *end = c->data + n;
    c->cwd = take_string(&cursor, end);
    require(clean_path(c->cwd), "config directory");
    for (uint32_t i = 0; i < argc; i++) c->argv[i] = take_string(&cursor, end);
    c->argv[argc] = NULL;
    require(clean_path(c->argv[0]) && strcmp(c->argv[0], "/") != 0 &&
            strcmp(c->argv[0], ENTRY) != 0, "config executable");
    for (uint32_t i = 0; i < envc; i++) {
        c->env[i] = take_string(&cursor, end);
        const char *eq = strchr(c->env[i], '=');
        require(eq && eq != c->env[i], "config environment");
        size_t key = (size_t)(eq - c->env[i]);
        for (uint32_t j = 0; j < i; j++) {
            require(!(strncmp(c->env[j], c->env[i], key) == 0 &&
                      c->env[j][key] == '='), "duplicate environment");
        }
    }
    c->env[envc] = NULL;
    require(cursor == end, "config trailing data");
}

static void read_config(struct config *c)
{
    struct stat st;
    int flags = fcntl(CONFIG_FD, F_GETFL);
    require(flags >= 0 && !(flags & O_PATH) &&
            (flags & O_ACCMODE) == O_RDONLY &&
            fstat(CONFIG_FD, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_nlink == 0 && st.st_size >= 20 && st.st_size <= MAX_CONFIG,
            "config descriptor");
    /* This is a completed local regular file, not a stream. A short read fails
     * closed; retry only EINTR, before any bytes have been returned. */
    ssize_t n;
    do { n = pread(CONFIG_FD, c->data, sizeof(c->data), 0); }
    while (n < 0 && errno == EINTR);
    require(n == st.st_size, "config read");
    char extra;
    require(pread(CONFIG_FD, &extra, 1, st.st_size) == 0, "config length");
    parse_config(c, (size_t)n);
}

static void read_proc(const char *path, char *data, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct statfs fs;
    require(fd >= 0 && fstatfs(fd, &fs) == 0 && fs.f_type == PROC_SUPER_MAGIC,
            "proc descriptor");
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, data + used, size - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        require(n >= 0, "proc read");
        if (n == 0) break;
        used += (size_t)n;
        require(used < size - 1, "proc bounds");
    }
    require(close(fd) == 0 && used > 0 && memchr(data, 0, used) == NULL,
            "proc content");
    data[used] = 0;
}

static void check_label(const char *label)
{
    require(strcmp(label, LABEL) == 0 || strcmp(label, LABEL "\n") == 0,
            "AppArmor label");
}

static void check_caps(const char *status)
{
    const char *names[] = {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        unsigned int found = 0;
        for (const char *line = status; *line; ) {
            const char *end = strchr(line, '\n');
            require(end != NULL, "capability status");
            if (strncmp(line, names[i], strlen(names[i])) == 0) {
                require((size_t)(end - line) == strlen(names[i]) + 17 &&
                        memcmp(line + strlen(names[i]), "\t0000000000000000", 17) == 0,
                        "capabilities");
                found++;
            }
            line = end + 1;
        }
        require(found == 1, "capability sets");
    }
}

static void verify_confinement(void)
{
    char label[256], status[8192];
    read_proc("/proc/self/attr/apparmor/current", label, sizeof(label));
    check_label(label);
    read_proc("/proc/self/status", status, sizeof(status));
    check_caps(status);
    require(strstr(status, "\nThreads:\t1\n") != NULL, "thread count");
}

static void check_trusted_stat(const struct stat *st, int directory)
{
    require(st->st_uid == 0 && !(st->st_mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) &&
            (directory ? S_ISDIR(st->st_mode) :
             (S_ISREG(st->st_mode) && (st->st_mode & 0111))), "trusted path");
}

static void check_readonly(int fd)
{
    struct statvfs fs;
    require(fstatvfs(fd, &fs) == 0 && (fs.f_flag & ST_RDONLY) &&
            (fs.f_flag & ST_NOSUID) && (fs.f_flag & ST_NODEV) &&
            !(fs.f_flag & ST_NOEXEC), "trusted mount");
}

/* Pin every component, as session.go does for host sources. All executable
 * components must be on real read-only mounts; pathname exec cannot race an
 * untrusted writer. PID1 is responsible for the approved dependency set. */
static int open_trusted_executable(const char *path)
{
    require(clean_path(path) && strcmp(path, "/") != 0, "executable path");
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0, "executable root");
    struct stat st;
    require(fstat(fd, &st) == 0, "executable stat");
    check_trusted_stat(&st, 1);
    check_readonly(fd);
    char copy[PATH_MAX];
    memcpy(copy, path + 1, strlen(path));
    char *part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (slash) *slash = 0;
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        if (slash) flags |= O_DIRECTORY;
        int next = openat(fd, part, flags);
        require(next >= 0 && close(fd) == 0, "executable component");
        fd = next;
        require(fstat(fd, &st) == 0, "executable stat");
        check_trusted_stat(&st, slash != NULL);
        check_readonly(fd);
        if (!slash) break;
        part = slash + 1;
    }
    Elf64_Ehdr header;
    require(pread(fd, &header, sizeof(header), 0) == sizeof(header) &&
            memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
            header.e_ident[EI_CLASS] == ELFCLASS64 &&
            header.e_ident[EI_DATA] == ELFDATA2LSB &&
            header.e_ident[EI_VERSION] == EV_CURRENT &&
            header.e_version == EV_CURRENT && header.e_machine == EM_X86_64 &&
            (header.e_type == ET_EXEC || header.e_type == ET_DYN), "executable ELF");
    return fd;
}

static void verify_executables(const char *target)
{
    int self = open_trusted_executable(ENTRY);
    struct stat approved, running;
    require(fstat(self, &approved) == 0 && stat("/proc/self/exe", &running) == 0 &&
            approved.st_dev == running.st_dev && approved.st_ino == running.st_ino,
            "bootstrap identity");
    require(close(self) == 0, "bootstrap close");
    int guest = open_trusted_executable(target);
    require(fstat(guest, &running) == 0 &&
            !(approved.st_dev == running.st_dev && approved.st_ino == running.st_ino),
            "recursive bootstrap");
    require(close(guest) == 0, "executable close");
}

static void verify_stdio(void)
{
    for (int fd = 0; fd <= 2; fd++) {
        int access = fcntl(fd, F_GETFL), flags = fcntl(fd, F_GETFD);
        struct stat st;
        require(access >= 0 && flags >= 0 && !(access & O_PATH) &&
                !(flags & FD_CLOEXEC) && fstat(fd, &st) == 0, "stdio descriptor");
        int mode = access & O_ACCMODE;
        require(mode == O_RDWR || mode == (fd == 0 ? O_RDONLY : O_WRONLY),
                "stdio access");
        if (S_ISCHR(st.st_mode)) {
            struct stat null;
            require(stat("/dev/null", &null) == 0 && S_ISCHR(null.st_mode) &&
                    null.st_rdev == st.st_rdev, "stdio device");
        } else {
            require(S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode), "stdio type");
        }
    }
}

static void close_descriptors(void)
{
    require(syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0, "descriptor close");
    require(fcntl(CONFIG_FD, F_GETFD) == -1 && errno == EBADF, "config close");
    DIR *dir = opendir("/proc/self/fd");
    require(dir != NULL, "descriptor scan");
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            require(errno == 0, "descriptor scan");
            break;
        }
        if (entry->d_name[0] == '.') continue;
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        require(*end == 0 && fd >= 0 && fd <= INT_MAX, "descriptor number");
        if (fd <= 2 || fd == dirfd(dir)) continue;
        require(fcntl((int)fd, F_GETFD) == -1 && errno == EBADF, "descriptor leak");
    }
    int scan_fd = dirfd(dir);
    require(closedir(dir) == 0 && fcntl(scan_fd, F_GETFD) == -1 && errno == EBADF,
            "descriptor scan close");
}

static scmp_filter_ctx prepare_filter(void)
{
    require(seccomp_arch_native() == SCMP_ARCH_X86_64, "filter architecture");
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    require(filter != NULL, "filter allocation");
    require(seccomp_attr_set(filter, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) == 0,
            "filter architecture action");
    /* Initial amd64 shell/Go policy. Filesystem authority comes from mounts and
     * AppArmor. Full confined Shell/Go acceptance is a separate integration gate.
     * No networking, ptrace, mount, BPF, keyring, namespace, or policy mutation. */
    const int calls[] = {
        SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(readv), SCMP_SYS(writev),
        SCMP_SYS(pread64), SCMP_SYS(pwrite64), SCMP_SYS(close), SCMP_SYS(close_range),
        SCMP_SYS(openat), SCMP_SYS(newfstatat), SCMP_SYS(fstat), SCMP_SYS(stat),
        SCMP_SYS(lstat), SCMP_SYS(statx), SCMP_SYS(lseek), SCMP_SYS(access),
        SCMP_SYS(faccessat), SCMP_SYS(readlink), SCMP_SYS(readlinkat), SCMP_SYS(getdents64),
        SCMP_SYS(getcwd), SCMP_SYS(chdir), SCMP_SYS(fchdir), SCMP_SYS(umask),
        SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(rmdir), SCMP_SYS(unlink),
        SCMP_SYS(unlinkat), SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
        SCMP_SYS(ftruncate), SCMP_SYS(fsync), SCMP_SYS(fdatasync),
        SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3), SCMP_SYS(pipe), SCMP_SYS(pipe2),
        SCMP_SYS(poll), SCMP_SYS(ppoll), SCMP_SYS(select), SCMP_SYS(pselect6),
        SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_wait),
        SCMP_SYS(epoll_pwait), SCMP_SYS(eventfd2),
        SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(mprotect), SCMP_SYS(munmap),
        SCMP_SYS(mremap), SCMP_SYS(madvise), SCMP_SYS(mincore),
        SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn),
        SCMP_SYS(rt_sigsuspend), SCMP_SYS(sigaltstack),
        SCMP_SYS(kill), SCMP_SYS(tgkill), SCMP_SYS(tkill),
        SCMP_SYS(futex), SCMP_SYS(set_robust_list), SCMP_SYS(rseq),
        SCMP_SYS(set_tid_address), SCMP_SYS(sched_yield), SCMP_SYS(sched_getaffinity),
        SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep), SCMP_SYS(nanosleep),
        SCMP_SYS(gettimeofday), SCMP_SYS(getrandom), SCMP_SYS(uname),
        SCMP_SYS(getpid), SCMP_SYS(getppid), SCMP_SYS(gettid),
        SCMP_SYS(getuid), SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid),
        SCMP_SYS(getgroups), SCMP_SYS(getpgrp), SCMP_SYS(getpgid), SCMP_SYS(setpgid),
        SCMP_SYS(getrlimit), SCMP_SYS(getrusage),
        SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(wait4), SCMP_SYS(waitid),
        SCMP_SYS(execve), SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(restart_syscall),
    };
    for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
        require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, calls[i], 0) == 0, "filter rule");
    }
    const unsigned long namespaces = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET |
        CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWTIME;
    require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
            SCMP_A0(SCMP_CMP_MASKED_EQ, namespaces | CLONE_PTRACE | CLONE_UNTRACED, 0)) == 0,
            "filter clone");
    /* clone3's pointed-to flags cannot be inspected. ENOSYS lets libc fall back
     * to the argument-filtered clone syscall without granting clone3. */
    require(seccomp_rule_add(filter, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) == 0,
            "filter clone3");
    const int commands[] = {F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD, F_DUPFD_CLOEXEC};
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 1,
                SCMP_A1(SCMP_CMP_EQ, commands[i], 0)) == 0, "filter fcntl");
    }
    require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 1,
            SCMP_A0(SCMP_CMP_EQ, 0x1002 /* ARCH_SET_FS */, 0)) == 0, "filter TLS");
    require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 2,
            SCMP_A0(SCMP_CMP_EQ, 0, 0), SCMP_A2(SCMP_CMP_EQ, 0, 0)) == 0, "filter limits");
    const int queries[] = {PR_GET_NO_NEW_PRIVS, PR_GET_SECCOMP};
    for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
        require(seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 1,
                SCMP_A0(SCMP_CMP_EQ, queries[i], 0)) == 0, "filter prctl");
    }
    return filter;
}

static void install_filter(scmp_filter_ctx filter)
{
    require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs");
    require(seccomp_load(filter) == 0, "filter load");
    require(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2 &&
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "filter verification");
}

int main(int argc, char **argv, char **env)
{
    require(argc == 1 && strcmp(argv[0], ENTRY) == 0 && env[0] == NULL, "invocation");
    verify_stdio();
    verify_confinement();
    struct config c;
    read_config(&c);
    verify_executables(c.argv[0]);
    require(chdir(c.cwd) == 0, "working directory");
    scmp_filter_ctx filter = prepare_filter();
    close_descriptors();
    install_filter(filter);
    /* No allocator/stdio cleanup after filter load. exec discards the context.
     * Its success is not inferred from diagnostics, exit status, or EOF. */
    execve(c.argv[0], c.argv, c.env);
    fail("guest exec");
}
