/* Unit and unprivileged filter tests. No test switches exist in the artifact. */
#define main bootstrap_main
#include "bootstrap.c"
#undef main
#include <assert.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int fault;
int __real_prctl(int option, ...);
int __wrap_prctl(int option, unsigned long a, unsigned long b,
                 unsigned long c, unsigned long d)
{
    if (fault == 1 && option == PR_SET_NO_NEW_PRIVS) { errno = EPERM; return -1; }
    if (fault == 2 && option == PR_GET_NO_NEW_PRIVS) return 0;
    if (fault == 4 && option == PR_GET_SECCOMP) return 0;
    /* amd64 register arguments, including libseccomp's possible pointers. */
    return __real_prctl(option, a, b, c, d);
}

int __real_seccomp_load(scmp_filter_ctx filter);
int __wrap_seccomp_load(scmp_filter_ctx filter)
{
    return fault == 3 ? -EACCES : __real_seccomp_load(filter);
}

static unsigned int cases;
static void run(const char *name, void (*test)(void), int expected)
{
    fflush(NULL);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        alarm(15);
        test();
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) {
        fprintf(stderr, "FAIL %s: wait status=%#x expected=%d\n", name, status, expected);
        exit(1);
    }
    cases++;
    printf("PASS %s\n", name);
}

static struct config input;
static size_t input_size;
static void put32(char *p, uint32_t n)
{
    p[0] = (char)(n >> 24); p[1] = (char)(n >> 16);
    p[2] = (char)(n >> 8); p[3] = (char)n;
}
static void make_input(void)
{
    memset(&input, 0, sizeof(input));
    const char payload[] = "/workspace\0/bin/sh\0-c\0printf ok\0A=1\0B=2";
    memcpy(input.data, "AGBOOT\0\1", 8);
    input_size = 20 + sizeof(payload);
    put32(input.data + 8, sizeof(payload));
    put32(input.data + 12, 3);
    put32(input.data + 16, 2);
    memcpy(input.data + 20, payload, sizeof(payload));
}
static void parse(void) { parse_config(&input, input_size); }
static void valid_input(void)
{
    parse();
    assert(strcmp(input.cwd, "/workspace") == 0);
    assert(strcmp(input.argv[0], "/bin/sh") == 0 && input.argv[3] == NULL);
    assert(strcmp(input.env[1], "B=2") == 0 && input.env[2] == NULL);
}

static void label_ok(void) { check_label(LABEL "\n"); }
static void label_stack(void) { check_label("outer//&" LABEL); }
static void label_complain(void) { check_label("agentguard-launcher//workload (complain)"); }
static void label_missing(void) { check_label("unconfined\n"); }
static char caps[] = "Name:\tbootstrap\nCapInh:\t0000000000000000\n"
    "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n"
    "CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n";
static void check_test_caps(void) { check_caps(caps); }
static void caps_missing(void) { check_caps("CapEff:\t0000000000000000\n"); }
static void caps_duplicate(void)
{
    char duplicate[512];
    snprintf(duplicate, sizeof(duplicate), "%sCapEff:\t0000000000000000\n", caps);
    check_caps(duplicate);
}

static void readonly_reject(void)
{
    char name[] = "/tmp/agentguard-readonly-test-XXXXXX";
    int fd = mkstemp(name);
    assert(fd >= 0 && unlink(name) == 0);
    check_readonly(fd);
}
static struct stat metadata;
static void check_metadata(void) { check_trusted_stat(&metadata, 0); }
static void symlink_reject(void) { open_trusted_executable("/proc/self/exe"); }

static void prepare_stdio(void)
{
    int null = open("/dev/null", O_RDWR);
    assert(null >= 0 && dup2(null, 0) == 0 && dup2(null, 1) == 1);
    if (null > 2) close(null);
}
static void stdio_null(void) { prepare_stdio(); verify_stdio(); }
static void stdio_pipe(void)
{
    int p[2];
    assert(pipe(p) == 0 && dup2(p[0], 0) == 0 && dup2(p[1], 1) == 1);
    verify_stdio();
}
static void stdio_file(void)
{
    char name[] = "/tmp/agentguard-stdio-test-XXXXXX";
    int fd = mkstemp(name);
    assert(fd >= 0 && unlink(name) == 0 && dup2(fd, 0) == 0 && dup2(fd, 1) == 1);
    verify_stdio();
}
static void stdio_closed(void) { close(0); verify_stdio(); }
static void stdio_wrong_access(void)
{
    int fd = open("/dev/null", O_WRONLY);
    assert(fd >= 0 && dup2(fd, 0) == 0);
    verify_stdio();
}
static void stdio_ioctl_only(void)
{
    int fd = open("/dev/null", O_ACCMODE);
    assert(fd >= 0 && dup2(fd, 0) == 0);
    verify_stdio();
}
static void stdio_cloexec(void)
{
    assert(fcntl(0, F_SETFD, FD_CLOEXEC) == 0);
    verify_stdio();
}
static void stdio_socket(void)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 && dup2(pair[0], 0) == 0);
    verify_stdio();
}
static void descriptor_cleanup(void)
{
    int source = open("/dev/null", O_RDONLY);
    assert(source >= 0);
    assert(dup2(source, 3) == 3 && dup2(source, 4) == 4 && dup2(source, 1000) == 1000);
    /* Check actual inherited objects before invoking cleanup. */
    assert(fcntl(3, F_GETFD) == 0 && fcntl(4, F_GETFD) == 0 && fcntl(1000, F_GETFD) == 0);
    close_descriptors();
    const int fds[] = {3, 4, 1000};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        assert(fcntl(fds[i], F_GETFD) == -1 && errno == EBADF);
    }
}

static void config_descriptor(void)
{
    char name[] = "/tmp/agentguard-config-test-XXXXXX";
    int writer = mkstemp(name);
    assert(writer >= 0 && write(writer, input.data, input_size) == (ssize_t)input_size);
    int reader = open(name, O_RDONLY);
    assert(reader >= 0 && unlink(name) == 0 && close(writer) == 0);
    assert(dup2(reader, CONFIG_FD) == CONFIG_FD);
    if (reader != CONFIG_FD) close(reader);
    read_config(&input);
    assert(strcmp(input.argv[0], "/bin/sh") == 0);
}
static void config_pipe(void)
{
    int p[2];
    assert(pipe(p) == 0 && dup2(p[0], CONFIG_FD) == CONFIG_FD);
    read_config(&input);
}
static void config_writable(void)
{
    char name[] = "/tmp/agentguard-config-test-XXXXXX";
    int fd = mkstemp(name);
    assert(fd >= 0 && unlink(name) == 0 && dup2(fd, CONFIG_FD) == CONFIG_FD);
    read_config(&input);
}

static void install(void) { install_filter(prepare_filter()); }
static void denied_syscalls(void)
{
    /* Prove this process can make the control syscall before our filter; an
     * outer policy's denial must not be counted as Bootstrap's success. */
    assert(syscall(SYS_getpriority, 0, 0) >= 0);
    install();
    assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    assert(syscall(SYS_getpriority, 0, 0) == -1 && errno == EPERM);
    assert(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
    assert(syscall(SYS_unshare, CLONE_NEWUSER) == -1 && errno == EPERM);
    assert(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0) == -1 && errno == EPERM);
    assert(syscall(SYS_clone3, NULL, 0) == -1 && errno == ENOSYS);
    assert(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1 && errno == EPERM);
    assert(syscall(SYS_seccomp, 0, 0, NULL) == -1 && errno == EPERM);
}
static const char *go_guest;
static void shell_guest(void)
{
    install();
    char *args[] = {"/bin/sh", "-c", "test \"$(/bin/sh -c 'printf child')\" = child", NULL};
    char *env[] = {NULL};
    execve(args[0], args, env);
    fail("test shell exec");
}
static void go_process(void)
{
    install();
    char *args[] = {(char *)go_guest, NULL};
    char *env[] = {NULL};
    execve(go_guest, args, env);
    fail("test Go exec");
}
static void bad_exec(void)
{
    install();
    char *args[] = {"/no-such-agentguard-guest", NULL};
    char *env[] = {NULL};
    execve(args[0], args, env);
    fail("guest exec");
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    go_guest = argv[1];
    assert(clean_path("/") && clean_path("/bin/sh"));
    const char *bad[] = {"", "relative", "//bin/sh", "/bin/../sh", "/bin/./sh", "/bin/"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) assert(!clean_path(bad[i]));
    make_input(); run("valid config", valid_input, 0);
    input.data[7] = 2; run("unknown version", parse, 125);
    make_input(); input_size--; run("truncated frame", parse, 125);
    make_input(); put32(input.data + 12, UINT32_MAX); run("argument overflow", parse, 125);
    make_input(); put32(input.data + 16, UINT32_MAX); run("environment overflow", parse, 125);
    make_input(); put32(input.data + 12, 0); run("missing executable", parse, 125);
    make_input(); input.data[input_size - 1] = 'x'; run("unterminated string", parse, 125);
    make_input(); input.data[input_size - 4] = 'A'; run("duplicate environment", parse, 125);
    make_input(); input.data[20] = '.'; run("relative cwd", parse, 125);
    make_input(); input.data[input_size++] = 0; put32(input.data + 8, input_size - 20);
    run("trailing string", parse, 125);
    make_input(); run("read-only anonymous config", config_descriptor, 0);
    run("config pipe rejected without blocking", config_pipe, 125);
    run("writable config rejected", config_writable, 125);
    run("enforced label", label_ok, 0);
    run("stacked label", label_stack, 125);
    run("complain label", label_complain, 125);
    run("missing label", label_missing, 125);
    run("zero capabilities", check_test_caps, 0);
    const char *names[] = {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char *bit = strstr(caps, names[i]) + strlen(names[i]) + 16;
        *bit = '1'; run(names[i], check_test_caps, 125); *bit = '0';
    }
    run("missing capability set", caps_missing, 125);
    run("duplicate capability set", caps_duplicate, 125);
    metadata.st_uid = 0; metadata.st_mode = S_IFREG | 0755;
    run("trusted executable metadata", check_metadata, 0);
    metadata.st_uid = 1000; run("untrusted executable owner", check_metadata, 125);
    metadata.st_uid = 0; metadata.st_mode |= 0020;
    run("writable executable", check_metadata, 125);
    metadata.st_mode = S_IFREG | 04755; run("setuid executable", check_metadata, 125);
    metadata.st_mode = S_IFLNK | 0777; run("symlink metadata", check_metadata, 125);
    run("writable mount", readonly_reject, 125);
    run("host executable path", symlink_reject, 125);
    run("null stdio", stdio_null, 0);
    run("pipe stdio", stdio_pipe, 0);
    run("regular stdio", stdio_file, 0);
    run("closed stdio", stdio_closed, 125);
    run("wrong stdio access", stdio_wrong_access, 125);
    run("ioctl-only stdio access", stdio_ioctl_only, 125);
    run("CLOEXEC stdio", stdio_cloexec, 125);
    run("socket stdio", stdio_socket, 125);
    run("close and verify inherited descriptors", descriptor_cleanup, 0);
    for (fault = 1; fault <= 4; fault++) run("NNP/filter failure rejects exec", install, 125);
    fault = 0;
    run("default deny and constrained rules", denied_syscalls, 0);
    run("shell and child exec", shell_guest, 0);
    run("Go threads and Go/shell child exec", go_process, 0);
    run("failed exec", bad_exec, 125);
    printf("%u Bootstrap checks passed\n", cases);
    return 0;
}
