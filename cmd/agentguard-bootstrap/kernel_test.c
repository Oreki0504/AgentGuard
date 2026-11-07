/* Real-kernel controls: no linker wrapping or production fault switches. */
#define main bootstrap_main
#include "bootstrap.c"
#undef main
#include <assert.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>

static void rejected_filter(void)
{
    scmp_filter_ctx filter = prepare_filter();
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    struct sock_filter allow = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog valid = {.len = 1, .filter = &allow};
    /* The exact valid BPF program succeeds before the inherited restriction. */
    assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &valid) == 0);
    scmp_filter_ctx guard = seccomp_init(SCMP_ACT_ALLOW);
    assert(guard != NULL);
    assert(seccomp_rule_add(guard, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(seccomp), 0) == 0);
    assert(seccomp_rule_add(guard, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(prctl), 1,
                           SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP, 0)) == 0);
    assert(seccomp_load(guard) == 0);
    assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &valid) == -1 && errno == EACCES);
    assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &valid) == -1 && errno == EACCES);
    /* Exercise the real C failure branch; libseccomp calls the actual kernel. */
    install_filter(filter);
    _exit(99); /* Any return would permit Guest exec and fails this control. */
}

static int kernel_filter_failure(void)
{
    int error_pipe[2];
    if (pipe(error_pipe) != 0) return 1;
    pid_t child = fork();
    if (child == 0) {
        close(error_pipe[0]);
        if (dup2(error_pipe[1], STDERR_FILENO) != STDERR_FILENO) _exit(98);
        close(error_pipe[1]);
        rejected_filter();
        _exit(99);
    }
    close(error_pipe[1]);
    if (child < 0) { close(error_pipe[0]); return 1; }
    char diagnostic[256];
    size_t used = 0;
    while (used < sizeof(diagnostic) - 1) {
        ssize_t n = read(error_pipe[0], diagnostic + used, sizeof(diagnostic) - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    diagnostic[used] = 0;
    close(error_pipe[0]);
    int status;
    if (waitpid(child, &status, 0) != child) return 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 125 ||
        strcmp(diagnostic, "agentguard-bootstrap: filter load\n") != 0) {
        fprintf(stderr, "kernel filter refusal: status=%#x stderr=%s\n", status, diagnostic);
        return 1;
    }
    puts("PASS actual kernel EACCES on valid seccomp/prctl filter loads; real Bootstrap exits125 at filter load");
    return 0;
}

struct tracer_ready {
    pid_t tracee;
    unsigned long options;
    ino_t pid_namespace;
};

static void tracer(int notify, unsigned long options)
{
    pid_t child = fork();
    if (child == 0) {
        close(notify);
        int death_signal = -1;
        if (prctl(PR_GET_PDEATHSIG, &death_signal) != 0 || death_signal != 0 ||
            ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(90);
        raise(SIGSTOP);
        for (;;) pause();
    }
    if (child < 0) _exit(91);
    int status;
    struct stat ns;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP || stat("/proc/self/ns/pid", &ns) != 0 ||
        ptrace(PTRACE_SETOPTIONS, child, NULL, options) != 0 ||
        ptrace(PTRACE_CONT, child, NULL, NULL) != 0) goto failed;
    struct tracer_ready ready = {child, options, ns.st_ino};
    if (write(notify, &ready, sizeof(ready)) != sizeof(ready)) goto failed;
    close(notify);
    for (;;) pause();
failed:
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    _exit(92);
}

static int exitkill_control(int enabled)
{
    int notify[2];
    if (pipe(notify) != 0) return 1;
    unsigned long options = PTRACE_O_TRACEEXEC | (enabled ? PTRACE_O_EXITKILL : 0);
    pid_t tracing = fork();
    if (tracing == 0) {
        close(notify[0]);
        tracer(notify[1], options);
        _exit(93);
    }
    close(notify[1]);
    if (tracing < 0) { close(notify[0]); return 1; }
    int result = 1, status = 0, tracer_reaped = 0, tracee_reaped = 0;
    struct tracer_ready ready = {0};
    struct stat ns;
    ssize_t n;
    do { n = read(notify[0], &ready, sizeof(ready)); } while (n < 0 && errno == EINTR);
    close(notify[0]);
    if (n != sizeof(ready) || ready.tracee <= 0 || ready.options != options ||
        stat("/proc/self/ns/pid", &ns) != 0 || ready.pid_namespace != ns.st_ino) goto cleanup;
    /* Kill only the tracer PID. No Runner, cgroup kill, process-group kill,
     * PID-namespace teardown, or parent-death signal can kill this tracee. */
    if (kill(tracing, SIGKILL) != 0 || waitpid(tracing, &status, 0) != tracing) goto cleanup;
    tracer_reaped = 1;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) goto cleanup;
    if (enabled) {
        for (int i = 0; i < 200; i++) {
            pid_t got = waitpid(ready.tracee, &status, WNOHANG);
            if (got == ready.tracee) {
                tracee_reaped = 1;
                if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) result = 0;
                break;
            }
            if (got < 0) break;
            struct timespec tick = {0, 10000000};
            nanosleep(&tick, NULL);
        }
    } else {
        struct timespec grace = {0, 100000000};
        nanosleep(&grace, NULL);
        pid_t got = waitpid(ready.tracee, &status, WNOHANG);
        if (got == 0 && kill(ready.tracee, 0) == 0) result = 0;
        if (got == ready.tracee) tracee_reaped = 1;
    }
cleanup:
    if (!tracer_reaped) {
        kill(tracing, SIGKILL);
        while (waitpid(tracing, &status, 0) < 0 && errno == EINTR) {}
    }
    if (ready.tracee > 0 && !tracee_reaped) {
        kill(ready.tracee, SIGKILL);
        while (waitpid(ready.tracee, &status, 0) < 0 && errno == EINTR) {}
    }
    if (result == 0) {
        printf("PASS EXITKILL=%d tracer=%d tracee=%d same_pid_namespace=%lu: %s; cleanup reaped\n",
               enabled, tracing, ready.tracee, (unsigned long)ready.pid_namespace,
               enabled ? "tracee killed by kernel SIGKILL" : "tracee survived until explicit cleanup");
    } else {
        fprintf(stderr, "FAIL EXITKILL=%d status=%#x\n", enabled, status);
    }
    return result;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getuid() == 0) return 2;
    if (kernel_filter_failure() != 0) return 1;
    /* This single-threaded test process adopts the tracee after tracer death
     * to collect its actual wait status. It is not namespace PID1. */
    if (getpid() == 1 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) return 1;
    if (exitkill_control(0) != 0 || exitkill_control(1) != 0) return 1;
    int status;
    if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) return 1;
    puts("3 real-kernel controls passed; no descendants remain");
    return 0;
}
