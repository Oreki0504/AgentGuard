# C Bootstrap

The independent, single-threaded C Bootstrap performs the final confinement
checks, installs no_new_privs and seccomp, and executes the approved Guest.
The existing Go Runtime owns resource limits and cleanup; Go PID1 prepares
namespaces/rootfs, confirms Guest exec, forwards signals and reaps descendants.
Building or installing the C artifact alone does not enable the full chain;
the matching Launcher and AppArmor policy are also required.

## Build and installation

Target: Debian/Ubuntu Linux amd64, a C compiler with static PIE support, glibc
static development libraries, binutils, and libseccomp development files.
The Bootstrap has no dynamic interpreter or shared-library dependencies.

```sh
sh scripts/build-bootstrap.sh
sh scripts/test-bootstrap.sh
```

For an already approved, locally extracted libseccomp development package, set
`SECCOMP_INCLUDE_DIR` to its include directory and `SECCOMP_STATIC_LIB` to its
`libseccomp.a`. These are build inputs, never workload-controlled configuration.
No experiment source, binary, policy, or package is fetched by the build.
The ELF checker requires amd64 ELF64 static PIE, RELRO, BIND_NOW, and a
non-executable stack, and rejects an interpreter, shared dependencies and text
relocations. Tests require Go and run as a non-root user; seccomp and NNP affect
only disposable test children. They do not create namespaces, cgroups, mounts,
or AppArmor policies.

After separate operator authorization, `sh scripts/install-bootstrap.sh` run
by a host administrator installs `/usr/local/libexec/agentguard-bootstrap`.
It follows the launcher's root-owned 0755 installation convention, validates
the copied ELF, and atomically renames a temporary file. It does not load or
alter AppArmor. Install the matching Launcher and policy as described in the
[sandbox setup instructions](../README.md#building-and-testing-the-sandbox).
There is no extra hash-pinning scheme. The host-side wiring reuses the
launcher's trusted path/ancestor validation and pins the approved source before
copying it into the sandbox; ELF shape alone does not establish provenance.

The two installation scripts do not provide a transaction across Bootstrap,
Launcher and the loaded AppArmor policy. Before an update, stop new jobs, wait
for existing jobs and their resources to be cleaned up, and save root-owned
copies of all three installed files with their ownership and modes. Also record
the loaded parent/child profiles' enforce modes and policy hashes. Keep this
backup until the update has passed its installed-path checks.

If an update fails, keep job admission stopped. Confirm no AgentGuard processes,
cgroups or rootfs mounts remain before restoring the saved policy file and
reloading it with `apparmor_parser -r -K`; restore both saved executables using
temporary files and atomic renames. Check file contents, ownership and modes,
and the loaded profiles' modes and hashes against the backup before resuming
jobs. Restoring only the policy file does not restore the kernel's loaded
policy. An interrupted or failed recovery requires operator inspection; retain
the backup and do not resume jobs while the installed state is uncertain.

## Bootstrap contract

Only the fixed `/.agentguard/bootstrap` entry may transition through AppArmor
`Cx`. Bootstrap expects exactly that argv[0], no other arguments, and an empty
initial environment. Workload environment comes from the configuration after
Cx, so Cx's environment scrubbing cannot silently change it. The label must be
exactly `agentguard-launcher//workload (enforce)`, with at most one trailing
newline. Unknown stacking, complain, missing policy and proc read failures
are rejected. The AppArmor-specific proc attribute is used; no generic-LSM
fallback silently changes the meaning of this check.

FD 3 carries one anonymous, unlinked, read-only regular configuration file.
The trusted parent must finish writing, close all writable references, and
pass a read-only descriptor. FIFOs, writable descriptors, linked files,
short/trailing input and files larger than 64 KiB are rejected. The parent
retains ownership of startup deadlines and cancellation.

| Offset | Encoding |
| --- | --- |
| 0–7 | Bytes `41 47 42 4f 4f 54 00 01` (`AGBOOT`, NUL, version 1) |
| 8–11 | Big-endian uint32 payload byte length, excluding 20-byte header |
| 12–15 | Big-endian uint32 argc (1–256) |
| 16–19 | Big-endian uint32 envc (0–256) |
| 20 onward | NUL-terminated working directory, argc arguments, envc environment entries |

All bytes must be consumed. The working directory and argv[0] must be clean
absolute paths. Environment keys must be nonempty and unique, with `=` as the
separator, matching the existing Go configuration rules. Embedded NULs cannot
be part of a field. Empty arguments and empty environment values are allowed.
The Go encoder enforces these bounds before starting Bootstrap. Its C wire
version remains 1; the outer JSON launcher/status protocol is version 2.

Both Bootstrap and Guest must be native ELF executables on a real read-only,
nosuid, nodev, executable mount. Each path component is opened with no symlink
following and must be root-owned without group/world write permission. Setuid
and setgid entries are rejected. The running Bootstrap inode must match the
fixed entry. Guest cannot be another path to that inode. Shell scripts are
invoked via an approved ELF shell, e.g. `/bin/sh -c ...`; they are not accepted
as the initial executable. PID1 must prepare the complete approved executable
and dependency set on the immutable layer, with separate writable mounts.
Old Phase 2B launcher/client combinations do not meet this contract; the outer
v2 protocol rejects mixed-version components.

All five capability sets must be zero and the Bootstrap must have one thread.
Standard streams may be pipes, regular files, or `/dev/null`, with appropriate
read/write access and without CLOEXEC. Other character devices, sockets,
directories and missing streams are rejected. The trusted parent authorizes
the objects behind standard streams; Bootstrap cannot infer that authorization
from a file type. No FIFO-only production assumption is made.

The parent rejects missing standard streams before Cx. This check also protects
libc's secure-exec startup, which runs before C main: with AT_SECURE set, glibc
may attempt to repair a closed stdin using `/dev/full`. That device is absent
from the private rootfs, so bypassing the parent's check can abort in libc
before Bootstrap can emit its own diagnostic. The confined closed-stdio
diagnostic test observes this boundary without weakening the rootfs or policy.

After preparation, `close_range(3, UINT_MAX, 0)` closes protocol and source
descriptors. Bootstrap verifies FD 3 is EBADF, scans `/proc/self/fd` for any
remaining descriptor above stderr, and checks the scan descriptor's closure
with `F_GETFD`. Unsupported/failed `close_range` fails closed. Unit tests first
prove their deliberately inherited FDs exist, then check actual closure; they
do not credit AppArmor for closing them.

NNP is set and read back after Cx; libseccomp installs an amd64 default-EPERM
allowlist with bad-architecture kill. Namespace/ptrace clone flags are rejected;
clone3 returns ENOSYS to permit libc's constrained-clone fallback. fcntl,
arch_prctl, prlimit64 and prctl have argument constraints. Networking, mount,
ptrace, BPF, keyring, unshare, and seccomp policy changes are absent. Filesystem
syscalls rely on read-only mounts and AppArmor for object authorization; the
allowlist does not itself authorize paths. Additional workloads and their
dependencies need compatibility testing under the actual confinement policy;
an unprivileged syscall test alone does not establish that compatibility.

Failure emits a fixed stage diagnostic to stderr and exits 125. No argument or
environment values are logged. There is no success/status FD, export mode,
test fault mode, or READY emission in the production binary. PID1 must observe
the specified Guest's kernel exec event and successfully resume/detach before
sending READY. EOF or exit 0 is never exec evidence.

## Exec confirmation and cleanup

Go PID1 locks its OS thread before starting Bootstrap and remains the sole
tracer/reaper. It distinguishes Bootstrap's initial plain SIGTRAP from the
subsequent Guest PTRACE_EVENT_EXEC, binds the event to the expected PID and
former TID, and requires successful DETACH before sending one READY. AppArmor
ptrace rules name only the parent and workload peers. Unexpected events,
identity mismatches, tracing failures, startup deadlines and cancellation fail
startup without a weaker readiness fallback.

Running confirms successful exec and resume; a Guest can exit immediately
afterward. The existing PID1 reaper and signal forwarding continue after
confirmation. Runtime waits for an empty workload cgroup before releasing
rootfs; uncertain cleanup retains resources for inspection.

## Testing

`scripts/test-bootstrap.sh` exercises configuration, labels, capabilities,
executable metadata, standard streams, FD closure, default-deny rules and
shell/Go child execution. NNP/filter setup branches use test-only linker
wrapping. A separate executable without wrappers also installs an inherited
seccomp restriction that makes the kernel reject valid filter loads through
both seccomp and prctl with EACCES. It verifies that the real Bootstrap filter
installer emits its diagnostic and exits 125 instead of continuing toward
Guest exec. This covers kernel policy refusal, not every possible kernel load
failure such as filter-budget exhaustion. No fault-injection mode is compiled
into production.

The same executable tests PTRACE_O_EXITKILL independently: it kills only the
tracer PID and compares the tracee's actual wait status with a no-EXITKILL
control. Both remain in the host PID namespace, without cgroup cleanup or a
parent-death signal. A test subreaper collects all descendants; the positive
control requires kernel SIGKILL, while the negative control must survive until
explicit cleanup. This isolates EXITKILL from the production PID1 and Runner
cleanup mechanisms.

The Go suite checks protocol compatibility, descriptor ownership, exec-event
identity, readiness ordering and lifecycle failures. Host integration tests
also require the installed trusted artifacts, AppArmor and a delegated cgroup
scope. Use the explicit case selector in the sandbox setup instructions.
Ordinary test runs skip privileged cases when those prerequisites are absent.

`scripts/build-phase2c-probe.sh` builds the confined Bootstrap test binary and
generates its alternate executable attachment from the production AppArmor
policy. It compiles the policy offline without installing or loading it. This
probe covers stdio compatibility and exec-observer failure paths; production
Runtime lifecycle tests use the actual Launcher.
