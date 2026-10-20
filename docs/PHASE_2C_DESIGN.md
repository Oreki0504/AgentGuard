# Phase 2C — Security Contract and Execution Boundary

> Status: Phase 2C-0 design contract. **Documentation only; no Phase 2C enforcement is implemented by this change.**
> Acceptance remains governed by [ROADMAP.md](ROADMAP.md). Do not describe the sandbox as production-ready after merging this document.

## 1. Scope and current baseline

Phase 2C adds privilege reduction, `no_new_privs`, seccomp-BPF, and security-profile resolution to the Phase 2B Linux sandbox. It does not implement the Phase 3 Policy Engine, the Phase 5 Network Gateway, network namespaces, or protection against a compromised trusted Agent Runtime.

The Phase 2B implementation already:

- creates per-Workload user, mount, and PID namespaces with a private root filesystem;
- supervises descendants from a namespace PID 1 and uses cgroup v2 for Workload-wide lifecycle/resource enforcement;
- clears capability bounding, ambient, effective, permitted, and inheritable sets on the locked init OS thread before starting the guest, and locks `SECBIT_NOROOT`;
- switches from the installed launcher AppArmor profile to its local `workload` profile through `/bin/** rCx -> workload` on guest execution;
- reports setup errors rather than falling back to direct execution.

These are implementation observations, **not** proof of the full Phase 2C security baseline. In particular, the current backend does **not** install `no_new_privs` or seccomp filters.

## 2. Workload-facing security contract

Keep the WorkloadSpec backend-neutral. The proposed Go representation for the following implementation stage is:

```go
type SecurityProfile string

const (
    SecurityProfileCodingDefault SecurityProfile = "coding-default"
)

type SecuritySpec struct {
    Profile SecurityProfile
}

type Spec struct {
    // Existing command, environment, timeout, and resource fields.
    Security SecuritySpec
}
```

**Decisions:**

1. The initial sandbox supports only `coding-default`. A profile name is a high-level request for a trusted, fixed bundle of controls, not a guest-supplied policy definition.
2. Do not expose `seccomp_profile`, BPF, capability bits, namespace flags, syscall lists, AppArmor transition names, or `no_new_privs` toggles through `workload.Spec`.
3. Unprivileged guest execution is a mandatory baseline, **not** a caller-configurable `privileged: true/false` choice. A UID of 0 *inside* the user namespace does not imply host root authority; verify capabilities rather than inferring safety from the visible UID.
4. On Phase 2C activation, an omitted/empty profile on the **sandbox path** resolves to `coding-default` in trusted Runtime code. Unknown or explicitly unsupported profile names fail validation. No `none`, `off`, or `unconfined` profile exists.
5. The Phase 3 WorkloadSpec builder may later choose among operator-authorized profiles, but no ordinary request or policy may remove the mandatory Security Baseline.
6. The existing explicit direct-execution developer path remains separate and **must never be presented as a protected sandbox**. A security-profile request must not be handled through that path.

**Migration rule:** Do not expose an active `SecuritySpec.Profile` field to callers before the Runtime and launcher actually enforce it. Otherwise the field would falsely promise protection. This 2C-0 change is intentionally documentation-only; the eventual field, default resolution, backend checks, and integration tests must land together.

## 3. Trusted mapping and validation

```text
ToolRequest + PolicyDecision (future phases)
             |
             v
   validated WorkloadSpec
   Security.Profile = coding-default
             |
             v
 Trusted Sandbox Runtime
   - resolve default / reject unknown profile
   - enforce non-optional baseline
   - construct versioned Linux launch configuration
             |
             v
 Installed, trusted Linux launcher
   - independently validate the profile ID
   - select an implementation-owned enforcement bundle
   - refuse missing/unsupported protections
             |
             v
     confined Workload
```

The Runtime-to-launcher config may carry a canonical profile ID and a version, but no arbitrary filter instructions from Workload input. Validation must occur both before host resource allocation and in the installed launcher. A mismatched launcher/protocol must produce an explicit startup error; it must not silently use Phase 2B behavior.

## 4. Execution and privilege boundary

Preserve the separation between namespace PID 1 (trusted supervisor) and user-controlled Workload code:

```text
Host Runtime
  |  verifies installed launcher, prepares approved files/cgroup
  v
Trusted launcher
  |  establishes new namespaces
  v
Namespace PID 1 (trusted)
  |  mounts private root and pivots
  |  drops mount/capability authority
  |  remains responsible for signals, reaping and exit status
  v
Trusted guest exec bootstrap (new in later 2C stage)
  |  enters the installed AppArmor workload profile on exec
  |  applies/verifies PR_SET_NO_NEW_PRIVS
  |  installs/verifies seccomp-BPF
  |  closes bootstrap-only descriptors on final exec
  v
execve(approved guest command)
  |  filter and no_new_privs are inherited
  v
User-controlled Workload + descendants
```

The existing AppArmor `rCx` transition occurs on exec from the launcher/init profile into its `workload` profile. The `workload` profile uses `rix` for subsequent guest executables. Installing `no_new_privs` **before** the `rCx` transition may prohibit that transition: AppArmor respects `no_new_privs` and permits changes only when it can prove confinement is not weakened. Accordingly, place `no_new_privs` and seccomp installation **after the intended AppArmor transition and before any guest-supplied program or dynamic loader executes**. Test the actual installed AppArmor profile, not just an unconfined development environment.

The bootstrap must be a **trusted, pinned executable** staged by the operator/Runtime at a reserved guest target. User-supplied tool mappings and guest writable mounts must not replace, overlap, or modify it. This bootstrap is an implementation component, not an arbitrary command accepted from `WorkloadSpec`. Its implementation language and packaging (for example, a minimal single-thread executable) are left to a targeted 2C-1 spike; do not assume a multithreaded Go process can safely install a per-thread seccomp filter and then fork/exec without verification.

Seccomp is per-thread unless thread synchronization is explicitly used. Filters are inherited by children and persist across `execve`; `no_new_privs` is inherited and cannot be undone. Do not accidentally confine only one launcher thread while guest execution originates from another.

## 5. Startup handshake and fail-closed behavior

The current Phase 2B `READY` means `os.StartProcess` successfully started the guest. Adding a bootstrap creates a new intermediate exec and invalidates that assumption. The launcher must not forward `READY` merely because it started the bootstrap.

Require the following ordering:

1. Validate profile and protocol before allocating or starting a Workload.
2. Prepare namespaces/rootfs, then complete AppArmor transition into the trusted bootstrap.
3. Install and verify all mandatory protections on the execution path that performs the final guest `execve`.
4. Report setup failure with a bounded `ERROR` stage such as `profile`, `privilege`, or `seccomp`; never emit `READY` first.
5. Only report `READY` after the supervisor has credible evidence of successful protection setup and the handoff to the requested executable. Design a dedicated bootstrap handshake/close-on-exec error channel; **EOF alone is not sufficient**, because a crashed bootstrap also closes its descriptors.
6. Preserve the existing Workload state machine: failure before `READY` means no `WorkloadStarted` audit event and triggers the established cgroup/rootfs cleanup path.

Do not inject production bypass switches through environment variables, omit filters when installation fails, or select the direct runner as a fallback. If the required AppArmor/NNP/seccomp combination is unavailable on a host, reject that sandbox Workload.

## 6. Initial Linux profile and explicit limits

`coding-default` is an implementation-owned minimum privilege/syscall profile. Its first seccomp implementation should:

- validate syscall architecture, including amd64/x32 handling;
- begin with a small auditable deny policy for unnecessary high-risk operations (candidate tests: `ptrace`, `bpf`, `perf_event_open`, `setns`, `unshare`);
- preserve normal shells, Go test guest payloads, dynamic linking, process creation, and exit/reaping functionality where these are expected;
- use deterministic denial actions and fail if the filter cannot be installed;
- be exercised on the tested Linux/amd64 host with the installed AppArmor policy.

Do not describe this initial deny policy as a comprehensive syscall allowlist. In particular, Phase 2C alone does **not** isolate the network: the current Workload still shares host networking, including reachable host services and abstract Unix sockets. Those controls require later network work.

## 7. Test matrix and acceptance evidence

| Area | Required evidence |
| --- | --- |
| Profile mapping | Default resolves to `coding-default` on the sandbox path; unknown/disallowed profiles fail before execution |
| Capabilities | Guest `/proc/self/status` shows `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all zero where supported |
| `no_new_privs` | Guest and fork/exec descendants report `NoNewPrivs: 1`; inability to apply it is a startup failure |
| Seccomp | Guest and descendants have seccomp filter mode; a deliberately forbidden syscall fails, with a control that distinguishes the seccomp denial from an existing AppArmor/capability denial |
| AppArmor compatibility | Actual launcher-to-workload `rCx` transition completes before NNP/filter installation; subsequent execs retain confinement |
| Bootstrap integrity | Guest paths/file exposures cannot shadow bootstrap; bootstrap-only FDs do not leak into guest |
| Failure handling | Unsupported profile, filter-install failure, bootstrap crash, and exec failure never produce false `READY` or `WorkloadStarted` |
| Cleanup | On every setup failure the cgroup and runtime-owned rootfs are cleaned up or an explicit cleanup failure is audited |
| No downgrade | Sandbox launch failure never selects direct execution |

Evidence follows the roadmap rule: **implementation + adversarial test + observable result**. Unit tests are necessary but cannot replace the host integration test with the installed launcher and AppArmor policy.

## 8. Sequencing

- **2C-0 (this change):** freeze the high-level contract, trust boundary, implementation order and tests; no functional code changes.
- **2C-1:** bootstrap packaging/integrity and the verified AppArmor-to-NNP execution transition; capability/NNP tests.
- **2C-2:** install a minimal seccomp filter, architecture checks, failure propagation and adversarial syscall tests.
- **2C-3:** wire `SecuritySpec`, default resolution, backend profile mapping and protocol/version validation **as an atomic functional change**.
- **2C-4:** run host integration/adversarial regression suite; update evidence, documentation and security claims; check Phase 2C acceptance only after all pass.

## References

- Linux kernel documentation: [No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html).
- Linux manual: [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html).
- AppArmor manual: [apparmor.d(5), No-new-privs](https://apparmor.dev/man/apparmor.d/).
- Repository: [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md), [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md), and [ROADMAP.md](ROADMAP.md).
