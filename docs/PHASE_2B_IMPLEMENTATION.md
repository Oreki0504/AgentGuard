# Phase 2B — Linux Sandbox Implementation Plan

> **Status:** Draft for implementation review (2026-10-10). No acceptance criteria are marked complete by this document.
>
> **Purpose:** Convert the verified namespace/rootfs experiments into an integrated Linux Sandbox Backend without disrupting Phase 1 or Phase 2A.
>
> **Document boundaries:** `ROADMAP.md` defines scope and acceptance criteria; `ARCHITECTURE.md` defines the system-level boundaries; `DESIGN_PRINCIPLES.md` defines security invariants; `THREAT_MODEL.md` records threats. This document specifies the Phase 2B implementation sequence, contracts, and tests.

---

## 1. Starting Point

### Existing components to preserve

- `internal/workload/`: workload identity, backend-neutral `WorkloadSpec`, lifecycle and resources.
- `internal/runner/`: process execution, stdio, context/timeout/cancellation, and startup hooks.
- `internal/runtime/`: orchestration, cgroup ownership, lifecycle transitions, audit, and Runtime-owned rootfs allocations.
- `internal/cgroupv2/`: Phase 2A resource enforcement and Workload-wide termination.
- `internal/audit/`: structured events.

Do not rename these components, replace the Phase 2A runtime, or introduce Policy/Gateway packages solely for this refactor.

### Experimental evidence already obtained locally

The `cmd/agentguard-ns-probe/` experiments have demonstrated:

- Rootless user, mount, and PID namespaces with explicit UID/GID mappings under a delegated cgroup scope.
- Private mount propagation, a minimal tmpfs root, bind mounts, `pivot_root`, an isolated `/proc`, and restricted host visibility.
- Read-only workspace and writable scratch *under the tested execution conditions*.
- PID 1 signal behavior, reparenting and zombie reaping experiments.
- Namespace + cgroup inheritance and normal cleanup.
- A reproduced rootfs leak when a launcher owning its own rootfs is killed; subsequent Runtime-owned rootfs and timeout cleanup tests passed.
- An outer Runner-to-Probe startup handshake that rejects an explicit setup failure without waiting for Workload timeout.

These are **probe and experimental-integration results**, not evidence that a production Sandbox Backend exists. The remote repository may lag local, uncommitted implementation changes.

### Known gaps to resolve during the refactor

1. The Probe executes a fixed demonstration shell script, not the requested Workload command.
2. The running workload itself is PID 1; a general-purpose, trusted init/reaper is not integrated.
3. The Probe's internal `FD_CLOEXEC`/EOF path can treat an early exit as successful `execve`.
4. The outer startup protocol is prototype-only and does not yet establish a general command-exec contract.
5. Filesystem exposures are hard-coded in the Probe rather than expressed as validated, per-Workload inputs.
6. AppArmor's experimental broad profile and user-namespace capabilities are **not** adequate for hostile workloads. A prior experiment successfully remounted a read-only bind writable while `CAP_SYS_ADMIN` was available.

**Rule:** Freeze the Probe as a reference and regression laboratory; put new production-oriented work in the real Launcher/Backend. Do not copy the fault-injection switches into the shipping Launcher.

---

## 2. Target Boundaries and Source Layout

```text
cmd/
  agentguard/                     # existing CLI
  agentguard-ns-probe/            # frozen experiments; no production dependency
  agentguard-launcher/            # new, host-installed trusted launcher

internal/
  workload/                       # existing: Workload and WorkloadSpec
  runner/                         # existing: host process execution
  runtime/
    runtime.go                    # existing: lifecycle orchestration
    rootfs.go                     # existing: host-side allocation/ownership
    sandbox/
      linux/
        namespace.go              # namespace creation and ID maps
        mount.go                  # mount operations / propagation
        rootfs.go                 # guest root assembly and pivot_root
        init.go                   # trusted PID 1 supervisor and reaping
        protocol.go               # typed startup/control messages
  cgroupv2/                       # existing: cgroup v2 enforcement
  audit/                          # existing: audit events
```

These are proposed responsibilities, **not a requirement to create empty files or packages immediately**. Extract files as real functions are migrated.

### Responsibility separation

| Owner | Responsibilities | Must not do |
| --- | --- | --- |
| `workload` | Define validated, backend-neutral execution requirements | Know cgroup paths, namespace flags, or FD numbers |
| `runtime` | Allocate and track resources; create cgroup; launch; transition states; perform final cleanup | Parse stdout to find cleanup paths |
| `runner` | Launch host-side executable, provide cgroup placement, await trusted startup status, collect result and handle cancellation | Treat `cmd.Start()` as sandbox-ready |
| `sandbox/linux` | Apply Linux namespaces, prepare mounts/rootfs, implement trusted sandbox init and internal protocol | Decide high-level policy |
| `agentguard-launcher` | Thin, installed and authenticated entry point into Linux setup | Contain exploratory fault-injection behavior |
| `agentguard-ns-probe` | Mechanism experiments and diagnostic reproduction | Become a runtime dependency |

Import direction must stay acyclic. In particular, `sandbox/linux` must not import `runtime`; pass a small internal launch configuration instead.

---

## 3. Execution Contract

### 3.1 Direct execution remains unchanged

The existing Runner path remains available for Phase 1 tests and controlled internal use. A request must **explicitly** choose sandbox execution; failures must not fall back to direct host execution.

During migration, an experimental feature flag may select the new Launcher. After integration, a separate explicit direct-execution path can be retained for development, never as an implicit fallback.

### 3.2 Workload input versus Linux launch configuration

The current Go `workload.Spec` provides command, arguments, working directory, environment, timeout, and resources. Phase 2B must run **that command**, not the Probe's fixed shell script.

Use a validated, internal Linux launch configuration containing at least:

- Workload ID and intended argv;
- explicit environment and guest working directory;
- Runtime-allocated rootfs location;
- filesystem exposures with host source, guest target, and read-only/read-write intent;
- bounded startup timeout and protocol version.

The Linux-specific paths and protocol fields belong to this internal configuration, not to the public `WorkloadSpec`. Any necessary filesystem additions to `WorkloadSpec` should be small and backend-neutral, so callers can request explicit workspace exposure without supplying raw namespace or mount flags.

Only trusted runtime configuration may select the installed Launcher executable or authorize host mount sources. Agent-controlled strings must not be interpreted as trusted Launcher parameters.

For the first integration, a minimal approved rootfs/tool profile is sufficient; supporting arbitrary host-installed executables and full distro rootfs images is **not** a Phase 2B prerequisite.

### 3.3 Host installation and trust

The trusted Launcher is installed at a controlled, root-owned executable path. New executable paths require an updated, narrowly scoped AppArmor user-namespace policy; the Probe's experimental `flags=(unconfined)` profile is not acceptable as a final security configuration.

Use a systemd-delegated cgroup subtree for ordinary-user Runtime management. Avoid changing global unprivileged-userns settings as an implementation shortcut.

**Important limitation:** A rootless user namespace is not, by itself, a safe boundary against an actively hostile workload. Phase 2B must not be advertised as ready for untrusted Agents while privilege reduction and syscall hardening remain incomplete.

---

## 4. Startup and Process Model

```text
WorkloadSpec
    |
    v
Runtime (trusted host process)
    |-- allocate rootfs directory and store path
    |-- create Workload cgroup
    |-- prepare validated launcher configuration
    v
Runner -- starts installed Launcher inside Workload cgroup
    |                     |
    |   control channel   v
    |<---------------- Launcher parent
    |                       |
    |                       +-- create user/mount/PID namespaces
    |                       +-- build rootfs and pivot_root
    |                       +-- trusted namespace PID 1 (init)
    |                                |
    |                                +-- start requested argv
    |                                +-- report start result
    |                                +-- reap/forward signals
    |
    +-- trusted READY -> OnReady -> Workload RUNNING
    +-- failure / EOF / timeout -> no OnReady -> CLEANING -> FAILED
    +-- normal completion -> CLEANING -> FINISHED (exit code preserved)
```

### 4.1 Trusted PID 1 supervisor

Do not make the arbitrary Workload executable PID 1. A small trusted init inside the PID namespace should:

- spawn the requested command after sandbox setup;
- observe start errors and collect the command's real exit status;
- handle signal forwarding and child/orphan reaping with `wait4`;
- stay alive until owned children are terminated or reaped;
- keep startup-control FDs and host-resource FDs away from the Workload.

The initial trusted init may run as the already-started namespace child; it does not need to be copied into the guest rootfs and re-executed unless implementation demands it.

### 4.2 Startup protocol (must be independent of stdout)

Make `PREPARING -> RUNNING` contingent on a message sent by **trusted Launcher/init code**, not by an untrusted Workload script.

Suggested internal messages, encoded and bounded by `protocol.go`:

- `READY`: guest setup complete **and** the trusted init has successfully started the requested command;
- `ERROR(stage, reason)`: validation, namespace, rootfs, or command-start failure;
- exit result: normal process completion, distinct from startup status.

The trusted init should use a proper child-start/exec-error mechanism (for example, Go's `os.StartProcess`/`exec.Cmd.Start` semantics) and report success only after it returns successfully. This does **not** claim that the command remains alive after startup; a command that immediately exits still counts as successfully launched.

**Never infer exec success from control-pipe EOF alone.** EOF before `READY`, malformed messages, a dead trusted init, or a startup deadline exceeded are failures. Do not require an arbitrary Workload process to send `EXEC_READY`.

Use separate, explicitly whitelisted FDs for internal child startup and outer Runner reporting. Close unused pipe ends promptly, prevent accidental inheritance by workload exec, and set bounded protocol reads. A Setup Failure must be detected without waiting for the entire Workload timeout whenever failure is already known.

### 4.3 Lifecycle semantics

- `OnStarted` means the host Launcher process exists; it is **not** `WorkloadStarted`.
- `OnReady` means trusted sandbox startup succeeded and the requested program was launched.
- A successfully started Workload that exits nonzero is `FINISHED` with a nonzero exit code, not a setup failure.
- Setup/exec failure before `READY` is `FAILED` without a `WorkloadStarted` event.
- Timeout/cancellation at any stage must terminate the entire Workload cgroup, including descendants that change process groups.

---

## 5. Namespace and Filesystem Requirements

1. Create the required user, mount, and PID namespaces with explicit UID/GID maps. Verify this does not grant host-root privileges.
2. Make mount propagation private before mounting; do not mutate host mount topology.
3. Prepare a minimal rootfs with explicitly provisioned executable/dependency content. Mount a guest `/proc` only after entering the new PID namespace, and provide only required device nodes such as `/dev/null`.
4. Bind approved host paths at validated guest targets, with explicit read-only/read-write modes and appropriate `nosuid`/`nodev`/`noexec` options.
5. Use `pivot_root`, detach the old root, and prevent inherited directory FDs from exposing the host filesystem.
6. Preserve Workload-wide cgroup placement across fork/exec and Namespace creation.
7. Verify that the requested executable, arguments, environment and guest working directory are applied, rather than inherited implicitly from the Launcher.

**Security gate:** The Probe showed that a child with mount authority can reverse an intended read-only remount. Phase 2B cannot honestly claim enforced read-only access while the executable can regain `CAP_SYS_ADMIN` or equivalent mount control. A narrow pre-exec removal of remount authority may be required to satisfy the Phase 2B filesystem criterion; broader capability policy, `no_new_privs` and seccomp remain Phase 2C. If the bypass test still succeeds, leave the read-only acceptance item unchecked.

---

## 6. Runtime-Owned Cleanup and Failure Handling

This follows `DESIGN_PRINCIPLES.md` `14 (Runtime-Owned Cleanup).

Runtime holds the allocation record; Launcher receives only the resources it needs to use. A Launcher crash or `SIGKILL` must not be the sole reason a rootfs directory survives.

For every post-allocation path (success, setup error, exec error, timeout, cancellation, force-kill):

1. Enter `CLEANING` and use a fresh, bounded cleanup context, independent of the canceled Workload context.
2. Kill the remaining Workload cgroup if needed; do not rely only on process-group signals.
3. Wait for `cgroup.events: populated 0` via the cgroup backend. If this cannot be established, **do not remove the rootfs directory** as though it were unused.
4. Verify/release owned mount references. In the initial private-mount implementation, test that no host-visible mounts or namespace/FD holders remain; `WaitEmpty` alone is not a universal proof that all mount references vanished.
5. Remove only the exact Runtime-owned rootfs allocation; do not parse stdout or scan a global `/tmp` wildcard.
6. Remove the empty Workload cgroup.
7. Report cleanup errors as structured audit events and mark the Workload `FAILED` on cleanup failure.

Prefer non-recursive removal for the experimental empty host-side mountpoint; do not silently replace it with broad `RemoveAll`. Unexpected non-empty content needs a specifically owned, safe cleanup policy and tests before recursive deletion is introduced.

If the **Runtime itself** is killed, in-process cleanup cannot execute. Persistent crash-recovery ownership or an external supervisor is a separate follow-up design; do not claim it already exists.

---

## 7. Incremental Implementation Sequence

Complete one step and its regression tests before the next. Keep the Probe functional as a historical reference; do not copy its `AGENTGUARD_PROBE_*` failure switches into the new Launcher.

### 2B-01 — Freeze baseline and define contracts

- [ ] Record the current local passing `go test ./... -count=1` baseline and separate experimental integration tests.
- [ ] Add a minimal internal sandbox launch configuration and startup result types.
- [ ] Define explicit direct-vs-sandbox selection and prevent fallback.
- [ ] Add tests for validation, invalid target paths, and forbidden ambient environment inheritance.

**Done when:** contracts exist without modifying the Phase 2A execution semantics.

### 2B-02 — Extract namespace, mount, and rootfs mechanisms

- [ ] Create `internal/runtime/sandbox/linux/` only as implementation requires.
- [ ] Move validated user/mount/PID namespace and rootfs routines out of Probe experiments.
- [ ] Replace `must()` / `os.Exit` in reusable setup functions with returned errors.
- [ ] Verify private mount propagation, guest `/proc`, `pivot_root`, controlled bind mounts, and host FD isolation.

**Done when:** the new Backend can prepare an isolated guest view, with a diagnostic Workload, without relying on Probe code.

### 2B-03 — Implement thin Launcher and trusted init

- [ ] Add `cmd/agentguard-launcher/` as a small host-installed entry point.
- [ ] Add a trusted PID 1 init/reaper and real argv/env/working-directory execution.
- [ ] Keep Workload command exit codes distinct from launcher/setup failure.
- [ ] Install the new executable and scoped AppArmor authorization for development tests.

**Done when:** at least a small representative guest executable can run and exit correctly, including nonzero exit and descendant process cases.

### 2B-04 — Replace prototype startup semantics

- [ ] Implement bounded, versioned and validated internal control messages.
- [ ] Only call Runtime `OnReady` after trusted init confirms command start.
- [ ] Fail closed on premature EOF, malformed status, setup/exec errors and startup timeout.
- [ ] Ensure workload processes cannot write trusted startup messages or inherit unrelated host FDs.

**Done when:** early-exit, exec-failure, and setup-failure regression tests fail quickly without ever emitting `WorkloadStarted`.

### 2B-05 — Wire new Backend into existing Runtime

- [ ] Use Runtime-owned rootfs allocations; pass their identity to the Launcher without stdout parsing.
- [ ] Start Launcher in the existing Workload cgroup and preserve Phase 2A resource limits.
- [ ] Apply the existing lifecycle, timeout, cancellation, audit and ordered cleanup contract.
- [ ] Keep direct Runner tests passing, with no silent fallback from sandbox failure.

**Done when:** real namespace + cgroup + rootfs execution and cleanup work together on normal and abnormal paths.

### 2B-06 — Acceptance and adversarial regression

- [ ] Automate the filesystem, PID visibility, mount restriction, FD leak and whole-cgroup termination probes.
- [ ] Test Launcher crashes, init crashes, quick command exits, startup timeout, cancellation and partial cleanup failure.
- [ ] Verify read-only mounts cannot be made writable by the permitted Workload privileges.
- [ ] Confirm cleanup records, audit events and no tracked rootfs/cgroup leaks.
- [ ] Update `ARCHITECTURE.md` and `THREAT_MODEL.md` only where the implemented design changes them.

**Done when:** all applicable `ROADMAP.md` Phase 2B acceptance criteria have evidence and the full test suite passes.

---

## 8. Test Matrix

| Scenario | Required evidence |
| --- | --- |
| Normal sandbox execution | Real requested argv executes; `PREPARING -> RUNNING -> CLEANING -> FINISHED` |
| Legitimate nonzero exit | Exit code is preserved; not misclassified as setup failure |
| Namespace / rootfs setup error | Prompt `FAILED`; no `WorkloadStarted`; resources cleaned |
| Exec error (missing executable) | Explicit startup failure; no false readiness |
| Trusted init exits before confirmation | EOF/crash rejected; no timeout-only false PASS |
| Runner startup deadline / cancellation | Whole cgroup terminated; Runtime-owned rootfs cleaned |
| Host file and FD attempts | Unexposed host files/FDs inaccessible |
| Read-only and writable binds | Intended permissions work; remount bypass fails before marking acceptance |
| PID 1 and descendants | Unrelated host PIDs hidden; orphans reaped; cgroup tracks descendants |
| Cleanup error | `FAILED` plus audit; never delete rootfs before process/mount safety conditions |
| Regression | `go test ./... -count=1` passes, including Phase 1 and 2A tests |

### Local Linux integration prerequisites

Use a systemd-delegated cgroup subtree with `cpu`/`memory`/`pids` enabled and an explicit `AGENTGUARD_CGROUP_ROOT`. Install the trusted Launcher at its configured fixed path and match the AppArmor rule to that binary.

Tests that require privileges or delegation may skip when prerequisites are **not configured**. When prerequisites are explicitly supplied but invalid, report a test failure instead of silently skipping. Do not weaken global AppArmor or namespace restrictions to make tests pass.

---

## 9. Exit Criteria and Phase Boundary

The seven Phase 2B acceptance items in `ROADMAP.md` remain authoritative and unchecked until demonstrated. Passing the old Probe tests is supporting evidence, not completion evidence for the new Launcher.

**Phase 2B is complete only when**:

1. The formal Launcher executes a validated Workload command in the intended namespaces and filesystem view.
2. Startup readiness comes from trusted setup/execution code, not `cmd.Start()`, stdout, shell acknowledgement, or EOF alone.
3. Host visibility, workspace permissions and PID isolation satisfy the listed adversarial tests (including the remount-authority issue).
4. Runtime owns and safely cleans associated resources on every tested termination path, while preserving Phase 2A.
5. Structured failures and Workload lifecycle results are accurate and repeatable.

**Phase 2C remains necessary before claiming an untrusted-code security boundary**: complete Linux capability reduction, `no_new_privs`, seccomp, and the final workload confinement profile there. Network enforcement and Gateway/Policy integration remain in later phases.
