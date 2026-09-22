# AgentGuard Threat Model

> This document defines the security threats AgentGuard is designed to mitigate.
>
> System structure belongs in `ARCHITECTURE.md`.  
> Implementation order belongs in `ROADMAP.md`.  
> Project-wide security rules belong in `DESIGN_PRINCIPLES.md`.

---

## 1. Scope

This threat model covers the initial **single-host Linux** design of AgentGuard.

The current analysis focuses on:

- agent-controlled tool execution;
- Workload isolation;
- host filesystem protection;
- host resource protection;
- network egress;
- credential exposure;
- policy enforcement;
- security-relevant auditability.

Model Gateway-specific threats will be expanded when that component is implemented.

---

## 2. Trust Assumptions

The initial design assumes that:

- the Linux kernel is trusted;
- the AgentGuard process is trusted;
- the host administrator is trusted;
- policy configuration is controlled by an authorized operator;
- the Agent Runtime integration is trusted to route protected capabilities through AgentGuard rather than intentionally bypassing it.

Agent-controlled inputs are **not trusted**.

This includes:

- tool calls;
- generated commands;
- generated code;
- requested file paths;
- requested network destinations;
- downloaded dependencies;
- external content that may influence the Agent;
- Workloads created from Agent requests.

The initial MVP does **not** claim to contain a fully compromised Agent Runtime that intentionally accesses host capabilities outside AgentGuard.

---

## 3. Protected Assets

AgentGuard aims to protect:

- host files and source code;
- host processes;
- CPU and memory;
- process capacity;
- credentials and secrets;
- internal network services;
- other Workloads;
- policy configuration;
- audit data.

---

## 4. Threat Sources

Unsafe behavior may originate from:

- a malicious Agent;
- an Agent influenced by prompt injection;
- incorrect Agent behavior;
- malicious generated code;
- malicious third-party dependencies;
- unsafe tool arguments;
- unsafe operator configuration.

AgentGuard does not depend on correctly determining whether unsafe behavior was intentional.

---

## 5. Trust Boundaries

The important boundaries are:

```text
Agent Runtime
     |
     | untrusted Agent-controlled request
     v
===============================
         AgentGuard
```

```text
AgentGuard
    |
    | approved execution contract
    v
===============================
        Workload
```

```text
Workload
   |
   | syscalls / resource use
   v
===============================
Linux Kernel / Host Resources
```

```text
Workload
   |
   | controlled egress
   v
===============================
Network Gateway
```

Inputs crossing these boundaries must be validated, constrained, or isolated according to policy.

---

## 6. Threat Scenarios

### T01 — Host Filesystem Access

**Threat**

A Workload attempts to read or modify host files that were not explicitly exposed.

**Examples**

- `~/.ssh/id_rsa`
- `/etc/shadow`
- source code outside the workspace

**Expected controls**

- filesystem isolation;
- mount namespace;
- isolated root filesystem;
- explicit bind mounts;
- read-only mounts where appropriate.

**Required property**

Only explicitly exposed filesystem resources are visible to the Workload.

---

### T02 — Secret Inheritance

**Threat**

A Workload receives host or AgentGuard credentials through inherited environment variables or configuration.

**Expected controls**

- no default host-environment inheritance;
- explicit environment allowlist;
- controlled secret injection;
- audit redaction.

**Required property**

Host secrets are not implicitly available inside a Workload.

---

### T03 — Resource Exhaustion

**Threat**

A Workload attempts to exhaust shared host resources.

Examples include:

- excessive memory allocation;
- fork bombs;
- infinite CPU loops.

**Expected controls**

- cgroup v2 memory limits;
- cgroup v2 process limits;
- CPU controls;
- execution timeout.

**Required property**

Resource limits apply to the entire Workload, including child processes.

---

### T04 — Host Process Interference

**Threat**

A Workload attempts to inspect, trace, signal, or interfere with unrelated host processes.

**Expected controls**

- PID namespace;
- user namespace;
- reduced Linux capabilities;
- syscall restrictions where appropriate.

**Required property**

A Workload cannot directly interfere with unrelated host processes.

---

### T05 — Dangerous System Calls

**Threat**

A Workload invokes unnecessary high-risk system calls.

**Examples**

- `ptrace`;
- `mount`;
- unnecessary namespace operations.

**Expected controls**

- seccomp;
- reduced capabilities;
- `no_new_privs`.

---

### T06 — Child Process Escape

**Threat**

A child process escapes Workload accounting or survives after the Workload should have terminated.

**Expected controls**

- Workload-wide cgroup membership;
- process-group management;
- namespace containment;
- verified cleanup.

**Required property**

Every process created for a Workload remains attributable to that Workload for its entire lifetime.

---

### T07 — Network Exfiltration

**Threat**

A Workload attempts to send sensitive data to an unauthorized destination.

**Expected controls**

- controlled egress;
- Network Gateway;
- deny-by-default network policy.

**Required property**

A Workload configured for controlled networking cannot obtain unrestricted Internet access.

---

### T08 — Internal Network Access

**Threat**

A Workload attempts to access:

- localhost services;
- private networks;
- internal APIs;
- link-local services;
- cloud metadata endpoints.

**Expected controls**

- network isolation;
- Network Gateway policy;
- private-address restrictions;
- link-local restrictions.

---

### T09 — Network Enforcement Bypass

**Threat**

A Workload attempts to bypass the Network Gateway or another required network enforcement path.

**Expected controls**

- network isolation;
- forced controlled egress;
- explicit bypass tests.

**Required property**

Controlled networking cannot silently become direct host networking.

---

### T10 — Policy Bypass

**Threat**

A protected capability is reached without an explicit policy decision.

**Expected controls**

- Gateway mediation;
- deny-by-default behavior;
- explicit PolicyDecision.

**Required property**

No protected capability is implicitly allowed.

---

### T11 — Policy Constraint Loss

**Threat**

A PolicyDecision contains restrictions, but one or more restrictions are lost while building the WorkloadSpec.

Example:

```text
PolicyDecision:
    network = controlled

WorkloadSpec:
    network = unrestricted
```

**Expected controls**

- typed constraint structures;
- WorkloadSpec validation;
- policy-to-spec tests;
- mandatory Security Baseline checks.

---

### T12 — Silent Security Downgrade

**Threat**

A required security mechanism fails and AgentGuard silently continues with weaker security.

**Expected controls**

- fail-closed behavior;
- setup validation;
- no unrestricted fallback.

**Required property**

If required protection cannot be established, the Workload does not start.

---

### T13 — Security Baseline Override

**Threat**

Policy, defaults, or request data weakens a mandatory security invariant.

Example:

```text
Security Baseline:
    host secrets are not inherited

Request or Policy:
    inherit all host environment variables
```

**Expected controls**

- mandatory baseline validation;
- explicit WorkloadSpec construction order;
- validation before execution.

**Required property**

Security Baseline requirements cannot be weakened by ordinary policy or request data.

---

### T14 — Cross-Workload Interference

**Threat**

One Workload attempts to inspect or interfere with another Workload.

**Expected controls**

- per-Workload identity;
- separate cgroups;
- isolated process visibility;
- isolated filesystem state.

---

### T15 — Audit Data Leakage

**Threat**

Credentials or other sensitive values are written into security events.

**Expected controls**

- structured audit schema;
- field allowlists;
- redaction;
- avoid raw environment logging.

**Required property**

Audit must not become a secret-exfiltration channel.

---

### T16 — Missing or Uncorrelated Security Events

**Threat**

A security-relevant action occurs but cannot later be reconstructed because events are missing or lack correlation identifiers.

**Expected controls**

- structured event types;
- stable request and Workload identifiers;
- correlation fields;
- tests for expected security events.

**Required property**

Important security decisions and enforcement outcomes remain observable.

---

### T17 — Prompt-Injection-Induced Unsafe Action

**Threat**

External content causes the Agent to request an unsafe action.

**Expected controls**

The request must still pass through normal AgentGuard enforcement:

```text
Agent-controlled request
        |
        v
Policy Engine
        |
        v
Gateway
        |
        v
Workload / Sandbox
        |
        v
Network controls, if applicable
```

**Required property**

Security enforcement does not depend on correctly determining the Agent's intent.

---

## 7. Threat-to-Control Matrix

| Threat | Primary Controls |
|---|---|
| Host filesystem access | Filesystem isolation |
| Secret inheritance | Environment allowlist, secret handling |
| Resource exhaustion | cgroup v2, timeout |
| Host process interference | Namespaces, privilege reduction |
| Dangerous syscalls | seccomp, `no_new_privs` |
| Child process escape | cgroup membership, lifecycle cleanup |
| Network exfiltration | Network Gateway, controlled egress |
| Internal network access | Network isolation and policy |
| Network bypass | Forced controlled egress |
| Policy bypass | Gateway mediation |
| Constraint loss | WorkloadSpec validation |
| Silent downgrade | Fail closed |
| Security baseline override | Mandatory baseline validation |
| Cross-Workload interference | Per-Workload isolation |
| Audit leakage | Structured schema, redaction |
| Missing audit correlation | Correlation identifiers |
| Prompt-injection action | Independent policy and enforcement |

---

## 8. Out of Scope

The initial threat model does not claim protection against:

- a fully compromised Agent Runtime that intentionally bypasses AgentGuard;
- unknown Linux kernel vulnerabilities that fully escape the sandbox;
- malicious host root administrators;
- physical or hardware attacks;
- firmware compromise;
- microarchitectural side channels;
- compromise of the AgentGuard binary itself;
- perfect semantic detection of prompt injection;
- distributed multi-host threats.

---

## 9. Residual Risk

Even when all planned controls work correctly:

- the Linux kernel remains part of the trusted computing base;
- the Agent Runtime integration remains trusted in the initial design;
- policies may still be too permissive;
- allowed destinations may be malicious;
- allowed files may already contain secrets;
- AgentGuard may contain implementation bugs.

AgentGuard should document these limitations rather than imply perfect isolation.

---

## 10. Security Test Mapping

Security claims should be backed by adversarial tests.

Planned categories include:

```text
tests/attacks/
├── host_file_read/
├── secret_inheritance/
├── memory_exhaustion/
├── fork_bomb/
├── cpu_spin/
├── host_process_probe/
├── forbidden_syscall/
├── child_process_escape/
├── network_bypass/
├── metadata_access/
└── cross_workload_probe/
```

Each security test should define:

- the attack action;
- the expected enforcement behavior;
- the expected structured audit event;
- the expected cleanup behavior.

The audit event is evidence that the security-relevant outcome was observable, not the enforcement mechanism itself.

---

## 11. Summary

AgentGuard assumes that Agent-controlled behavior may be unsafe, whether intentionally or accidentally.

Its security model is based on independent enforcement:

```text
Agent-controlled Request
        |
        v
Policy Decision
        |
        v
Gateway Enforcement
        |
        v
WorkloadSpec
        |
        v
Sandbox Runtime
        |
        v
Controlled Workload
```

The initial design also assumes that the Agent Runtime integration itself does not intentionally bypass AgentGuard.

The central threat-model principle is:

> **Assume Agent-controlled requests and Workloads may behave incorrectly or maliciously, and enforce security boundaries independently of their intent.**
