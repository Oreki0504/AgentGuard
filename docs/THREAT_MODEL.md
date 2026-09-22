# AgentGuard Threat Model

> This document describes the security threats AgentGuard is designed to mitigate.
> Architecture and component responsibilities are defined in `ARCHITECTURE.md`.

---

## 1. Scope

This threat model covers the initial single-host Linux design of AgentGuard.

The current analysis focuses on:

- agent-controlled tool execution;
- Workload isolation;
- host filesystem protection;
- host resource protection;
- network egress;
- credential exposure.

Model Gateway-specific threats will be expanded when that component is implemented.

---

## 2. Trust Assumptions

The initial design assumes:

- the Linux kernel is trusted;
- the AgentGuard process is trusted;
- the host administrator is trusted;
- policy configuration is controlled by an authorized operator.

Agent-controlled inputs are **not trusted**.

This includes:

- shell commands;
- generated code;
- tool arguments;
- requested file paths;
- requested network destinations;
- downloaded dependencies;
- content influenced by prompt injection.

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
- AgentGuard policy and audit data.

---

## 4. Threat Sources

Threats may come from:

- a malicious Agent;
- a compromised Agent;
- prompt-injection-induced behavior;
- incorrect Agent behavior;
- malicious generated code;
- malicious third-party dependencies;
- unsafe operator configuration.

AgentGuard does not rely on determining whether unsafe behavior was intentional.

---

## 5. Trust Boundaries

The main trust boundaries are:

```text
Agent Runtime
     |
=====|========================
     v
 AgentGuard
```

```text
AgentGuard
    |
====|=========================
    v
 Workload
```

```text
Workload
   |
===|==========================
   v
Linux Kernel / Host Resources
```

```text
Workload
   |
===|==========================
   v
Network Gateway
```

Inputs crossing these boundaries must be validated and constrained according to policy.

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

- no default host environment inheritance;
- explicit environment allowlist;
- secret redaction in audit logs.

**Required property**

Host secrets are not implicitly available inside a Workload.

---

### T03 — Resource Exhaustion

**Threat**

A Workload attempts to exhaust host resources.

Examples include:

- excessive memory allocation;
- fork bombs;
- infinite CPU loops.

**Expected controls**

- cgroup v2 `memory.max`;
- cgroup v2 `pids.max`;
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
- seccomp where appropriate.

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
- dropped capabilities;
- `no_new_privs`.

---

### T06 — Child Process Escape

**Threat**

A child process escapes Workload accounting or survives after the Workload should have terminated.

**Expected controls**

- workload-wide cgroup membership;
- process-group management;
- namespace containment;
- verified cleanup.

**Required property**

Every process created for a Workload remains attributable to that Workload for its entire lifetime.

---

### T07 — Network Exfiltration

**Threat**

A Workload attempts to send sensitive data to an unauthorized external destination.

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
- cloud metadata endpoints.

**Expected controls**

- Network Gateway policy;
- private-address restrictions;
- link-local restrictions;
- no unrestricted host networking.

---

### T09 — Network Enforcement Bypass

**Threat**

A Workload attempts to bypass the Network Gateway or other required network enforcement path.

**Expected controls**

- network isolation;
- forced controlled egress;
- explicit bypass tests.

---

### T10 — Policy Bypass

**Threat**

A protected action reaches a capability without an explicit allow decision.

**Expected controls**

- Gateway mediation;
- deny-by-default behavior;
- explicit policy decisions.

**Required property**

No protected action is implicitly allowed.

---

### T11 — Policy Constraint Loss

**Threat**

A PolicyDecision contains restrictions, but one or more restrictions are lost when creating the WorkloadSpec.

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
- policy-to-spec tests.

---

### T12 — Silent Security Downgrade

**Threat**

A required isolation mechanism fails and AgentGuard silently continues with weaker security.

**Expected controls**

- fail-closed behavior;
- setup validation;
- no unrestricted fallback.

**Required property**

If required protection cannot be established, the Workload does not start.

---

### T13 — Cross-Workload Interference

**Threat**

One Workload attempts to inspect or interfere with another Workload.

**Expected controls**

- per-Workload namespaces;
- separate cgroups;
- isolated filesystem state;
- per-Workload identity.

---

### T14 — Audit Data Leakage

**Threat**

Credentials or other sensitive values are written into logs.

**Expected controls**

- structured audit schemas;
- redaction;
- field allowlists;
- avoid raw environment logging.

---

### T15 — Prompt-Injection-Induced Unsafe Action

**Threat**

External content causes an Agent to request an unsafe action.

**Expected controls**

The requested action must still pass through normal AgentGuard enforcement:

```text
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
| Secret inheritance | Environment allowlist |
| Resource exhaustion | cgroup v2, timeout |
| Host process interference | PID/user namespaces, capabilities |
| Dangerous syscalls | seccomp, `no_new_privs` |
| Child process escape | cgroup membership, cleanup |
| Network exfiltration | Network Gateway, controlled egress |
| Internal network access | Network policy |
| Network bypass | Network isolation |
| Policy bypass | Gateway mediation |
| Constraint loss | WorkloadSpec validation |
| Silent downgrade | Fail closed |
| Cross-Workload interference | Per-Workload isolation |
| Audit leakage | Redaction |
| Prompt-injection action | Independent policy and enforcement |

---

## 8. Out of Scope

The initial threat model does not claim protection against:

- unknown Linux kernel vulnerabilities that fully escape the sandbox;
- malicious host root administrators;
- physical or hardware attacks;
- firmware compromise;
- microarchitectural side channels;
- compromise of the AgentGuard binary itself;
- complete semantic detection of prompt injection;
- distributed multi-host threats.

---

## 9. Residual Risk

Even when all planned controls work correctly:

- the Linux kernel remains part of the trusted computing base;
- policies may still be too permissive;
- allowed destinations may be malicious;
- allowed files may already contain secrets;
- AgentGuard itself may contain implementation bugs.

AgentGuard should document these limitations rather than imply perfect isolation.

---

## 10. Security Test Mapping

The threat model should be backed by adversarial tests.

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

Each test should define:

- the attack action;
- the expected enforcement behavior;
- the expected audit result;
- cleanup requirements.

---

## 11. Summary

AgentGuard assumes that Agent-controlled behavior may be unsafe, whether intentionally or accidentally.

Its security model is therefore based on independent enforcement rather than trust in Agent intent:

```text
Agent Request
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

The central principle is:

> **Assume the Agent or its Workload may behave incorrectly or maliciously, and enforce security boundaries independently of that intent.**
