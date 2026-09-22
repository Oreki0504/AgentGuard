# AgentGuard Architecture

> This document defines AgentGuard's system structure, component boundaries, and major data flows.
>
> Threats belong in `THREAT_MODEL.md`.  
> Implementation order belongs in `ROADMAP.md`.  
> Project-wide security rules belong in `DESIGN_PRINCIPLES.md`.

---

## 1. Overview

AgentGuard is a **security control plane for AI agents**.

Its purpose is to mediate and constrain access to capabilities such as:

- local tools;
- shell execution;
- filesystems;
- networks;
- APIs;
- LLM providers.

The central architectural rule is:

> **Policy decides what is allowed. Gateways enforce capability access. The Sandbox Runtime enforces workload-level operating-system constraints. Audit records security-relevant events.**

AgentGuard is divided conceptually into:

- **Control Plane** — policy and security decisions;
- **Enforcement Plane** — components that make those decisions effective.

---

## 2. Trust Model

The initial single-host design assumes that the **Agent Runtime integration itself is trusted to route protected capabilities through AgentGuard**.

Agent-controlled inputs are not trusted.

Examples include:

- tool calls;
- generated commands;
- generated code;
- requested paths;
- network destinations;
- external content;
- downloaded dependencies;
- Workloads.

The initial MVP does **not** claim to prevent a fully compromised Agent Runtime from intentionally bypassing AgentGuard by directly accessing host capabilities.

That stronger model would require additional runtime confinement and is outside the first implementation scope.

---

## 3. High-Level Architecture

```text
                         CONTROL PLANE

                    +-------------------+
                    |   Policy Engine   |
                    +-------------------+
                       ^       ^       ^
                       |       |       |
                 PolicyQuery / PolicyDecision
                       |       |       |
-----------------------|-------|-------|-----------------------
                    ENFORCEMENT PLANE

                 +-----+-----+ +-----+-----+ +------+------+
                 |   Model   | |   Tool    | |   Network   |
                 |  Gateway  | |  Gateway  | |   Gateway   |
                 +-----+-----+ +-----+-----+ +------+------+
                       ^             ^              ^
                       |             |              |
                       +-------------+--------------+
                                     |
                               Agent Runtime
```

Capability paths then continue from the Gateways:

```text
Model Gateway   ----> LLM Providers

Tool Gateway    ----> WorkloadSpec Builder
                          |
                          v
                    Sandbox Runtime
                          |
                          v
                       Workload

Network Gateway ----> Internet / APIs

Workload        ----> controlled egress ----> Network Gateway
```

The **Agent Runtime sends capability requests to the appropriate Gateway**. The Policy Engine is logically above the Gateways, but it is not an inline transport hop for those requests. Instead, each Gateway submits a `PolicyQuery` and receives a `PolicyDecision` before enforcing the operation.

The Network Gateway may appear in two roles:

1. as a peer Gateway for network capability requests;
2. as the controlled egress path for Workload traffic.

This does not make it part of the Sandbox Runtime.

---

## 4. Control Plane

The Control Plane defines the intended security state.

Its primary component is the **Policy Engine**.

A policy decision may answer questions such as:

```text
May agent "coding-agent" execute shell commands?

If yes:
    timeout <= 30s
    memory <= 512MiB
    processes <= 64
    filesystem = workspace-only
    network = controlled
```

The Control Plane describes **what must be true**.

It should not depend on Linux-specific mechanisms such as:

- cgroup files;
- mount operations;
- namespace setup;
- seccomp filters.

---

## 5. Policy Engine

The Policy Engine is AgentGuard's central **Policy Decision Point (PDP)**.

A conceptual query contains:

```text
Subject
    who is requesting?

Action
    what operation is requested?

Resource
    what capability or resource is targeted?

Context
    what additional conditions apply?
```

Example:

```text
Subject:
    agent = coding-agent

Action:
    tool.execute

Resource:
    tool = shell

Context:
    workspace = project-a
```

A decision may be:

```text
DENY
```

or:

```text
ALLOW

Constraints:
    timeout = 30s
    memory = 512MiB
    processes = 64
    filesystem = workspace-only
    network = controlled
```

The Policy Engine does not perform enforcement.

It does not:

- execute processes;
- configure cgroups;
- create namespaces;
- mount filesystems;
- install seccomp filters;
- proxy network traffic;
- call LLM providers.

---

## 6. Enforcement Plane

The Enforcement Plane applies Control Plane decisions.

It contains:

- Tool Gateway;
- Network Gateway;
- Model Gateway;
- Sandbox Runtime;
- low-level Linux enforcement mechanisms.

The major enforcement rule is:

> **A capability may be used only through its intended enforcement path.**

For the initial MVP, this is guaranteed for Workloads created by AgentGuard.

---

## 7. Gateways

Gateways are application-level **Policy Enforcement Points (PEPs)**.

Each Gateway mediates one capability class and consults the same Policy Engine.

The generic interaction is:

```text
Capability Request
       |
       v
Gateway (PEP)
       |
       +---- PolicyQuery --------> Policy Engine (PDP)
       |                               |
       |<--- PolicyDecision -----------+
       |
       +---- DENY ----> return denial
       |
       +---- ALLOW ---> enforce capability-specific constraints
```

The request itself enters through a Gateway. The Policy Engine acts as the **Policy Decision Point (PDP)**; it does not proxy the capability request.

This same pattern applies to Model, Tool, and Network Gateways.

Gateways:

- validate requests;
- submit policy queries;
- receive policy decisions;
- enforce those decisions;
- produce security-relevant audit events.

Gateways do not define independent global policy.

---

## 8. Tool Gateway

The Tool Gateway mediates tool access.

Initial tool classes may include:

- shell execution;
- command execution;
- file reads;
- file writes;
- local tools.

For execution-oriented tools, the Tool Gateway:

```text
ToolRequest
    |
    v
validate
    |
    v
PolicyQuery
    |
    v
PolicyDecision
    |
    +---- DENY ----> return denial
    |
   ALLOW
    |
    v
build WorkloadSpec
    |
    v
Sandbox Runtime
```

The Tool Gateway must not contain Linux isolation logic.

---

## 9. Network Gateway

The Network Gateway controls outbound network access.

Potential controls include:

- destination allowlists;
- destination denylists;
- private-network restrictions;
- loopback restrictions;
- link-local restrictions;
- cloud metadata protection;
- domain/IP policy;
- network auditing.

For Workload traffic, responsibilities are split:

```text
Sandbox Runtime
    prevents bypass of the controlled path

Network Gateway
    decides what destinations are allowed

Policy Engine
    defines the policy
```

---

## 10. Model Gateway

The Model Gateway mediates access to LLM providers.

Potential controls include:

- provider allowlists;
- model allowlists;
- request limits;
- token limits;
- credential isolation;
- usage auditing;
- optional routing.

The Model Gateway is not required for the initial MVP.

---

## 11. Workload

A **Workload** is a uniquely identifiable, policy-constrained execution unit created by AgentGuard.

A Workload may contain multiple processes.

Example:

```text
Workload ag-wl-00042
    |
    +-- bash
         |
         +-- python
              |
              +-- gcc
              |
              +-- worker
```

This is one Workload containing multiple processes.

Security and resource controls apply to the Workload as a whole.

A Workload is not the same as:

- a Process;
- a ToolRequest;
- a PolicyDecision;
- the Sandbox Runtime.

---

## 12. Workload Lifecycle

A Workload has an explicit lifecycle.

```text
PREPARING
    |
    +---- setup failure --------> CLEANING --------> FAILED
    |
    v
RUNNING
    |
    +---- process exit --------------------------+
    |                                            |
    +---- timeout / explicit kill /              |
    |     runtime-control failure                |
    |                 |                          |
    |                 v                          |
    |            TERMINATING                     |
    |                 |                          |
    +-----------------+--------------------------+
                      |
                      v
                   CLEANING
                      |
              +-------+-------+
              |               |
       cleanup success   cleanup failure
              |               |
              v               v
           FINISHED         FAILED
```

A denied ToolRequest does not create a Workload.

Once runtime resources have been created, failure paths must pass through cleanup before reaching a terminal state. A process exit may still carry a non-zero exit code; terminal Workload state and process result should remain distinguishable.

The exact state model may evolve during implementation.

---

## 13. WorkloadSpec

The **WorkloadSpec** is the execution contract passed to the Sandbox Runtime.

It describes **what the Workload must look like**, not the Linux-specific mechanisms used to create it.

Conceptual example:

```yaml
workload:
  id: ag-wl-00042

  identity:
    agent: coding-agent
    request_id: req-1234

  execution:
    argv:
      - python3
      - main.py
    working_directory: /workspace
    timeout: 30s

  resources:
    memory: 512MiB
    processes: 64
    cpu: 1

  filesystem:
    workspace:
      path: /workspace
      mode: read-write
    host_visibility: restricted

  network:
    mode: controlled

  security:
    profile: coding-default
    privilege: unprivileged
```

The exact serialization format is not fixed.

The WorkloadSpec should avoid unnecessary backend-specific fields such as:

```text
seccomp_profile
cgroup_path
namespace_flags
```

Those belong to the runtime implementation.

---

## 14. Building a WorkloadSpec

A WorkloadSpec is produced from several inputs:

```text
ToolRequest
     +
PolicyDecision
     +
Runtime Defaults
     +
Security Baseline
     |
     v
WorkloadSpec
```

These inputs have different meanings.

### Runtime Defaults

Defaults are implementation-provided values used when policy does not specify a value.

Example:

```text
default timeout = 30s
```

Defaults may be overridden by policy when allowed.

### Security Baseline

The Security Baseline contains mandatory protections that must not be weakened by policy.

Examples:

- no implicit inheritance of host secrets;
- no unrestricted fallback when isolation fails;
- Workload-wide lifecycle control.

The WorkloadSpec builder must preserve these mandatory properties.

---

## 15. Sandbox Runtime

The Sandbox Runtime consumes a WorkloadSpec and translates it into operating-system enforcement.

Example:

```text
WorkloadSpec:
    memory <= 512MiB

Linux Sandbox Runtime:
    configure cgroup v2 memory limit
```

Another example:

```text
WorkloadSpec:
    privilege = unprivileged

Linux Sandbox Runtime:
    drop capabilities
    apply no_new_privs
    apply suitable syscall restrictions
```

The Sandbox Runtime does not make high-level authorization decisions.

---

## 16. Linux Sandbox Backend

The first Sandbox Runtime backend targets Linux.

Likely mechanisms include:

### Process Isolation

- PID namespace;
- user namespace;
- IPC namespace;
- UTS namespace where useful.

### Filesystem Isolation

- mount namespace;
- isolated root filesystem;
- bind mounts;
- read-only mounts;
- writable workspace;
- tmpfs where useful.

### Resource Control

- cgroup v2 `memory.max`;
- cgroup v2 `pids.max`;
- cgroup v2 `cpu.max`.

### Privilege Reduction

- unprivileged execution;
- reduced capabilities;
- `no_new_privs`.

### System Call Restriction

- seccomp.

The exact mechanism set will be refined through implementation and testing.

---

## 17. Environment and Secrets

Host environment variables must not be inherited by default.

A Workload should receive only explicitly provided or explicitly allowed values.

Conceptually:

```yaml
environment:
  inherit: false

  allow:
    - PATH
    - LANG

  values:
    APP_MODE: test
```

Sensitive credentials should eventually be represented by references or controlled injection mechanisms rather than being embedded directly into WorkloadSpec or audit logs.

---

## 18. Audit

Audit is a cross-cutting capability that provides a **structured and correlated record of security-relevant events**.

It is intended to support:

- debugging;
- security forensics;
- incident investigation;
- security test evidence;
- operational monitoring;
- future detection and alerting systems.

Security-relevant components may emit structured events:

```text
Policy Engine  -----+
Tool Gateway    ----+
Sandbox Runtime ----+----> Audit Event Stream
Network Gateway ----+
Model Gateway   ----+
```

Audit should make it possible to reconstruct a security-relevant execution path and answer questions such as:

- what happened?
- who requested it?
- which request and Workload were involved?
- what policy decision was made?
- what enforcement action occurred?
- what network or resource event occurred?
- how did the Workload terminate?
- was cleanup successful?

Events should carry correlation identifiers where available, for example:

```text
agent_id
request_id
workload_id
policy_id
correlation_id
```

A minimal event may conceptually look like:

```json
{
  "event_type": "network.denied",
  "agent_id": "coding-agent",
  "request_id": "req-123",
  "workload_id": "ag-wl-42",
  "destination": "169.254.169.254",
  "decision": "deny",
  "reason": "link-local destination"
}
```

The initial implementation may begin with a small structured event interface and a simple sink such as JSON output. More advanced consumers can be added later:

```text
Audit Event Stream
        |
        +--> Logs / Forensics
        +--> Metrics
        +--> Monitoring
        +--> Alerting
        +--> Detection
        +--> External SIEM
```

Audit does **not** make authorization decisions and does not directly enforce policy.

If future active response is needed, that responsibility should belong to a separate monitoring or detection component that consumes Audit events.

Audit must also avoid becoming a secret-leakage channel. Sensitive fields should be omitted or redacted before events are emitted.

---

## 19. Execution Flow

The first complete MVP path is:

```text
Agent Runtime
     |
     v
Tool Gateway
     |
     +---- PolicyQuery --------> Policy Engine
     |                              |
     |<--- PolicyDecision ----------+
     |
     +---- DENY ----------------> Audit + ToolResult
     |
    ALLOW
     |
     v
WorkloadSpec Builder
     |
     v
Sandbox Runtime
     |
     v
Workload
     |
     v
Cleanup
     |
     v
Audit + ToolResult
```

The Tool Gateway remains the enforcement point throughout the request. The Policy Engine only returns the decision and constraints used by that enforcement path.

The Agent Runtime does not directly create AgentGuard-managed Workloads.

---

## 20. Workload Network Flow

A Workload with:

```text
network = controlled
```

must not receive unrestricted host networking.

Conceptually:

```text
Workload
   |
   v
Sandbox Network Boundary
   |
   v
Network Gateway
   |
   +---- PolicyQuery --------> Policy Engine
   |                              |
   |<--- PolicyDecision ----------+
   |
   +---- DENY
   |
   +---- ALLOW ----------------> Internet / API
```

The Sandbox Runtime guarantees that the controlled path cannot be bypassed.

The Network Gateway remains the enforcement point and evaluates the destination using the Policy Engine's decision.

---

## 21. Creation-Time and Runtime Policy

Some policy decisions apply before the Workload starts.

Examples:

- timeout;
- memory limit;
- process limit;
- CPU limit;
- filesystem visibility;
- initial network mode;
- security profile.

Other decisions may occur while the Workload is running.

Example:

```text
Workload
   |
   v
connect to github.com?
   |
   v
Network Gateway
   |
   +---- PolicyQuery --------> Policy Engine
   |                              |
   |<--- PolicyDecision ----------+
   |
   v
ALLOW / DENY
```

The Policy Engine may therefore remain active after Workload creation, while the Network Gateway remains responsible for enforcement.

---

## 22. Dependency Direction

The codebase should preserve simple dependency direction.

Conceptually:

```text
cmd
 |
 v
gateway
 | \
 |  +----> policy
 |  +----> workload
 |  +----> audit
 |
 v
workload orchestration
 |
 +----> runtime
 +----> audit

runtime
 |
 v
linux backend
```

Important rules:

- Policy Engine must not depend on Gateways.
- Policy Engine must not depend on Sandbox Runtime.
- Sandbox Runtime must not depend on Tool Gateway.
- Network Gateway must not own the global policy model.
- Audit must not make authorization decisions.
- Circular package dependencies should be avoided.

---

## 23. Possible Package Layout

A future layout may resemble:

```text
internal/
├── policy/
├── gateway/
│   ├── tool/
│   ├── network/
│   └── model/
├── workload/
├── runtime/
│   └── sandbox/
├── audit/
└── linux/
```

This is not a requirement to create all packages immediately.

Packages should be introduced only when their functionality exists.

---

## 24. Open Architecture Questions

The following questions remain intentionally unresolved.

### Workload

- When should a Workload ID be allocated?
- Should WorkloadSpec be persisted?
- How should cleanup success be verified?
- How should Workload identity propagate to the Network Gateway?

### Sandbox Runtime

- Which namespaces are mandatory in the first version?
- Should rootless operation be mandatory initially?
- Should the sandbox use an internal init process?
- How should root filesystem state be prepared?

### Policy

- What initial policy serialization format should be used?
- How should policy precedence work?
- How should path and domain matching work?

### Network

- Should controlled egress use a proxy?
- Should every Workload receive a dedicated network namespace?
- How should DNS rebinding and redirects be handled?
- How should non-HTTP traffic be handled?

### Audit

- Should audit emission be synchronous?
- What happens if the audit sink fails?
- Which fields require redaction?

These questions should be answered through focused implementation work rather than premature abstraction.

---

## 25. Summary

AgentGuard separates security responsibilities:

```text
Policy Engine
    decides what is allowed

Gateways
    enforce capability-level access

WorkloadSpec
    defines the execution contract

Sandbox Runtime
    translates the contract into OS enforcement

Workload
    is the controlled execution unit

Audit
    records security-relevant behavior
```

The most important architectural boundary is:

> **High-level policy must remain independent from low-level enforcement mechanisms.**

The initial design also assumes that the Agent Runtime integration itself is trusted not to bypass AgentGuard. Stronger confinement of the Agent Runtime may be added in future hardening work.
