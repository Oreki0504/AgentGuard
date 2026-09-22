# AgentGuard Architecture

> This document defines the initial architecture of AgentGuard.  
> It focuses on component boundaries, trust boundaries, workload execution, policy decisions, and enforcement responsibilities.
>
> AgentGuard is still in early development. This document is expected to evolve as implementation work provides new constraints and evidence.

---

## 1. Overview

AgentGuard is a **security control plane for AI agents**.

Its purpose is to mediate and constrain how AI agents interact with external capabilities such as:

- local tools;
- shell execution;
- filesystems;
- networks;
- APIs;
- LLM providers.

AgentGuard assumes that an agent, its generated code, its tool arguments, and content influenced by external inputs may be untrusted or less trusted.

The core architectural principle is:

> **Policy defines the allowed security state. Gateways enforce capability-level policy. The Sandbox Runtime enforces operating-system-level isolation. Audit records what happened.**

AgentGuard is organized into two conceptual planes:

- **Control Plane** — policy, identity, configuration, and security decisions;
- **Enforcement Plane** — gateways and runtime mechanisms that make those decisions real.

---

## 2. Architectural Goals

AgentGuard should:

- provide a unified security policy layer across multiple agent capabilities;
- prevent agent runtimes from directly accessing sensitive capabilities without mediation;
- separate policy decisions from low-level enforcement mechanisms;
- provide a reusable runtime for executing untrusted workloads;
- prevent sandboxed workloads from bypassing network or filesystem controls;
- make security behavior testable and observable;
- fail closed when required protections cannot be established;
- support incremental development without requiring the entire control plane to exist from day one.

---

## 3. Non-Goals

AgentGuard is not intended to be:

- a replacement for Docker;
- a general-purpose container runtime;
- a Kubernetes platform;
- an AI agent framework;
- an MCP framework;
- an antivirus product;
- an EDR platform;
- a general-purpose firewall;
- a complete DLP product;
- a guarantee that arbitrary untrusted code is safe;
- a defense against all kernel vulnerabilities, side channels, or hardware attacks.

AgentGuard aims to reduce the impact of untrusted or compromised agent behavior under a clearly defined threat model.

---

# 4. High-Level Architecture

AgentGuard is divided into a **Control Plane** and an **Enforcement Plane**.

```text
                         Agent Runtime
                              |
                              v

+------------------------------------------------------------------+
|                    AgentGuard Control Plane                      |
|                                                                  |
|                      +----------------+                          |
|                      | Policy Engine  |                          |
|                      +--------+-------+                          |
|                               |                                  |
|                     policy decisions                             |
|                               |                                  |
+-------------------------------|----------------------------------+
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v

        +-----------+     +-----------+     +-------------+
        |   Model   |     |   Tool    |     |   Network   |
        |  Gateway  |     |  Gateway  |     |   Gateway   |
        +-----+-----+     +-----+-----+     +------+------+
              |                 |                  |
              |                 |                  |
              v                 v                  v
       LLM Providers       Workload Path        Internet / APIs
                                |
                                v
                        +---------------+
                        | Workload Spec |
                        +-------+-------+
                                |
                                v
                        +---------------+
                        |    Sandbox    |
                        |    Runtime    |
                        +-------+-------+
                                |
                                v
                        +---------------+
                        |   Workload    |
                        |               |
                        | Process Tree  |
                        | Filesystem    |
                        | Resources     |
                        | Network ID    |
                        | Audit Context |
                        +-------+-------+
                                |
                        outbound traffic
                                |
                                v
                         Network Gateway
                                |
                                v
                         Internet / APIs
```

The Network Gateway appears in two logical relationships:

1. it is a peer of the Model Gateway and Tool Gateway as an application-level enforcement point;
2. it may also act as the controlled egress path for network traffic originating from a workload.

This does **not** make the Network Gateway a child of the Sandbox Runtime.

---

# 5. Control Plane and Enforcement Plane

## 5.1 Control Plane

The Control Plane defines desired security behavior.

Initial Control Plane responsibilities include:

- policy loading;
- policy evaluation;
- workload security constraints;
- agent identity;
- policy identity and versioning;
- configuration;
- future policy distribution.

The Policy Engine belongs to the Control Plane.

The Control Plane should describe **what is allowed**, not how Linux implements it.

For example:

```text
memory <= 512 MiB
network = controlled
filesystem = workspace-only
timeout <= 30 s
```

The Policy Engine should not need to know whether those constraints are implemented using:

- cgroup v2;
- network namespaces;
- proxies;
- mount namespaces;
- seccomp;
- virtual machines.

---

## 5.2 Enforcement Plane

The Enforcement Plane makes Control Plane decisions real.

It contains:

- Model Gateway;
- Tool Gateway;
- Network Gateway;
- Sandbox Runtime;
- Linux enforcement mechanisms.

The Enforcement Plane is responsible for ensuring that an allowed operation stays within its authorized boundaries.

---

# 6. Policy Engine

The Policy Engine is AgentGuard's central **Policy Decision Point (PDP)**.

Its responsibility is to answer:

> **Who may perform what action on which resource, under what conditions?**

A conceptual policy query may contain:

```text
Subject:
    agent = coding-agent

Action:
    tool.execute

Resource:
    tool = shell
    command = ["python3", "main.py"]

Context:
    workspace = project-A
    environment = development
```

A policy decision may be:

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

The Policy Engine does **not**:

- execute processes;
- create namespaces;
- create cgroups;
- install seccomp filters;
- configure mounts;
- proxy network traffic;
- call LLM providers.

It produces **security decisions and constraints**.

---

# 7. Gateways

Gateways are application-level **Policy Enforcement Points (PEPs)**.

Each Gateway mediates a specific class of capability.

```text
                 Policy Engine
                /      |      \
               /       |       \
              v        v        v
           Model      Tool    Network
          Gateway   Gateway   Gateway
```

The Policy Engine is logically above all Gateways.

Gateways do not own the policy model.

They consume Policy Engine decisions and enforce them for their respective capability class.

---

## 7.1 Tool Gateway

The Tool Gateway mediates agent tool usage.

Initial tool classes may include:

- shell execution;
- command execution;
- file reads;
- file writes;
- future local tools;
- future external tool integrations.

The Tool Gateway answers questions such as:

- is this tool available to this agent?
- is this request structurally valid?
- has policy authorized this invocation?
- does this request require a workload?

For execution-oriented tools, the Tool Gateway converts an authorized request into a **WorkloadSpec**.

The Tool Gateway should not contain Linux isolation code.

---

## 7.2 Network Gateway

The Network Gateway controls outbound network access.

It may enforce:

- destination allowlists;
- destination denylists;
- private-network restrictions;
- loopback restrictions;
- link-local restrictions;
- cloud metadata protections;
- domain-based policy;
- IP-based policy;
- request auditing.

The Network Gateway can act as the controlled egress path for sandboxed workloads.

The Sandbox Runtime is responsible for preventing workloads from bypassing that path.

This creates two complementary controls:

```text
Sandbox Runtime:
    "You may only exit through this controlled path."

Network Gateway:
    "This controlled path may reach these destinations."
```

---

## 7.3 Model Gateway

The Model Gateway mediates access to LLM providers.

Potential controls include:

- model allowlists;
- provider allowlists;
- provider routing;
- request-size limits;
- token limits;
- secret detection;
- request auditing;
- cost controls;
- rate limits.

The Model Gateway is not required for the first MVP.

---

# 8. Workload

## 8.1 Definition

A **Workload** is a uniquely identifiable, policy-constrained execution unit created by AgentGuard to run an approved untrusted or less-trusted task.

A workload may contain one or more processes and is associated with:

- an immutable execution specification;
- an isolated runtime environment;
- resource limits;
- filesystem visibility;
- network context;
- security controls;
- lifecycle state;
- audit identity.

A Workload is **not** the same thing as:

- a process;
- a sandbox;
- a tool request;
- a policy decision.

---

## 8.2 Workload vs Process

One Workload may contain many processes.

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

This is:

```text
1 Workload
4 Processes
```

Security constraints apply to the Workload as a whole.

For example:

```text
Workload memory <= 512 MiB
Workload process count <= 64
```

Child processes must not escape those constraints.

---

## 8.3 Workload vs Sandbox Runtime

The **Sandbox Runtime** is infrastructure.

The **Workload** is an execution instance created by that infrastructure.

Conceptually:

```text
Sandbox Runtime
      |
      +-- Workload A
      +-- Workload B
      +-- Workload C
```

The Sandbox Runtime creates, runs, monitors, and destroys Workloads.

---

# 9. WorkloadSpec

The **WorkloadSpec** is the contract between higher-level policy/orchestration and the Sandbox Runtime.

It describes the final security and execution requirements for one Workload.

A conceptual WorkloadSpec may look like:

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
    host:
      visible: false

  network:
    mode: controlled

  security:
    no_new_privs: true
    seccomp_profile: coding-default
    capabilities: []
```

The exact serialization format is not fixed.

---

## 9.1 WorkloadSpec Construction

A WorkloadSpec is produced from multiple sources.

```text
ToolRequest
     +
PolicyDecision
     +
Runtime Defaults
     |
     v
WorkloadSpec
```

The ToolRequest answers:

> What is being requested?

The PolicyDecision answers:

> What is allowed?

Runtime Defaults answer:

> What baseline protections must always exist?

The WorkloadSpec answers:

> What must this specific execution look like?

---

## 9.2 WorkloadSpec Properties

The first implementation should treat the WorkloadSpec as effectively immutable once execution begins.

A Workload must not silently weaken its own constraints.

For example:

```text
network = controlled
```

must not silently become:

```text
network = unrestricted
```

during execution.

---

# 10. Runtime Security Invariants

The Sandbox Runtime must enforce several security invariants regardless of agent behavior.

Examples:

1. **No silent fallback to unrestricted execution.**

   If required isolation cannot be established, execution must fail.

2. **All workload processes remain attributable to the workload.**

   Child processes must not escape workload resource and lifecycle controls.

3. **A workload must not inherit AgentGuard's full privilege set.**

4. **Required security mechanisms must fail closed.**

   If a required cgroup, namespace, filesystem rule, or security filter cannot be established, the workload must not start.

5. **Host secrets must not be implicitly inherited.**

6. **Cleanup must be complete.**

   Remaining processes and temporary resources must be removed when the workload terminates.

A key invariant is:

> **Every process created for a workload MUST remain attributable to and contained within that workload for its entire lifetime.**

---

# 11. Workload Lifecycle

A Workload should have an explicit lifecycle.

A request that is denied by policy does not need to become a Workload.

Conceptually:

```text
ToolRequest
    |
    v
Policy Evaluation
    |
    +------ DENY ------> Request Denied
    |
   ALLOW
    |
    v
WorkloadSpec
    |
    v
PREPARING
    |
    +------ setup failure ------> FAILED
    |
    v
RUNNING
    |
    +------ normal exit --------> CLEANING
    |
    +------ timeout ------------> TERMINATING
    |
    +------ explicit kill ------> TERMINATING
    |
    +------ runtime failure ----> TERMINATING
                                    |
                                    v
                                 CLEANING
                                    |
                                    v
                                 FINISHED
```

Possible initial states:

```text
PREPARING
RUNNING
TERMINATING
CLEANING
FINISHED
FAILED
```

---

# 12. Workload Data Model

A Workload should conceptually contain three categories of information.

## 12.1 Immutable Specification

```text
WorkloadSpec

- command
- arguments
- working directory
- timeout
- filesystem constraints
- resource constraints
- network mode
- security profile
```

---

## 12.2 Runtime State

```text
WorkloadState

- status
- host PID
- start time
- end time
- exit code
- termination reason
- resource usage
```

---

## 12.3 Security and Audit Context

```text
SecurityContext

- workload_id
- request_id
- agent_id
- policy_id
- policy_version
- correlation_id
```

This allows events across Tool Gateway, Sandbox Runtime, and Network Gateway to be correlated.

---

# 13. Environment and Secret Handling

Host environment variables must not be inherited by default.

For example, the host may contain:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
OPENAI_API_KEY
GITHUB_TOKEN
```

A workload should receive only explicitly allowed environment values.

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

Secrets should eventually be referenced indirectly rather than stored as plaintext in WorkloadSpec or audit logs.

Example future model:

```text
secret_ref: github-token-for-build
```

rather than:

```text
GITHUB_TOKEN=ghp_xxxxxxxxx
```

---

# 14. Sandbox Runtime

The Sandbox Runtime consumes WorkloadSpec and translates it into operating-system enforcement.

It does not make high-level authorization decisions.

Example:

```text
WorkloadSpec:
    memory = 512MiB

Sandbox Runtime:
    cgroup v2 memory.max = 512MiB
```

Another example:

```text
WorkloadSpec:
    network = controlled

Sandbox Runtime:
    isolate workload networking
    prevent direct host egress
    route permitted traffic through controlled network path
```

The Sandbox Runtime may eventually include:

- process creation;
- process-group management;
- PID namespaces;
- user namespaces;
- mount namespaces;
- network namespaces;
- filesystem isolation;
- cgroup v2;
- seccomp;
- Linux capability reduction;
- `no_new_privs`;
- timeout enforcement;
- process-tree cleanup;
- result collection.

---

# 15. Linux Enforcement Layers

The initial Linux Sandbox is expected to use multiple mechanisms.

## 15.1 Process Isolation

Likely mechanisms:

- PID namespace;
- user namespace;
- IPC namespace;
- UTS namespace.

Goal:

> reduce the workload's visibility into and ability to interfere with host processes and namespaces.

---

## 15.2 Filesystem Isolation

Likely mechanisms:

- mount namespace;
- isolated root filesystem;
- bind mounts;
- read-only mounts;
- writable workspace;
- tmpfs;
- possibly `pivot_root`.

Goal:

> expose only the filesystem resources required by the workload.

---

## 15.3 Resource Control

Resource control will use **cgroup v2**.

Initial controls:

```text
memory.max
pids.max
cpu.max
```

Possible later controls:

```text
io.max
```

Goal:

> prevent one workload from exhausting shared host resources.

---

## 15.4 System Call Restriction

The sandbox will use **seccomp** to reduce the available system-call surface.

Potentially restricted operations may include:

- `ptrace`;
- `mount`;
- unnecessary namespace operations;
- other high-risk or unnecessary syscalls.

The exact policy will be determined experimentally.

Seccomp is one layer of defense, not a complete sandbox.

---

## 15.5 Privilege Reduction

Potential mechanisms:

- unprivileged execution;
- user namespaces;
- dropped Linux capabilities;
- `no_new_privs`.

The workload should receive only the privilege required by its task.

---

# 16. Tool Execution Flow

The first complete execution path will be Tool Gateway -> Workload -> Sandbox Runtime.

Example request:

```text
shell(["python3", "main.py"])
```

Flow:

```text
1. Agent Runtime sends ToolRequest
                |
                v
2. Tool Gateway validates request
                |
                v
3. Tool Gateway submits PolicyQuery
                |
                v
4. Policy Engine returns PolicyDecision
                |
         +------+------+
         |             |
       DENY           ALLOW
         |             |
         v             v
5a. Audit denial   5b. Build WorkloadSpec
         |             |
         v             v
6a. Return error   6b. Sandbox Runtime prepares workload
                       |
                       v
                   7. Establish isolation
                       |
                       v
                   8. Start workload
                       |
                       v
                   9. Monitor workload
                       |
                       v
                  10. Collect result
                       |
                       v
                  11. Cleanup
                       |
                       v
                  12. Audit
                       |
                       v
                  13. Return ToolResult
```

The agent never directly starts an unrestricted host process.

---

# 17. Network Flow for Workloads

A Workload with:

```text
network = controlled
```

must not receive unrestricted host networking.

Conceptual flow:

```text
Workload
   |
   | outbound connection
   v
Sandbox Network Boundary
   |
   | controlled egress only
   v
Network Gateway
   |
   | Policy Engine decision
   v
ALLOW / DENY
   |
   v
Internet / API
```

The responsibilities are deliberately split.

### Sandbox Runtime

Ensures:

> the workload cannot bypass the controlled network path.

### Network Gateway

Ensures:

> only policy-approved destinations are reachable through that path.

### Policy Engine

Defines:

> which network destinations and classes of traffic are allowed.

---

# 18. Creation-Time and Runtime Policy

Not all policy decisions occur at the same moment.

## 18.1 Creation-Time Policy

These decisions typically shape the Workload before it starts:

- timeout;
- memory limit;
- process limit;
- CPU limit;
- filesystem visibility;
- security profile;
- initial network mode.

Example:

```text
PolicyDecision:
    memory <= 512MiB
```

This becomes part of WorkloadSpec.

---

## 18.2 Runtime Policy

Some decisions may occur while the Workload is running.

Examples:

- connect to `github.com`?
- connect to `pypi.org`?
- access external API X?
- future dynamic capability request?

Conceptually:

```text
Workload
   |
   v
Network Gateway
   |
   v
Policy Engine
   |
   v
ALLOW / DENY
```

The Policy Engine therefore remains an active Control Plane component throughout the workload lifecycle.

---

# 19. Audit System

Audit is a cross-cutting capability.

Security-sensitive components emit structured events.

```text
Policy Engine  ----+
Tool Gateway   ----+
Sandbox Runtime----+----> Audit System
Network Gateway----+
Model Gateway  ----+
```

Audit should answer:

- what happened?
- who requested it?
- which workload was involved?
- what policy was used?
- what decision was made?
- what enforcement action occurred?
- what was the final result?

Example:

```json
{
  "event_type": "network.denied",
  "agent_id": "coding-agent",
  "workload_id": "ag-wl-00042",
  "destination": "169.254.169.254",
  "policy_id": "coding-default",
  "decision": "deny"
}
```

Sensitive values should be redacted by default.

Audit must not become a new secret-leakage channel.

---

# 20. Failure Model

Security-sensitive failures should fail closed unless explicitly documented otherwise.

## 20.1 Policy Failure

```text
cannot evaluate policy
        |
        v
       DENY
```

---

## 20.2 Sandbox Setup Failure

```text
required isolation cannot be established
        |
        v
do not start workload
```

AgentGuard must never silently fall back to unrestricted host execution.

---

## 20.3 Network Enforcement Failure

If a workload requires controlled networking but the controlled egress path cannot be established:

```text
network enforcement unavailable
        |
        v
do not start workload
```

unless policy explicitly permits a more restrictive fallback such as:

```text
network = disabled
```

It should never fall back to unrestricted networking.

---

## 20.4 Timeout

```text
timeout reached
      |
      v
terminate complete workload process tree
      |
      v
cleanup
      |
      v
audit
```

---

## 20.5 Cleanup Failure

Cleanup failures must be observable.

Examples:

- surviving processes;
- leaked mounts;
- leaked cgroups;
- leaked network namespaces;
- leaked temporary files.

Cleanup failure must not be silently ignored.

---

# 21. Dependency Direction

The codebase should preserve clear dependency direction.

A possible logical dependency model is:

```text
cmd
 |
 v
gateway
 |
 +--------> policy
 |
 +--------> workload
 |
 +--------> audit

workload / orchestration
 |
 +--------> sandbox
 |
 +--------> audit

sandbox
 |
 +--------> low-level Linux implementation

network gateway
 |
 +--------> policy
 |
 +--------> audit
```

Important rules:

- Policy Engine must not depend on Gateways.
- Policy Engine must not depend on Sandbox Runtime.
- Sandbox Runtime must not depend on Tool Gateway.
- Network Gateway must not own the global policy model.
- Audit must not make authorization decisions.
- Circular package dependencies should be avoided.

---

# 22. Possible Package Layout

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

This is not a commitment to create all directories immediately.

Packages should be introduced only when their corresponding functionality exists.

---

# 23. Security Test Categories

Security claims should be backed by adversarial tests.

Possible categories:

```text
tests/attacks/
├── memory_exhaustion/
├── fork_bomb/
├── host_file_read/
├── host_file_write/
├── process_probe/
├── forbidden_syscall/
├── timeout_escape/
├── network_bypass/
└── secret_inheritance/
```

Expected results:

| Test | Expected Result |
|---|---|
| Excessive memory allocation | Limited by cgroup |
| Fork bomb | Limited by workload process limit |
| Host sensitive-file read | Denied or unavailable |
| Host process enumeration | Isolated |
| Forbidden syscall | Denied |
| Execution beyond timeout | Entire workload terminated |
| Direct network bypass | Blocked |
| Unauthorized destination | Denied by Network Gateway |
| Host secret environment inheritance | Not present |

---

# 24. Implementation Sequence

The architecture is intended to be implemented incrementally.

```text
Phase 0
Architecture & Threat Model
        |
        v
Phase 1
Execution Core
        |
        v
Phase 2
Workload + Linux Sandbox
        |
        v
Phase 3
Policy Engine
        |
        v
Phase 4
Tool Gateway
        |
        v
First MVP
        |
        +-------------------+
        |                   |
        v                   v
Phase 5             Phase 6
Network Gateway     Model Gateway
        |                   |
        +---------+---------+
                  |
                  v
              Phase 7
     Unified Security Control Plane
```

Each phase must have explicit acceptance criteria.

---

# 25. Open Architecture Questions

The following questions remain intentionally unresolved.

## Workload

- When exactly is a Workload ID allocated?
- Should WorkloadSpec be persisted?
- Should workloads support runtime policy changes in the future?
- How should workload identity be propagated to Network Gateway?
- How should workload cleanup be verified?

## Sandbox

- Should the first sandbox use an internal init process?
- Which namespaces are mandatory for the first version?
- Should rootless operation be mandatory from the beginning?
- What should the first seccomp profile allow?
- How should root filesystem images be managed?

## Policy

- What serialization format should policies use?
- How should policy precedence work?
- Should the first version support roles or only profiles?
- How should path patterns be matched?
- How should domain policies be matched?

## Network

- Should controlled egress use a proxy?
- Should workloads receive a dedicated network namespace?
- How should DNS rebinding be handled?
- How should redirects be re-evaluated?
- How should non-HTTP protocols be handled?

## Audit

- Should audit emission be synchronous?
- What happens if the audit sink fails?
- Which fields must be redacted?
- How long should workload correlation metadata be retained?

These should be resolved through focused design work and implementation evidence rather than premature abstraction.

---

# 26. Summary

The core AgentGuard architecture is:

```text
                     CONTROL PLANE

                    Policy Engine
                         |
                 security decisions
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
 Model Gateway      Tool Gateway      Network Gateway
                         |
                         v
                    WorkloadSpec
                         |
                         v
                   Sandbox Runtime
                         |
                         v
                      Workload
                         |
                  controlled egress
                         |
                         v
                  Network Gateway
```

The key responsibilities are:

```text
Policy Engine
    defines what is allowed

Gateways
    enforce capability-level policy

WorkloadSpec
    defines the final execution contract

Sandbox Runtime
    translates that contract into OS-level enforcement

Workload
    is the actual controlled execution unit

Audit
    records what happened
```

The most important boundary is:

> **Policy defines the desired security state. Gateways enforce capability access. The Sandbox Runtime makes workload-level restrictions non-bypassable at the operating-system layer.**

This separation allows AgentGuard to evolve into a unified agent security control plane without coupling high-level policy directly to Linux implementation details.
