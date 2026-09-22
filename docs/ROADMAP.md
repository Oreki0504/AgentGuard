# AgentGuard Roadmap

> This document defines the implementation order for AgentGuard.
>
> Architecture belongs in `ARCHITECTURE.md`.  
> Security threats belong in `THREAT_MODEL.md`.  
> Project-wide security rules belong in `DESIGN_PRINCIPLES.md`.
>
> This file defines **what to build, in what order, and how to know each phase is complete**.

---

## Phase 0 — Design Baseline

### Goal

Define enough of the system before implementation begins.

### Scope

- project positioning;
- architecture baseline;
- trust assumptions;
- Workload / WorkloadSpec model;
- threat model;
- development roadmap;
- design principles.

### Deliverables

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/ROADMAP.md`
- `docs/DESIGN_PRINCIPLES.md`

### Acceptance Criteria

- [x] AgentGuard has a clear project definition.
- [x] Control Plane and Enforcement Plane are defined.
- [x] Policy Engine, Gateways, Sandbox Runtime, Workload, and WorkloadSpec have clear responsibilities.
- [x] Agent Runtime trust assumptions are documented.
- [x] Initial threat scenarios and trust boundaries are documented.
- [x] Runtime Defaults and mandatory Security Baseline are distinguished.
- [x] Implementation phases are defined.
- [x] Design principles are documented.
- [ ] Phase 0 documents have been reviewed for duplicated or conflicting responsibilities.
- [ ] Repository metadata and root files are aligned with the current project definition.

---

## Phase 1 — Execution Core

### Goal

Build a reliable local process-execution foundation before adding isolation.

### Scope

Implement a process runner capable of executing a command and reliably managing its lifecycle.

Initial capabilities:

- command execution;
- argument handling;
- working directory;
- controlled environment variables;
- stdout capture;
- stderr capture;
- exit code;
- execution duration;
- timeout;
- cancellation;
- process-tree cleanup.

### Deliverables

- AgentGuard CLI entry point;
- execution request/result types;
- process runner;
- unit tests;
- basic integration tests.

Example target interface:

```text
agentguard run -- python3 main.py
```

### Acceptance Criteria

- [ ] A normal command executes successfully.
- [ ] Command arguments are passed correctly.
- [ ] stdout and stderr are captured separately.
- [ ] Non-zero exit codes are reported correctly.
- [ ] Working directory can be controlled.
- [ ] Host environment variables are not blindly inherited.
- [ ] A configured timeout terminates execution.
- [ ] Child processes do not remain alive after timeout or cancellation.
- [ ] Tests cover success, failure, timeout, and cancellation paths.

---

## Phase 2 — Workload + Linux Sandbox

### Goal

Turn unrestricted process execution into a policy-constrained Linux Workload.

Phase 2 is split into smaller implementation steps so that each isolation mechanism can be understood and verified independently.

---

### Phase 2A — Workload Lifecycle + Resource Control

#### Scope

Introduce the Workload abstraction and establish Workload-wide lifecycle and resource control.

Initial capabilities:

- Workload identity;
- Workload lifecycle;
- WorkloadSpec;
- process-tree attribution;
- cgroup v2;
- memory limits;
- process-count limits;
- CPU controls;
- cleanup;
- minimal structured security events.

#### Deliverables

- `WorkloadSpec`;
- Workload state model;
- Sandbox Runtime skeleton;
- cgroup v2 integration;
- minimal Audit event interface;
- resource-abuse tests.

#### Acceptance Criteria

- [ ] Every execution receives a unique Workload identity.
- [ ] Workload state transitions are observable.
- [ ] All child processes remain attributable to the Workload.
- [ ] Memory limits apply to the entire Workload.
- [ ] Process-count limits apply to the entire Workload.
- [ ] CPU usage can be constrained.
- [ ] A fork bomb cannot exhaust the host process table.
- [ ] A memory-exhaustion Workload cannot destabilize the host.
- [ ] Timeout or cancellation terminates the complete Workload process tree.
- [ ] Cleanup removes remaining processes and temporary runtime state.
- [ ] Important lifecycle and failure events are emitted as structured events.

---

### Phase 2B — Namespace + Filesystem Isolation

#### Scope

Introduce process-visibility and filesystem boundaries.

Initial capabilities:

- PID namespace;
- user namespace where appropriate;
- mount namespace;
- isolated filesystem view;
- explicit bind mounts;
- writable workspace;
- read-only mounts.

#### Deliverables

- namespace setup;
- filesystem-isolation layer;
- workspace mount model;
- adversarial filesystem/process tests.

#### Acceptance Criteria

- [ ] Host files not explicitly exposed are unavailable.
- [ ] A writable workspace can be explicitly provided.
- [ ] Read-only mounts remain read-only.
- [ ] The Workload cannot directly inspect unrelated host processes.
- [ ] Namespace or filesystem setup failure prevents execution.
- [ ] Host-file and host-process attack tests produce the expected denial behavior.
- [ ] Security-relevant failures are observable through structured events.

---

### Phase 2C — Privilege Reduction + Syscall Hardening

#### Scope

Reduce the privilege and syscall surface available to Workloads.

Initial capabilities:

- unprivileged execution;
- Linux capability reduction;
- `no_new_privs`;
- seccomp;
- security-profile mapping;
- fail-closed setup behavior.

#### Deliverables

- privilege-reduction layer;
- initial seccomp profile;
- Workload security-profile handling;
- syscall adversarial tests.

#### Acceptance Criteria

- [ ] Unnecessary Linux capabilities are removed.
- [ ] `no_new_privs` is applied where required.
- [ ] A first seccomp profile is implemented.
- [ ] At least one intentionally forbidden syscall is verified to fail.
- [ ] WorkloadSpec security intent is translated into backend-specific enforcement without exposing Linux details in the high-level policy model.
- [ ] Failure to establish required protection prevents Workload startup.
- [ ] AgentGuard never silently falls back to unrestricted host execution.

### Phase 2 Complete When

All Phase 2A, 2B, and 2C acceptance criteria are satisfied.

---

## Phase 3 — Policy Engine

### Goal

Move security decisions out of hard-coded runtime behavior into an explicit policy layer.

### Scope

Implement a minimal Policy Engine capable of:

1. loading policy;
2. evaluating a request;
3. returning an explicit decision and constraints.

The first version should remain intentionally small.

### Deliverables

- policy data model;
- `PolicyQuery`;
- `PolicyDecision`;
- policy loader;
- evaluator;
- policy tests;
- WorkloadSpec builder integration.

Example conceptual result:

```text
ALLOW

timeout = 30s
memory = 512MiB
processes = 64
filesystem = workspace-only
network = disabled
```

### Acceptance Criteria

- [ ] Requests without an explicit allow rule are denied.
- [ ] Policy can allow or deny tool execution.
- [ ] Policy can produce execution constraints.
- [ ] Runtime Defaults can be overridden only where allowed.
- [ ] Security Baseline requirements cannot be weakened by ordinary policy.
- [ ] Policy constraints are preserved when building WorkloadSpec.
- [ ] Conflicting or invalid policy fails predictably.
- [ ] Policy Engine contains no Linux-specific enforcement logic.
- [ ] Policy evaluation is covered by unit tests.
- [ ] Policy-to-WorkloadSpec translation is covered by tests.

---

## Phase 4 — Tool Gateway

### Goal

Create the first complete AgentGuard enforcement path.

This phase completes the **initial MVP**.

### Scope

Add a Tool Gateway between the Agent Runtime and execution capabilities.

Initial focus:

- shell / command execution;
- request validation;
- policy evaluation;
- WorkloadSpec construction;
- Sandbox Runtime invocation;
- structured results;
- correlated audit events.

### Deliverables

- `ToolRequest` / `ToolResult`;
- Tool Gateway;
- integration with Policy Engine;
- integration with Sandbox Runtime;
- request / Workload correlation;
- structured Audit events;
- end-to-end tests.

### Acceptance Criteria

- [ ] Agent requests cannot directly invoke unrestricted execution through the Tool Gateway path.
- [ ] Tool Gateway validates incoming requests.
- [ ] Every protected tool request receives an explicit PolicyDecision.
- [ ] Denied requests never create a Workload.
- [ ] Allowed execution requests create a validated WorkloadSpec.
- [ ] Sandbox execution respects PolicyDecision constraints and the Security Baseline.
- [ ] ToolResult reports execution outcome consistently.
- [ ] Important allow, deny, execution, timeout, and cleanup events are correlated.
- [ ] Audit output avoids leaking sensitive data.
- [ ] End-to-end tests cover both allowed and denied requests.

### MVP Complete When

The following path works end to end:

```text
Agent Request
     |
     v
Tool Gateway
     |
     v
Policy Engine
     |
     v
WorkloadSpec
     |
     v
Sandbox Runtime
     |
     v
Controlled Workload
     |
     v
Audit + Result
```

---

## Phase 5 — Network Gateway

### Goal

Provide controlled outbound network access for AgentGuard-managed Workloads.

### Scope

Introduce network policy enforcement with a deny-by-default model.

Initial capabilities:

- controlled egress;
- destination allow / deny policy;
- private-network blocking;
- loopback restrictions;
- link-local blocking;
- cloud metadata protection;
- Workload identity propagation;
- network auditing.

The exact mechanism may use a proxy, network namespaces, or a combination determined during implementation.

### Deliverables

- Network Gateway;
- network policy request/decision model;
- controlled Workload egress path;
- Network Gateway audit events;
- network adversarial tests.

### Acceptance Criteria

- [ ] A Workload with networking disabled has no outbound network access.
- [ ] A Workload with controlled networking cannot bypass the Network Gateway.
- [ ] Explicitly allowed destinations are reachable.
- [ ] Non-allowed destinations are denied.
- [ ] Private-network access is denied by default.
- [ ] Loopback and link-local access are denied by default unless explicitly allowed.
- [ ] Cloud metadata endpoints are denied by default.
- [ ] Network decisions are attributable to a Workload identity.
- [ ] Network enforcement failure never results in unrestricted egress.
- [ ] Network bypass tests are included.
- [ ] Network allow / deny events are correlated with the originating Workload.

---

## Phase 6 — Model Gateway

### Goal

Mediate Agent access to LLM providers through AgentGuard policy and auditing.

### Scope

Initial capabilities may include:

- provider allowlists;
- model allowlists;
- provider-owned credentials;
- request limits;
- token limits;
- basic secret detection;
- usage auditing;
- optional provider routing.

### Deliverables

- Model Gateway;
- model request/response abstraction;
- provider adapter interface;
- policy integration;
- credential isolation;
- audit events;
- tests.

### Acceptance Criteria

- [ ] Agent code does not need direct access to provider credentials.
- [ ] Unauthorized models/providers are denied.
- [ ] Allowed models/providers can be accessed through the Gateway.
- [ ] Request limits are enforced.
- [ ] Sensitive provider credentials are not exposed to Workloads.
- [ ] Model requests produce structured, correlated audit events.
- [ ] Policy failure defaults to deny.

---

## Phase 7 — Unified Security Control Plane

### Goal

Integrate the major AgentGuard enforcement domains into a coherent security control plane.

### Scope

Unify:

- identity;
- policy;
- Workload context;
- auditing;
- configuration;
- Tool Gateway;
- Network Gateway;
- Model Gateway.

This phase focuses on coherence rather than adding many new features.

### Deliverables

- unified Agent identity model;
- shared policy context;
- cross-component correlation identifiers;
- unified audit schema;
- configuration model;
- end-to-end multi-gateway tests;
- updated Architecture and Threat Model.

### Acceptance Criteria

- [ ] Tool, Network, and Model Gateways use the same Agent identity model.
- [ ] Policy decisions use consistent subject/action/resource/context semantics.
- [ ] Workload events can be correlated with originating Agent requests.
- [ ] Network activity can be correlated with the originating Workload.
- [ ] Model activity can be correlated with the originating Agent request.
- [ ] Audit records across components use a consistent schema.
- [ ] No Gateway maintains an independent conflicting global policy model.
- [ ] End-to-end tests exercise multiple enforcement domains together.
- [ ] Architecture and Threat Model are updated to reflect the implemented system.

---

## Post-MVP / Optional Extensions

These are intentionally **not part of the core roadmap** until justified by implementation needs.

Possible future work:

- Agent Runtime confinement;
- gVisor backend;
- VM / Firecracker backend;
- remote sandbox workers;
- persistent Workloads;
- multi-tenant isolation;
- secret injection service;
- dynamic runtime policy;
- additional Tool protocols;
- MCP integration;
- advanced DLP;
- distributed policy delivery;
- external audit sinks;
- monitoring / detection engine;
- performance benchmarking.

These should not block the core AgentGuard implementation.

---

## Roadmap Rule

A Phase is complete only when its **Acceptance Criteria are demonstrably satisfied**.

Completing code is not enough.

Each security claim should be supported by:

```text
implementation
     +
test
     +
observable result
```

If implementation evidence shows that the Architecture or Threat Model is wrong, the relevant design document should be updated before continuing.