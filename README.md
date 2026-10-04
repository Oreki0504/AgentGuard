# AgentGuard

> A security control plane for AI agents.

**AgentGuard** is a Go-based security infrastructure project for controlling how AI agents access local tools, untrusted workloads, networks, and model providers.

The project separates **security policy** from **enforcement** so that agent-controlled actions can be evaluated, constrained, isolated, and audited before they reach sensitive host capabilities.

> **Status:** Early development.  
> Current phase: **Phase 2A — Workload Lifecycle + Resource Control**

---

## Why AgentGuard?

AI agents may be able to:

- execute commands;
- read or modify files;
- run generated code;
- access external APIs;
- connect to internal services;
- call LLM providers.

Agent-controlled behavior may be incorrect, compromised, or influenced by untrusted external content.

AgentGuard is designed to place explicit security boundaries between those requests and the capabilities they use.

---

## Architecture

AgentGuard is organized around a **Control Plane** and an **Enforcement Plane**.

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

### Policy Engine

Defines **what is allowed** and under which constraints.

Examples:

- tool permissions;
- execution timeout;
- memory and process limits;
- filesystem access;
- network mode;
- model/provider access.

### Gateways

Gateways are capability-level enforcement points.

- **Tool Gateway** — mediates shell, command, filesystem, and local tool access.
- **Network Gateway** — controls outbound network access.
- **Model Gateway** — controls access to LLM providers.

### Workload

A **Workload** is a uniquely identifiable, policy-constrained execution unit.

A Workload may contain an entire process tree rather than a single process.

### WorkloadSpec

A **WorkloadSpec** is the execution contract passed to the Sandbox Runtime.

It is derived from the request, policy decision, runtime defaults, and mandatory security requirements.

### Sandbox Runtime

The Sandbox Runtime translates a WorkloadSpec into operating-system-level enforcement.

The initial Linux backend will use mechanisms such as:

- namespaces;
- cgroup v2;
- filesystem isolation;
- seccomp;
- Linux capability reduction;
- `no_new_privs`;
- process-tree cleanup.

---

## Trust Model

The initial single-host design assumes that the **Agent Runtime integration itself is trusted to route protected capabilities through AgentGuard**.

Agent-controlled inputs are not trusted, including:

- tool calls;
- generated code;
- command arguments;
- requested paths;
- external content;
- downloaded dependencies;
- Workloads.

Protecting against a fully compromised Agent Runtime that intentionally bypasses AgentGuard is outside the initial MVP and may be addressed by future runtime-confinement work.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the detailed threat model.

---

## Initial MVP

The first complete MVP focuses on secure local tool execution:

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

The MVP will include:

- reliable process execution;
- timeout and cancellation;
- Workload lifecycle management;
- Linux isolation;
- resource limits;
- filesystem isolation;
- syscall restrictions;
- explicit policy evaluation;
- structured audit events;
- adversarial security tests.

Network Gateway and Model Gateway are later phases.

---

## Security Principles

AgentGuard follows a small set of project-wide rules:

- deny by default;
- fail closed;
- least privilege;
- separate policy from enforcement;
- never silently downgrade security;
- constrain the entire Workload;
- do not implicitly inherit host secrets;
- make security claims testable;
- make security-relevant decisions observable.

See [`docs/DESIGN_PRINCIPLES.md`](docs/DESIGN_PRINCIPLES.md).

---

## Roadmap

Development is incremental:

```text
Phase 0   Design Baseline
Phase 1   Execution Core
Phase 2   Workload + Linux Sandbox
Phase 3   Policy Engine
Phase 4   Tool Gateway              <- First MVP
Phase 5   Network Gateway
Phase 6   Model Gateway
Phase 7   Unified Security Control Plane
```

Detailed milestones and acceptance criteria are maintained in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Non-Goals

AgentGuard is not intended to be:

- a Docker replacement;
- a general-purpose container runtime;
- a Kubernetes platform;
- an AI agent framework;
- an MCP framework;
- an antivirus or EDR product;
- a general-purpose firewall;
- a guarantee that arbitrary untrusted code is perfectly safe.

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component boundaries and system design
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — threats, trust assumptions, and expected controls
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — implementation order and acceptance criteria
- [`docs/DESIGN_PRINCIPLES.md`](docs/DESIGN_PRINCIPLES.md) — project-wide engineering and security principles

---

## Platform

AgentGuard is implemented in **Go** and primarily targets **Linux**.

The first sandbox backend will use Linux security mechanisms directly.

---

## Development Status

AgentGuard is currently in **Phase 1   Execution Core**.

No production-ready security guarantees are currently provided.
