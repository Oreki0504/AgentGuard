# AgentGuard

> A security control plane for AI agents.

**AgentGuard** is a security infrastructure project for controlling how AI agents interact with external capabilities such as models, local tools, filesystems, and networks.

Instead of trusting an agent runtime to enforce its own restrictions, AgentGuard introduces explicit security boundaries between the agent and the resources it can access.

> **Status:** Early design and development.  
> The project is currently in **Phase 0 — Architecture & Threat Modeling**.

---

## Why AgentGuard?

Modern AI agents can do much more than generate text.

A coding or automation agent may be able to:

- execute shell commands;
- read and modify files;
- invoke external tools;
- access LLM providers;
- make outbound network requests;
- interact with APIs and internal services.

This significantly expands the security boundary of an AI application.

For example, an untrusted or compromised agent could attempt to:

- read sensitive host files;
- exfiltrate credentials or source code;
- consume excessive CPU or memory;
- spawn large numbers of processes;
- interfere with other processes;
- access internal network services;
- invoke unauthorized tools;
- send sensitive information to external model providers.

AgentGuard aims to reduce these risks by placing security enforcement points between the agent runtime and the capabilities it uses.

---

## Architecture

The planned architecture consists of a shared policy and auditing layer with dedicated gateways for different capability classes.

```text
                         Agent Runtime
                              |
                              v
                    +-------------------+
                    |    AgentGuard     |
                    +-------------------+
                              |
                       Policy Engine
                              |
               +--------------+--------------+
               |              |              |
               v              v              v
            Model           Tool          Network
           Gateway         Gateway         Gateway
               |              |              |
               v              v              v
          LLM Providers     Sandbox        Internet
                            Filesystem       APIs
                            Shell
```

### Policy Engine

The **Policy Engine** makes authorization decisions for operations passing through AgentGuard.

Policies may eventually define rules such as:

- which models an agent may access;
- which tools it may invoke;
- which filesystem paths are visible;
- which network destinations are allowed;
- execution time and resource limits.

Policy decisions are intentionally separated from the mechanisms used to enforce them.

### Tool Gateway

The **Tool Gateway** mediates access to capabilities such as:

- shell execution;
- filesystem operations;
- local tools;
- future agent tool integrations.

Untrusted process execution will be delegated to an isolated Linux sandbox.

The sandbox is planned to use mechanisms such as:

- Linux namespaces;
- cgroup v2;
- filesystem isolation;
- seccomp;
- Linux capabilities;
- process and execution time limits.

The sandbox is one component of AgentGuard rather than the complete security boundary.

### Network Gateway

The **Network Gateway** is intended to control outbound network access from agents and sandboxed workloads.

Planned capabilities include:

- default-deny egress policies;
- domain and IP allowlists;
- private-network restrictions;
- protection against access to sensitive link-local and metadata services;
- network activity auditing.

### Model Gateway

The **Model Gateway** is intended to mediate requests from agents to LLM providers.

Potential controls include:

- model allowlists;
- provider routing;
- request limits;
- secret detection;
- request auditing;
- usage and cost controls.

### Audit System

Security-sensitive actions should generate structured audit events.

Examples include:

- tool invocation;
- policy decisions;
- sandbox execution results;
- denied operations;
- resource-limit violations;
- outbound network requests;
- model requests.

The goal is to make security decisions observable and explainable rather than silently enforced.

---

## Security Model

AgentGuard follows several core principles.

### Secure by Default

Capabilities should be denied unless they are explicitly allowed by policy.

### Least Privilege

Agents should receive only the permissions and resources required to complete their tasks.

### Defense in Depth

No single isolation mechanism is treated as a complete security boundary.

Process isolation, filesystem isolation, resource control, syscall filtering, policy enforcement, and auditing are intended to work together.

### Policy and Enforcement Separation

The policy layer determines **what should be allowed**.

Enforcement components determine **how those decisions are enforced**.

### Verifiable Security Properties

Security claims should be backed by tests.

For example, if AgentGuard claims that a sandbox cannot access host files, the project should contain tests that attempt that access and verify that it fails.

---

## Initial MVP

The first AgentGuard MVP will focus on securing local tool execution.

```text
                 Agent
                   |
                   v
              Tool Gateway
                   |
                   v
              Policy Engine
                   |
                allow?
                   |
                   v
                Sandbox
              /    |    \
             /     |     \
      Namespace  cgroup  seccomp
             \     |     /
              Filesystem
                   |
                   v
                 Audit
```

The MVP will include:

- controlled process execution;
- execution timeout and cancellation;
- structured execution results;
- Linux process isolation;
- filesystem isolation;
- cgroup v2 resource limits;
- seccomp syscall restrictions;
- basic policy evaluation;
- structured audit logging;
- security-focused integration tests.

The Model Gateway and Network Gateway are planned for later development phases.

---

## Roadmap

AgentGuard will be developed incrementally.

### Phase 0 — Architecture & Threat Modeling

- define project scope;
- define architecture;
- define threat model;
- define security principles;
- define MVP and non-goals.

### Phase 1 — Execution Core

Build a reliable process execution layer with:

- command execution;
- argument handling;
- working-directory control;
- stdout and stderr capture;
- exit-code reporting;
- timeout and cancellation;
- structured results.

### Phase 2 — Linux Sandbox

Introduce operating-system-level isolation:

- Linux namespaces;
- cgroup v2;
- filesystem isolation;
- resource limits;
- seccomp;
- sandbox security tests.

### Phase 3 — Policy Engine

Move security configuration out of implementation code and into explicit policies.

### Phase 4 — Tool Gateway

Expose controlled tool execution through a security enforcement layer.

This phase represents the first complete AgentGuard MVP.

### Phase 5 — Network Gateway

Add outbound network policy and auditing.

### Phase 6 — Model Gateway

Add security controls for model-provider access.

### Phase 7 — Unified Security Control Plane

Integrate the gateways around shared:

- identity;
- policy;
- configuration;
- auditing.

More detailed planning will be maintained in `docs/ROADMAP.md`.

---

## Non-Goals

AgentGuard is not intended to be:

- a replacement for Docker;
- a general-purpose container runtime;
- a Kubernetes platform;
- an AI agent framework;
- an antivirus or EDR product;
- a general-purpose firewall;
- a guarantee that arbitrary untrusted code is safe.

AgentGuard instead focuses on reducing the impact of untrusted or compromised AI-agent behavior under a clearly defined threat model.

---

## Project Structure

The project is currently in the design phase.

The expected structure will evolve approximately as follows:

```text
AgentGuard/
├── cmd/
│   └── agentguard/
├── internal/
│   ├── runner/
│   ├── sandbox/
│   ├── policy/
│   ├── gateway/
│   └── audit/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── ROADMAP.md
│   └── DESIGN_PRINCIPLES.md
├── tests/
├── go.mod
└── README.md
```

Directories will be introduced only when their corresponding functionality is implemented.

---

## Platform

AgentGuard is implemented in **Go** and primarily targets **Linux**.

Linux-specific security mechanisms will form the foundation of the execution sandbox.

---

## Development Status

AgentGuard is currently under active development.

Current phase:

```text
Phase 0
Architecture & Threat Modeling
```

No production-ready security guarantees are currently provided.
