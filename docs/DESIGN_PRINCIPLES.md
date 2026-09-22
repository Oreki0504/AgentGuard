# AgentGuard Design Principles

> These principles guide implementation decisions across AgentGuard.
>
> They define stable engineering and security rules, not component architecture or implementation order.

---

## 1. Deny by Default

Protected capabilities are unavailable unless explicitly allowed.

If no policy rule matches, the result is:

```text
DENY
```

This applies to:

- tool access;
- filesystem access;
- network access;
- model access;
- other protected capabilities.

---

## 2. Fail Closed

If a required security mechanism cannot be established, the protected operation must fail.

Examples:

- cgroup setup fails;
- namespace setup fails;
- filesystem isolation fails;
- seccomp installation fails;
- controlled network egress cannot be established.

AgentGuard must never silently fall back to unrestricted execution.

---

## 3. Least Privilege

Agents and Workloads receive only the permissions and resources required for their task.

Examples:

- expose only required filesystem paths;
- grant only required Linux capabilities;
- provide only necessary environment variables;
- allow only required network destinations;
- enforce bounded resource usage.

---

## 4. Separate Policy from Enforcement

The Policy Engine decides **what is allowed**.

Gateways and runtime mechanisms decide **how those decisions are enforced**.

Policy code must not depend on low-level enforcement details such as:

- cgroup paths;
- namespace flags;
- mount operations;
- seccomp rules.

---

## 5. Security Baseline Cannot Be Weakened by Defaults or Policy

AgentGuard distinguishes between:

```text
Runtime Defaults
    configurable fallback values

Security Baseline
    mandatory protections
```

Runtime Defaults may be overridden where allowed.

Security Baseline requirements must not be weakened by:

- request data;
- ordinary policy;
- runtime defaults;
- backend configuration.

---

## 6. No Silent Security Downgrade

A security requirement must never become weaker without an explicit and valid security decision.

For example:

```text
network = controlled
```

must not silently become:

```text
network = unrestricted
```

If the required protection cannot be provided, AgentGuard should fail or choose a more restrictive behavior.

---

## 7. Contain the Entire Workload

Security, lifecycle, and resource controls apply to the entire Workload, not only to its initial process.

Child processes must remain:

- attributable to the Workload;
- subject to its resource limits;
- subject to its isolation boundaries;
- subject to its termination and cleanup.

---

## 8. Do Not Implicitly Inherit Host Secrets

Workloads must not automatically inherit the host process environment.

Sensitive values such as:

- API keys;
- cloud credentials;
- SSH credentials;
- provider tokens;

must be introduced through explicit controlled mechanisms.

---

## 9. Make Important Security State Explicit

Security-relevant state should be represented explicitly rather than hidden in defaults or side effects.

Examples:

- `PolicyDecision`;
- `WorkloadSpec`;
- Workload lifecycle state;
- network mode;
- filesystem permissions;
- correlation identifiers.

Explicit state is easier to validate, test, audit, and reason about.

---

## 10. Security Claims Must Be Testable

A security claim is not complete until it can be verified.

Example:

```text
Claim:
The Workload cannot read host SSH keys.

Verification:
Attempt the access from an adversarial test and confirm that it fails.
```

Security features should provide:

```text
implementation
+
test
+
observable result
```

---

## 11. Security-Relevant Events Must Be Observable

Important security decisions and enforcement outcomes should produce structured, correlated events.

Examples:

- policy allow / deny;
- Workload start / stop;
- timeout;
- sandbox setup failure;
- resource-limit violation;
- blocked network request;
- cleanup failure.

Audit provides evidence, debugging, and forensic visibility.

Audit must not make authorization decisions, and sensitive fields must be omitted or redacted.

---

## 12. Security Boundaries Must Not Depend on Agent Intent

AgentGuard should not need to determine whether Agent-controlled behavior is:

- malicious;
- accidental;
- confused;
- prompt-injected;
- simply incorrect.

The same security boundaries apply regardless of intent.

---

## 13. Trust Assumptions Must Be Explicit

AgentGuard must clearly document which components are trusted and which are not.

The initial design trusts the Agent Runtime integration to route protected capabilities through AgentGuard.

Agent-controlled requests and Workloads are not trusted.

If future versions reduce a trust assumption, the architecture and threat model must be updated accordingly.

---

## 14. Cleanup Is Part of Security

A Workload is not complete until its resources are cleaned up.

Cleanup may include:

- remaining processes;
- cgroups;
- mounts;
- namespaces;
- temporary files;
- network resources.

Cleanup failures must be observable.

---

## 15. Prefer Simple Mechanisms Before Premature Abstraction

Do not introduce complexity before the underlying requirement is understood.

Examples:

- do not build a custom policy language before simple structured policies are insufficient;
- do not add multiple sandbox backends before the Linux backend works reliably;
- do not introduce distributed execution before single-host execution is correct.

Abstractions should be justified by real implementation needs.

---

## 16. Architecture May Evolve, Security Invariants Must Not Drift Silently

Implementation experience may justify architecture changes.

When that happens:

1. update the architecture;
2. update the threat model when security assumptions change;
3. update the roadmap when implementation order changes;
4. verify that required security properties still hold.

Refactoring must not silently weaken security behavior.

---

## Summary

AgentGuard should prefer:

```text
explicit over implicit
deny over assume
fail closed over silent fallback
least privilege over convenience
mandatory baselines over configurable weakening
testable guarantees over undocumented assumptions
structured evidence over opaque behavior
simple mechanisms over premature abstraction
```
