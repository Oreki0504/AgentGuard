# AgentGuard Design Principles

> These principles guide implementation decisions across AgentGuard.
> They are intentionally short and should remain stable even as the architecture evolves.

---

## 1. Deny by Default

Capabilities are unavailable unless explicitly allowed.

If no rule matches, the result is:

```text
DENY
```

This applies to:

- tool access;
- filesystem access;
- network access;
- model access;
- workload capabilities.

---

## 2. Fail Closed

If a required security mechanism cannot be established, execution must fail.

Examples:

- cgroup setup fails;
- namespace setup fails;
- seccomp installation fails;
- controlled network egress cannot be established.

AgentGuard must never silently fall back to weaker or unrestricted execution.

---

## 3. Least Privilege

Agents and Workloads receive only the permissions and resources required for their task.

Examples:

- expose only the required filesystem paths;
- grant only required Linux capabilities;
- provide only necessary environment variables;
- allow only required network destinations.

---

## 4. Separate Policy from Enforcement

The Policy Engine decides **what is allowed**.

Gateways and runtime mechanisms decide **how those decisions are enforced**.

Policy code should not contain low-level Linux enforcement logic such as:

- cgroup manipulation;
- namespace setup;
- mount operations;
- seccomp installation.

---

## 5. No Silent Security Downgrade

A security requirement must not become weaker without an explicit decision.

For example:

```text
network = controlled
```

must never silently become:

```text
network = unrestricted
```

If the requested protection cannot be provided, AgentGuard should fail or choose a more restrictive behavior.

---

## 6. Contain the Entire Workload

Security and resource controls apply to the complete Workload, not only to its initial process.

Child processes must remain:

- attributable to the Workload;
- subject to its resource limits;
- subject to its lifecycle;
- subject to its cleanup.

---

## 7. Do Not Implicitly Inherit Host Secrets

Workloads must not automatically inherit the host process environment.

Sensitive values such as:

- API keys;
- cloud credentials;
- SSH credentials;
- provider tokens;

must be explicitly provided through controlled mechanisms.

---

## 8. Security Claims Must Be Testable

A security claim is not considered complete until it can be verified.

Example:

```text
Claim:
The Workload cannot read host SSH keys.

Verification:
Attempt the read from an adversarial test and confirm failure.
```

Security features should have:

```text
implementation
+
test
+
observable result
```

---

## 9. Security-Relevant Decisions Must Be Observable

Important security events should produce structured audit information.

Examples:

- policy allow / deny;
- workload start / stop;
- timeout;
- resource-limit violation;
- blocked network request;
- sandbox setup failure.

Audit output must avoid leaking sensitive data.

---

## 10. Prefer Explicit State and Boundaries

Important security state should be represented explicitly.

Examples:

- WorkloadSpec;
- PolicyDecision;
- Workload lifecycle state;
- network mode;
- filesystem permissions.

Avoid security behavior that depends on hidden defaults or implicit side effects.

---

## 11. Prefer Simple Mechanisms Before Premature Abstraction

Do not introduce complexity before the underlying problem is understood.

Examples:

- do not build a custom policy language before simple structured policies are insufficient;
- do not add multiple sandbox backends before the Linux backend works reliably;
- do not introduce distributed execution before single-host execution is correct.

Abstractions should be justified by real implementation needs.

---

## 12. Security Boundaries Must Not Depend on Agent Intent

AgentGuard should not need to determine whether an Agent is:

- malicious;
- confused;
- prompt-injected;
- simply wrong.

The same policy and enforcement boundaries apply regardless of intent.

---

## 13. Cleanup Is Part of Security

A Workload is not finished until its resources are cleaned up.

Cleanup includes, where applicable:

- remaining processes;
- cgroups;
- mounts;
- namespaces;
- temporary files;
- network resources.

Cleanup failures must be observable.

---

## 14. Architecture May Evolve, Invariants Should Not Drift Silently

Implementation experience may justify architecture changes.

When that happens:

1. update the architecture;
2. update the threat model if necessary;
3. verify that security invariants still hold.

Security behavior must not change accidentally as a side effect of refactoring.

---

## Summary

AgentGuard should prefer:

```text
explicit over implicit
deny over assume
fail closed over silent downgrade
least privilege over convenience
testable guarantees over undocumented assumptions
simple mechanisms over premature abstraction
```