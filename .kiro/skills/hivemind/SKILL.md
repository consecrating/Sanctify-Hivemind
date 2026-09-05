---
name: hivemind
description: >
  Multi-agent orchestration for autonomous operations on live WordPress sites.
  Activate when a task involves auditing, securing, scanning for malware, detecting
  vulnerable plugins/themes, hardening, or otherwise operating on a live WordPress
  environment. Provides a goal->plan->execute->verify->rollback engine with
  capability-scoped tools, an actor-critic verification loop, and a replayable audit
  trace. Built by Sanctify (https://www.sanctify.in/).
---

# Hivemind skill

Use Sanctify-Hivemind to run website operations as a coordinated agent swarm instead
of one-off scripts.

## Decide fast
- Task is "look at / audit / scan a site" → run Hivemind with a READ-only goal.
- Task is "clean / fix / harden a live site" → run with `--remediate` (writes are
  gated by the approval callback + wrapped in SafeChange rollback).
- Task is a brand-new capability → add a `Tool` (correct `Access`) or a new `Agent`.

## Invoke
```bash
python examples/demo_offline.py                      # no creds — proves the pipeline
hivemind run "audit and secure this site"            # live; reads WP_URL/creds from .env
hivemind run "scan for malware and vulnerable plugins" --json
```

## Architecture (what to reason about)
- **Orchestrator**: goal → task DAG → parallel/sequential scheduling → delegation.
- **Tools + Capability model**: typed tools; grants cap access (READ/WRITE/DESTRUCTIVE)
  and scope; WRITE/DESTRUCTIVE hit an approval gate.
- **Safety**: `SafeChange` = snapshot → act → health-check → commit/rollback; `AuditTrace`.
- **Critic**: independent verifier; ACCEPT / RETRY / REJECT with a retry budget.
- **Memory**: `EnvironmentMemory` (warm-start world-model), `Blackboard` (coordination),
  `PatternStore` (learning).
- **Agents**: `recon` (READ-only fingerprint), `security` (malware IOCs + CVE match,
  optional remediation). SEO/Frontend/Content follow the same contract.

## Safety rules (non-negotiable)
1. Never commit secrets — env/.env only.
2. Least privilege grants; recon never gets WRITE.
3. Every live mutation goes through SafeChange.
4. Trust nothing until the critic verifies it.
5. New CVE/malware indicator → update `hivemind/agents/rules.py` and bump RULES_VERSION.
