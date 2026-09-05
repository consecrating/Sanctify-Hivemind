# Sanctify-Hivemind — how to use

Sanctify-Hivemind is a multi-agent orchestration framework for autonomous operations
on live systems (WordPress is the first environment). Built by
[Sanctify](https://www.sanctify.in/).

## When to use it
When a task is "operate on a live WordPress site" — audit, security scan, malware
detection/cleanup, SEO, hardening — prefer routing through Hivemind's orchestrator
instead of ad-hoc scripts. It gives you: task decomposition, capability-scoped tools,
snapshot→act→verify→rollback safety, an independent critic, and a replayable trace.

## Run
```bash
pip install -e ".[wordpress]"          # from the repo root
cp .env.example .env                    # fill WP_URL (+ creds if acting, not just recon)
python examples/demo_offline.py         # offline proof (no live site)
hivemind run "audit and secure this site"        # live (reads .env)
hivemind run "audit and secure this site" --json # machine-readable
```

## Golden rules
- **Credential-free repo.** Secrets only in env / gitignored `.env`. Never commit them.
- **Least privilege.** Give an agent the smallest `CapabilityGrant` it needs. Recon is
  READ-only; remediation grants WRITE **with the approval gate on**.
- **Every write is a transaction.** Wrap mutating actions in `SafeChange`
  (snapshot → act → health-check → rollback). Never mutate a live site otherwise.
- **Verify, don't trust.** An agent asserting "done" is not evidence — the critic must
  independently confirm against the goal.
- **Grow the rules.** New incident/CVE → add to `hivemind/agents/rules.py`
  (bump `RULES_VERSION`). This is how the swarm gets smarter.

## Extending
- New capability → register a `Tool` on the adapter with the correct `Access` level.
- New specialist → subclass `Agent`, declare `capabilities`, implement `run()`, add to
  `hivemind/app.py` and the planner.
- New environment → add an adapter under `hivemind/environments/` exposing scoped tools.
