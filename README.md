# 🧠 Sanctify-Hivemind

**A multi-agent orchestration framework for autonomous operations on live systems.**

Hivemind lets a *swarm* of specialized AI agents take a one-line goal, decompose it
into a task graph, execute tool calls against a **real production environment**,
independently verify every action, and roll back on failure — with a full,
replayable audit trace.

WordPress is the **first environment adapter** (and a demanding one: live sites,
credentials, no room for "oops"). But the framework is environment-agnostic —
the interesting part is the *architecture*, not the CMS.

> The website is the proving ground. The product is the agent system.

---

## Why this exists

Letting an LLM *act* on a live system is easy to demo and terrifying to run. The
hard problems aren't "call an API" — they're:

1. **Coordination** — how do you decompose a fuzzy goal into ordered, parallelizable
   work and delegate it to the right specialists?
2. **Safety on production** — how do you let an agent write to a live system without
   a bad step causing an outage?
3. **Reliability** — how do you know an action actually *worked*, and recover when it
   didn't, without a human watching every step?

Hivemind is an opinionated answer to those three, learned the hard way from real
incident-response and site-operations work.

---

## Architecture

```
                         ┌──────────────────────────────┐
          goal  ───────► │        Orchestrator          │
   "harden + audit       │  goal → task DAG → schedule   │
    this site"           └───────────────┬──────────────┘
                                          │ dispatch (parallel where independent)
                 ┌────────────────────────┼────────────────────────┐
                 ▼                        ▼                         ▼
          ┌────────────┐          ┌────────────┐            ┌────────────┐
          │  Recon     │          │  Security  │    ...      │   SEO      │   ◄── specialist agents
          │  Agent     │          │  Agent     │            │  Agent     │
          └─────┬──────┘          └─────┬──────┘            └─────┬──────┘
                │  tool calls (typed, capability-scoped)          │
                ▼                        ▼                         ▼
          ┌──────────────────────────────────────────────────────────┐
          │        Tool Registry  +  Capability / Permission model     │
          │   read-only vs write · allowlists · human-approval gate     │
          └───────────────────────────┬──────────────────────────────┘
                                       ▼
          ┌──────────────────────────────────────────────────────────┐
          │  Environment Adapter (WordPress: REST · FTP · Browser)     │
          └───────────────────────────┬──────────────────────────────┘
                                       ▼   every write is wrapped by:
          ┌──────────────────────────────────────────────────────────┐
          │  Safety Engine   snapshot → act → health-check → rollback   │
          └───────────────────────────┬──────────────────────────────┘
                                       ▼
          ┌────────────┐   reject/retry   ┌──────────────────────────┐
          │  Critic /  │◄─────────────────│  every action's outcome   │
          │  Verifier  │─── approve ─────►│  checked against the goal │
          └────────────┘                  └──────────────────────────┘

   Cross-cutting:  Memory (world-model + shared blackboard + pattern store)
                   Audit Trace (every decision + tool call, replayable)
                   Cognition (pluggable LLM backends / SuperBrain)
```

### The six systems

| System | Responsibility | Why engineers care |
|---|---|---|
| **Orchestrator** | Goal → task DAG → parallel/sequential scheduling → delegation | Real task decomposition, not a linear script |
| **Tool Registry + Capability model** | Typed tools with permission scoping (read vs write, allowlists, approval gate) | The "how do you let an agent touch prod safely" answer |
| **Safety Engine** | Snapshot-before-act, post-act health check, auto-rollback, circuit breakers | Responsible autonomy on live systems |
| **Critic / Verifier** | Independent check of each action vs. the goal; retry or roll back | Actor–critic on real infra — separates agents from LLM wrappers |
| **Memory** | Per-environment world-model, shared blackboard, reusable pattern store | Agents don't start cold; they coordinate + learn |
| **Audit Trace** | Every decision and tool call logged + replayable | Debuggability, trust, post-mortems |

---

## Design principles

- **Environment-agnostic core.** WordPress is an adapter; the orchestrator/critic/
  safety layers know nothing about it.
- **Capability-scoped by default.** Agents get the *least* access needed. Writes are
  explicit, gated, and reversible.
- **Verify everything.** No action is "done" until an independent critic confirms it
  against the goal.
- **Every write is a transaction.** snapshot → act → verify → commit or rollback.
- **Model-agnostic cognition.** Reasoning is pluggable (local rules, hosted LLMs, or
  SuperBrain as the cognition/decision layer).
- **Credential-free repo.** Secrets live in env / a secret manager, per environment,
  never committed.

---

## Repository layout

```
Sanctify-Hivemind/
├── hivemind/
│   ├── core/
│   │   ├── tools.py          # typed tool registry + capability/permission model
│   │   ├── safety.py         # snapshot/rollback, health checks, audit trace
│   │   ├── agent.py          # base agent contract
│   │   ├── orchestrator.py   # goal → task DAG → scheduler → delegation
│   │   ├── critic.py         # verification / actor-critic loop
│   │   └── memory.py         # world-model, blackboard, pattern store
│   ├── environments/
│   │   └── wordpress/        # the WordPress adapter (first environment)
│   ├── agents/
│   │   ├── recon.py          # site reconnaissance specialist
│   │   └── security.py       # security specialist (malware/CVE)
│   └── cognition/            # pluggable LLM/SuperBrain backends
├── examples/                 # runnable end-to-end demos
├── traces/                   # replayable run logs (gitignored)
├── tests/
└── .kiro/                    # steering + skill (SuperBrain integration)
```

---

## Status

🚧 **Vertical slice.** The core (orchestrator, tools, safety, critic, memory), the
WordPress adapter, and the Security/Recon specialists run a real goal end-to-end.
Additional specialists (SEO, Frontend, Content) plug into the same contracts.

## Credits

Built and maintained by **[Sanctify — Digital Marketing Agency, Goa](https://www.sanctify.in/)**.

Sanctify-Hivemind was distilled from real-world WordPress security incident response,
SEO, and site-operations work. If it helps you, a link back to
[www.sanctify.in](https://www.sanctify.in/) is appreciated.

## License

MIT © [Sanctify](https://www.sanctify.in/)
