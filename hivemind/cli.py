"""CLI: `hivemind run "<goal>" [--offline] [--remediate]`.

Runs a goal through the WordPress orchestrator and prints the plan, per-task
verdicts, findings, and the trace summary. Credential-free: reads WP_URL / creds
from env or .env.
"""

from __future__ import annotations

import argparse
import json
import sys

from .app import build_wordpress_orchestrator


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hivemind", description="Sanctify-Hivemind agent runner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a goal against a WordPress environment")
    run.add_argument("goal", help='e.g. "audit and secure this site"')
    run.add_argument("--offline", action="store_true", help="no live network (demo/testing)")
    run.add_argument("--remediate", action="store_true", help="allow WRITE remediation (gated)")
    run.add_argument("--trace", default=None, help="write JSONL trace to this path")
    run.add_argument("--json", action="store_true", help="emit machine-readable JSON report")

    args = ap.parse_args(argv)
    if args.cmd == "run":
        orch = build_wordpress_orchestrator(
            offline=args.offline, remediate=args.remediate, trace_path=args.trace,
        )
        report = orch.run(args.goal)
        if args.json:
            print(json.dumps({
                "goal": report.goal, "ok": report.ok,
                "findings": report.findings, "trace": report.trace_summary,
            }, indent=2, default=str))
        else:
            _print_human(report)
        return 0 if report.ok else 2
    return 1


def _print_human(report) -> None:
    print("\n🧠 Sanctify-Hivemind  ·  by Sanctify (https://www.sanctify.in/)")
    print(f"goal: {report.goal}\n" + "─" * 64)
    print("Plan:")
    for t in report.tasks:
        deps = f" (after {', '.join(t.deps)})" if t.deps else ""
        print(f"  • {t.id} → {t.agent}{deps} [{t.status.value}]")
    print("\nResults:")
    for tid, r in report.results.items():
        mark = "✅" if r.ok else "❌"
        print(f"  {mark} {tid}: {r.summary}")
    sec = report.findings.get("security")
    if sec:
        print("\nSecurity:")
        print(f"  infected={sec['infected']} | rules={sec['rules_version']} | counts={sec['counts']}")
        for f in sec["findings"][:12]:
            print(f"   - [{f['severity']}] {f['ref']}: {f['detail'][:90]}")
    print("\nTrace summary:", json.dumps(report.trace_summary))
    print("─" * 64)


if __name__ == "__main__":
    sys.exit(main())
