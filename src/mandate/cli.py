"""``mandate`` command-line entry point.

Subcommands:

* ``mandate compile <image> <deployment> [--org-policy F]`` — compile the three
  manifests into an effective capability bundle and print it (or fail loudly with the
  compile error). This is "show me the binary".
* ``mandate demo`` — run the P0 adversarial demo and render the audit dashboard.
"""

from __future__ import annotations

import argparse
import sys

import yaml

from . import __version__
from .errors import CompileError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mandate", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"mandate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="compile manifests into a capability bundle")
    p_compile.add_argument("image", help="path to agent.yaml (AgentImage)")
    p_compile.add_argument("deployment", help="path to agent-compose.yaml (AgentDeployment)")
    p_compile.add_argument("--org-policy", help="path to org-policy.yaml (optional)")
    p_compile.add_argument("--agent", help="agent name when the deployment has several")
    p_compile.add_argument("--json", action="store_true", help="emit JSON instead of YAML")
    p_compile.set_defaults(func=_cmd_compile)

    p_demo = sub.add_parser("demo", help="run the P0 adversarial demo + dashboard")
    p_demo.add_argument("--quiet", action="store_true", help="dashboard only, skip narration")
    p_demo.add_argument(
        "--isolated",
        action="store_true",
        help="also demonstrate the process-isolated kernel (the real no-bypass boundary)",
    )
    p_demo.set_defaults(func=_cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_compile(args: argparse.Namespace) -> int:
    # Imported lazily so `mandate demo` doesn't pay for the compiler's imports, etc.
    from .compiler import compile_bundle, load_deployment, load_image, load_org_policy

    try:
        image = load_image(args.image)
        deployment = load_deployment(args.deployment, agent=args.agent)
        org_policy = load_org_policy(args.org_policy)
        bundle = compile_bundle(
            image, deployment, org_policy, session="sess_cli", run="run_cli"
        )
    except (CompileError, ValueError) as exc:
        print(f"compile error: {exc}", file=sys.stderr)
        return 1

    data = bundle.to_dict()
    if args.json:
        import json

        print(json.dumps(data, indent=2, default=str))
    else:
        print(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from .dashboard import render_for_gateway
    from .demo import prove_isolation, run

    result = run(emit=(None if args.quiet else print))
    print(render_for_gateway(result.gateway, result.bundle))
    print("\nKill-switch run (scenario 6, tiny budget):")
    print(render_for_gateway(result.budget_gateway, result.bundle))
    if args.isolated:
        prove_isolation(emit=print)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
