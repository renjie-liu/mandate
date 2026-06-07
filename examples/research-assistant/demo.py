#!/usr/bin/env python3
"""Run the Mandate P0 demo against the manifests in this directory.

This is a thin runner; the scenario logic and the kernel-side tools live in
``mandate.demo`` so the CLI (``mandate demo``) and the test suite drive the exact same
code path. From the repo root:

    PYTHONPATH=src python examples/research-assistant/demo.py
    #   ...or, once installed:
    mandate demo
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when run straight from a checkout (no install needed).
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mandate.dashboard import render_for_gateway  # noqa: E402
from mandate.demo import run  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> int:
    result = run(example_dir=HERE, emit=print)
    print(render_for_gateway(result.gateway, result.bundle))
    print("\nKill-switch run (scenario 6, tiny budget):")
    print(render_for_gateway(result.budget_gateway, result.bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
