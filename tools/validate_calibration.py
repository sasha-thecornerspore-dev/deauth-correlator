"""Measure whether the verdict rule is honest, and ship the measurement.

Two properties decide whether this tool is fit to produce evidence:

**Calibration.** When there is no relationship at all, how often does it say
there is one? That figure must not exceed the significance threshold. A tool
that declares a correlation on 7% of null data at alpha = 0.01 is not reporting
a 1-in-100 result, whatever the report says.

**Power.** When there *is* a relationship, how often does it find it? A tool
that never says anything is trivially well-calibrated and useless.

Both are measured here by simulation against the real :func:`deauth_correlator.
stats.analyze` and :func:`~deauth_correlator.stats.decide`, so the numbers in
docs/VALIDATION.md can be reproduced rather than taken on trust.

Run:

    python tools/validate_calibration.py               # default, a few minutes
    python tools/validate_calibration.py --reps 1000   # tighter intervals
    python tools/validate_calibration.py --compare     # also show the old rule

Exits non-zero if calibration fails, so it can be wired into CI.
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deauth_correlator import stats as st  # noqa: E402

WINDOW_S = 30.0
PERIOD_S = 6 * 3600
SEED = 20260803


def gate(s) -> bool:
    """The non-statistical half of the verdict, shared by both rules."""
    return (s.n_coincident >= st.MIN_COINCIDENCES_FOR_VERDICT
            and s.rate_ratio >= st.MIN_RATE_RATIO_FOR_VERDICT)


def run_null(rng, reps: int, alpha: float, trials: int, clustered: bool):
    """Camera events and disruptions drawn independently. Any finding is false.

    With ``clustered`` set, each vehicle pass produces five camera rows a few
    seconds apart - a second camera covering the same driveway, or a plate
    reader firing more than once. That is realistic, and it breaks the binomial
    test's assumption that every camera event is an independent draw while
    leaving the permutation test's assumption intact. It is precisely the case
    where taking the most favourable p-value goes wrong.
    """
    old = new = 0
    for _ in range(reps):
        passes = np.sort(rng.uniform(0, PERIOD_S, size=8))
        if clustered:
            camera = np.sort(np.concatenate(
                [p + rng.uniform(0, 3, size=5) for p in passes]))
        else:
            camera = passes
        incidents = np.sort(rng.uniform(0, PERIOD_S, size=75))
        s = st.analyze(camera, incidents, 0.0, PERIOD_S, WINDOW_S,
                       trials=trials, seed=int(rng.integers(1_000_000_000)))
        if not gate(s):
            continue
        old += s.best_p < alpha
        new += s.worst_p < alpha
    return old, new


def run_power(rng, reps: int, alpha: float, trials: int,
              n_passes: int, hit_rate: float, background: int):
    """A real relationship: a share of passes cause a disruption 2-8 s later."""
    old = new = 0
    for _ in range(reps):
        passes = np.sort(rng.uniform(0, PERIOD_S, size=n_passes))
        caused = np.array([p + rng.uniform(2, 8) for p in passes
                           if rng.random() < hit_rate])
        noise = rng.uniform(0, PERIOD_S, size=background)
        incidents = np.sort(np.concatenate([caused, noise]) if caused.size else noise)
        s = st.analyze(passes, incidents, 0.0, PERIOD_S, WINDOW_S,
                       trials=trials, seed=int(rng.integers(1_000_000_000)))
        if not gate(s):
            continue
        old += s.best_p < alpha
        new += s.worst_p < alpha
    return old, new


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval - correct near 0, unlike the normal approximation."""
    if n == 0:
        return 0.0, 1.0
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = (z / denominator) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(centre - half, 0.0), min(centre + half, 1.0)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reps", type=int, default=300,
                        help="replicates per scenario (default: 300)")
    parser.add_argument("--alpha", type=float, default=st.DEFAULT_ALPHA)
    parser.add_argument("--trials", type=int, default=600,
                        help="permutation trials inside each replicate")
    parser.add_argument("--compare", action="store_true",
                        help="also report the discarded most-favourable-p rule")
    args = parser.parse_args(argv)

    rng = np.random.default_rng(SEED)
    started = time.time()

    print(f"deauth-correlator calibration and power")
    print(f"alpha = {args.alpha:g}, {args.reps} replicates per scenario, "
          f"window +/-{WINDOW_S:g} s, seed {SEED}\n")

    failures = []

    print("CALIBRATION - no relationship exists, so every finding is false")
    print(f"{'scenario':46s} {'rate':>8s} {'95% CI':>16s}")
    print("-" * 72)
    for label, clustered in (("independent camera events", False),
                             ("5 rows per pass (clustered)", True)):
        old, new = run_null(rng, args.reps, args.alpha, args.trials, clustered)
        low, high = wilson(new, args.reps)
        marker = "" if low <= args.alpha else "   *** EXCEEDS ALPHA ***"
        print(f"{label:46s} {new / args.reps * 100:7.2f}% "
              f"{low * 100:6.2f}-{high * 100:5.2f}%{marker}")
        if args.compare:
            print(f"{'  (discarded most-favourable-p rule)':46s} "
                  f"{old / args.reps * 100:7.2f}%")
        if low > args.alpha:
            failures.append(f"{label}: false-positive rate {new / args.reps:.4f} "
                            f"is above alpha {args.alpha:g}")

    print("\nPOWER - a real relationship exists, so a finding is correct")
    print(f"{'scenario':46s} {'rate':>8s} {'95% CI':>16s}")
    print("-" * 72)
    scenarios = [
        ("12 passes, every one causes a drop", 12, 1.00, 20),
        ("12 passes, three quarters cause a drop", 12, 0.75, 20),
        ("12 passes, half cause a drop", 12, 0.50, 20),
        ("30 passes, half cause a drop", 30, 0.50, 60),
        ("8 passes, every one causes a drop", 8, 1.00, 15),
    ]
    for label, n, rate, background in scenarios:
        old, new = run_power(rng, args.reps, args.alpha, args.trials,
                             n, rate, background)
        low, high = wilson(new, args.reps)
        print(f"{label:46s} {new / args.reps * 100:7.2f}% "
              f"{low * 100:6.2f}-{high * 100:5.2f}%")
        if args.compare:
            print(f"{'  (discarded most-favourable-p rule)':46s} "
                  f"{old / args.reps * 100:7.2f}%")

    elapsed = time.time() - started
    print(f"\nCompleted in {elapsed:.0f} s.")

    if failures:
        print("\nCALIBRATION FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nCalibration holds: the false-positive rate is at or below alpha.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
