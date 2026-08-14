# Validation

A forensic tool should be able to answer "how do you know it works?" with a measurement
rather than an assurance. This page is that measurement, and the script that produces it
ships with the tool so anyone can reproduce or challenge it:

```bash
python tools/validate_calibration.py --reps 300 --compare
```

Two properties decide whether the tool is fit to produce evidence.

**Calibration** — when there is no relationship at all, how often does it claim one?
That rate must not exceed the significance threshold. A tool that declares a correlation
on 7% of null data at α = 0.01 is not reporting a one-in-a-hundred result, whatever the
report says.

**Power** — when a relationship really is there, how often does it find it? A tool that
never concludes anything is trivially well-calibrated and useless. Calibration alone is
not a virtue.

---

## Results

α = 0.01, 300 replicates per scenario, ±30 s window, seed 20260803, over a six-hour
simulated observation period. Intervals are Wilson score intervals, which stay correct
near zero where the normal approximation does not.

### Calibration: no relationship exists, so every finding is false

| Scenario | False-positive rate | 95% CI |
| --- | ---: | ---: |
| Independent camera events | **0.33%** | 0.06–1.86% |
| Five camera rows per vehicle pass | **0.00%** | 0.00–1.26% |

Both sit at or below α = 0.01, which is what "p < 0.01" is supposed to mean.

### Power: a real relationship exists, so a finding is correct

| Scenario | Detection rate | 95% CI |
| --- | ---: | ---: |
| 12 passes, every one causes a drop | 100.00% | 98.74–100% |
| 12 passes, three quarters cause a drop | 100.00% | 98.74–100% |
| 12 passes, half cause a drop | 90.33% | 86.46–93.19% |
| 30 passes, half cause a drop | 97.00% | 94.40–98.41% |
| 8 passes, every one causes a drop | 100.00% | 98.74–100% |

A relationship that shows up in at least three quarters of passes is found essentially
every time, even from eight observations. Where roughly half the passes cause a drop and
there are only twelve of them, the tool misses about one case in ten — which is the
honest cost of a strict threshold on a small sample, and the report says so when the
sample is small.

---

## Why the verdict rests on the weakest test, not the best

Version 1.0.0 originally compared the *smallest* of the three p-values against α. That
was wrong, and the measurement shows how wrong.

| Scenario | Most-favourable-p rule | Every-test rule |
| --- | ---: | ---: |
| Null, independent camera events | 1.33% | **0.33%** |
| Null, five rows per vehicle pass | **11.00%** | **0.00%** |
| Power, 12 passes, all cause a drop | 100.00% | 100.00% |
| Power, 12 passes, three quarters | 100.00% | 100.00% |
| Power, 12 passes, half | 96.33% | 90.33% |
| Power, 30 passes, half | 99.00% | 97.00% |

The second row is the one that matters. Nothing exotic is going on there: one vehicle
pass simply produces five camera rows a few seconds apart, which is what happens with a
second camera covering the same driveway, or a plate reader that fires more than once per
vehicle. That breaks the binomial test's assumption that each camera event is an
independent draw, while leaving the permutation test's assumption intact — and taking the
minimum promotes exactly the test whose assumptions have failed. The result was a tool
that would declare a correlation on more than one null case in ten while printing
"p < 0.01".

Requiring every test to clear the threshold removes that failure completely and costs
about six percentage points of power in the weakest scenario. For a document that may be
attached to a court filing, that trade is not close.

The report states the rule explicitly, names which test was weakest, and flags the case
where the tests disagree about the answer — because disagreement is itself informative:
it usually means several camera rows are describing one vehicle.

---

## What this validation does not cover

- **It simulates, it does not sample reality.** Disruptions are drawn uniformly at
  random; real interference is bursty and correlated with time of day. Bursty background
  makes the permutation test's advantage larger, not smaller, so the calibration figures
  should be read as conservative — but they are not a substitute for a field trial.
- **It tests the statistics, not the parsers.** Whether a log line is read correctly is
  covered by `--self-test` (190 checks), not here.
- **It assumes the clocks are right.** Clock skew is a much larger practical risk than
  statistical error, and no amount of calibration addresses it. See the timezone and
  camera-clock sections of the README.
- **Power depends on the disruption rate.** These runs use a background of 15–60
  disruptions over six hours. A network with far more background noise needs more camera
  observations to reach the same confidence.

## Reproducing

```bash
python tools/validate_calibration.py                 # ~3 minutes at 300 replicates
python tools/validate_calibration.py --reps 1000     # tighter intervals, ~12 minutes
python tools/validate_calibration.py --compare       # show the discarded rule too
```

The script exits non-zero if the false-positive rate rises above α, so a change that
quietly breaks calibration fails rather than passing silently. The seed is fixed, so the
same command reproduces the same numbers; change `--reps` to check the result is not an
artefact of the sample size.
