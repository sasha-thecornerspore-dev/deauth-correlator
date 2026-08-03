"""The statistics behind the verdict.

Four independent tests are reported rather than one, because a single p-value
from a single window invites the obvious cross-examination question - "how many
windows did you try before you found that one?". They are:

1. **Coincidence count** - the headline: N of M camera passes had a wireless
   disruption within +/-X seconds.
2. **Binomial test** - the union of +/-X-second windows around disruptions covers
   some fraction p0 of the observation period. A randomly-timed vehicle pass
   lands inside one with probability p0. Getting N or more hits out of M has an
   exact binomial tail probability.
3. **Circular-shift permutation test** - slide the whole camera-event sequence
   by a random offset (wrapping around the observation period) 10,000 times and
   recount. This keeps the spacing of the camera events and the clustering of
   the disruptions intact, which the binomial test does not.
4. **Fisher's exact test and chi-square** on a 2x2 table built by cutting the
   observation period into disjoint bins of width 2X and classifying each bin
   by whether it contained a camera event and whether it contained a disruption.

Every test is implemented against SciPy when it is installed and against a
pure-Python exact fallback when it is not, so the numbers can be reproduced
without the dependency.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd

try:
    from scipy import stats as _scipy_stats
    HAVE_SCIPY = True
except Exception:  # pragma: no cover - exercised only without scipy
    _scipy_stats = None
    HAVE_SCIPY = False

DEFAULT_WINDOW_S = 30.0
DEFAULT_ALPHA = 0.01
DEFAULT_TRIALS = 10000
MIN_COINCIDENCES_FOR_VERDICT = 3
MIN_RATE_RATIO_FOR_VERDICT = 2.0
SENSITIVITY_WINDOWS = (10.0, 15.0, 30.0, 60.0, 120.0)

VERDICT_FOUND = "CORRELATION FOUND"
VERDICT_NOT_FOUND = "CORRELATION NOT ESTABLISHED"
VERDICT_INSUFFICIENT = "INSUFFICIENT DATA"


@dataclass
class WindowStats:
    window_s: float
    n_camera: int
    n_coincident: int
    coincidence_rate: float          # N / M
    baseline_rate: float             # p0, chance coincidence probability
    expected_by_chance: float        # M * p0
    lift: float                      # observed rate / baseline rate
    binom_p: float
    perm_p: float
    perm_trials: int
    perm_mean: float
    fisher_odds_ratio: float
    fisher_p: float
    chi2: float
    chi2_p: float
    table: list                      # [[a, b], [c, d]]
    table_labels: list = field(default_factory=lambda: [
        "bins with a camera event", "bins with no camera event"])
    incidents_in_window: int = 0
    incidents_outside: int = 0
    exposed_minutes: float = 0.0
    unexposed_minutes: float = 0.0
    rate_in_per_min: float = 0.0
    rate_out_per_min: float = 0.0
    rate_ratio: float = 0.0
    rate_ratio_corrected: bool = False
    backend: str = "scipy" if HAVE_SCIPY else "pure-python"

    @property
    def best_p(self) -> float:
        candidates = [p for p in (self.binom_p, self.perm_p, self.fisher_p)
                      if p == p and p is not None]
        return min(candidates) if candidates else 1.0

    @property
    def worst_p(self) -> float:
        candidates = [p for p in (self.binom_p, self.perm_p, self.fisher_p)
                      if p == p and p is not None]
        return max(candidates) if candidates else 1.0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["best_p"] = self.best_p
        data["worst_p"] = self.worst_p
        return data


@dataclass
class Verdict:
    label: str
    headline: str
    reasons: list = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.label == VERDICT_FOUND


def analyze(camera_times: np.ndarray, incident_times: np.ndarray,
            obs_start: float, obs_end: float, window_s: float,
            trials: int = DEFAULT_TRIALS, seed: int = 20260803) -> WindowStats:
    """Run all four tests for one window width.

    Times are float epoch seconds. ``obs_start``/``obs_end`` bound the period
    over which both the camera log and the wireless evidence are in force.
    """
    camera_times = np.sort(np.asarray(camera_times, dtype=float))
    incident_times = np.sort(np.asarray(incident_times, dtype=float))
    span = max(obs_end - obs_start, 1e-9)

    m = len(camera_times)
    n_coincident = int(_count_hits(camera_times, incident_times, window_s))

    # 1) Chance baseline: fraction of the period within +/-window of a disruption.
    disruption_union = _merge_intervals(incident_times, window_s, obs_start, obs_end)
    covered = sum(hi - lo for lo, hi in disruption_union)
    p0 = min(max(covered / span, 0.0), 1.0)

    binom_p = _binom_sf(n_coincident, m, p0) if m else float("nan")

    # 2) Circular-shift permutation: preserves camera-event spacing.
    perm_p, perm_mean = _circular_shift_test(
        camera_times, incident_times, window_s, obs_start, obs_end, trials, seed)

    # 3) 2x2 on disjoint bins of width 2*window.
    table, fisher_or, fisher_p, chi2, chi2_p = _binned_association(
        camera_times, incident_times, obs_start, obs_end, window_s)

    # 4) Per-minute disruption rate inside vs outside camera windows.
    camera_union = _merge_intervals(camera_times, window_s, obs_start, obs_end)
    exposed_s = sum(hi - lo for lo, hi in camera_union)
    unexposed_s = max(span - exposed_s, 0.0)
    inside = int(_count_in_intervals(incident_times, camera_union))
    outside = int(len(incident_times) - inside)

    rate_in = inside / (exposed_s / 60.0) if exposed_s > 0 else 0.0
    rate_out = outside / (unexposed_s / 60.0) if unexposed_s > 0 else 0.0
    corrected = False
    if rate_out == 0:
        # Haldane-Anscombe: with zero background events the ratio is undefined,
        # so half an event is added to each cell and the report says so.
        corrected = True
        rate_in_c = (inside + 0.5) / (exposed_s / 60.0) if exposed_s > 0 else 0.0
        rate_out_c = (outside + 0.5) / (unexposed_s / 60.0) if unexposed_s > 0 else 0.0
        ratio = rate_in_c / rate_out_c if rate_out_c else 0.0
    else:
        ratio = rate_in / rate_out

    observed_rate = n_coincident / m if m else 0.0
    lift = observed_rate / p0 if p0 > 0 else float("inf") if observed_rate else 0.0

    return WindowStats(
        window_s=window_s,
        n_camera=m,
        n_coincident=n_coincident,
        coincidence_rate=observed_rate,
        baseline_rate=p0,
        expected_by_chance=m * p0,
        lift=lift,
        binom_p=binom_p,
        perm_p=perm_p,
        perm_trials=trials,
        perm_mean=perm_mean,
        fisher_odds_ratio=fisher_or,
        fisher_p=fisher_p,
        chi2=chi2,
        chi2_p=chi2_p,
        table=table,
        incidents_in_window=inside,
        incidents_outside=outside,
        exposed_minutes=exposed_s / 60.0,
        unexposed_minutes=unexposed_s / 60.0,
        rate_in_per_min=rate_in,
        rate_out_per_min=rate_out,
        rate_ratio=ratio,
        rate_ratio_corrected=corrected,
    )


def decide(stats: WindowStats, alpha: float = DEFAULT_ALPHA,
           n_incidents: int = 0) -> Verdict:
    """Turn the numbers into a verdict, stating every reason."""
    reasons: list[str] = []

    if stats.n_camera < MIN_COINCIDENCES_FOR_VERDICT:
        return Verdict(
            VERDICT_INSUFFICIENT,
            f"Only {stats.n_camera} camera event(s) in the analysis period - at least "
            f"{MIN_COINCIDENCES_FOR_VERDICT} are needed before a correlation can be "
            f"tested meaningfully.",
            ["too few camera events"])
    if n_incidents == 0:
        return Verdict(
            VERDICT_INSUFFICIENT,
            "No wireless-disruption events were found in the evidence, so there is "
            "nothing to correlate the camera events against.",
            ["no disruption events"])

    passes_count = stats.n_coincident >= MIN_COINCIDENCES_FOR_VERDICT
    passes_p = stats.best_p < alpha
    passes_ratio = stats.rate_ratio >= MIN_RATE_RATIO_FOR_VERDICT

    if not passes_count:
        reasons.append(
            f"only {stats.n_coincident} of {stats.n_camera} camera events coincided "
            f"(at least {MIN_COINCIDENCES_FOR_VERDICT} coincidences are required)")
    if not passes_p:
        reasons.append(
            f"the strongest significance test gave p = {stats.best_p:.4g}, which does "
            f"not clear the threshold of {alpha:g}")
    if not passes_ratio:
        reasons.append(
            f"disruptions were only {stats.rate_ratio:.2f}x more frequent during camera "
            f"windows than outside them (at least {MIN_RATE_RATIO_FOR_VERDICT:g}x is "
            f"required)")

    if passes_count and passes_p and passes_ratio:
        return Verdict(
            VERDICT_FOUND,
            f"{stats.n_coincident} of {stats.n_camera} camera passes "
            f"({stats.coincidence_rate * 100:.0f}%) coincided with a wireless "
            f"disruption within +/-{stats.window_s:g} s; "
            f"{stats.expected_by_chance:.1f} would be expected by chance "
            f"(p = {stats.best_p:.3g}, {stats.rate_ratio:.1f}x the background rate).",
            [f"{stats.n_coincident} coincidences",
             f"p = {stats.best_p:.3g} < {alpha:g}",
             f"rate ratio {stats.rate_ratio:.2f}x"])

    return Verdict(
        VERDICT_NOT_FOUND,
        f"{stats.n_coincident} of {stats.n_camera} camera passes coincided with a "
        f"wireless disruption within +/-{stats.window_s:g} s, which is not "
        f"distinguishable from chance ({stats.expected_by_chance:.1f} expected).",
        reasons)


def sensitivity(camera_times: np.ndarray, incident_times: np.ndarray,
                obs_start: float, obs_end: float, primary_window: float,
                trials: int = 2000) -> list[WindowStats]:
    """Re-run the analysis at several window widths to show the result is stable."""
    widths = sorted({*SENSITIVITY_WINDOWS, primary_window})
    return [analyze(camera_times, incident_times, obs_start, obs_end, w, trials=trials)
            for w in widths]


# -- primitives -----------------------------------------------------------

def _count_hits(camera_times: np.ndarray, incident_times: np.ndarray,
                window_s: float) -> int:
    """How many camera times have at least one incident within +/-window."""
    if len(camera_times) == 0 or len(incident_times) == 0:
        return 0
    idx = np.searchsorted(incident_times, camera_times)
    hits = np.zeros(len(camera_times), dtype=bool)
    left = np.clip(idx - 1, 0, len(incident_times) - 1)
    right = np.clip(idx, 0, len(incident_times) - 1)
    hits |= np.abs(incident_times[left] - camera_times) <= window_s
    hits |= np.abs(incident_times[right] - camera_times) <= window_s
    return int(hits.sum())


def nearest_delta(camera_times: np.ndarray, incident_times: np.ndarray) -> np.ndarray:
    """Signed seconds from each camera time to the nearest incident.

    Negative means the disruption happened before the camera event.
    """
    if len(camera_times) == 0:
        return np.array([], dtype=float)
    if len(incident_times) == 0:
        return np.full(len(camera_times), np.nan)
    idx = np.searchsorted(incident_times, camera_times)
    left = np.clip(idx - 1, 0, len(incident_times) - 1)
    right = np.clip(idx, 0, len(incident_times) - 1)
    d_left = incident_times[left] - camera_times
    d_right = incident_times[right] - camera_times
    take_left = np.abs(d_left) <= np.abs(d_right)
    return np.where(take_left, d_left, d_right)


def _merge_intervals(centers: np.ndarray, window_s: float,
                     lo: float, hi: float) -> list[tuple[float, float]]:
    """Union of [t-window, t+window] for each centre, clipped to [lo, hi]."""
    if len(centers) == 0:
        return []
    starts = np.clip(centers - window_s, lo, hi)
    ends = np.clip(centers + window_s, lo, hi)
    order = np.argsort(starts)
    starts, ends = starts[order], ends[order]

    merged: list[tuple[float, float]] = []
    cur_lo, cur_hi = starts[0], ends[0]
    for s, e in zip(starts[1:], ends[1:]):
        if s <= cur_hi:
            cur_hi = max(cur_hi, e)
        else:
            if cur_hi > cur_lo:
                merged.append((cur_lo, cur_hi))
            cur_lo, cur_hi = s, e
    if cur_hi > cur_lo:
        merged.append((cur_lo, cur_hi))
    return merged


def _count_in_intervals(times: np.ndarray, intervals: list[tuple[float, float]]) -> int:
    if len(times) == 0 or not intervals:
        return 0
    starts = np.array([lo for lo, _ in intervals])
    ends = np.array([hi for _, hi in intervals])
    idx = np.clip(np.searchsorted(starts, times, side="right") - 1, 0, len(starts) - 1)
    return int(((times >= starts[idx]) & (times <= ends[idx])).sum())


def _circular_shift_test(camera_times: np.ndarray, incident_times: np.ndarray,
                         window_s: float, lo: float, hi: float,
                         trials: int, seed: int) -> tuple[float, float]:
    """Empirical p from sliding the camera sequence around the observation period.

    Shifts close to zero are excluded. A shift of nearly nothing reproduces the
    real alignment exactly, so leaving those in puts the observed arrangement
    into its own null distribution and floors the p-value at roughly
    ``2 * window / span`` no matter how strong the real effect is. The exclusion
    zone is the larger of four windows and 2% of the observation period.
    """
    observed = _count_hits(camera_times, incident_times, window_s)
    if len(camera_times) == 0 or len(incident_times) == 0 or trials <= 0:
        return float("nan"), float("nan")

    span = hi - lo
    if span <= 0:
        return float("nan"), float("nan")

    rng = np.random.default_rng(seed)
    min_shift = max(4.0 * window_s, 0.02 * span)
    if span > 4.0 * min_shift:
        offsets = rng.uniform(min_shift, span - min_shift, size=trials)
    else:
        # The period is too short to exclude anything without exhausting the
        # available shifts; use the full circle and accept the weaker bound.
        offsets = rng.uniform(0.0, span, size=trials)
    base = camera_times - lo
    counts = np.empty(trials, dtype=np.int64)
    for i, shift in enumerate(offsets):
        shifted = np.sort((base + shift) % span) + lo
        counts[i] = _count_hits(shifted, incident_times, window_s)

    # Add-one correction: an empirical p is never reported as exactly zero.
    p = (int((counts >= observed).sum()) + 1) / (trials + 1)
    return float(p), float(counts.mean())


def _binned_association(camera_times: np.ndarray, incident_times: np.ndarray,
                        lo: float, hi: float, window_s: float):
    """Build the 2x2 bin table and run Fisher's exact test plus chi-square."""
    bin_width = max(2.0 * window_s, 1e-6)
    n_bins = max(int(math.ceil((hi - lo) / bin_width)), 1)

    def occupied(times: np.ndarray) -> set:
        if len(times) == 0:
            return set()
        idx = np.floor((times - lo) / bin_width).astype(np.int64)
        idx = np.clip(idx, 0, n_bins - 1)
        return set(idx.tolist())

    cam_bins = occupied(camera_times)
    inc_bins = occupied(incident_times)

    a = len(cam_bins & inc_bins)              # camera + disruption
    b = len(cam_bins) - a                     # camera, no disruption
    c = len(inc_bins - cam_bins)              # disruption, no camera
    d = max(n_bins - a - b - c, 0)            # neither

    table = [[a, b], [c, d]]
    odds, fisher_p = _fisher_exact_greater(a, b, c, d)
    chi2, chi2_p = _chi_square(a, b, c, d)
    return table, odds, fisher_p, chi2, chi2_p


def _fisher_exact_greater(a: int, b: int, c: int, d: int) -> tuple[float, float]:
    if HAVE_SCIPY:
        result = _scipy_stats.fisher_exact([[a, b], [c, d]], alternative="greater")
        return float(result[0]), float(result[1])

    # Pure-Python hypergeometric tail, summing tables at least as extreme.
    row1, row2 = a + b, c + d
    col1 = a + c
    total = row1 + row2
    if min(row1, row2, col1, total - col1) == 0:
        return float("nan"), 1.0

    def prob(x: int) -> float:
        return (math.comb(row1, x) * math.comb(row2, col1 - x)) / math.comb(total, col1)

    upper = min(row1, col1)
    p = sum(prob(x) for x in range(a, upper + 1)
            if 0 <= col1 - x <= row2)
    odds = ((a * d) / (b * c)) if b and c else float("inf") if a * d else float("nan")
    return odds, min(max(p, 0.0), 1.0)


def _chi_square(a: int, b: int, c: int, d: int) -> tuple[float, float]:
    total = a + b + c + d
    if total == 0:
        return float("nan"), float("nan")
    row1, row2 = a + b, c + d
    col1, col2 = a + c, b + d
    if 0 in (row1, row2, col1, col2):
        return float("nan"), float("nan")

    if HAVE_SCIPY:
        chi2, p, _dof, _exp = _scipy_stats.chi2_contingency([[a, b], [c, d]],
                                                            correction=True)
        return float(chi2), float(p)

    # Yates-corrected chi-square. The shortcut formula is only valid while
    # |ad - bc| exceeds N/2; below that the bracket goes negative and squaring
    # it inflates chi2 instead of shrinking it. Clamping to zero is exactly
    # equivalent to capping the per-cell correction at 0.5, which is what a
    # correct implementation does. For one degree of freedom the survival
    # function is exactly erfc(sqrt(chi2 / 2)).
    excess = max(abs(a * d - b * c) - total / 2.0, 0.0)
    chi2 = (excess ** 2) * total / (row1 * row2 * col1 * col2)
    return float(chi2), float(math.erfc(math.sqrt(chi2 / 2.0)))


def _binom_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""
    if n == 0:
        return float("nan")
    if k <= 0:
        return 1.0
    if p <= 0.0:
        return 0.0 if k > 0 else 1.0
    if p >= 1.0:
        return 1.0

    if HAVE_SCIPY:
        return float(_scipy_stats.binomtest(k, n, p, alternative="greater").pvalue)

    total = 0.0
    for x in range(k, n + 1):
        total += math.comb(n, x) * (p ** x) * ((1.0 - p) ** (n - x))
    return min(max(total, 0.0), 1.0)


@dataclass
class LagScan:
    """Result of asking whether the two streams line up at some other offset."""

    best_lag_s: float = 0.0
    best_hits: int = 0
    hits_at_zero: int = 0
    n_camera: int = 0
    searched_s: float = 0.0

    @property
    def suspicious(self) -> bool:
        """True when a shifted alignment beats the real one by enough to matter."""
        if self.n_camera < 3 or abs(self.best_lag_s) < 1.0:
            return False
        return (self.best_hits >= self.hits_at_zero + 3
                and self.best_hits >= 0.6 * self.n_camera
                and self.best_hits >= 2 * max(self.hits_at_zero, 1))

    def explanation(self) -> str:
        lag = self.best_lag_s
        magnitude = abs(lag)
        if abs(magnitude - 3600) < 90:
            likely = ("This is almost exactly one hour, which nearly always means a "
                      "timezone or daylight-saving mismatch between the camera and "
                      "the network logs rather than a real delay.")
        elif abs(magnitude - 1800) < 60:
            likely = ("This is almost exactly thirty minutes, which suggests a "
                      "half-hour timezone offset was applied to one source and not "
                      "the other.")
        elif magnitude % 3600 < 120 or 3600 - (magnitude % 3600) < 120:
            likely = ("This is close to a whole number of hours, which points to a "
                      "timezone mismatch rather than a real delay.")
        else:
            likely = ("A clock on one of the devices is probably wrong by about this "
                      "much; check the camera with 'camera probe' and the firewall "
                      "with 'date -u'.")
        direction = "later than" if lag > 0 else "earlier than"
        return (f"The camera events line up with the wireless disruptions if the "
                f"camera times are treated as {abs(lag):.0f} s {direction} recorded "
                f"({self.best_hits} of {self.n_camera} would coincide, against "
                f"{self.hits_at_zero} as the data stands). {likely}")


def scan_for_lag(camera_times: np.ndarray, incident_times: np.ndarray,
                 window_s: float, max_lag_s: float = 7200.0,
                 max_candidates: int = 20000) -> LagScan:
    """Look for a constant offset at which the two streams would align.

    A camera whose clock is an hour out, or a ``--tz`` that does not match the
    zone the camera writes, produces a confident "no correlation" from evidence
    that in fact lines up perfectly once shifted. That silent false negative is
    the most common way this analysis goes wrong in practice, so the tool checks
    for it and says so.

    This is a diagnostic, never a finding. A correlation that only appears at a
    shifted offset means "go and check the clocks, correct them, and run again"
    - not "there is a correlation at a lag".
    """
    scan = LagScan(n_camera=len(camera_times), searched_s=max_lag_s)
    if len(camera_times) < 3 or len(incident_times) == 0:
        return scan

    scan.hits_at_zero = int(_count_hits(camera_times, incident_times, window_s))
    scan.best_hits = scan.hits_at_zero

    # The only lags worth testing are the ones that actually align some pair of
    # events, so the candidates come from the observed differences rather than
    # from a blind grid.
    deltas = (incident_times[None, :] - camera_times[:, None]).ravel()
    deltas = deltas[np.abs(deltas) <= max_lag_s]
    if deltas.size == 0:
        return scan
    candidates = np.unique(np.round(deltas))
    if candidates.size > max_candidates:
        step = int(np.ceil(candidates.size / max_candidates))
        candidates = candidates[::step]

    for lag in candidates:
        hits = _count_hits(camera_times + lag, incident_times, window_s)
        if hits > scan.best_hits:
            scan.best_hits = int(hits)
            scan.best_lag_s = float(lag)
    return scan


def observation_period(camera_times: np.ndarray, disruption_times: np.ndarray,
                       pad_s: float = 0.0) -> tuple[float, float, list[str]]:
    """The window over which both evidence streams are actually in force.

    Using the full span of whichever log is longer would understate the
    background rate: a week of camera clips against two hours of packet capture
    makes any coincidence look extraordinary. The analysis period is therefore
    the intersection of the two spans, and anything discarded is reported.
    """
    notes: list[str] = []
    if len(camera_times) == 0 or len(disruption_times) == 0:
        lo = float(min([*camera_times, *disruption_times], default=0.0))
        hi = float(max([*camera_times, *disruption_times], default=0.0))
        return lo - pad_s, hi + pad_s, notes

    cam_lo, cam_hi = float(camera_times.min()), float(camera_times.max())
    dis_lo, dis_hi = float(disruption_times.min()), float(disruption_times.max())

    lo = max(cam_lo, dis_lo) - pad_s
    hi = min(cam_hi, dis_hi) + pad_s

    if hi <= lo:
        notes.append(
            "The camera log and the wireless evidence do not overlap in time "
            f"(camera covers {_fmt_span(cam_lo, cam_hi)}, wireless evidence covers "
            f"{_fmt_span(dis_lo, dis_hi)}). No correlation can be computed. Re-export "
            "the logs so they cover the same period.")
        return lo, hi, notes

    discarded_camera = (max(0.0, lo - cam_lo) + max(0.0, cam_hi - hi)) / 3600.0
    discarded_wireless = (max(0.0, lo - dis_lo) + max(0.0, dis_hi - hi)) / 3600.0
    if discarded_camera > 0.25:
        notes.append(
            f"{discarded_camera:.1f} h of camera events fall outside the period covered "
            f"by the wireless evidence and were excluded from the statistics (they are "
            f"still drawn on the timeline).")
    if discarded_wireless > 0.25:
        notes.append(
            f"{discarded_wireless:.1f} h of wireless evidence falls outside the period "
            f"covered by the camera log and was excluded from the statistics.")
    return lo, hi, notes


def _fmt_span(lo: float, hi: float) -> str:
    return (f"{pd.Timestamp(lo, unit='s', tz='UTC')} to "
            f"{pd.Timestamp(hi, unit='s', tz='UTC')} UTC")
