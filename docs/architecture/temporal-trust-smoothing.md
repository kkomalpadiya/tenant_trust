# Temporal trust smoothing and cold start

T6.4 applies temporal behavior after T6.3 has produced a complete weighted observation score. The policy uses only explicit timestamps and the active tenant configuration, so the same inputs always produce the same result.

## Fresh observations

For a fresh complete observation, the exponentially weighted average is:

`new score = alpha × observation score + (1 - alpha) × previous score`

`alpha` must be greater than zero and no greater than one. The result is rounded once to two decimal places using half-up rounding. On the first fresh observation, the configured `initial_score` is the previous score. This prevents a single initial sample from establishing the entire trust state unless `alpha` is explicitly configured as one.

An observation is fresh when its age is less than or equal to `stale_after_seconds`. Future timestamps and fresh observations that are not newer than the last applied observation fail closed.

## Missing and stale observations

Missing evidence is never converted to a zero component or an invented observation score. While the last complete observation remains within the freshness window, the current smoothed score is held unchanged.

A stale observation is recorded in the explanation as stale but is not applied and does not refresh the last-fresh timestamp. Once the last applied observation is older than the freshness window, the score decays exponentially. The decay half-life equals `stale_after_seconds`:

`decayed score = baseline + (anchor score - baseline) × 2^(-elapsed beyond stale / stale_after_seconds)`

The anchor is the smoothed score produced by the last fresh observation. It is retained across repeated evaluations so decay is independent of polling frequency. The conservative baseline is the lower of the configured initial score and the anchor score. Therefore, missing or stale evidence can reduce an above-baseline score but can never improve a below-baseline score.

## Cold start

Before any complete fresh observation exists, the result is the configured initial score and the last-fresh timestamp remains absent. A missing or already-stale first observation cannot establish or refresh trust.

The result identifies whether it was initialized, updated, held, decayed or remained at cold start. Its temporal state retains both the last fresh observation and last evaluation timestamps, so callers cannot move the calculation backward in time. It also exposes the observation status, configuration and calculation terms. Hysteresis, critical-evidence overrides and bounded source influence remain T6.6 responsibilities.

Run `npm run trust-smoothing:verify` for temporal unit tests and independent sequential calculations.
