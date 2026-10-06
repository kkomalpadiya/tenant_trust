# Deterministic weighted trust score

T6.3 calculates a bounded trust score from the five normalized components defined in T6.1. It uses a weighted arithmetic mean:

`score = identity × w_identity + device × w_device + behaviour × w_behaviour + certificate × w_certificate + compliance × w_compliance`

Every component must be a finite number from 0 through 100. The calculation applies identity normalization: a validated component enters the formula unchanged because all component producers already share the same higher-is-more-trusted 0-100 scale. Every model configuration must contain the five canonical non-negative weights, a semantic model version and a weight total of one.

The implementation converts the JavaScript decimal representations to integer-and-scale pairs before multiplication and addition. This avoids intermediate binary floating-point drift. It rounds each displayed contribution to six decimal places and rounds the final sum once to two decimal places using half-up rounding. It does not sum the displayed contributions, so contribution display rounding cannot change the score.

The result includes the model version, normalized inputs, weights, per-component weighted contributions, normalization rule, score range and rounding rule. This is a calculation explanation, not a trust transition record. T6.8 will combine contributions with prior/new state, evidence references and configuration versions when transition events are implemented.

The calculation deliberately does not define missing-signal substitution, temporal smoothing, cold-start behavior, confidence, trust bands, hysteresis or critical-evidence overrides. Those policies are separate Phase 6 tasks and must not be hidden inside the deterministic weighted mean.

Run `npm run trust-score:verify` for focused unit tests and independent hand-calculated examples.
