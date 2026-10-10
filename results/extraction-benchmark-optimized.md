# Live extraction benchmark: PASS

Extraction-only evaluation of the unchanged 12 labeled communications (15 expected critical predicates). No NVIDIA, FCA, RDAP, Companies House or email verification was run.

Model: gpt-6.1-sol. Sequential requests, zero retries. Source corpus SHA-256: 92243a60204682adf3a9264cc84cd97d55242bc8d7c7eab358b044ee4e9c69b1.

| Metric | Exact result |
|---|---:|
| Model responses received | 12 / 12 |
| API requests made | 12 |
| Critical-claim recall | 100.00% |
| Unsupported/hallucinated critical candidates | 0 |
| Schema-valid response rate | 100.00% |
| Invalid routing count / rate | 0 / 0.00% |
| Median latency | 3.465s |
| p95 latency | 6.490s |
| Median under 5s target | PASS |

| Case | Recalled / expected | Recall | Unsupported | Schema valid | Invalid routes | Latency | Status |
|---|---:|---:|---:|---|---:|---:|---|
| flagship | 4 / 4 | 100.00% | 0 | True | 0 | 5.775s | PASS |
| official_contact | 2 / 2 | 100.00% | 0 | True | 0 | 6.490s | PASS |
| fee_only | 1 / 1 | 100.00% | 0 | True | 0 | 3.979s | PASS |
| refund_only | 1 / 1 | 100.00% | 0 | True | 0 | 4.134s | PASS |
| urgency | 1 / 1 | 100.00% | 0 | True | 0 | 3.485s | PASS |
| selection_only | 0 / 0 | N/A (no expected claims) | 0 | True | 0 | 2.958s | PASS |
| benign | 0 / 0 | N/A (no expected claims) | 0 | True | 0 | 3.450s | PASS |
| negative_fee | 1 / 1 | 100.00% | 0 | True | 0 | 2.829s | PASS |
| auth | 1 / 1 | 100.00% | 0 | True | 0 | 3.237s | PASS |
| registration | 1 / 1 | 100.00% | 0 | True | 0 | 3.091s | PASS |
| injection | 1 / 1 | 100.00% | 0 | True | 0 | 2.894s | PASS |
| lookalike | 2 / 2 | 100.00% | 0 | True | 0 | 3.479s | PASS |

p95 uses nearest rank ceil(0.95*n); with 12 network samples it is the largest latency. Timing includes API wall time plus local validation. Missing-key local checks do not count as extraction latency.

## Gate

- all_12_cases_completed: PASS
- critical_claim_recall_at_least_90_percent: PASS
- zero_unsupported_hallucinated_critical_claims: PASS
- 100_percent_schema_valid_responses: PASS
- invalid_verification_routing_at_most_5_percent: PASS
- deterministic_evidence_states_outside_llm: PASS

## Errors


## Optimization and boundaries

- The model emits only seven compact candidate fields: kind, organization, exact quote, domain, polarity, basis and route. It emits no IDs, repeated statement, character counts, explanations, risk scores or evidence states.
- Python derives IDs, statements and Unicode offsets from exact uniquely occurring quotes; missing/ambiguous quotes fail. Existing claim/domain/type and routing validation remains active.
- Extraction uses reasoning effort low and max_output_tokens=1600, with at most five candidates. Unsupported fields, excess claims and incomplete responses fail rather than being truncated or fabricated.
- Semantic recall and route validity are separately audited. An invalid route is rejected by the real extractor even when its factual candidate is correctly recalled by the metric audit. This audit does not enter an investigation engine.
- Recall uses all 15 expected critical predicates, including failed cases. Unsupported emitted candidates are not silently filtered before scoring. Two no-claim cases have N/A per-case recall and must remain empty.
- Labels compare kind, organization, domain and polarity with grounded input spans. They are a small extraction regression corpus, predominantly recruiting messages; they do not establish general clone-firm extraction accuracy or exhaustive paraphrase understanding.
- The supplied 16.5–19.1s timings are prior user-reported observations, not a controlled before/after benchmark. No speed improvement is claimed until measured.
- Focused extractor/metric tests passed 13/13; these use explicitly synthetic transport doubles and are not live model measurements.

Official API controls: [GPT-6.1 Sol reasoning effort](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-6.1-sol) and [latency optimization](https://developers.openai.com/api/docs/guides/latency-optimization).

Rerun only this benchmark in a shell that has the configured key:

```powershell
python -m investigation.benchmark --output results/extraction-benchmark-optimized.json
```

The CLI also writes this Markdown report. Credentials are read from the process environment or ignored workspace .env; they are never requested in chat or included in output.
