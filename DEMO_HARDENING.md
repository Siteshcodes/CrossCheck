# Demo hardening: FAIL

No frontend work was started. Four critical NVIDIA claims are extracted in the explicit annotation baseline: recruiter affiliation, official recruiting-domain association, equipment payment, and reimbursement. Candidate schemas include routes and polarity, forbid evidence states, and validate exact input spans. Incidental selection/deadline/vendor details and redundant official-status claims are removed with diagnostics; important claims are never truncated to force the gate.

## Result

| Gate measure | Actual | Required |
|---|---:|---:|
| Critical claims | 4 | 4–5 |
| Useful independent evidence groups | 1 | ≥3 |
| Useful verification mechanisms | 1 | ≥2 |
| Contradicted claims | 1 | reported separately |
| Verified claims | 0 | reported separately |
| Unresolved critical claims | 3 | ≤2 |
| Live LLM extraction | blocked: missing API key | working |
| Fabricated evidence | 0 | 0 |

Policy capture and its derived domain comparison have the same evidence_group_id. The NVIDIA recruiting rule says: “NVIDIA conducts its own recruitment and hiring, and all communications will come from an @nvidia.com or @career.nvidia.com email.” The supplied nvidia-careers-team.com conflicts with that official recruiting-channel requirement. This does not prove the human sender’s identity or every possible organizational association.

Source: https://www.nvidia.com/en-us/about-nvidia/careers/recruitment-scams/ . Raw HTTPS response, exact quotes, hashes, errors and timestamps are retained in each investigation artifact.

The fee passage is a descriptive warning about upfront-fee requests, not an explicit universal equipment-fee prohibition. It cannot establish the requested payment obligation or reimbursement promise. Recruiter affiliation is also unresolved in V1. These claims keep NO_AUTHORITATIVE_DATA.

## Repeated validation

| Run | Suite | Flagship latency | Gate |
|---|---|---:|---|
| 1 | 37/37 passed (3.101s) | 8.871s | FAIL |
| 2 | 37/37 passed (2.985s) | 1.998s | FAIL |
| 3 | 37/37 passed (3.009s) | 1.843s | FAIL |

RDAP queried the registry endpoint https://rdap.verisign.com/com/v1/domain/nvidia-careers-team.com and returned HTTP 404 in every run. No registration age or registrar is invented, and the failed query is not counted as a useful independent finding. Missing NVIDIA .eml remains unavailable, rather than an SPF/DKIM/DMARC failure. No lookalike website was visited.

An initial test run exposed a fixture Unicode serialization error (2 failed tests, 7 errors); exact excerpts were restored from the original Unicode message. The final repeated suites passed.

## Extraction evaluation

Twelve labeled communications cover recruitment, official/ lookalike addresses, payment, refund, urgency, incidental selection, benign text, negative fee assertions, authentication, registration and prompt injection. Expected kind/organization/domain/polarity signatures are compared with schema-valid, grounded live candidate claims. Recall, unsupported/hallucinated claims, invalid routing and latency are recorded. No annotation fallback is used in this benchmark.

Requested model: gpt-6.1-sol, without substitution. All 12 benchmark cases and three live flagship attempts failed before any network request because OPENAI_API_KEY was unavailable. Recall, hallucination and routing metrics are null, not fabricated zeros. Local configuration supports environment variables or a workspace .env; both key files and the genuine email are ignored. API errors, refusals, malformed output and validation failures remain explicit.

Grounding and schema guards prevent a generated domain-registration predicate without an explicit registration assertion from triggering verification. Organization names, domain literals, supported routes and exact source spans are checked. This is a conservative guard, not a complete semantic truth evaluator; generated assertions remain untrusted, and real extraction reliability has not been measured.

The genuine LeetCode receiver export separately parsed SPF pass, DKIM passes and DMARC pass in 36.320ms with no parser error. This is receiver-reported authentication, not cryptographic verification, and is excluded from NVIDIA evidence. Raw export-derived evidence is stored locally in ignored results/real-email-pipeline.json. V1 also excludes unbound email exports from gate counting; submitter assertions do not independently bind an email to the text.

## Reproduce

```powershell
python run_demo_hardening.py
```

Runs the 12-case live benchmark, the whole suite three times, annotated flagship live-source investigations three times, and live-LLM flagship investigations three times. It writes results/hardening-rerun.json plus complete investigation files and exits 1 when the gate fails. It may incur real API requests once credentials are configured. No model fallback or fake transport is used.

```powershell
python -m investigation demo --extractor llm --source-mode live --rdap-mode live --output results/live-nvidia.json
python -m investigation.benchmark --output results/extraction-benchmark.json
```

Offline annotation demo remains available via python -m investigation demo. Its extraction metadata explicitly says used_llm=false, and it cannot pass the live-extraction gate.

## Files

- investigation/models.py: schemas, route validation, critical projection, grounding guards and stable underlying source identity.
- investigation/llm.py: actual structured Responses adapter and safe local configuration.
- investigation/engine.py: fixed routing, grouped evidence and terminal states.
- investigation/evaluation.py: conservative independent-source summary and gate.
- investigation/benchmark.py and fixtures/extraction_communications.json: labeled live evaluation.
- tests/test_hardening.py: grouping, anti-inflation, grounding, routing and missing-key regression checks.
- run_demo_hardening.py: repeatable validation command.
- results/hardening-rerun.json: latest repeated suite/provider/source failures and latency.

The flagship does not demonstrate the requested multi-primitive evidence conflict with available evidence. A better supported scenario or additional independently attributable evidence is needed; rerunning extraction alone cannot create missing sources.
