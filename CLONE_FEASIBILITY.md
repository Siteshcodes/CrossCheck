# Regulated-investment clone-firm feasibility: PASS

Validated with live authoritative sources on 9 October 2026. This passes the deterministic evidence-density gate. The separate live LLM extraction benchmark remains blocked because OPENAI_API_KEY is not configured locally. No frontend work was started.

## Fixture and exact results

The communication is a synthetic, explicitly annotated feasibility fixture; it is not a captured message from a victim. Its factual assertions are deliberately correlated against real live records.

> We are IPO Horizon, representing Horizon Financial Planning Limited. Horizon Financial Planning Limited is FCA authorised with Firm Reference Number 307222. Horizon Financial Planning Limited is an active UK company. Our official website is ipohorizon.com and our contact number is +447721904036.

| Critical assertion | Evidence state | Scope/source |
|---|---|
| IPO Horizon represents Horizon Financial Planning Limited | CONTRADICTED_BY_AUTHORITATIVE_SOURCE | FCA named-clone warning expressly disavows the connection |
| Horizon Financial Planning Limited is FCA authorised with FRN 307222 | VERIFIED_BY_AUTHORITATIVE_SOURCE | Genuine-firm details published in the FCA warning |
| Horizon Financial Planning Limited is an active UK company | VERIFIED_BY_AUTHORITATIVE_SOURCE | Companies House company 04333954, status Active |
| Supplied domain and phone are official contacts for the genuine firm | CONTRADICTED_BY_AUTHORITATIVE_SOURCE | Exact comparison to regulator-published genuine contacts |

The FCA page identifies IPO Horizon / www.ipohorizon.com as a clone, names the genuine firm and FRN 307222, and states that the genuine authorised firm has no connection with the clone. The two true credentials do not authenticate the contacting party. This is the central correlation, and neither true credential overrides the contradictory affiliation/contact facts.

[FCA warning](https://www.fca.org.uk/news/warnings/ipo-horizon-clone-fca-authorised-firm) · [Companies House record](https://find-and-update.company-information.service.gov.uk/company/04333954)

| Contact field | Named clone | Genuine regulator-published firm |
|---|---|
| Website | www.ipohorizon.com | www.horizonfp.co.uk |
| Telephone, source formatting retained | +447721904036 | +4401214279009 |

Both differences are established from the actual FCA record, not a brand-substring heuristic. Host comparison removes only a www. presentation prefix and requires exact remaining domain equality; arbitrary subdomains do not match. Phone comparison removes visual whitespace/parentheses/hyphens, without inferring alternate national/international numbering. Emails are obfuscated in the fetched page and are not compared or guessed.

## Infrastructure evidence

The contacting domain was queried only through IANA RDAP bootstrap and the Verisign registry endpoint; its website was not visited. RDAP succeeded and reported:

- Registration: 2025-09-09T08:48:37+00:00.
- Age at recorded lookup: 395 days.
- Registrar: In2net Network Inc..
- Registrant identity: unresolved/redacted or absent.

[Verisign RDAP record](https://rdap.verisign.com/com/v1/domain/ipohorizon.com). Registration is an independently established infrastructure fact. It does not prove ownership by the authorised firm or authenticate the contact; domain age is not converted into a fraud score.

## Gate and repeated live runs

| Measure | Actual | Target |
|---|---:|---:|
| Critical claims | 4 | 4–5 |
| Useful resolved critical findings | 4 | ≥3 |
| Independent evidence groups | 3 | ≥2 |
| Independent mechanisms | 3 | ≥2 |
| Verified / contradicted / unresolved critical claims | 2 / 2 / 0 | ≤2 unresolved |
| True fact does not authenticate party | demonstrated | required |
| Fabricated evidence | 0 | 0 |

Useful findings are distinct critical predicates, not an assertion that every finding has an independent source. The authorisation, named-clone disavowal, genuine contacts and contact comparison all share one FCA evidence_group_id. Companies House has a second group. RDAP registration has a third. The two contradicted claims are supported by one underlying FCA source. The legal entity and regulator evidence alone meet the two-source requirement; failed RDAP would remain a visible gap rather than being necessary to force a pass.

| Live run | Total latency | Source failures | Gate |
|---|---:|---:|---|
| 1 | 2.945s | 0 | PASS |
| 2 | 2.585s | 0 | PASS |
| 3 | 2.519s | 0 | PASS |

Entire suite: 52/52 tests passed. New regressions cover grouping, correct facts versus identity, exact contacts/lookalikes, source failures, structural changes, integrity checks, negative predicates, fabricated candidate statements, unknown entities and API dispatch. Offline tests use genuine saved captures labelled as unit replays or explicitly labelled failure doubles. They do not count as live API evaluations.

## Live extraction remains a separate experiment

The same 12 labeled communications are preserved. The runner checks for a locally configured key and runs the real gpt-6.1-sol benchmark only when it is available. This run did not rerun the live benchmark: the key was absent. Recall, hallucination, invalid-routing and latency metrics remain unavailable. An annotation is never labelled a model response. The provider schema and backend route/span validation reject final evidence-state fields.

New regulated candidate kinds require statement equal to exact source_quote. Unreviewed paraphrases and ungrounded/negative predicates cannot become verified using an unrelated genuine record. This conservative restriction improves the boundary but must still be evaluated against live extraction once credentials are configured. No model decides evidence states.

## Reproduce

```powershell
python run_clone_feasibility.py
```

Runs the whole suite, three fresh live-source investigations and, if credentials are present, the separate 12-case live extraction benchmark. Full raw evidence, status/errors, exact parsed fields, source URLs, hashes, source groups and latencies are saved to results/clone-investigation-1.json through -3.json and results/clone-feasibility-report.json. No source-success fallback is used. The command exits nonzero if the deterministic gate fails.

```powershell
python -m investigation clone-demo --output results/clone-investigation.json
python -m investigation clone-demo --extractor llm --output results/clone-llm-investigation.json
python -m investigation.benchmark --output results/extraction-benchmark.json
```

The default clone-demo uses explicit manual fixture annotations. The second command uses real structured LLM extraction. For custom communications use python -m investigation investigate --message-file your-message.txt; analyst annotations remain opt-in. The existing POST /investigate endpoint routes the new schema kinds through the same deterministic slice.

## Added files and scope

- investigation/regulated_firm.py: curated FCA warning record and Companies House record retrieval/parsing plus exact contact comparison.
- investigation/clone_firm.py: four-claim verification, independent-group summary, evidence correlation and deterministic explanation.
- fixtures/clone_firm/: synthetic communication, hash-bound annotations, API request, actual captured FCA/Companies House bytes for regression tests.
- tests/test_clone_firm.py: fifteen regression tests.
- run_clone_feasibility.py: repeatable live verification and separate extraction benchmark.

## Limitations

1. This is curated record lookup for one named case, not arbitrary firm discovery or a general FCA-register API.
2. FCA authorisation/FRN verification is scoped to the genuine-firm description in the warning, not current product/service permissions or current register status. The warning was published/updated 1 October 2026.
3. Companies House proves the registry record and recorded active status; it does not check all filed information and does not prove investment authorisation or caller identity.
4. Input is a synthetic annotated communication. Personal sender identity, actual message provenance and a victim’s original communication are not established.
5. Contact comparison proves consistency/conflict with the published record. Matching a public contact alone would remain CONSISTENT_BUT_NOT_IDENTITY_PROVING.
6. Email values are obfuscated and unavailable for comparison; no email evidence is fabricated.
7. RDAP registrant identity is unavailable. Registration age/registrar are infrastructure facts, not affiliation or risk probability.
8. Live LLM extraction accuracy remains unmeasured without credentials; errors will be retained, with no model substitution.
9. Parser/HTTP changes fail visibly. Authority facts are taken from these sources at the recorded retrieval times, without a general historical applicability check.

No frontend, authentication, database, browser extension, dashboard or autonomous agent system was created.
