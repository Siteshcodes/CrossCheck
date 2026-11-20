# Executed engineering validation

Audit started 19 November and completed 20 November 2026, Asia/Calcutta.
Baseline commit: `76bfc58ec154e1ee36f4d236ccb704243d063ee4`.
Validation was performed on `codex/audit-hardening`. These results describe local
checks and explicitly labelled live-source runs, not a deployed release.

Environment: Windows, Python 3.14.7, Node 24.19.0, npm 11.17.0. Other operating
systems/Python versions and the Docker image were not executed in this audit.

## Commands and observed outcomes

| Executed command | Baseline | Final observed result |
|---|---|---|
| `python -m unittest discover -s tests -v` | 90 passed | **134 passed**, exit 0; final run 26.358 s |
| `npm --prefix web test` | 13 passed | **22 passed**, exit 0, Vitest 4.1.12 |
| `npm --prefix web run lint` | Passed | **Passed**, exit 0; ESLint and TypeScript |
| `npm --prefix web run build` | Passed | **Passed**, exit 0; Vite 7.3.7, 30 modules |
| `npm --prefix web audit --json` | 10 findings: 8 moderate, 2 critical | **0 reported vulnerabilities** after targeted development dependency updates |
| `python check_product_live.py` | Missing key | **SKIPPED / exit 1**; no OPENAI_API_KEY in the launching environment or repository `.env` |
| `git diff --check` | Clean checkout | Passed after changes |

The test suites contain labelled doubles, real captured public evidence and actual
local HTTP requests. They are not proof that a real model executed. The release
checker now validates quoted spans, evidence links, FCA grouping and the expected
flagship counts, rather than accepting any nonempty claim list.

The current [release-check artifact](../results/product-live-extraction-check.json)
records the missing-key blocker instead of leaving an old success looking current.
No credentials were requested in chat or written to source. Historical live-model
measurements remain in separate checked-in reports linked from the README.

## Fresh public-source validation

On 19 November, the exact synthetic flagship was run through the changed engine
with explicitly labelled analyst annotations and real outbound source requests.
The model did not run. The [compact result](../results/audit-public-sources.json)
records **2 verified, 2 contradicted, 0 unresolved**, **3 independent source groups**
and **3894.338 ms** total engine time. FCA, Companies House and registry RDAP all
returned usable evidence. The FCA contact comparison shares the FCA group.

This single run establishes that the new HTTPS connection policy worked for those
sources at that time. It is not a benchmark, availability estimate, accuracy
measurement or improvement relative to historical live-model timings.

To reproduce an annotated live-source run without a model key:

```bash
python -m investigation clone-demo --extractor annotation --source-mode live --rdap-mode live --output results/local-clone.json
```

The output contains the synthetic communication and raw public evidence. Keep
custom-input exports private. Sources may change or be unavailable on a rerun.

For the real model, configure a private environment variable or root `.env`, then
run `python check_product_live.py`. A fresh successful release check remains a
prerequisite for claiming live-extraction readiness.

## Browser checks

The built application was served by the actual product proxy/backend using
`python run_product.py --annotated-example --port 8080`. Browser interactions
verified labelled annotation mode, pending status without invented completions,
the four-claim live-source result, contact comparison and grouped provenance.

At a **390 × 844** viewport, the rendered document had no horizontal overflow.
Submitting custom synthetic text without credentials returned HTTP 502, preserved
the input and focused the error alert. The temporary viewport override was reset.
The labelled result's displayed processing time was 2.18 s for that separate
browser run; it is not combined with the recorded 3.894-second run.

Screenshots: [desktop result](../results/audit-desktop.jpg),
[mobile result](../results/audit-mobile.jpg), [missing-key error](../results/audit-error.jpg).
Automated UI tests additionally cover empty extraction, all claims in mixed
results, untrusted text escaping, malformed contracts, keyboard selection,
retry, cancellation and stale-response suppression.

## Confirmed fixes and regression scope

- Negated/qualified regulatory wording cannot reuse an authorization fact;
  supplied company numbers and formatted phones are compared explicitly.
- Distinct conflicting FRNs survive deduplication, while repeated FCA findings
  retain one provenance group. Domain substrings are not accepted as whole domains.
- Mixed routes preserve claims and evidence references after one extraction.
  Receiver-report mismatches no longer look consistent with pass assertions.
- Repeated/conflicting authoritative fields and failed decisive adapters become
  explicit gaps; missing evidence never automatically becomes fraud.
- Private-address/redirect SSRF paths, local DNS-rebinding requests, cross-origin
  submissions, malformed framing/JSON, body timeouts and worker saturation have
  regression coverage. Provider/internal errors omit arbitrary sensitive text.
- Empty results and extra claims are represented honestly in the interface.

## Remaining limits and demonstration assessment

CrossCheck is ready to demonstrate as a scoped software engineering prototype
using explicit annotations, inspectable public evidence and the offline suites.
Live OpenAI extraction has **not** been revalidated with these changes because
credentials are unavailable. No production accuracy, traffic load, cross-browser
coverage, full accessibility conformance or service-level guarantee was measured.

Coverage is curated and conservative. Prompt injection can affect claim selection;
exact quotes do not guarantee correct semantics. Records may be stale or mutually
incompatible outside implemented scopes. DNS/socket calls can outlive the
cooperative outbound budget. Public deployment still needs authentication,
per-user quotas, operational monitoring and a retention policy. The app does not
authenticate a human sender.
