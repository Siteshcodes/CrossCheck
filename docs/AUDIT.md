# Engineering audit — 19 November 2026

Baseline: `76bfc58ec154e1ee36f4d236ccb704243d063ee4`. Reviewed README,
PRODUCT_README, MVP_VALIDATION, MVP_README architecture, demo/clone reports,
engine, extractors, adapters, API/proxy, React contract/rendering and tests before edits.

## Baseline executed

- Python 3.14.7: 90 tests passed (12.573 s).
- Node 24.19.0 / npm 11.17.0: 13 frontend tests passed; lint and build passed.
- Real-provider check: no OPENAI_API_KEY available; no live model run.
- npm audit: 10 affected packages (8 moderate, 2 critical), all development
  dependencies. This count is dependency findings, not ten independent exploits.

## Prioritized assessment

| Priority | Confirmed defect / exposure | Reproduction or code evidence |
|---|---|---|
| P1 correctness | Negated authorization can be verified | `FCA unauthorised with FRN 307222` matches the unbounded `authori[sz]ed` regex. |
| P1 correctness | Supplied legal identifier is ignored | Active-company claim with company number `99999999` is verified against record `04333954`. |
| P1 correctness | Distinct claims disappear | Two different FRNs for the same organization collapse to one `(kind, organization, domain, polarity)` key. |
| P1 correctness | Wrong domain can be grounded | Extracted `example.com` is accepted inside `attacker-example.com`. |
| P1 correctness | Formatted telephone escapes comparison | Official genuine website plus `+44 (0)20 1234 5678` is marked consistent, with phone treated as absent. |
| P1 security | RDAP permits unsafe redirects | Redirect handler accepts `https://127.0.0.1/admin`; initial service selection also lacks public-address checks. This requires an upstream redirect/record, not a direct user URL fetch. |
| P1 correctness | Mixed inputs lose supported routes | Any clone-kind candidate sends every candidate to the clone slice, where RDAP/NVIDIA routes are unimplemented. |
| P2 reliability | Request handling diverges | Proxy reads outside its error handler; timeouts can terminate without JSON. Deep nesting/non-scalar annotation fields lack consistent validation. |
| P2 security | Unbounded request workers | ThreadingHTTPServer has no application concurrency limit; slow clients/parallel requests consume workers and provider capacity. |
| P2 privacy | Failure details expose arbitrary text | Provider raw bodies/candidate outputs and unexpected exception strings reach API responses. |
| P2 correctness | Conflicting record fields are accepted | ScopedHTML concatenates repeated record IDs; ambiguous status text can become a contradiction. |
| P2 maintenance | Vulnerable development dependency tree | npm audit identifies Vitest/mocker/tinypool and typescript-eslint/minimatch advisories. |
| P2 UX | Empty extraction sounds resolved | Zero claims reaches “Facts checked”; graph layout can omit extra claims when flagship nodes exist. |
| P2 validation | Live release check accepts unresolved flagship | Gate checks only nonempty claims, route/state fields and a model flag; it never requires the expected evidence findings. |

## Implemented versus planned at baseline

Implemented: OpenAI structured extraction, deterministic states, exact input spans,
curated FCA/Companies House records, RDAP, NVIDIA policy rules, receiver-reported
email authentication, source groups, local HTTP API, React inspector and real
HTTP regression tests. No database or account system is needed for these flows.

Not implemented: universal regulatory lookup, independent SPF/DKIM verification,
human authentication, universal fraud detection, broad policy coverage,
multi-channel integrations or production abuse controls. Historical live reports
are checked-in observations, not measurements repeated by this audit.

## Improvements and residual risks (not claimed exploits)

Bound retries for transient public GET failures, preserve attempt diagnostics,
strengthen runtime frontend validation, add a restrictive content policy and
clear data-handling text. Exact quotes do not prove correct semantic extraction;
curated positive predicates must remain deliberately narrow. A bounded local
server still needs external authentication/rate limits before public exposure.
Socket timeouts are not a whole-investigation deadline. Public source layout,
availability, staleness and record accuracy remain external dependencies.

Final changes and executed validation are recorded in `VALIDATION.md` and
`ENGINEERING_DECISIONS.md`; this section preserves the pre-change assessment.
