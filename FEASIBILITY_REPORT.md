# Feasibility experiment results

Final verification completed on 9 October 2026 (Asia/Calcutta), using Python 3.14.7. HTTP evidence records and source responses are preserved in results/. Earlier RDAP/policy runs are also retained. These are smoke experiments; sample counts do not estimate production reliability.

| Probe | Default live evidence checks | Local fixture checks | Measured default total | Result |
|---|---:|---:|---:|---|
| RDAP | 3/3 | 5/5 domain comparison | 2876.963 ms | PASS for current registration metadata |
| Email headers | 0 real exports available | 6/6 expected outcomes | 272.277 ms | Parser suite PASS; real authentication UNTESTED |
| Organization/contact | 0/2 complete cases; 4/4 registry identity/phone facts | No mocked source tests | 6298.434 ms | Both cases FAIL/UNRESOLVED on official-domain linkage |
| India process contradictions | 2/3 live sourced rules (synthetic observations) | 14/14 engine expectations | 1680.421 ms | Overall FAIL; recruiter rule blocked |

## Observed evidence

| Domain | Registration date (UTC) | Age, full days at retrieval | Registrar | Case latency |
|---|---|---:|---|---:|
| microsoft.com | 1991-05-02T04:00:00+00:00 | 12943 | MarkMonitor Inc. | 1125.995 ms |
| nvidia.com | 1993-04-20T04:00:00+00:00 | 12224 | SafeNames Ltd. | 739.153 ms |
| google.com | 1997-09-15T04:00:00+00:00 | 10615 | MarkMonitor Inc. | 829.219 ms |

All three supplied official-domain literals match exactly. This does not independently verify their association with the claimed organization. Registry responses did not provide independently established registrant identities. Full RDAP query URLs, raw bootstrap and raw registry bodies are in results/rdap_domain_provenance-final.json.

Email fixtures: aligned sender, display-name spoof, wrong From domain, SPF pass/DMARC misalignment, valid multiline headers, and malformed headers. Five assessments had complete parseable results. The malformed assessment remained FAIL; its expected rejection passed the sixth fixture test. All Authentication-Results and DKIM-Signature content in those fixtures is explicitly synthetic and never presented as cryptographic verification.

Microsoft and NVIDIA SEC submissions each returned HTTP 200. Exact filer names/CIKs and listed phones were corroborated. Both website and investorWebsite fields were empty. Separate operator-designated Microsoft and NVIDIA contact pages returned HTTP 200, with published contact tokens and context preserved. They cannot independently establish the SEC-filer-to-domain link; both full cases remain UNRESOLVED. Extracted phone-shaped strings require context review and may include non-phone numbers.

| India rule | Source | Exact quote checked live | Assessment |
|---|---|---|---|
| india-synthetic-infosys-recruiter-equipment-training-fee | https://www.infosys.com/careers/apply/recruitment-fraud-alert.html | NO: HTTP 403 | FAIL |
| india-synthetic-police-immediate-safe-account-transfer | https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2024-0050&pageid=PUBVLNOTES02 | YES | PASS |
| india-synthetic-sbi-caller-otp-pin-password-request | https://sbi.bank.in/en/web/personal-banking/cyber-security | YES | PASS |

Exact quotes are in examples/contradiction_case.json and each report source entry; complete fetched text and exact captured bytes are preserved. The failed Infosys request remains visible. CERT-In supports the narrowly scoped immediate money-pressure contradiction; it does not prove every transfer or government fee unlawful. SBI supports the credential-disclosure-to-caller contradiction; entering credentials in a legitimate bank flow is a different scope. No source was silently replaced after a failure.

## Additional validation

- RDAP: 4/4 expected failures checked: invalid URL input, actual registry HTTP 404 for www.microsoft.com, response-size limit, and tiny-timeout failure. Exact failures are in results/rdap-negative-checks.json and individual raw reports.
- RDAP: 10/10 targeted local input/schema validations passed, including multiple trailing dots, Unicode mapping ambiguity, IP input, malformed roles and empty registrar names. These are labeled local synthetic schema tests; no API responses were mocked.
- All four scripts compiled successfully; 8/8 help and malformed CLI checks passed. All emitted evidence_state values were checked against the permitted four-value set.
- India engine: 14/14 deterministic expectations passed, including contradictory/consistent inputs, mismatched scope, unknown null facts, missing excerpts and malformed facts. This suite fetches no policy source.

## Complete boundaries and limitations

### Shared experiment

- Smoke tests do not measure availability rates, latency percentiles, false positives, false negatives or real-world scam detection accuracy.
- All HTTP calls depend on local DNS, network, TLS, source availability, rate limiting and response format. Socket timeouts do not impose a total wall-clock deadline.
- Raw output is bounded. Oversized, unsupported, malformed or inaccessible evidence fails explicitly; no CAPTCHA bypass is attempted.
- Custom official domains, trust anchors, policy interpretations and observation facts are operator inputs. Literal consistency does not establish sender identity.
- All suspicious domains/messages are synthetic fixtures. No live malicious URLs were used.
- Exit code 1 can represent a valid experimental finding that evidence is unresolved, including a source HTTP failure. Test-expectation PASS and evidence-assessment PASS have different denominators.

### RDAP

- PASS requires a real domain RDAP record, usable registration date, and a named registrar. This is metadata feasibility, not a scam verdict.
- RDAP records current registration metadata; registration age is not proof of ownership continuity, sender identity, or legitimacy.
- Registry responses can redact registrants. Registrar identity is not registrant identity. No registrar referral or historical WHOIS lookup is performed.
- The exact supplied domain is queried. A subdomain is not silently replaced with a registrable parent.
- One selected HTTPS service, no cache/retries/hidden fallback. Timeout bounds each blocking socket operation, not total wall time.
- Only ASCII/A-label domains are accepted; Unicode normalization or lookalike identification is not inferred.
- Registrars and registration age do not establish registrant identity; privacy/redaction and registry-level omissions limit provenance.
- Subdomains may have no independent registration record. The exact supplied hostname is queried; no public-suffix or parent-domain inference is performed.

### Email

- PASS means this input supplied complete, interpretable receiver-reported evidence; it does not mean the email is safe or authentic.
- No SPF DNS evaluation, DKIM cryptographic verification, DMARC policy lookup, or network requests are performed.
- Trust is a caller assertion: use an original export from a known receiver that strips spoofed Authentication-Results for its own authserv-id. An authserv-id match alone is forgeable.
- Only outer message headers are read. Forwarded/attached headers, screenshots, and copied sender-provided headers are not trusted exports.
- Conservative syntax subset: ASCII Authentication-Results, version 1, compact property names (header.from), exactly one matching trusted header, one SPF and DMARC result; multiple DKIM results are preserved. Other layouts fail closed.
- Receiver-reported DMARC is used; relaxed alignment and organizational domains are not independently calculated.
- A single message cannot establish population-level accuracy or reliability. Test a labeled set of real receiver exports separately.
- Organization names and official domains are caller configuration, not independently verified authoritative identities; display names never establish identity.
- Domains must be ASCII or explicit IDNA2008 A-labels (xn--). Unicode domains fail closed rather than using Python's older IDNA mapping.
- No genuine .eml export was supplied, so real receiver-export provenance and crypto/DNS feasibility remain untested.
- Unicode domains require explicit ASCII/A-labels; unsupported syntax fails conservatively rather than being guessed.

### Organization/contact

- Authority is scoped to the US SEC EDGAR submissions record obtained over certificate-validated HTTPS from data.sec.gov.
- An exact current filer name and CIK corroborate registry presence; this is not a certificate of incorporation or current legal good standing.
- A phone match verifies a contact listed in the same filer record, not present control, reachability, or a sender's identity.
- Official domain is verified only by an explicit website or investorWebsite field in that same identified SEC record; empty fields remain UNRESOLVED.
- A separate operator-designated official contact page is fetched and its visible contacts and matching domain links are reported. This is conditional on the explicit trust basis and cannot independently prove its relationship to the SEC filer.
- HTML extraction is static, excludes scripts/styles/templates/head and hidden attributes, and does not run JavaScript or evaluate CSS. Extracted contacts may serve different departments; context is preserved.
- A different phone/domain listing does not prove a claimed alternative is false: lists can be incomplete, so absence or mismatch remains UNRESOLVED.
- The requested organization name must match the current filer name after case and whitespace normalization; aliases are not guessed.
- Phone matching removes presentation separators only and requires equal digits. Country codes are not guessed.
- US SEC filer coverage is narrow; arbitrary organizations and unlisted entities need other authoritative registries.
- PASS requires registry identity, official domain, and requested phone all verified. FAIL/UNRESOLVED never means scam.
- There are no retries, redirects, cached answers, invented responses, alternate sources, or outbound contact attempts.
- Observed SEC website fields were empty for both default organizations, preventing full-case PASS despite verified identity and phone facts.
- Phone-shaped text extraction is an evidence aid, not a determination that each number is an official contact.

### India rules

- PASS measures evidence retrieval and explicit fact comparison, not whether a message is a scam or safe.
- An operator must independently choose authoritative hosts and correctly interpret policy scope, quote, and observation facts. Quote presence does not verify that interpretation.
- Scopes must match exactly. No fuzzy matching, text inference, urgency scoring, or universal payment/interview/credential rule is used.
- Live HTTPS HTML/plain-text only; blocked pages, HTTP errors, unsupported content, and missing quotes fail visibly. Dynamic-only text and PDFs are unsupported.
- Observation text is supplied by the operator and its authenticity is not verified. Synthetic examples cannot establish real-world detection accuracy.
- Bank credential comparisons concern disclosure to a caller; they do not prohibit entering an OTP/password into the bank's own legitimate authentication flow.
- The police example concerns immediate money pressure during a claimed investigation; it does not classify every government fee, fine, or transfer as illegitimate.
- Infosys rejected the direct HTTP fetch with 403; the equipment/training-fee rule remains NO_AUTHORITATIVE_DATA.
- The selected recruiter policy is specific to Infosys and the bank guidance is specific to SBI; neither becomes an all-employers/all-banks legal rule.
- Exact quotes are checked after whitespace normalization. Matching text is necessary evidence, but does not machine-verify that a human encoded its meaning or jurisdiction correctly.
- HTML extraction does not execute JavaScript or fully evaluate hidden/CSS-dependent text. No PDFs are interpreted.
- Source quote and policy formats can change; historical applicability is not checked.

## Feasibility decision

RDAP current metadata and deterministic domain comparison are demonstrated. Email-header parsing is demonstrated on fixtures; independent SPF/DKIM/DMARC verification remains untested. Organization verification is useful for narrow SEC identity/contact facts but does not satisfy complete organization/domain/contact attribution with these sources. Two manually scoped India process checks are demonstrated against live policy evidence; the recruitment source is inaccessible from this environment. Broader reliability is not established.
