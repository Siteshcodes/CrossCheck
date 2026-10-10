# Feasibility probes

The MVP vertical slice is documented in [MVP_README.md](MVP_README.md). Run `python -m investigation demo --output results/nvidia-investigation.json` for the complete NVIDIA fixture investigation. The original feasibility probes below remain independently runnable.

Four independent Python 3.10+ scripts, using only the standard library. No installation or API key is required. Each prints JSON containing input, raw evidence, source, latency, result, confidence/boundary, PASS/FAIL and failure reason. Raw HTTP failures remain visible. Exit code 0 means PASS; 1 means FAIL. `--help` describes custom inputs.

Run from this directory:

```powershell
python rdap_domain_provenance.py
python email_header_analysis.py
python organization_contact_verification.py
python scam_process_contradictions.py
```

Saved actual runs are in `results/`; the completion table and full limitations are in `FEASIBILITY_REPORT.md`. A failed or unresolved capability is an experiment result, not a finding that an organization or message is fraudulent. Fixture expectations are counted separately from evidence assessments.

## RDAP

Default: live Microsoft, NVIDIA and Google RDAP queries, plus five explicitly synthetic domain-comparison fixtures. Registration date, age, registrar, IANA-discovered query source, timing and official-domain comparison are printed. Synthetic lookalikes are never queried and never receive invented registration data.

```powershell
python rdap_domain_provenance.py microsoft.com --claimed-organization Microsoft --official-domain microsoft.com
python rdap_domain_provenance.py --self-test
```

The official domain is independently supplied configuration. RDAP metadata cannot prove a sender's identity or current domain ownership. Unicode names require explicit ASCII IDNA A-labels. `--require-registrant` fails explicitly because this probe cannot independently establish registrant identity.

## Email headers

Default: six local `.eml` fixtures in `fixtures/email/`, all labeled SYNTHETIC. Covers aligned sender, display-name spoof, wrong From domain, SPF pass with DMARC failure, valid folded headers and malformed headers. It parses existing `Authentication-Results`; it performs no DNS lookup or cryptographic DKIM verification. A malformed assessment remains FAIL even when its rejection passes the fixture expectation.

```powershell
python email_header_analysis.py --self-test
python email_header_analysis.py --eml YOUR_EXPORT.eml --trusted-authserv-id YOUR_RECEIVER_ID --assert-trusted-receiver-export --claimed-organization Microsoft --official-domain microsoft.com
```

Use the trust assertion only for an original export from a receiver whose boundary strips forged results for its own identifier. The identifier alone is forgeable. Real-email feasibility is UNTESTED until real exports are available.

## Organization/contact

Default: Microsoft and NVIDIA SEC EDGAR submissions records plus explicitly designated official contact pages. SEC identities and listed phones are checked exactly. Empty registry website fields remain UNRESOLVED. Contact-page evidence is conditional on the recorded operator trust basis; fetching a website does not independently link it to the legal filer. Published contact tokens include context for review.

```powershell
python organization_contact_verification.py --cik 789019 --organization "MICROSOFT CORP" --domain microsoft.com --phone 425-882-8080 --contact-url https://www.microsoft.com/en-us/worldwide --authority-basis "Independently established Microsoft official office directory"
```

Optional `--user-agent` or `SEC_USER_AGENT` supplies real application/contact information to SEC. No false contact address is invented. The adapter currently covers SEC filers, not arbitrary organizations or Indian corporate registries.

## India process contradictions

Default: three synthetic observed claims paired with live policy retrieval: Infosys recruiter equipment/training fees; immediate police safe-account transfer pressure; SBI caller requesting OTP/PIN/password. Every rule includes a source URL, exact quote(s), explicit jurisdiction/process scope, and operator-normalized facts. An absent quote, source failure or scope mismatch prevents evaluation.

```powershell
python scam_process_contradictions.py --self-test
python scam_process_contradictions.py --input examples/contradiction_case.json --authority-host www.infosys.com --authority-host www.cert-in.org.in --authority-host sbi.bank.in --authority-host home.sbi.bank.in
```

To test custom claims, copy the JSON example and replace its observations, source quotes and scoped facts. Set `dataset_origin` to `operator_supplied` for real observations. Specify independently chosen authority hosts; the script never learns authority from a suspicious message. All quotes must appear in retrieved text after whitespace normalization. This checks explicitly encoded contradictions, not natural-language understanding or universal legal rules. The police rule is about immediate money pressure; the bank rule is about disclosing credentials to a caller.

Only these `evidence_state` values are used:

- `VERIFIED_BY_AUTHORITATIVE_SOURCE`
- `CONTRADICTED_BY_AUTHORITATIVE_SOURCE`
- `CONSISTENT_BUT_NOT_IDENTITY_PROVING`
- `NO_AUTHORITATIVE_DATA`

`UNRESOLVED` is a fact outcome, separate from those evidence states. PASS evaluates the probe's declared evidence requirements; it never means an email is safe. One smoke run cannot establish availability rates, accuracy, false-positive rates or latency percentiles.
