# CrossCheck interview notes

## A 60-second explanation

CrossCheck investigates impersonation claims in suspicious messages. A scammer
can quote a real company and registration number while using an unrelated
website, so a single suspicious/not-suspicious label loses useful detail.

I use the OpenAI API to extract atomic claims with exact source quotes. Python
validates the schema and routes claims to curated authoritative sources, including
the FCA, Companies House and RDAP. Deterministic code compares the specific facts
and returns one of four evidence states. The model cannot assign those states.

The React interface shows each claim, the original quote, source evidence and
limitations. Related facts from one FCA warning count as one source group. An
active company never authenticates the person contacting you, and missing
evidence stays unknown.

The engineering work includes strict API validation, bounded HTTP operations,
SSRF defenses, provenance grouping and regression tests. It is a scoped prototype,
not a production fraud detector or a human identity authenticator.

## Three engineering challenges

1. **Grounding a claim without accidentally verifying a different fact.** A
   substring regex accepted “unauthorised” as “authorised,” and an extracted
   domain could match inside an attacker domain. I added whole-token/domain
   boundaries, narrow affirmative predicate checks and explicit comparison of
   supplied company numbers and formatted phones. Unsupported language remains
   unresolved; broad language coverage is a deliberate limitation.
2. **Retaining conflicting assertions without inflating evidence.** A deduplication
   key based only on kind/organization/domain/polarity discarded a second,
   conflicting FRN. Exact statement/source wording now participates in the key.
   Separate claims remain visible, but their evidence still shares the same
   underlying source group. Mixed routes remap local evidence IDs without
   changing source identities or extracting twice.
3. **Making network failures safe and explainable.** Source errors must not turn
   into fraud findings. HTTPS connections reject private DNS answers, connect to
   the checked address and preserve TLS hostname validation. Public GET retries,
   byte limits, request budgets and worker limits bound resource use. Failures
   return explicit gaps; API errors expose safe metadata rather than raw provider
   content. Actual local HTTP tests exercise timeouts and malformed framing.

## Algorithms and data structures actually used

| Code | Technique | Why it is used |
|---|---|---|
| `investigation/models.py` | Frozen dataclasses and enum | Explicit claim/evidence contracts and four allowed states. Nested dictionaries are not deeply immutable; do not claim otherwise. |
| `validate_claims` / `expand_candidates` | Exact substring search and span equality | Anchor each quote to the submitted text; reject ambiguous generated quote occurrences. |
| `critical_claims` | Set of assertion tuples | Remove exact duplicates without losing distinct contact values or identifiers. |
| `engine.py`, `clone_firm.py` | Route table, dictionaries | Dispatch deterministic rules and reuse per-slice domain/contact lookups. |
| `ScopedHTML` | HTMLParser plus a stack | Scope visible text to authoritative record fields; detect repeated fields. |
| `rdap_domain_provenance.select_service` | Linear longest-suffix selection | Choose the most specific matching IANA RDAP service without fetching the suspicious website. |
| `evidence_group`, summaries | SHA-256 keys, sets, dictionaries, Counter | Stable provenance groups, claim-state totals and duplicate-source prevention. No blockchain or machine-learning scoring is involved. |
| `routing.py` | ID map and stable sorting | Merge result slices and preserve original claim order. |
| `strict_json` | Linear depth scan with string/escape state | Bound decoder nesting before recursive JSON parsing. |
| `safe_http.py`, `http_support.py` | ContextVar and bounded semaphores | Isolate per-investigation budgets and bound concurrent work. |

Let N be input characters, C candidate claims, E evidence records, B retrieved
bytes, D maximum HTML depth and S bootstrap service entries. These are algorithmic
descriptions, not measured throughput claims:

- JSON nesting scan: O(N) time, O(1) extra scanner state; decoding still stores
  the resulting JSON tree. Depth is capped at 64.
- Claim grounding performs searches over input for each claim: roughly O(C × N)
  for these bounded inputs; substring implementation details and regex matching
  affect exact worst-case behavior. Live C ≤ 5; annotations C ≤ 32.
- Deduplication: expected O(C × L) including hashing claim text of length L;
  O(C) set entries. No claim is dropped to force a demo score.
- The record parser processes B text with a stack; collecting data for ancestors
  can cost O(B × D), rather than claiming all HTML parsing is constant-space or
  unconditionally linear. Bodies are bounded at about 2 MB.
- RDAP selection scans S entries and compares suffixes: O(S × domain length).
  It is not a trie or a search engine.
- Grouping/counting is expected O(C + E) plus referenced edges. The legacy general
  engine's correlation loop is O(C²); C is capped, so a graph database is unjustified.
- Mixed-result sorting is O(C log C), with O(C + E + B) result storage/copying.
  Network latency dominates this small workload. No speed-up percentage was measured.

## Security and reliability boundaries

The model receives untrusted communications, has no evidence-fetching tools and
cannot choose final states. Schema checks and exact quotes restrict fabricated
outputs; they cannot guarantee complete or correct extraction. Real-provider
validation is separate from labelled mocks and capture replays.

The HTTP layer rejects unsafe addresses and redirect targets, bounds input and
response sizes, and limits retries/concurrency. The 90-second outbound budget is
cooperative; DNS and blocking operations are not forcibly cancelled. Client
cancellation does not stop server work. There is no application authentication
or per-user quota, so a public deployment needs additional controls.

No database stores investigations. Logs omit communication text and credentials.
Live extraction transmits text to OpenAI; responses/CLI exports contain private
input and potentially email headers. Explain this boundary rather than claiming
the system is entirely offline or has zero retention everywhere.

## Five likely questions

**Why use an LLM if verification is deterministic?**

Natural-language extraction benefits from flexible language interpretation. Truth
assignment needs inspectable rules and evidence. Separating the two lets me test
the verifier independently, retain useful unknown states and avoid letting the
same model invent both a claim and its justification.

**What happens if two claims or sources disagree?**

Distinct input claims survive deduplication and can have different states. The
curated source decides only its stated scope: a correct FRN and a false
affiliation can coexist. Repeated/ambiguous authoritative fields fail closed.
There is no general cross-source majority vote; incompatible records outside
implemented scopes remain a limitation, not an invented confidence score.

**How do you avoid SSRF and DNS rebinding?**

User text never supplies the fetch URL. Policy hosts are configured; RDAP starts
from IANA. HTTPS/443 and redirect-host checks restrict requests. At connection
time all DNS answers must be global addresses; the socket connects to a checked
sockaddr, avoiding a second lookup, and TLS validates the original hostname.
Environment proxies are disabled. Unit tests simulate private and mixed answers.

**Why no database, queue or async framework?**

The current product is a stateless, small, local investigation workflow. Bounded
threads and per-request dictionaries are sufficient for the demonstrated scope.
A queue would require durable jobs, cancellation semantics and operations that
the project does not currently need. Public multi-user scale would justify
revisiting that design after measuring load and defining retention requirements.

**What did your tests establish, and what did they not establish?**

They establish reproducible behavior for schema validation, routing, evidence
comparison, grouping, failure handling and UI rendering. Actual HTTP tests exercise
the proxy/backend. One fresh annotated run used three live public source groups
and produced the expected four-claim result. The fresh OpenAI release run is
blocked by missing credentials. Test counts and a small historical benchmark do
not establish general fraud accuracy, availability or production readiness.

## Three measured resume bullet candidates

- Built a Python/React investigation pipeline with **4 deterministic evidence
  states**, exact-quote grounding and shared-source provenance, keeping AI claim
  extraction separate from authoritative verification.
- Expanded regression coverage from **90 to 134 Python tests** and **13 to 22
  frontend tests**, including adversarial input, SSRF, timeouts, conflicting
  claims and real local HTTP integration checks; all passed in the audit.
- Validated a **4-claim** clone-firm scenario against **3 live public source
  groups**, returning **2 verified, 2 contradicted and 0 unresolved** findings in
  one explicitly annotated **3.894-second** run.

Use the last bullet only with its annotation qualifier. These are measured test
and demonstration results, not user adoption, production accuracy or a latency
improvement. Be ready to point to `docs/VALIDATION.md` and the raw public-source
summary. Describe work you can explain and reproduce, including any assistance
used, rather than implying unsupported sole authorship.

## Demonstration readiness

Ready to demonstrate the scoped engineering prototype with explicit annotations
and live public evidence, or the older fully offline NVIDIA example. Before a
live-extraction interview demo, configure a private API key and run
`python check_product_live.py`; do not rely on historical successes. Have the
labelled offline tests/captures available if a public source is unavailable.
