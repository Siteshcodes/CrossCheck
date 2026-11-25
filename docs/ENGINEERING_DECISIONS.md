# Engineering decisions

## Keep extraction separate from verification

The OpenAI Responses adapter proposes at most five critical claims using a strict
schema. Exact quotes determine offsets; unknown fields, final states, invented
domains and invalid routes are rejected. Python assigns the four terminal states.
There is no model-selected URL or verification tool. Retrieved HTML is parsed by
code, not passed to a model. Optional narration receives established findings and
cannot change their canonical states.

Trade-off: exact quotations prove provenance, not semantic correctness. The
curated legal/regulatory rules accept narrow affirmative forms. Compound,
qualified, negative or unsupported assertions stay unresolved. This reduces
coverage to avoid upgrading loosely related facts into proof. Prompt injection
can still affect extraction coverage; the system is not injection-proof.

## Verify the proposition and preserve source dependence

An active company, a correct FRN and a matching contact are different predicates.
The engine compares asserted FRNs/company numbers and contacts, preserves source
quotes, and requires the named clone relationship before applying its warning.
A clone's own website assertion is not automatically a claim to use the genuine
firm's website. Receiver-reported authentication is compared to explicit outcomes
and never establishes human identity.

Exact-assertion deduplication uses a hash set including source wording. The prior
coarse key dropped conflicting FRNs; the replacement retains both. Evidence IDs
identify local records, while SHA-256-derived group IDs identify underlying
sources. All FCA facts and derived contact comparisons share one group. Counts
are descriptive; no probability or independent-signal score is computed.

## Compose the existing routes

Mixed inputs are partitioned after one extraction. The existing clone and general
verification slices retain their own rules; `routing.py` remaps local evidence IDs
and parent references, restores candidate order and recomputes grouped summaries.
Single-scenario response shapes remain intact. The mixed-input demo gate is
explicitly not applicable because the curated flagship benchmark is a different
scope. Domain/comparison dictionaries avoid duplicate requests within each slice;
the same domain can still be requested by both slices. No global success cache is
introduced, so failed sources cannot silently reuse stale successful evidence.

## Fail closed on ambiguous evidence

Pinned snapshot bytes/hashes and exact normalized policy quotations are checked.
Live records must parse within known fields; duplicate selectors/labels and
unknown company-status values fail closed. A fetch error or adapter exception is
`NO_AUTHORITATIVE_DATA`. A failed adapter may not return decisive evidence. A
missing record is not an inactive company, failed authentication or fraud.

There is no general multi-source voting algorithm: each supported proposition
has a curated authority. Input claims can disagree and both remain visible.
Cross-source adjudication of incompatible authoritative records beyond those
scopes is future work; source count is never used to outvote a contradiction.

## Bound outbound work without new infrastructure

`safe_http.py` is shared by the existing standard-library adapters. It restricts
HTTPS to port 443, rejects unsafe URL forms and private DNS answers, then connects
to the checked address without a second DNS lookup. TLS still verifies the
original hostname. Environment proxies are disabled so they cannot bypass that
connection policy. RDAP redirects stay on the selected registry host; policy
redirects stay on configured authority hosts. Cross-host RDAP redirects become
visible gaps, trading coverage for a smaller trust boundary.

Public GETs get at most two attempts for selected transient network errors or
429/502/503/504, separated by 250 ms. Attempts are recorded. Certificate failures,
404s and malformed evidence are not retried. Model POSTs are not automatically
retried because requests may already have been processed and billed. A
ContextVar carries a 32-request/90-second cooperative budget per investigation,
shared by nested routes and isolated between concurrent requests. Response reads
are bounded and checked between chunks. DNS and an in-progress blocking operation
prevent this from being a strict total deadline.

## Keep HTTP behavior predictable and private

The API and same-origin proxy share body framing, size and error handling. They
reject ambiguous Content-Length, chunked input, wrong media types, duplicate JSON
keys, deep nesting, nonfinite numbers and invalid Unicode. Body reads have a
15-second deadline. Semaphores bound connection workers to eight per server and
active investigations to four. Saturation returns 503 with Retry-After; request
timeouts return 408. Cancellation stops the browser waiting, not the server job.
Cross-origin browser submissions are rejected, and loopback listeners require
loopback Host values to prevent an attacker-controlled hostname from using DNS
rebinding to reach the local paid-API proxy. These checks do not authenticate CLI
clients or users of a publicly bound server.

Unexpected errors and provider failures return a stable JSON envelope with safe
transport metadata. Logs expose request IDs/status/byte counts, not input or
secrets. Responses intentionally retain the user's submitted communication and
inspectable evidence. They are private investigation artifacts, not safe public
reports. `store: false` is set on provider requests but is not a zero-retention
guarantee. No key enters the frontend bundle.

The React UI escapes text, permits only credential-free HTTPS source links and
validates response states, types, quotes and evidence references at runtime. A
Content Security Policy restricts scripts/connections to the same origin.

## Keep the architecture small

Python standard library, React, TypeScript and Vite remain in place. No database,
queue, microservice or framework was added. Vitest moved from 3.2.7 to 4.1.12 and
typescript-eslint to 8.73.0 to remove the audited vulnerable dependency paths;
tests, lint and production build were rerun. [Vitest advisory](https://github.com/advisories/GHSA-82fw-gwwq-j7x9),
[tinypool advisory](https://github.com/advisories/GHSA-5gmw-xhrv-c9v3),
[minimatch advisory](https://github.com/advisories/GHSA-g3hv-75wg-m249).

This is a validated local prototype. Public deployment still needs an authenticated
gateway, per-user quotas, request deadlines, operational monitoring and an explicit
data-retention policy. Those are deployment requirements, not features claimed
by this repository.
