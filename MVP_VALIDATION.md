# MVP validation

Validated on 9 October 2026 (Asia/Calcutta), Python 3.14.7.

| Check | Result | Evidence |
|---|---|---|
| Unit and integration suite | 30/30 passed | `python -m unittest discover -s tests -v` |
| One-command fixture | Completed: 8 claims, 2 contradicted, 6 unresolved | `results/nvidia-investigation.json` |
| Actual local HTTP endpoint | Passed inside the test suite | `APITests.test_real_http_endpoint_vertical_slice` |
| Live NVIDIA RDAP adapter | Verified current metadata; 1325.320 ms | `results/mvp-live-rdap-nvidia.json` |
| Live NVIDIA policy vertical slice | HTTP 200; same scoped domain-policy findings | `results/nvidia-investigation-live-policy.json` |
| Live LLM API | Not run: no API key configured | Missing credentials are an explicit failure; adapter validation uses labeled test doubles |

The fixture uses manually annotated claims and a genuine, hash-pinned NVIDIA recruitment-policy capture. No lookalike-domain RDAP registration data is invented. The original `.eml` is absent in the recruiter fixture and remains a reported evidence gap. Header unit tests use the existing explicitly synthetic `.eml` fixtures and never perform or claim cryptographic verification.

Two contradicted claims share one independent domain-policy conflict. Six claims remain unresolved because these primitives do not establish individual affiliation, selection, onboarding deadline, vendor authorization, reimbursement or an explicit official equipment-fee obligation. NVIDIA's published upfront-fee warning is preserved; it is not rewritten as a categorical no-fee policy.

Test coverage includes exactly-one terminal state per claim; exact source spans; forbidden model state fields; hallucinated domain literals; missing, corrupt and inaccessible policy evidence; preserved HTTP failure evidence; missing/forged/malformed receiver headers; domain lookalikes; passing attacker authentication without affiliation proof; unknown organizations; ambiguous contact-domain correlation; explanation failure without verdict mutation; probability-output rejection; strict JSON; API source/path overrides; invalid original-EML base64; and explicitly enabled analyst annotations.

Full architecture, commands, source semantics and limitations are in [MVP_README.md](MVP_README.md). Source availability, population-level detection accuracy and live LLM extraction quality are not established by this validation.
