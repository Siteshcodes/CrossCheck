# Forge evidence workbench

React + TypeScript + Vite frontend, served by a small Python same-origin launcher. The existing investigation API and deterministic evidence semantics remain unchanged.

## Run

From the repository root:

```powershell
cd web
npm ci
npm run build
cd ..
python run_product.py
```

Open http://127.0.0.1:8080. Configure OPENAI_API_KEY in the launching environment; the existing extractor uses OPENAI_MODEL when configured. Keep credentials out of the browser and source files.

Default mode submits only the communication to the real POST /investigate API. Load example reads the actual clone-firm fixture. No saved investigation response is used by the product.

The backend is a thread inside the launcher, not a child process. It shares the parent environment directly and uses the same LLMExtractor/OpenAIClient implementation as the benchmark. Startup logs only the boolean API-key availability. Environment changes made in another shell after launch do not update an already-running process; restart from the configured shell. The existing client also reads OPENAI_API_KEY and OPENAI_MODEL from a private repository-root .env (ignored by version control). Never paste credentials into chat or commit that file.

Run the real-provider release check from that same configured environment:

```powershell
python check_product_live.py
```

This starts the actual product proxy/backend in production mode on temporary local ports, submits both the flagship and manual text without annotations, and requires real model extraction followed by verification. It writes results/product-live-extraction-check.json and exits nonzero on failure. Offline provider-transport regression tests are explicitly mocked and are not proof that the real provider ran.

For an explicitly annotated example with live public-source checks:

```powershell
python run_product.py --annotated-example
```

This mode visibly labels its extraction as analyst annotations. Annotations apply only to the exact fixture text; custom communications still require live LLM extraction. There is no automatic fallback after extraction failure.

## Experience and boundaries

The workbench provides communication entry, honest pending status, an interactive evidence relationship graph, claim inspector, raw evidence disclosures, exact regulator contact comparisons, source links, grouped provenance, and investigation boundaries. Canonical evidence states come exclusively from the backend. Multiple FCA findings retain one evidence group; website and telephone remain one returned contact claim.

The backend returns its investigation in one response, so pending UI shows elapsed time and requested methods without inventing per-source completion events. Cancelling stops waiting; server processing may continue. Public-source availability and the existing curated verification coverage remain backend limitations. No probability score or identity authentication is inferred from genuine company records.

## Validation

```powershell
python -m unittest discover -s tests -v
cd web
npm test
npm run lint
npm run build
```

Final checks: 70 backend tests and 11 frontend tests passed; lint and production build passed. Browser checks covered actual API submission, claim selection, regulator contact comparison, mobile overflow, and missing-key HTTP 502 with input preserved and no substituted result.

The current agent process could not access an API key. Browser success therefore used explicitly labelled fixture annotations with real live FCA, Companies House and authoritative RDAP requests, not a new live extraction benchmark. Latest live evidence request took 1.769 seconds and returned four claims: two verified, two contradicted, zero unresolved; three independent provenance groups and mechanisms. See results/product-validation.json and results/product-live-investigation.json for the actual response and report. Screenshot proof is in results/product-desktop.png and results/product-mobile.png.

No authentication, database, history, chatbot, autonomous agents, or additional product surface was added.
