# Malicious Email Scorer

A Gmail add-on that scores the email you have open and explains the verdict.

**What you see in Gmail:** a score from 0–100, a verdict (**Safe** / **Suspicious** / **Malicious**), short reasons, a checklist of what was checked, and actions to report phishing or block the sender.

**What does the work:** a FastAPI backend that treats every message as untrusted input, fuses several independent signals, and never stores mail.

---

## Why this shape

| Choice | Reason |
| --- | --- |
| Thin Gmail add-on + real backend | Apps Script is ideal for UI and Gmail actions; heavy inspection, threat feeds, and LLM policy belong in a service you can test, harden, and scale. |
| Deterministic layers first, LLM second | Headers, URLs, attachments, and wording must produce a score even if Claude is down. The model may refine wording and nudge the score — it cannot invent a “safe” verdict when hard signals say otherwise. |
| Explainable UI | Analysts and end users need *why*, not a black-box number. Reasons stay short; internal analyst notes stay off the sidebar. |
| Stateless API | One request in, one verdict out. No mailbox sync, no mail archive — smaller blast radius if the API is abused. |

---

## Architecture

```text
┌─────────────────┐     HTTPS + API key      ┌──────────────────────────┐
│  Gmail Add-on   │     + HMAC signature     │  FastAPI on Cloud Run    │
│  (Apps Script)  │ ───────────────────────► │  POST /v1/analyze        │
│                 │ ◄─────────────────────── │                          │
│  Sidebar card   │     score, verdict,      │  Layers → fuse → respond │
│  Report / Block │     reasons, checks      └────────────┬─────────────┘
└─────────────────┘                                       │
                                                          ▼
                                    ┌─────────────────────────────────────┐
                                    │ Optional: URLhaus / Safe Browsing / │
                                    │ MalwareBazaar / Claude (redacted)   │
                                    └─────────────────────────────────────┘
```

### Components

1. **`addon/`** — Gmail Workspace add-on. Builds a capped JSON payload from the open message (headers subset, body truncated, limited attachment types/sizes) and calls the backend. Signs each request when `REQUEST_SIGNING_SECRET` is set. Report phishing moves the message to Spam; Block sender trashes it and creates a filter.
2. **`backend/`** — FastAPI scoring service. Sanitizes HTML, extracts URLs, runs analysis layers in parallel where safe, fuses findings into a banded score, returns a UI-ready response.
3. **Deploy** — Production path is **Cloud Run** (request-based billing, scale to zero) with secrets in **Secret Manager**. Local demo uses uvicorn + optional tunnel. `clasp` syncs add-on source from git to Apps Script.

### Scoring layers

| Layer | What it looks at |
| --- | --- |
| Authentication & identity | SPF / DKIM / DMARC from Gmail’s stored `Authentication-Results` (not a fresh DNS vote on the live domain alone). Display-name spoofing and lookalike hosts (confusable folding). |
| Link reputation | Extracted URLs vs URLhaus; PhishTank / Google Safe Browsing when configured. Destinations are **not** fetched. |
| Attachments | PDF / Office / ZIP inspected in-process (macros, scripts, embedded executables, phishing text). Only SHA-256 hashes go to MalwareBazaar — file bytes stay on the scorer. |
| Wording | Local lexical classifier for credential theft, urgency, payment pressure. Optional Hugging Face model (off by default in production for cold-start cost). |
| Domain age | Optional WHOIS for young sender domains. |
| Meta-analysis | Local correlator always runs. Claude (optional) sees **redacted** evidence and a locked system prompt; output is clamped to the band supported by deterministic checks. Prompt-injection patterns can skip the LLM entirely. |

**Verdict bands:** Safe &lt; 40 · Suspicious 40–84 · Malicious ≥ 85.

---

## Security

Security was treated as a product requirement, not a checklist at the end.

### Untrusted email

- Message body and HTML are sanitized before analysis; invisible / bidi characters that hide instructions from humans are stripped before any LLM path.
- Prompt-injection phrases are detected; on hit, Claude is not called and the injection is recorded as a finding.
- Attachments are type-gated and size-capped in the add-on; inspection runs with isolation/timeouts on the server.
- Threat-feed and LLM failures degrade gracefully — the API still returns a score from local signals.

### Sensitive data

- **No mail storage.** The scorer does not persist message bodies or attachments.
- Before Claude: PII-style redaction (emails, phones, card-like numbers, etc.) and mode `LLM_MODE=redacted` (or `evidence_only` / `off`).
- Attachment **contents** never leave the scorer host; only hashes are queried externally.
- Logs stay quiet in production (`WARNING`, no access log on Cloud Run). Validation errors do not echo the submitted email back to the client.

### API authenticity

| Control | Purpose |
| --- | --- |
| `API_KEY` / per-user tokens | Callers must present a key; production refuses to start without auth material. |
| HMAC request signing (`X-Timestamp`, `X-Nonce`, `X-Signature`) | Stops trivial replay of a captured body; nonce store rejects reuse within the time window. |
| Body size limit + rate limit | Caps abuse and oversized payloads. |
| Demo / OpenAPI routes | Bound to `DEV_MODE` only. |

Secrets live in environment / Secret Manager / Apps Script properties — never in source control (`.env`, `.deploy-credentials.txt`, `.clasp.json` are gitignored).

### Trust boundaries (honest limits)

- The add-on runs as the user; a malicious install with the user’s token can score that user’s mail through the API. Tokens must stay private.
- Gmail already decided authentication for the delivered message; we read those results rather than pretending we re-validated the wire path.
- URL reputation is feed-based; we deliberately do not crawl links (drive-by and SSRF risk).
- The score is **decision support**, not a guarantee.

---

## Repository layout

```text
addon/           Gmail add-on (clasp root)
backend/app/     FastAPI app, layers, scoring, privacy, security
backend/tests/   Offline pytest suite
deploy/          Cloud Run + Secret Manager scripts
landing/         Optional Firebase Hosting sign-in page
eval/            Evaluation helpers and sample data
```

---

## Run locally

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd backend
python -m pytest
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ for the local demo page (dev mode). Copy `.env.example` → `.env` for optional keys.

| Variable | Role |
| --- | --- |
| `API_KEY` / `REQUEST_SIGNING_SECRET` | Protect `/v1/analyze` (required when `DEV_MODE=false`) |
| `ANTHROPIC_API_KEY` | Claude meta-analysis |
| `SAFE_BROWSING_API_KEY` / `URLHAUS_AUTH_KEY` | URL / hash intel |
| `LLM_MODE` | `redacted` (default) · `evidence_only` · `off` |
| `USE_TRANSFORMERS` | Optional BERT classifier (default off) |

Apps Script cannot call `localhost`. For a live Gmail demo, deploy to Cloud Run (below) or use a tunnel and set Script property `BACKEND_URL`.

### Cloud Run (summary)

```powershell
.\deploy\create-secrets.ps1 -ProjectId YOUR_GCP_PROJECT
.\deploy\deploy-cloud-run.ps1 -ProjectId YOUR_GCP_PROJECT -Region us-central1
```

Then set Apps Script Script properties: `BACKEND_URL`, `REQUEST_SIGNING_SECRET`, `API_KEY`. Push add-on code with clasp (`npm install` → configure `.clasp.json` from the example → `npm run clasp:push`).

---

## Evaluation

Offline run on `backend/eval/corpus_v1.csv` (**201** messages: **43** phish, **158** legit). Phishing rows are a Nazario `phishing0.mbox` slice plus short credential templates; legitimate rows are an Enron slice from the Kaggle phishing-email dataset mirror. The synthetic attack suite (`backend/eval/attack_cases.json`) is scored separately so a feed timeout or a 2004-era phish without modern URLs does not get mixed into FPR.

**False-positive definitions (benign mail):**
- **FPR (strict)** — engine verdict is **Malicious**
- **FPR (alert)** — engine verdict is **Suspicious** or **Malicious** (the sidebar would warn)

Recall treats **Suspicious** as a catch on phishing.

| Slice | Accuracy | Precision | Recall | FPR strict | FPR alert | n |
| --- | --- | --- | --- | --- | --- | --- |
| Text classifier | 91% | 100% | 58% | 0% | 0% | 201 |
| Full engine (offline) | 86% | 100% | 35% | **0%** | **0%** | 201 |

| Attack class | Detected |
| --- | --- |
| Poisoned / lookalike URLs | 3/3 |
| Prompt-injection bodies | 4/4 |
| Office DDE / macro vs benign “added” workbook | 4/4 |

Reproduce (from `backend/`, LLM off, no live feeds):

```powershell
python eval/build_corpus.py
python eval/make_fixtures.py
python eval/evaluate.py --csv eval/corpus_v1.csv
```

This is an interview-sized corpus, not a SOC benchmark. Nazario samples from 2004 often lack live malicious URLs and modern lookalikes, so **recall is low on that slice by design** (the engine refuses to invent malware hits). FPR is the number that matters for “will this annoy a real inbox,” and both strict and alert FPR are **0%** on the Enron legit slice.

`pytest` covers auth, spoofing, URL intel mocks, prompt injection, scenario bands, sanitizing, and attachments. Three QA scenarios (Safe / Suspicious / Malicious) stay in `backend/app/scenarios.py`.

---

## Trade-offs and what I’d do next

**Done on purpose:** explainability over opaque ML; no link fetching; LLM as advisor behind clamps; production auth + signing before “more features.”

**With more time:** Workspace Marketplace listing and polished onboarding; tighter per-user quotas and anomaly alerts; richer attachment sandboxing; continuous eval on a larger phishing corpus; optional SOC export (SIEM) without storing full bodies.

---

## Demo checklist

1. Backend reachable (local demo or Cloud Run `/health`).
2. Add-on installed as a Gmail test deployment with Script properties set.
3. Open a known-good mail, a credential-phishing sample, and a malware-link sample — show score, reasons, checklist, and Report / Block.

---

*Built for a Security Analyst home assignment. The score helps a human decide; it does not replace judgment.*
