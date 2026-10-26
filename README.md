# Malicious Email Scorer

Gmail add-on and FastAPI service that score an opened email from 0 to 100 and explain the verdict.

The sidebar sends the open message to `POST /v1/analyze`. The service checks four layers:

1. **Authentication and identity.** SPF, DKIM, and DMARC are read from the headers Gmail stored on the message. Display names are compared with the real domain. Lookalike hosts are caught with confusable-character folding (for example `paypa1` to `paypal`).
2. **Link reputation.** URLs are checked against URLhaus, and against PhishTank and Google Safe Browsing when those keys are set.
3. **Attachments.** PDF, Office, and ZIP bytes are inspected in memory for macros, PDF scripts, embedded executables, and phishing wording. Only each file’s SHA-256 hash is sent to MalwareBazaar (same abuse.ch key as URLhaus). File contents never leave the machine.
4. **Wording.** A local classifier looks for credential requests, account threats, and payment pressure. Optional Hugging Face BERT when `USE_TRANSFORMERS=true`.
5. **Meta-analysis.** A local correlator sets the final score. If `ANTHROPIC_API_KEY` is set, Claude reviews the same evidence (not file bytes) and the deterministic checks keep its score inside the band those checks support.

Verdicts: **Safe** below 40, **Suspicious** from 40 to 84, **Malicious** from 85 to 100. The three QA emails are held to tighter ranges: Safe 0–15, Suspicious 60–80, Malicious 85–100.

## Run it locally

From the project root in PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd backend
python -m pytest
python eval/evaluate.py
python -m app.cli
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ and use the scenario buttons. `run.ps1` starts the same server after the virtual environment exists.

Copy `.env.example` to `.env` when you have keys. The service scores mail without them.

| Variable | What it unlocks |
| --- | --- |
| `ANTHROPIC_API_KEY` | Claude meta-analysis. Optional `ANTHROPIC_MODEL` (default `claude-sonnet-4-5`). |
| `SAFE_BROWSING_API_KEY` | Google Safe Browsing |
| `PHISHTANK_API_KEY` | PhishTank |
| `URLHAUS_AUTH_KEY` | URLhaus malware lookups and MalwareBazaar attachment-hash lookups (same abuse.ch Auth-Key). |
| `API_KEY` / `API_KEYS` | Requires `X-API-Key` on `POST /v1/analyze` |
| `REQUEST_SIGNING_SECRET` | Requires `X-Timestamp`, `X-Nonce`, `X-Signature` (add-on signs automatically) |
| `FIREBASE_PROJECT_ID` + `ACCOUNT_TOKEN_SECRET` | Enables `POST /v1/account/token` for per-user keys |
| `ENABLE_WHOIS` | Domain age. Also install `requirements-optional.txt` (`python-whois`). |
| `ENABLE_LIVE_DNS` | dnspython lookup of published SPF and DMARC records. The score for a received message still comes from its Authentication-Results header. |
| `USE_TRANSFORMERS` | Optional Hugging Face classifier. The QA ranges are defined for the built-in lexical classifier. |

`http://malicious-test-url.com` (any path) is the reserved QA URL. If URLhaus has no listing, it is still scored as a malware hit so scenario B stays reproducible.

## Deploy (Google Cloud free tier)

Cloud Run has an always-free monthly allowance (request-based billing, `min-instances=0`). Firebase Hosting + Auth free quotas cover the landing page.

1. Install [Google Cloud SDK](https://cloud.google.com/sdk) and enable billing on a project (free tier still applies).
2. Create secrets, then deploy:

```powershell
.\deploy\create-secrets.ps1 -ProjectId YOUR_PROJECT -AnthropicKey "..." -SafeBrowsingKey "..."
.\deploy\deploy-cloud-run.ps1 -ProjectId YOUR_PROJECT -Region us-central1
```

3. Put the printed `API_KEY` / `REQUEST_SIGNING_SECRET` into Apps Script (see below).
4. Landing page: copy `landing/firebase-config.example.js` → `landing/firebase-config.js`, then `firebase deploy --only hosting` (Firebase CLI).

Per-user keys: set `FIREBASE_PROJECT_ID` + `ACCOUNT_TOKEN_SECRET` on Cloud Run. The site’s **Sign in with Google** calls `POST /v1/account/token` and returns a stable `mg1…` key (no database).

## Gmail add-on (clasp)

Source lives in `addon/`. Prefer clasp over copy-paste:

```powershell
npm install
copy .clasp.json.example .clasp.json
# put your Apps Script project id in .clasp.json, then:
npm run clasp:login
npm run clasp:push
```

Script properties (shared): `BACKEND_URL`, `REQUEST_SIGNING_SECRET`.  
User property (per Gmail account): `API_KEY` from the landing page.

Apps Script cannot call `localhost` — use the Cloud Run URL. Opening a message scores it. **Report phishing** → Spam. **Block sender** → Trash + filter.

## Tests

`pytest` covers domain age, display-name spoofing, mocked URLhaus hits, feed timeouts, HTML sanitizing, the three scenario ranges, API auth, and the labeled CSV. `python eval/evaluate.py` prints accuracy, precision, recall, false-positive rate, and false-negative rate for the text classifier and the full engine. Point `--csv` at a file with columns `label,subject,from_display,from_address,body` (`phish` or `legit`) to score a larger export. `--live` uses the real URL feeds.

The score is decision support. It does not fetch link destinations, and a passed authentication check does not by itself make a credential request safe.
