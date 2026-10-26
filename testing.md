# Malicious Email Scorer - Testing Plan & Evaluation Framework

## 1. Objective

Test the Gmail add-on and FastAPI backend with active vectors: synthetic wording, current threat-feed URLs, and real authentication headers. Static corpora such as Nazario and Enron are not the acceptance set. They omit authentication headers and their links are usually dead.

## 2. Score policy under test

Strong urgency wording can reach **Suspicious** (48–70). It cannot reach **Malicious** by itself.

Malicious still requires one of these:

- A live threat-intel hit (URLhaus, Google Safe Browsing, or a MalwareBazaar attachment-hash match), which floors the score at 90.
- Failed authentication together with impersonation (brand spoof, lookalike, or a new domain), which floors the score at 88.

Credential wording plus a lookalike or newly minted link, with authentication still passing, stays **Suspicious** (64–80).

Active attachment content without a confirmed hit stays **Suspicious** (60–80): auto-run macros, PDF JavaScript or launch actions, embedded executables, and disguised executables. File bytes are inspected only on the local scorer. The only outbound attachment signal is each file’s SHA-256 hash to MalwareBazaar.

Mail with no strong text pattern, no active attachment, and no other risk stays **Safe**, at most 12, or 15 after the language-model guardrail.

## 3. Testing tiers

### Tier 1: Text layer, offline

No network. `pytest` in `backend/`.

- Urgency text, for example “Your account has been suspended, verify your password immediately,” with a harmless link and no authentication header. Expect Suspicious, 48–70, and `is_phishing` on the text layer. Not Malicious.
- Benign order, newsletter, and conversational text. Expect Safe, score at most 15, text layer not phishing.
- An HTML body whose only link is an `href`. The scorer must still extract that URL.

### Tier 2: Threat feeds, live

Run `python -m eval.live_vectors` from `backend/` while the scorer is listening on port 8000. This is not part of default `pytest`.

- Google Safe Browsing test pages for phishing, malware, and unwanted software. Expect Malicious, at least 90, provider `safebrowsing`.
- One URL taken at runtime from the current URLhaus recent feed. Expect Malicious, at least 90, provider `urlhaus`, when the feed still lists it.
- One SHA-256 taken at runtime from the MalwareBazaar recent feed. Expect a confirmed hash match. The sample itself is never downloaded.
- `https://github.com` and `https://example.com` inside benign text with passing authentication. Expect Safe and no feed match.

PhishTank stays off until a key exists.

### Tier 2b: Attachments, offline

No network. `pytest` in `backend/tests/test_attachments_content.py`.

- PDF with `/OpenAction` JavaScript. Expect Suspicious, band `attachment`, 60–80.
- PDF whose extracted text asks to verify a password. Expect Suspicious.
- `.xlsm` ZIP containing `vbaProject.bin`. Expect a macro finding.
- Windows executable bytes named `invoice.pdf`. Expect Suspicious, disguised executable.
- ZIP containing `invoice.exe`. Expect Suspicious.
- Extreme compression ZIP. Expect no crash.
- Plain PDF and plain `.xlsx`. Expect Safe.
- Mocked MalwareBazaar `ok` response. Expect Malicious, at least 90.

### Tier 3: Full metadata

Backend, automated by the same live runner and by `tests/test_header_vectors.py`:

- Passing SPF, DKIM, and DMARC, benign text, `https://github.com`. Expect Safe, 0–15.
- Failing SPF, a brand display name, and a lookalike login link. Expect Malicious, 85–100.
- Passing authentication, a credential request, and a lookalike link. Expect Suspicious, 60–80.

Gmail sidebar, manual. Composing a message in Gmail does not let you attach a fake `Authentication-Results` header, so the SPF-fail case is verified through the API. In the inbox:

1. Confirm the Apps Script property `BACKEND_URL` is the current ngrok URL with no trailing slash.
2. Send yourself the benign GitHub note. Open it and expect Safe, 0–15.
3. Send yourself the credential lookalike note. Open it and expect Suspicious, 60–80.
4. Send yourself a short note that contains `https://testsafebrowsing.appspot.com/s/phishing.html`. Open it and expect Malicious, at least 90.
5. Time the wait from opening the sidebar to the score. The target is under 2.5 seconds. Record the number; do not drop Claude to force it.

The message bodies are in `backend/eval/vectors.py`.

## 4. Metrics

A malicious vector is a false negative when the verdict is Safe. A benign vector is a false positive when the verdict is Malicious. Suspicious is a catch for a malicious vector and is not a false positive on a benign vector.

| Metric | Target |
| --- | --- |
| False negative rate | under 15% on the active vectors |
| False positive rate | 0% Malicious verdicts on benign vectors |
| Accuracy | over 85% |
| Sidebar latency | under 2.5 seconds from open to score |

The live runner also records local pipeline time with Claude and the threat feeds skipped, separate from the full request time.

## 5. How to run

1. Start the API from `backend/` with the URLhaus and Safe Browsing keys loaded: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
2. Keep the ngrok tunnel pointed at port 8000 and set that URL as `BACKEND_URL`.
3. Offline suite: `python -m pytest` in `backend/`.
4. Live suite: `python -m eval.live_vectors` in `backend/`. Results are written to `backend/eval/live_results.json`.
