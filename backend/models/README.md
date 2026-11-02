The Cloud Run image exports a DistilBERT phishing classifier into `phishing-onnx/` at build time (`model.onnx`, `tokenizer.json`, `config.json`). Those files are not committed.

Locally, either run `python scripts/export_onnx_classifier.py --out models/phishing-onnx` from `backend/` after installing torch + transformers, or leave the folder empty and the scorer falls back to lexical wording checks.
