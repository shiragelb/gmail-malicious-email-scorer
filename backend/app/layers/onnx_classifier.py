"""Optional ONNX phishing classifier. Missing files or timeouts fall back to lexical scoring."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path

from app.budget import ledger
from app.config import get_settings

logger = logging.getLogger(__name__)

_session_cache: dict[str, object] = {}
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="onnx")


def onnx_probability(text: str) -> float | None:
    settings = get_settings()
    if not settings.use_onnx_classifier or not text:
        return None
    book = ledger()
    if book.optional_paused:
        return None
    cost = max(0.0, settings.onnx_usd_per_call)
    if not book.reserve("onnx", cost):
        return None
    try:
        session = _load_session(settings.onnx_model_dir)
        if session is None:
            if cost:
                book.release(cost)
            return None
        timeout_s = max(0.05, settings.onnx_inference_timeout_ms / 1000.0)
        future = _executor.submit(_infer_probability, session, settings.onnx_model_dir, text)
        return future.result(timeout=timeout_s)
    except FuturesTimeoutError:
        logger.info("ONNX inference exceeded %sms", settings.onnx_inference_timeout_ms)
        if cost:
            book.release(cost)
        return None
    except Exception as exc:
        logger.info("ONNX classification failed: %s", type(exc).__name__)
        if cost:
            book.release(cost)
        return None


def _load_session(model_dir: str):
    path = Path(model_dir or "")
    model_file = path / "model.onnx"
    if not model_file.is_file():
        logger.info("USE_ONNX_CLASSIFIER is set but %s is missing.", model_file)
        return None
    cached = _session_cache.get(str(model_file))
    if cached is not None:
        return cached
    try:
        import onnxruntime
    except ImportError:
        logger.info("USE_ONNX_CLASSIFIER is set but onnxruntime is not installed.")
        return None
    session = onnxruntime.InferenceSession(str(model_file), providers=["CPUExecutionProvider"])
    _session_cache[str(model_file)] = session
    return session


def _infer_probability(session, model_dir: str, text: str) -> float | None:
    import numpy as np

    input_ids, attention_mask = _tokenize(model_dir, text)
    feeds = {}
    for item in session.get_inputs():
        name = item.name.lower()
        if "mask" in name:
            feeds[item.name] = attention_mask
        else:
            feeds[item.name] = input_ids
    outputs = session.run(None, feeds)
    logits = np.asarray(outputs[0]).reshape(-1)
    label, score = _label_and_score(model_dir, logits)
    return _as_phishing_probability(label, score)


def _tokenize(model_dir: str, text: str) -> tuple:
    import numpy as np

    clipped = (text or "")[:512]
    tokenizer_file = Path(model_dir) / "tokenizer.json"
    if tokenizer_file.is_file():
        from tokenizers import Tokenizer

        tokenizer = Tokenizer.from_file(str(tokenizer_file))
        encoded = tokenizer.encode(clipped)
        ids = list(encoded.ids[:128])
        mask = list(encoded.attention_mask[:128]) if encoded.attention_mask else [1] * len(ids)
        return (
            np.asarray([ids], dtype=np.int64),
            np.asarray([mask], dtype=np.int64),
        )
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    batch = tokenizer(clipped, return_tensors="np", truncation=True, max_length=128)
    return batch["input_ids"], batch["attention_mask"]


def _label_and_score(model_dir: str, logits) -> tuple[str, float]:
    import numpy as np

    values = np.asarray(logits, dtype=float).reshape(-1)
    if values.size == 0:
        return "", 0.0
    if values.size == 1:
        score = float(1.0 / (1.0 + np.exp(-values[0])))
        return "phishing" if score >= 0.5 else "benign", max(score, 1.0 - score)
    shifted = values - np.max(values)
    exp = np.exp(shifted)
    probs = exp / np.sum(exp)
    index = int(np.argmax(probs))
    labels = _id2label(model_dir, values.size)
    return labels.get(index, str(index)), float(probs[index])


def _id2label(model_dir: str, size: int) -> dict[int, str]:
    config_path = Path(model_dir) / "config.json"
    if config_path.is_file():
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            raw = payload.get("id2label") or {}
            return {int(key): str(value) for key, value in raw.items()}
        except (OSError, ValueError, TypeError):
            pass
    if size == 2:
        return {0: "benign", 1: "phishing"}
    return {index: str(index) for index in range(size)}


def _as_phishing_probability(label: str, score: float) -> float | None:
    token = (label or "").lower()
    if any(part in token for part in ("phish", "spam", "malicious")) or token in {"label_1", "1"}:
        return float(score)
    if any(part in token for part in ("ham", "legit", "benign", "safe")) or token in {"label_0", "0"}:
        return float(1.0 - score)
    return None
