from __future__ import annotations
import argparse, base64, csv, hashlib
import html, io, re, os, sys, time, uuid
import json, math, random, queue, shlex, logging
import signal, sqlite3, string, textwrap, threading
import traceback, unicodedata, webbrowser
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import (
    Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional,
    Protocol, Sequence, Tuple, TypeVar, Union,
)
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.cluster import MiniBatchKMeans
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import (
    ExtraTreesClassifier, GradientBoostingClassifier,
    HistGradientBoostingClassifier, RandomForestClassifier,
    StackingClassifier, VotingClassifier,
)
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.inspection import permutation_importance
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    accuracy_score, average_precision_score, balanced_accuracy_score,
    brier_score_loss, confusion_matrix, f1_score, log_loss,
    matthews_corrcoef, precision_recall_curve, precision_score,
    recall_score, roc_auc_score, roc_curve,
)
from sklearn.model_selection import (
    StratifiedKFold, cross_val_predict, cross_val_score, train_test_split,
)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
try:
    import joblib
    _HAS_JOBLIB = True
except Exception:
    _HAS_JOBLIB = False
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog, ttk
    _HAS_TK = True
except Exception:
    _HAS_TK = False

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.fromtimestamp(
                record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, Mapping):
            payload.update({k: v for k, v in extra.items()
                            if k not in payload})
        return json.dumps(payload, ensure_ascii=False, default=str)

def _setup_logging(path: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger("phishing")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(sh)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(path, encoding="utf-8")
            fh.setFormatter(_JsonFormatter())
            logger.addHandler(fh)
        except Exception:
            pass
    return logger
APP_DIR = Path.home() / ".phish_detector"
APP_DIR.mkdir(parents=True, exist_ok=True)
LOG = _setup_logging(APP_DIR / "events.jsonl")
FEATURES: Tuple[str, ...] = (
    "url_length", "dots", "hyphens", "digits", "slashes",
    "question_marks", "equals_signs", "ampersands", "percents",
    "path_length", "query_length", "has_at", "has_ip",
    "double_slash", "punycode", "hex_encoding",
    "subdomains", "domain_length", "suspicious_tld", "digit_ratio",
    "hyphen_ratio", "https", "ssl_hint",
    "brand_in_subdomain", "url_entropy", "params",
    "max_token", "tld_length", "port", "path_depth",
    "homoglyph", "unicode_mix", "scheme_risk",
    "brand_distance", "double_extension",
    "key_entropy", "path_tokens", "authority_length",
    "encoded_redirect", "max_digit_run",
    "subdomain_entropy", "path_entropy", "query_entropy",
    "jaro_winkler_brand", "ip_in_hex", "contains_port_8080",
    "too_many_dots", "ends_with_zip",
    "exclamation_marks", "consecutive_question_marks",
)

CONTINUOUS_FEATURES: Tuple[str, ...] = (
    "url_length", "dots", "hyphens", "digits", "slashes",
    "question_marks", "equals_signs", "ampersands", "percents",
    "path_length", "query_length", "subdomains", "domain_length",
    "digit_ratio", "hyphen_ratio", "url_entropy", "params",
    "max_token", "tld_length", "path_depth", "unicode_mix",
    "scheme_risk", "brand_distance", "key_entropy",
    "path_tokens", "authority_length", "max_digit_run",
    "subdomain_entropy", "path_entropy", "query_entropy",
    "jaro_winkler_brand",
)

BINARY_FEATURES: Tuple[str, ...] = tuple(
    f for f in FEATURES if f not in CONTINUOUS_FEATURES
)

SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "loan", "download", "racing", "win", "bid", "review", "country",
    "stream", "accountant", "science", "party", "gdn", "zip", "mov",
    "casa", "rest", "cyou", "sbs", "buzz", "monster", "quest", "lol",
    "icu", "vip", "cam", "surf", "bar", "beauty", "makeup", "skin",
    "fit", "cfd", "sarl", "hair", "mom", "lifestyle",
})

BRANDS = frozenset({
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "instagram", "netflix", "linkedin", "twitter", "dropbox", "dhl",
    "fedex", "ups", "usps", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "santander", "binance", "coinbase", "metamask",
    "steam", "roblox", "discord", "whatsapp", "telegram", "outlook",
    "office365", "icloud", "adobe", "spotify", "github", "gitlab",
    "stripe", "square", "venmo", "zelle", "revolut", "klarna",
    "sberbank", "tinkoff", "vtb", "alfabank", "gazprombank",
    "yandex", "mailru", "vk", "ok", "gosuslugi", "mos",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "t.ly", "shorte.st", "adf.ly", "bl.ink", "s.id", "v.gd",
    "clck.ru", "vk.cc", "u.to", "qps.ru",
})

SUSPICIOUS_WORDS = frozenset({
    "login", "signin", "verify", "secure", "update", "account",
    "confirm", "recover", "unlock", "billing", "invoice", "password",
    "credential", "wallet", "seed", "backup", "auth", "session",
    "kyc", "2fa", "otp", "webscr", "cmd", "dispatch", "tracking",
    "вход", "войти", "подтвердить", "восстановить", "пароль", "счет",
    "оплата", "перевод", "банк", "госуслуги", "сбербанк",
})

_HOMOGLYPH_MAP: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ь": "b", "п": "n",
    "ν": "v", "ρ": "p", "τ": "t", "ο": "o", "ι": "i", "κ": "k", "μ": "u",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
}
_URL_SAFE_CHARS = set(string.ascii_letters + string.digits + "-._~:/?#[]@!$&'()*+,;=%")
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_HEX_SEQ_RE = re.compile(r"(%[0-9A-Fa-f]{2}){3,}")
_HEX_BLOB_RE = re.compile(r"\b[0-9A-Fa-f]{16,}\b")
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9\u0400-\u04FF]+")
_DIGIT_RUN_RE = re.compile(r"\d+")
_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip|exe)\.(html?|php|asp|jsp)$",
    re.IGNORECASE,
)
_REDIRECT_RE = re.compile(
    r"(url|redirect|next|return|continue|goto|target)\s*=", re.IGNORECASE,
)

def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def _ratio(n: float, d: float) -> float:
    return float(n) / float(d) if d else 0.0

def _validate_ipv4(host: str) -> bool:
    m = _IPV4_RE.match(host)
    if not m:
        return False
    for g in m.groups():
        if len(g) > 1 and g[0] == "0":
            return False
        if not (0 <= int(g) <= 255):
            return False
    return True

@lru_cache(maxsize=16384)
def _entropy_cache(s: str) -> float:
    return _shannon(s)

def _unicode_mix(s: str) -> float:
    if not s:
        return 0.0
    non_ascii = sum(1 for ch in s if ord(ch) > 127)
    return non_ascii / len(s)

def _has_homoglyph(s: str) -> int:
    return int(any(ch in _HOMOGLYPH_MAP for ch in s))

def _scheme_risk(scheme: str) -> float:
    s = (scheme or "").lower()
    if s in ("http", ""):
        return 1.0
    if s == "https":
        return 0.0
    if s in ("ftp", "file", "data", "javascript"):
        return 1.0
    return 0.5

def _levenshtein(a: str, b: str, cap: int = 4) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            row_min = min(row_min, cur[j])
        if row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]

def _jaro_winkler(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    len_a, len_b = len(a), len(b)
    match_dist = max(len_a, len_b) // 2 - 1
    match_dist = max(0, match_dist)
    a_matches = [False] * len_a
    b_matches = [False] * len_b
    matches = 0
    for i in range(len_a):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len_b)
        for j in range(start, end):
            if b_matches[j] or a[i] != b[j]:
                continue
            a_matches[i] = b_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    t = 0
    k = 0
    for i in range(len_a):
        if not a_matches[i]:
            continue
        while not b_matches[k]:
            k += 1
        if a[i] != b[k]:
            t += 1
        k += 1
    t //= 2
    jaro = (matches / len_a + matches / len_b + (matches - t) / matches) / 3
    prefix = 0
    for i in range(min(4, len_a, len_b)):
        if a[i] == b[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1 - jaro)

def _min_distance_to_brand(host_labels: Sequence[str]) -> Tuple[float, float]:
    best_d = 99.0
    best_jw = 0.0
    for lbl in host_labels:
        if len(lbl) < 3:
            continue
        for brand in BRANDS:
            if abs(len(lbl) - len(brand)) > 3:
                continue
            d = _levenshtein(lbl, brand, cap=3)
            if d < best_d:
                best_d = d
            jw = _jaro_winkler(lbl, brand)
            if jw > best_jw:
                best_jw = jw
            if best_d == 0:
                return 0.0, 1.0
    return (float(best_d if best_d < 99 else 99), float(best_jw))

def _key_entropy(query: str) -> float:
    if not query:
        return 0.0
    keys = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    if not keys:
        return 0.0
    return _shannon("".join(keys))

def _max_digit_run(s: str) -> int:
    return max((len(m.group()) for m in _DIGIT_RUN_RE.finditer(s)),
               default=0)

def _safe_decode_punycode(host: str) -> str:
    if "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        try:
            parts = []
            for label in host.split("."):
                if label.startswith("xn--"):
                    parts.append(label.encode("ascii").decode("idna"))
                else:
                    parts.append(label)
            return ".".join(parts)
        except Exception:
            return host

def _normalize_unicode(s: str) -> str:
    try:
        s = unicodedata.normalize("NFKC", s)
        s = unicodedata.normalize("NFC", s)
    except Exception:
        pass
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in "\t\n\r":
            continue
        out.append(ch)
    return "".join(out)

def _safe_get(d: Mapping[str, Any], k: str, default: Any = 0) -> Any:
    try:
        v = d.get(k, default)
        return default if v is None else v
    except Exception:
        return default

@dataclass(slots=True)
class ParsedURL:
    raw: str
    features: Dict[str, float] = field(default_factory=dict)
    flags: Dict[str, Any] = field(default_factory=dict)
    tokens: List[Tuple[str, str, float]] = field(default_factory=list)
    error: Optional[str] = None

def parse_url(raw: str) -> ParsedURL:
    parsed = ParsedURL(raw=(raw or "").strip())
    if not parsed.raw:
        parsed.error = "empty url"
        return parsed
    text = _normalize_unicode(parsed.raw)
    if len(text) > 8192:
        parsed.error = "url too long (max 8192)"
        return parsed
    if "://" not in text:
        for_parse = "http://" + text
        implicit_scheme = True
    else:
        for_parse = text
        implicit_scheme = False
    try:
        u = urlparse(for_parse)
    except Exception as exc:
        parsed.error = f"could not parse url: {exc}"
        return parsed
    host = (u.hostname or "").lower()
    path = u.path or ""
    query = u.query or ""
    full = for_parse
    try:
        port = u.port
    except ValueError:
        port = None
    num_dots = full.count(".")
    num_hyphens = full.count("-")
    num_digits = sum(ch.isdigit() for ch in full)
    num_slashes = full.count("/")
    num_q = full.count("?")
    num_eq = full.count("=")
    num_amp = full.count("&")
    num_pct = full.count("%")
    has_at = int("@" in full)
    is_ip = int(_validate_ipv4(host)) if host else 0
    double_slash = int("//" in path or "//" in query)
    punycode = int(host.startswith("xn--") or ".xn--" in host)
    hex_encoding = int(
        bool(_HEX_SEQ_RE.search(full)) or bool(_HEX_BLOB_RE.search(full))
    )
    labels = [l for l in host.split(".") if l]
    num_subdomains = max(0, len(labels) - 2) if len(labels) >= 2 else 0
    domain_length = len(host)
    tld = ""
    if len(labels) >= 2 and not labels[-1].isdigit():
        candidate = labels[-1]
        if re.fullmatch(r"[a-z\u0400-\u04FF]{2,24}", candidate) or \
           candidate.startswith("xn--"):
            tld = candidate
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)
    url_len = max(1, len(full))
    digit_ratio = _ratio(num_digits, url_len)
    hyphen_ratio = _ratio(num_hyphens, url_len)
    scheme = u.scheme.lower()
    uses_https = int(scheme == "https")
    has_ssl_hint = int(uses_https and suspicious_tld == 0)
    brand_in_sub = 0
    sub_labels = labels[:-2] if len(labels) > 2 else []
    for lbl in sub_labels:
        if any(b in lbl for b in BRANDS):
            brand_in_sub = 1
            break
    if not brand_in_sub and len(labels) >= 2:
        registrable = "-".join(labels[-2:])
        if any(b in registrable for b in BRANDS) and num_hyphens > 0:
            brand_in_sub = 1
    entropy = _entropy_cache(full)
    path_tokens = [t for t in _TOKEN_SPLIT_RE.split(path) if t]
    longest_token = max((len(t) for t in path_tokens), default=0)
    path_depth = len([p for p in path.split("/") if p])
    params = parse_qsl(query, keep_blank_values=True) if query else []
    homoglyph = _has_homoglyph(full)
    unicode_mix = _unicode_mix(full)
    scheme_risk = _scheme_risk(scheme)
    brand_dist, brand_jw = _min_distance_to_brand(labels) if labels else (99.0, 0.0)
    double_ext = int(bool(_DOUBLE_EXT_RE.search(path)))
    qkey_entropy = _key_entropy(query)
    path_token_count = len(path_tokens)
    authority_len = len(host) + (6 if port else 0)
    has_enc_redirect = int(
        bool(_REDIRECT_RE.search(query)) or
        bool(re.search(r"%2f%2f", full, re.IGNORECASE))
    )
    digit_run = _max_digit_run(full)
    sub_entropy = _entropy_cache(".".join(sub_labels)) if sub_labels else 0.0
    path_entropy = _entropy_cache(path)
    query_entropy = _entropy_cache(query)
    ip_hex = int(bool(re.search(r"0x[0-9a-f]{8}", full, re.IGNORECASE)))
    port_8080 = int(port == 8080)
    too_many_dots = int(num_dots >= 5)
    ends_zip = int(path.lower().endswith(".zip"))
    exclaims = full.count("!")
    q_marks_run = int(bool(re.search(r"\?\?", full)))
    parsed.features = {
        "url_length": url_len,
        "dots": num_dots,
        "hyphens": num_hyphens,
        "digits": num_digits,
        "slashes": num_slashes,
        "question_marks": num_q,
        "equals_signs": num_eq,
        "ampersands": num_amp,
        "percents": num_pct,
        "path_length": len(path),
        "query_length": len(query),
        "has_at": has_at,
        "has_ip": is_ip,
        "double_slash": double_slash,
        "punycode": punycode,
        "hex_encoding": hex_encoding,
        "subdomains": num_subdomains,
        "domain_length": domain_length,
        "suspicious_tld": suspicious_tld,
        "digit_ratio": digit_ratio,
        "hyphen_ratio": hyphen_ratio,
        "https": uses_https,
        "ssl_hint": has_ssl_hint,
        "brand_in_subdomain": brand_in_sub,
        "url_entropy": entropy,
        "params": len(params),
        "max_token": longest_token,
        "tld_length": len(tld),
        "port": int(port is not None and port not in (80, 443)),
        "path_depth": path_depth,
        "homoglyph": homoglyph,
        "unicode_mix": unicode_mix,
        "scheme_risk": scheme_risk,
        "brand_distance": brand_dist,
        "double_extension": double_ext,
        "key_entropy": qkey_entropy,
        "path_tokens": path_token_count,
        "authority_length": authority_len,
        "encoded_redirect": has_enc_redirect,
        "max_digit_run": digit_run,
        "subdomain_entropy": sub_entropy,
        "path_entropy": path_entropy,
        "query_entropy": query_entropy,
        "jaro_winkler_brand": brand_jw,
        "ip_in_hex": ip_hex,
        "contains_port_8080": port_8080,
        "too_many_dots": too_many_dots,
        "ends_with_zip": ends_zip,
        "exclamation_marks": exclaims,
        "consecutive_question_marks": q_marks_run,
    }
    parsed.flags = {
        "scheme": u.scheme or ("http" if implicit_scheme else "(none)"),
        "implicit_scheme": implicit_scheme,
        "host": host,
        "port": port,
        "tld": tld,
        "ip_host": bool(is_ip),
        "shortener": host in URL_SHORTENERS,
        "brands": sorted({b for b in BRANDS if b in full.lower()}),
        "suspicious_words": sorted({
            k for k in SUSPICIOUS_WORDS
            if k in path.lower() or k in query.lower()
        }),
        "path": path,
        "query": query,
        "punycode_decoded": _safe_decode_punycode(host),
    }
    parsed.tokens = _tokenize(for_parse, labels, tld)
    return parsed

def _tokenize(full: str, labels: List[str], tld: str
                         ) -> List[Tuple[str, str, float]]:
    out: List[Tuple[str, str, float]] = []
    scheme = full.split("://", 1)[0] + "://"
    rest = full[len(scheme):] if "://" in full else full
    out.append(("scheme", scheme, 0.0))
    split_idx = len(rest)
    for i, ch in enumerate(rest):
        if ch in "/?#":
            split_idx = i
            break
    tail = rest[split_idx:]
    for lbl in labels:
        if lbl in BRANDS:
            out.append(("brand", lbl, 0.7))
        elif lbl == tld and tld in SUSPICIOUS_TLDS:
            out.append(("risky_tld", lbl, 0.6))
        elif lbl.startswith("xn--"):
            out.append(("punycode", lbl, 0.7))
        elif _has_homoglyph(lbl):
            out.append(("homoglyph", lbl, 0.8))
        elif lbl.isdigit():
            out.append(("digits", lbl, 0.3))
        else:
            out.append(("host", lbl, 0.1))
        out.append(("sep", ".", 0.0))
    if out and out[-1][0] == "sep":
        out.pop()
    if tail:
        for tok in re.split(r"([/?#&=])", tail):
            if not tok:
                continue
            low = tok.lower()
            if tok in "/?#&=":
                out.append(("sep", tok, 0.0))
            elif low in SUSPICIOUS_WORDS:
                out.append(("word", tok, 0.5))
            elif re.fullmatch(r"[0-9A-Fa-f]{12,}", tok):
                out.append(("hex", tok, 0.5))
            else:
                out.append(("path", tok, 0.1))
    return out

def _generate_benign(n: int, rng: np.random.Generator) -> pd.DataFrame:
    d = {
        "url_length": rng.integers(18, 65, n),
        "dots": rng.integers(1, 4, n),
        "hyphens": rng.integers(0, 3, n),
        "digits": rng.integers(0, 4, n),
        "slashes": rng.integers(2, 5, n),
        "question_marks": rng.integers(0, 2, n),
        "equals_signs": rng.integers(0, 3, n),
        "ampersands": rng.integers(0, 2, n),
        "percents": rng.integers(0, 2, n),
        "path_length": rng.integers(0, 30, n),
        "query_length": rng.integers(0, 25, n),
        "has_at": rng.choice([0, 1], n, p=[0.995, 0.005]),
        "has_ip": rng.choice([0, 1], n, p=[0.998, 0.002]),
        "double_slash": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "punycode": rng.choice([0, 1], n, p=[0.995, 0.005]),
        "hex_encoding": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "subdomains": rng.integers(0, 3, n),
        "domain_length": rng.integers(6, 22, n),
        "suspicious_tld": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "digit_ratio": rng.uniform(0.0, 0.10, n),
        "hyphen_ratio": rng.uniform(0.0, 0.05, n),
        "https": rng.choice([0, 1], n, p=[0.05, 0.95]),
        "ssl_hint": rng.choice([0, 1], n, p=[0.03, 0.97]),
        "brand_in_subdomain": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "url_entropy": rng.normal(3.6, 0.35, n).clip(2.5, 4.5),
        "params": rng.integers(0, 4, n),
        "max_token": rng.integers(3, 14, n),
        "tld_length": rng.choice([2, 3, 4], n, p=[0.4, 0.5, 0.1]),
        "port": rng.choice([0, 1], n, p=[0.995, 0.005]),
        "path_depth": rng.integers(0, 4, n),
        "homoglyph": rng.choice([0, 1], n, p=[0.999, 0.001]),
        "unicode_mix": rng.uniform(0.0, 0.005, n),
        "scheme_risk": rng.choice([0.0, 1.0], n, p=[0.95, 0.05]),
        "brand_distance": rng.integers(5, 12, n).astype(float),
        "double_extension": rng.choice([0, 1], n, p=[0.999, 0.001]),
        "key_entropy": rng.uniform(0.0, 1.8, n),
        "path_tokens": rng.integers(0, 5, n),
        "authority_length": rng.integers(8, 26, n),
        "encoded_redirect": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "max_digit_run": rng.integers(0, 3, n),
        "subdomain_entropy": rng.normal(2.0, 0.5, n).clip(0, 4),
        "path_entropy": rng.normal(2.5, 0.6, n).clip(0, 4.5),
        "query_entropy": rng.normal(1.5, 0.5, n).clip(0, 4),
        "jaro_winkler_brand": rng.uniform(0.0, 0.4, n),
        "ip_in_hex": rng.choice([0, 1], n, p=[0.999, 0.001]),
        "contains_port_8080": rng.choice([0, 1], n, p=[0.998, 0.002]),
        "too_many_dots": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "ends_with_zip": rng.choice([0, 1], n, p=[0.999, 0.001]),
        "exclamation_marks": rng.integers(0, 2, n),
        "consecutive_question_marks": rng.choice([0, 1], n, p=[0.98, 0.02]),
        "label": 0,
    }
    return pd.DataFrame(d)

def _generate_phishing(n: int, rng: np.random.Generator) -> pd.DataFrame:
    d = {
        "url_length": rng.integers(45, 180, n),
        "dots": rng.integers(2, 7, n),
        "hyphens": rng.integers(1, 6, n),
        "digits": rng.integers(1, 9, n),
        "slashes": rng.integers(3, 9, n),
        "question_marks": rng.integers(0, 4, n),
        "equals_signs": rng.integers(0, 5, n),
        "ampersands": rng.integers(0, 4, n),
        "percents": rng.integers(0, 5, n),
        "path_length": rng.integers(15, 90, n),
        "query_length": rng.integers(10, 80, n),
        "has_at": rng.choice([0, 1], n, p=[0.55, 0.45]),
        "has_ip": rng.choice([0, 1], n, p=[0.60, 0.40]),
        "double_slash": rng.choice([0, 1], n, p=[0.55, 0.45]),
        "punycode": rng.choice([0, 1], n, p=[0.80, 0.20]),
        "hex_encoding": rng.choice([0, 1], n, p=[0.55, 0.45]),
        "subdomains": rng.integers(1, 6, n),
        "domain_length": rng.integers(10, 44, n),
        "suspicious_tld": rng.choice([0, 1], n, p=[0.25, 0.75]),
        "digit_ratio": rng.uniform(0.05, 0.35, n),
        "hyphen_ratio": rng.uniform(0.02, 0.20, n),
        "https": rng.choice([0, 1], n, p=[0.45, 0.55]),
        "ssl_hint": rng.choice([0, 1], n, p=[0.60, 0.40]),
        "brand_in_subdomain": rng.choice([0, 1], n, p=[0.35, 0.65]),
        "url_entropy": rng.normal(4.1, 0.45, n).clip(2.5, 5.5),
        "params": rng.integers(1, 8, n),
        "max_token": rng.integers(8, 34, n),
        "tld_length": rng.choice([2, 3, 4, 5], n, p=[0.3, 0.4, 0.2, 0.1]),
        "port": rng.choice([0, 1], n, p=[0.85, 0.15]),
        "path_depth": rng.integers(2, 8, n),
        "homoglyph": rng.choice([0, 1], n, p=[0.75, 0.25]),
        "unicode_mix": rng.uniform(0.0, 0.15, n),
        "scheme_risk": rng.choice([0.0, 1.0], n, p=[0.45, 0.55]),
        "brand_distance": rng.integers(0, 4, n).astype(float),
        "double_extension": rng.choice([0, 1], n, p=[0.85, 0.15]),
        "key_entropy": rng.uniform(0.5, 3.5, n),
        "path_tokens": rng.integers(2, 10, n),
        "authority_length": rng.integers(12, 50, n),
        "encoded_redirect": rng.choice([0, 1], n, p=[0.55, 0.45]),
        "max_digit_run": rng.integers(0, 8, n),
        "subdomain_entropy": rng.normal(3.0, 0.7, n).clip(0, 5),
        "path_entropy": rng.normal(3.5, 0.8, n).clip(0, 5.5),
        "query_entropy": rng.normal(3.0, 0.8, n).clip(0, 5.5),
        "jaro_winkler_brand": rng.uniform(0.5, 0.95, n),
        "ip_in_hex": rng.choice([0, 1], n, p=[0.85, 0.15]),
        "contains_port_8080": rng.choice([0, 1], n, p=[0.9, 0.1]),
        "too_many_dots": rng.choice([0, 1], n, p=[0.4, 0.6]),
        "ends_with_zip": rng.choice([0, 1], n, p=[0.9, 0.1]),
        "exclamation_marks": rng.integers(0, 4, n),
        "consecutive_question_marks": rng.choice([0, 1], n, p=[0.6, 0.4]),
        "label": 1,
    }
    return pd.DataFrame(d)

def generate_dataset(cfg: "Config") -> pd.DataFrame:
    rng = np.random.default_rng(cfg.random_state)
    benign = _generate_benign(cfg.n_per_class, rng)
    phishing = _generate_phishing(cfg.n_per_class, rng)
    df = pd.concat([benign, phishing], ignore_index=True)
    noise_idx = rng.choice(df.index, size=int(0.02 * len(df)), replace=False)
    df.loc[noise_idx, "label"] = 1 - df.loc[noise_idx, "label"]
    return df.sample(frac=1.0, random_state=cfg.random_state).reset_index(drop=True)

@dataclass(slots=True)
class Config:
    random_state: int = 42
    n_per_class: int = 1500
    test_size: float = 0.20
    cv_folds: int = 5
    n_estimators: int = 300
    max_depth: Optional[int] = 16
    min_samples_leaf: int = 2
    use_calibration: bool = True
    calibration_method: str = "sigmoid"
    model_type: str = "stack"
    cost_fn: float = 10.0
    cost_fp: float = 1.0
    decision_threshold: Optional[float] = None
    bootstrap_iters: int = 400
    permutation_repeats: int = 5
    adversarial_probe: bool = True
    adversarial_mutations: int = 25
    threads: int = 0
    use_ngram_embeddings: bool = True
    ngram_dim: int = 256
    use_online_learning: bool = True
    conformal_alpha: float = 0.10
    drift_psi_warn: float = 0.10
    drift_psi_alert: float = 0.25
    schema_version: int = 3
    cache_size: int = 2048
    webhook_url: Optional[str] = None
    enable_stix_export: bool = True
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)
    @classmethod
    def from_json(cls, s: str) -> "Config":
        raw = json.loads(s)
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(raw) - known
        if unknown:
            LOG.warning("Config: ignoring unknown keys: %s", sorted(unknown))
        return cls(**{k: v for k, v in raw.items() if k in known})
    def hash(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

class NGramTransformer(BaseEstimator):
    def __init__(self, n_features: int = 256,
                 ngram_range: Tuple[int, int] = (2, 4)):
        self.n_features = n_features
        self.ngram_range = ngram_range
        self._vec: Optional[HashingVectorizer] = None
    def _get_vec(self) -> HashingVectorizer:
        if self._vec is None:
            self._vec = HashingVectorizer(
                n_features=self.n_features,
                ngram_range=self.ngram_range,
                analyzer="char_wb",
                alternate_sign=False,
                norm="l2",
                lowercase=True,
            )
        return self._vec
    def fit(self, X, y=None):
        return self
    def transform(self, X) -> np.ndarray:
        vec = self._get_vec()
        if hasattr(X, "columns") and "_url_raw" in X.columns:
            texts = X["_url_raw"].astype(str).tolist()
        elif hasattr(X, "iloc"):
            texts = X.iloc[:, -1].astype(str).tolist()
        else:
            texts = [str(x) for x in X]
        return vec.transform(texts).toarray()
    def get_feature_names_out(self, input_features=None):
        return np.array([f"ng_{i}" for i in range(self.n_features)],
                        dtype=object)
def build_preprocessor(feature_names: Sequence[str],
                          use_ngrams: bool = True,
                          ngram_dim: int = 256) -> ColumnTransformer:
    continuous = [c for c in CONTINUOUS_FEATURES if c in feature_names]
    passthrough = [c for c in feature_names if c not in continuous]
    transformers: List[Tuple[str, Any, Any]] = [
        ("scale", StandardScaler(), continuous),
        ("keep", "passthrough", passthrough),
    ]
    if use_ngrams:
        transformers.append(
            ("ng", NGramTransformer(n_features=ngram_dim), ["_url_raw"]))
    return ColumnTransformer(transformers=transformers, remainder="drop",
                             verbose_feature_names_out=False)
def build_base_estimator(cfg: Config, n_jobs: int = -1) -> BaseEstimator:
    rf = RandomForestClassifier(
        n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
        min_samples_leaf=cfg.min_samples_leaf, random_state=cfg.random_state,
        n_jobs=n_jobs, class_weight="balanced_subsample",
    )
    et = ExtraTreesClassifier(
        n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
        min_samples_leaf=cfg.min_samples_leaf, random_state=cfg.random_state,
        n_jobs=n_jobs, class_weight="balanced_subsample",
    )
    hgb = HistGradientBoostingClassifier(
        max_iter=400, learning_rate=0.06, random_state=cfg.random_state,
        early_stopping=True, validation_fraction=0.1,
    )
    mt = cfg.model_type.lower()
    if mt == "rf":
        return rf
    if mt == "extratrees":
        return et
    if mt == "hgb":
        return hgb
    if mt == "sgd":
        return SGDClassifier(
            loss="log_loss", penalty="elasticnet", alpha=1e-4,
            l1_ratio=0.15, max_iter=2000, random_state=cfg.random_state,
            class_weight="balanced", n_jobs=n_jobs,
        )
    if mt == "voting":
        return VotingClassifier(
            estimators=[
                ("rf", RandomForestClassifier(
                    n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
                    min_samples_leaf=cfg.min_samples_leaf,
                    random_state=cfg.random_state, n_jobs=1,
                    class_weight="balanced_subsample")),
                ("et", ExtraTreesClassifier(
                    n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
                    min_samples_leaf=cfg.min_samples_leaf,
                    random_state=cfg.random_state, n_jobs=1,
                    class_weight="balanced_subsample")),
                ("hgb", HistGradientBoostingClassifier(
                    max_iter=400, learning_rate=0.06,
                    random_state=cfg.random_state, early_stopping=True,
                    validation_fraction=0.1)),
            ],
            voting="soft", n_jobs=n_jobs,
        )
    return StackingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(
                n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
                min_samples_leaf=cfg.min_samples_leaf,
                random_state=cfg.random_state, n_jobs=1,
                class_weight="balanced_subsample")),
            ("et", ExtraTreesClassifier(
                n_estimators=cfg.n_estimators, max_depth=cfg.max_depth,
                min_samples_leaf=cfg.min_samples_leaf,
                random_state=cfg.random_state, n_jobs=1,
                class_weight="balanced_subsample")),
            ("hgb", HistGradientBoostingClassifier(
                max_iter=400, learning_rate=0.06,
                random_state=cfg.random_state, early_stopping=True,
                validation_fraction=0.1)),
        ],
        final_estimator=LogisticRegression(max_iter=1000, C=1.0),
        cv=StratifiedKFold(n_splits=3, shuffle=True,
                           random_state=cfg.random_state),
        stack_method="predict_proba", n_jobs=n_jobs,
    )
def _add_url_column(X: pd.DataFrame,
                           urls: Optional[Sequence[str]]) -> pd.DataFrame:
    X = X.copy()
    X["_url_raw"] = list(urls) if urls is not None else ""
    return X
def build_pipeline(cfg: Config,
                   use_ngrams: Optional[bool] = None) -> Pipeline:
    if use_ngrams is None:
        use_ngrams = cfg.use_ngram_embeddings
    return Pipeline([
        ("prep", build_preprocessor(
            FEATURES, use_ngrams, cfg.ngram_dim)),
        ("clf", build_base_estimator(cfg, n_jobs=-1)),
    ])
def wrap_with_calibration(pipeline: Pipeline, cfg: Config) -> BaseEstimator:
    method = cfg.calibration_method.lower()
    if method == "none" or not cfg.use_calibration:
        return pipeline
    if method == "auto":
        method = "sigmoid"
    return CalibratedClassifierCV(
        estimator=pipeline, method=method, cv=3, n_jobs=1,
    )

@dataclass(slots=True)
class ThresholdCandidates:
    f1: float
    cost: float
    youden: float
    balanced: float
    mcc: float
    def as_dict(self) -> Dict[str, float]:
        return asdict(self)

def scan_thresholds(y_true: np.ndarray, y_prob: np.ndarray,
                       cfg: Config) -> pd.DataFrame:
    rows: List[Dict[str, float]] = []
    grid = np.unique(np.concatenate([
        np.linspace(0.02, 0.98, 49),
        np.quantile(y_prob, np.linspace(0.01, 0.99, 33)),
    ]))
    for t in grid:
        preds = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(
            y_true, preds, labels=[0, 1]).ravel()
        tpr = tp / max(tp + fn, 1)
        fpr = fp / max(fp + tn, 1)
        rows.append({
            "threshold": round(float(t), 4),
            "accuracy": precision_score(y_true, preds, zero_division=0),
            "recall": recall_score(y_true, preds, zero_division=0),
            "f1": f1_score(y_true, preds, zero_division=0),
            "balanced_accuracy": balanced_accuracy_score(y_true, preds),
            "mcc": matthews_corrcoef(y_true, preds),
            "youden_j": tpr - fpr,
            "fp": int(fp), "fn": int(fn),
            "expected_cost": float(cfg.cost_fn * fn + cfg.cost_fp * fp),
        })
    return pd.DataFrame(rows)

def select_thresholds(df_scan: pd.DataFrame) -> ThresholdCandidates:
    return ThresholdCandidates(
        f1=float(df_scan.loc[df_scan["f1"].idxmax(), "threshold"]),
        cost=float(df_scan.loc[df_scan["expected_cost"].idxmin(), "threshold"]),
        youden=float(df_scan.loc[df_scan["youden_j"].idxmax(), "threshold"]),
        balanced=float(df_scan.loc[
            df_scan["balanced_accuracy"].idxmax(), "threshold"]),
        mcc=float(df_scan.loc[df_scan["mcc"].idxmax(), "threshold"]),
    )

def compute_metrics(y_true: np.ndarray, y_prob: np.ndarray,
                       threshold: float) -> Dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier": float(brier_score_loss(y_true, y_prob)),
        "log_loss": float(log_loss(y_true, y_prob, labels=[0, 1])),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }

def bootstrap_ci(y_true: np.ndarray, y_pred_or_prob: np.ndarray,
                 metric_fn: Callable[[np.ndarray, np.ndarray], float],
                 iters: int, rng: np.random.Generator,
                 alpha: float = 0.05) -> Tuple[float, float]:
    n = len(y_true)
    if n == 0 or iters <= 0:
        return (float("nan"), float("nan"))
    vals = np.empty(iters, dtype=float)
    for i in range(iters):
        idx = rng.integers(0, n, n)
        try:
            vals[i] = metric_fn(y_true[idx], y_pred_or_prob[idx])
        except Exception:
            vals[i] = float("nan")
    vals = vals[~np.isnan(vals)]
    if len(vals) < 2:
        return (float("nan"), float("nan"))
    return (float(np.quantile(vals, alpha / 2)),
            float(np.quantile(vals, 1 - alpha / 2)))

def metrics_with_ci(y_true: np.ndarray, y_prob: np.ndarray,
                  threshold: float, cfg: Config
                  ) -> Dict[str, Any]:
    m = compute_metrics(y_true, y_prob, threshold)
    rng = np.random.default_rng(cfg.random_state + 1)
    y_pred = (y_prob >= threshold).astype(int)
    specs: List[Tuple[str, str, Callable[[np.ndarray, np.ndarray], float]]] = [
        ("accuracy", "pred", lambda yt, yp: accuracy_score(yt, yp)),
        ("balanced_accuracy", "pred",
         lambda yt, yp: balanced_accuracy_score(yt, yp)),
        ("precision", "pred",
         lambda yt, yp: precision_score(yt, yp, zero_division=0)),
        ("recall", "pred",
         lambda yt, yp: recall_score(yt, yp, zero_division=0)),
        ("f1", "pred", lambda yt, yp: f1_score(yt, yp, zero_division=0)),
        ("mcc", "pred", lambda yt, yp: matthews_corrcoef(yt, yp)),
        ("roc_auc", "prob", lambda yt, pp: roc_auc_score(yt, pp)),
        ("pr_auc", "prob", lambda yt, pp: average_precision_score(yt, pp)),
    ]
    for name, kind, fn in specs:
        arr = y_prob if kind == "prob" else y_pred
        lo, hi = bootstrap_ci(y_true, arr, fn, cfg.bootstrap_iters, rng)
        m[f"{name}_lo"] = lo
        m[f"{name}_hi"] = hi
    return m

def cross_validation(model: BaseEstimator, X: pd.DataFrame, y: np.ndarray,
                     cfg: Config) -> Dict[str, float]:
    cv = StratifiedKFold(n_splits=cfg.cv_folds, shuffle=True,
                         random_state=cfg.random_state)
    scoring = {
        "accuracy": "accuracy", "balanced_accuracy": "balanced_accuracy",
        "precision": "precision", "recall": "recall", "f1": "f1",
        "roc_auc": "roc_auc", "pr_auc": "average_precision",
    }
    out: Dict[str, float] = {}
    for name, scorer in scoring.items():
        try:
            scores = cross_val_score(model, X, y, cv=cv, scoring=scorer,
                                     n_jobs=-1, error_score="raise")
            out[name] = float(scores.mean())
            out[f"{name}_std"] = float(scores.std())
        except Exception as exc:
            LOG.warning("CV %s failed: %s", name, exc)
            out[name] = float("nan")
            out[f"{name}_std"] = float("nan")
    return out

@dataclass(slots=True)
class ConformalCalibrator:
    alpha: float = 0.10
    q: float = 1.0
    n_calib: int = 0
    def fit(self, y_true: np.ndarray,
            y_prob_pos: np.ndarray) -> "ConformalCalibrator":
        p = np.clip(y_prob_pos, 1e-9, 1 - 1e-9)
        scores = np.where(y_true == 1, 1 - p, p)
        n = len(scores)
        if n == 0:
            self.q = 1.0
            self.n_calib = 0
            return self
        k = int(math.ceil((n + 1) * (1 - self.alpha)))
        k = min(max(k, 1), n)
        self.q = float(np.sort(scores)[k - 1])
        self.n_calib = n
        return self

    def predict_set(self, p_pos: float) -> Tuple[bool, bool, float]:
        p = float(np.clip(p_pos, 1e-9, 1 - 1e-9))
        s0 = p
        s1 = 1.0 - p
        return (s0 <= self.q, s1 <= self.q, s0)

    def to_dict(self) -> Dict[str, Any]:
        return {"alpha": self.alpha, "q": self.q, "n_calib": self.n_calib}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ConformalCalibrator":
        return cls(alpha=float(d.get("alpha", 0.10)),
                   q=float(d.get("q", 1.0)),
                   n_calib=int(d.get("n_calib", 0)))

def _tree_contribution(tree, x: np.ndarray
                   ) -> Tuple[Dict[int, float], float]:
    t = tree.tree_
    node = 0
    contrib: Dict[int, float] = {}
    def node_prob(n: int) -> float:
        w = t.weighted_n_node_samples[n]
        v = t.value[n]
        if v.ndim >= 2:
            return float(v[0, 1]) / max(w, 1e-9)
        return float(v) / max(w, 1e-9)
    base = node_prob(0)
    prev = base
    depth = 0
    max_depth = t.max_depth if hasattr(t, "max_depth") else 100
    while t.children_left[node] != -1 and depth < max_depth + 5:
        feat = int(t.feature[node])
        thresh = float(t.threshold[node])
        go_left = x[feat] <= thresh if 0 <= feat < len(x) else True
        child = int(t.children_left[node] if go_left
                    else t.children_right[node])
        cur = node_prob(child)
        delta = cur - prev
        w_child = t.weighted_n_node_samples[child]
        w_parent = t.weighted_n_node_samples[node]
        frac = float(w_child / w_parent) if w_parent > 0 else 0.0
        contrib[feat] = contrib.get(feat, 0.0) + delta * (0.5 + 0.5 * frac)
        prev = cur
        node = child
        depth += 1
    return contrib, base

def shap_contributions(estimator: BaseEstimator, x: np.ndarray,
                 feature_names: Sequence[str]
                 ) -> Tuple[Dict[str, float], float]:
    acc: Dict[str, float] = {}
    base_acc = 0.0
    count = 0
    def _collect(est: Any) -> None:
        nonlocal base_acc, count
        if est is None:
            return
        if hasattr(est, "estimators_") and hasattr(est, "classes_"):
            trees = est.estimators_
            if isinstance(trees, np.ndarray) and trees.ndim == 2:
                trees = trees[:, 0]
            for tree in trees:
                try:
                    contrib, base = _tree_contribution(tree, x)
                    for fi, v in contrib.items():
                        name = (feature_names[fi]
                                if 0 <= fi < len(feature_names)
                                else f"f{fi}")
                        acc[name] = acc.get(name, 0.0) + v
                    base_acc += base
                    count += 1
                except Exception:
                    continue
        elif hasattr(est, "estimators_"):
            for sub in est.estimators_:
                if isinstance(sub, tuple):
                    _collect(sub[1])
                else:
                    _collect(sub)
        elif hasattr(est, "calibrated_classifiers_"):
            for cc in est.calibrated_classifiers_:
                sub = (getattr(cc, "estimator", None) or
                       getattr(cc, "base_estimator", None))
                if sub is not None:
                    _collect(sub)
    _collect(estimator)
    if count == 0:
        return {}, 0.0
    base_value = base_acc / count
    avg = {k: v / count for k, v in acc.items()}
    return avg, base_value

class RiskCalibrator:
    def __init__(self) -> None:
        self.iso: Optional[IsotonicRegression] = None
    @staticmethod
    def _combine(prob: np.ndarray, reason_sum: np.ndarray,
                     rule_sum: np.ndarray) -> np.ndarray:
        return (0.6 * prob
                + 0.25 * np.tanh(reason_sum / 5.0)
                + 0.15 * np.tanh(rule_sum / 5.0))
    def fit(self, prob: np.ndarray, reason_sum: np.ndarray,
            rule_sum: np.ndarray, y_true: np.ndarray) -> "RiskCalibrator":
        z = self._combine(prob, reason_sum, rule_sum)
        self.iso = IsotonicRegression(out_of_bounds="clip",
                                       y_min=0.0, y_max=1.0)
        self.iso.fit(z, y_true.astype(float))
        return self
    def score(self, prob: float, reason_sum: float, rule_sum: float) -> int:
        z = float(self._combine(
            np.array([prob]), np.array([reason_sum]),
            np.array([rule_sum]))[0])
        if self.iso is None:
            return int(min(100, round(
                100 * (0.7 * prob + 0.3 * math.tanh(reason_sum / 5)))))
        p = float(self.iso.predict([z])[0])
        return int(min(100, max(0, round(p * 100))))

@dataclass(slots=True)
class Rule:
    name: str
    pattern: str
    severity: str
    weight: float
    kind: str = "contains"
    enabled: bool = True
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Rule":
        return cls(
            name=str(d["name"]), pattern=str(d["pattern"]),
            severity=str(d.get("severity", "medium")),
            weight=float(d.get("weight", 0.4)),
            kind=str(d.get("kind", "contains")),
            enabled=bool(d.get("enabled", True)),
        )

class RuleEngine:
    DEFAULT_RULES: Tuple[Rule, ...] = (
        Rule("shortener", "bit.ly", "medium", 0.5, "host_equals"),
        Rule("free_hosting",
                r"\.(000webhostapp|weebly|wixsite|godaddysites)\.",
                "medium", 0.4, "regex"),
        Rule("dodgy_tld",
                r"\.(tk|ml|ga|cf|gq|xyz|top|buzz)([/:?]|$)",
                "low", 0.3, "regex"),
        Rule("double_extension",
                r"\.(pdf|doc|docx|xls|xlsx|exe|zip)\.(html?|php|asp|jsp)",
                "high", 0.8, "regex"),
        Rule("many_subdomains", r"^([^.]+\.){4,}", "low", 0.3, "regex"),
        Rule("at_in_authority", r"://[^/]*@", "high", 0.9, "regex"),
        Rule("base64_block", r"[A-Za-z0-9+/]{40,}={0,2}",
                "medium", 0.5, "regex"),
        Rule("hex_ip", r"0x[0-9a-f]{8}", "high", 0.7, "regex"),
        Rule("octal_ip", r"://0\d{1,3}\.", "medium", 0.5, "regex"),
        Rule("data_uri", r"^data:", "medium", 0.4, "prefix"),
        Rule("javascript_uri", r"^javascript:", "high", 0.9, "prefix"),
        Rule("redirect_in_query",
                r"[?&](url|redirect|next|continue)=",
                "medium", 0.5, "regex"),
        Rule("russian_phishing",
                r"(госуслуги|сбербанк|тинькофф|втб).*(войти|пароль|вход)",
                "high", 0.8, "regex"),
    )

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        self.rules: List[Rule] = []
        self._lock = threading.RLock()
        if path is not None and path.exists():
            self.load()
        else:
            self.rules = list(self.DEFAULT_RULES)
            if path is not None:
                self.save()

    def load(self) -> None:
        with self._lock:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self.rules = [Rule.from_dict(r)
                              for r in raw.get("rules", [])]
                if not self.rules:
                    self.rules = list(self.DEFAULT_RULES)
            except Exception as exc:
                LOG.warning("Rule load failed: %s; using defaults", exc)
                self.rules = list(self.DEFAULT_RULES)

    def save(self) -> None:
        if self.path is None:
            return
        with self._lock:
            blob = {"rules": [r.to_dict() for r in self.rules]}
            try:
                self.path.write_text(
                    json.dumps(blob, indent=2, ensure_ascii=False),
                    encoding="utf-8")
            except Exception as exc:
                LOG.warning("Rules not saved: %s", exc)

    def add(self, rule: Rule) -> None:
        with self._lock:
            self.rules.append(rule)

    def evaluate(self, parsed: ParsedURL) -> List["Reason"]:
        out: List[Reason] = []
        raw = parsed.raw
        host = parsed.flags.get("host", "")
        tld = parsed.flags.get("tld", "")
        with self._lock:
            rules_snapshot = list(self.rules)
        for r in rules_snapshot:
            if not r.enabled:
                continue
            hit = False
            try:
                if r.kind == "contains":
                    hit = r.pattern.lower() in raw.lower()
                elif r.kind == "regex":
                    hit = bool(re.search(r.pattern, raw, re.IGNORECASE))
                elif r.kind == "host_equals":
                    hit = host == r.pattern
                elif r.kind == "tld":
                    hit = tld == r.pattern
                elif r.kind == "prefix":
                    hit = raw.lower().startswith(r.pattern.lower())
                elif r.kind == "suffix":
                    hit = raw.lower().endswith(r.pattern.lower())
            except re.error:
                continue
            if hit:
                out.append(Reason(f"rule: {r.name}", r.severity,
                                    r.weight, source="rule"))
        return out

_HOMOGLYPH_REVERSE: Dict[str, str] = {v: k for k, v in _HOMOGLYPH_MAP.items()}
def _mutate_homoglyph(url: str, rng: random.Random) -> str:
    out = []
    for ch in url:
        if ch in _HOMOGLYPH_REVERSE and rng.random() < 0.5:
            out.append(_HOMOGLYPH_REVERSE[ch])
        else:
            out.append(ch)
    return "".join(out)

def _mutate_tld(url: str, rng: random.Random) -> str:
    m = re.search(r"\.([a-z]{2,6})([/:?]|$)", url, re.IGNORECASE)
    if not m:
        return url
    return url[:m.start(1)] + rng.choice(sorted(SUSPICIOUS_TLDS)) + url[m.end(1):]

def _mutate_subdomain(url: str, rng: random.Random) -> str:
    m = re.match(r"^(\w+://)?([^/]+)(.*)$", url)
    if not m:
        return url
    scheme, authority, rest = m.group(1) or "", m.group(2), m.group(3)
    sub = rng.choice(sorted(BRANDS))
    return f"{scheme}{sub}-{authority}{rest}"

def _mutate_path_noise(url: str, rng: random.Random) -> str:
    noise = "".join(rng.choice(string.ascii_lowercase + string.digits)
                    for _ in range(rng.randint(4, 12)))
    return url.rstrip("/") + "/" + noise

def _mutate_percent(url: str, rng: random.Random) -> str:
    idxs = [i for i, c in enumerate(url) if c.isalpha()]
    if not idxs:
        return url
    i = rng.choice(idxs)
    return url[:i] + f"%{ord(url[i]):02X}" + url[i + 1:]

def _mutate_case(url: str, rng: random.Random) -> str:
    return "".join(c.upper() if rng.random() < 0.3 else c for c in url)

_MUTATORS = (
    _mutate_homoglyph, _mutate_tld, _mutate_subdomain,
    _mutate_path_noise, _mutate_percent, _mutate_case,
)

def adversarial_probe(urls: Sequence[str], analyzer: "Analyzer",
                 n_mutations: int, seed: int) -> Dict[str, float]:
    rng = random.Random(seed)
    phish = list(urls)
    if not phish:
        return {"n": 0.0}
    baseline = []
    for u in phish:
        try:
            r = analyzer.scan_url(u, apply_rules=False)
            baseline.append(1 if r.verdict == 1 else 0)
        except Exception:
            baseline.append(0)
    base_recall = sum(baseline) / len(baseline) if baseline else 0.0
    mutated_recalls: Dict[str, List[int]] = {m.__name__: []
                                              for m in _MUTATORS}
    per_mut = max(1, n_mutations // len(_MUTATORS))
    for u in phish:
        for _ in range(per_mut):
            for m in _MUTATORS:
                try:
                    mu = m(u, rng)
                except Exception:
                    continue
                try:
                    r = analyzer.scan_url(mu, apply_rules=False)
                    mutated_recalls[m.__name__].append(
                        1 if r.verdict == 1 else 0)
                except Exception:
                    mutated_recalls[m.__name__].append(0)
    out: Dict[str, float] = {
        "base_recall": base_recall,
        "n_url": float(len(phish)),
    }
    for name, vals in mutated_recalls.items():
        if not vals:
            continue
        rec = sum(vals) / len(vals)
        out[f"{name}_recall"] = rec
        out[f"{name}_drop"] = base_recall - rec
    return out

def psi(reference: np.ndarray, current: np.ndarray,
        bins: int = 10) -> float:
    ref = np.asarray(reference, dtype=float)
    cur = np.asarray(current, dtype=float)
    ref = ref[~np.isnan(ref)]
    cur = cur[~np.isnan(cur)]
    if len(ref) < 10 or len(cur) < 10:
        return 0.0
    edges = np.unique(np.quantile(ref, np.linspace(0, 1, bins + 1)))
    if len(edges) < 3:
        return 0.0
    edges[0] -= 1e-9
    edges[-1] += 1e-9
    ref_hist, _ = np.histogram(ref, bins=edges)
    cur_hist, _ = np.histogram(cur, bins=edges)
    ref_pct = ref_hist / max(ref_hist.sum(), 1)
    cur_pct = cur_hist / max(cur_hist.sum(), 1)
    eps = 1e-6
    ref_pct = np.clip(ref_pct, eps, None)
    cur_pct = np.clip(cur_pct, eps, None)
    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))

@dataclass(slots=True)
class FeedbackRecord:
    url: str
    features: Dict[str, float]
    predicted_prob: float
    predicted_label: int
    true_label: int
    ts: str
    source: str = "user"

class OnlineLearning:
    def __init__(self, feature_names: Sequence[str],
                 random_state: int = 42):
        self.feature_names = list(feature_names)
        self.model = SGDClassifier(
            loss="log_loss", penalty="elasticnet", alpha=1e-4,
            l1_ratio=0.15, learning_rate="optimal",
            random_state=random_state, class_weight="balanced",
            warm_start=True,
        )
        self.scaler = StandardScaler()
        self._fitted = False
        self._lock = threading.RLock()
        self._n = 0

    def _to_array(self, rows: Sequence[Mapping[str, float]]) -> np.ndarray:
        return np.array([[float(r.get(k, 0.0)) for k in self.feature_names]
                         for r in rows], dtype=float)
    def partial_fit(self, rows: Sequence[Mapping[str, float]],
                    labels: Sequence[int]) -> None:
        if not rows:
            return
        X = self._to_array(rows)
        y = np.asarray(labels, dtype=int)
        with self._lock:
            self.scaler.partial_fit(X)
            self._fitted = True
            Xs = self.scaler.transform(X)
            classes = np.array([0, 1])
            try:
                self.model.partial_fit(Xs, y, classes=classes)
            except Exception as exc:
                LOG.warning("Online partial_fit failed: %s", exc)
                return
            self._n += len(y)
    def predict_proba(self, row: Mapping[str, float]) -> Optional[float]:
        with self._lock:
            if not self._fitted:
                return None
            X = self._to_array([row])
            Xs = self.scaler.transform(X)
            try:
                return float(self.model.predict_proba(Xs)[0, 1])
            except Exception:
                return None
    @property
    def n_samples(self) -> int:
        return self._n
    def to_state(self) -> Dict[str, Any]:
        with self._lock:
            if not self._fitted:
                return {"n": 0, "fitted": False}
            return {
                "n": self._n,
                "fitted": True,
                "coef": self.model.coef_.tolist(),
                "intercept": self.model.intercept_.tolist(),
                "mean": self.scaler.mean_.tolist(),
                "scale": self.scaler.scale_.tolist(),
            }

    def load_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            if not state.get("fitted"):
                return
            coef = np.array(state["coef"], dtype=float)
            intercept = np.array(state["intercept"], dtype=float)
            if coef.shape[1] != len(self.feature_names):
                LOG.warning("Online model size mismatch; skipping")
                return
            self.model.coef_ = coef
            self.model.intercept_ = intercept
            self.model.classes_ = np.array([0, 1])
            self.scaler.mean_ = np.array(state["mean"])
            self.scaler.scale_ = np.array(state["scale"])
            self.scaler.var_ = self.scaler.scale_ ** 2
            self.scaler.n_features_in_ = len(self.feature_names)
            self._fitted = True
            self._n = int(state.get("n", 0))

class ActiveLearningQueue:
    def __init__(self, capacity: int = 500) -> None:
        self.capacity = capacity
        self._items: List[Tuple[float, str, float]] = []
        self._lock = threading.RLock()
    def push(self, url: str, prob: float) -> None:
        uncertainty = 1.0 - abs(prob - 0.5) * 2.0
        with self._lock:
            self._items.append((uncertainty, url, prob))
            self._items.sort(key=lambda t: -t[0])
            self._items = self._items[:self.capacity]
    def pop_batch(self, k: int = 20) -> List[Tuple[str, float, float]]:
        with self._lock:
            out = self._items[:k]
            self._items = self._items[k:]
            return out
    def __len__(self) -> int:
        return len(self._items)

class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                url TEXT NOT NULL,
                prob REAL NOT NULL,
                prediction INTEGER NOT NULL,
                risk INTEGER NOT NULL,
                threshold REAL NOT NULL,
                model_hash TEXT,
                source TEXT,
                latency_ms REAL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                url TEXT NOT NULL,
                true_label INTEGER NOT NULL,
                source TEXT,
                prob REAL
            )
        """)
        self._conn.commit()

    def log_prediction(self, url: str, prob: float, prediction: int,
                        risk: int, threshold: float, model_hash: str,
                        source: str, latency_ms: float) -> str:
        rec_id = uuid.uuid4().hex
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO predictions VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (rec_id, ts, url, prob, prediction, risk, threshold,
                     model_hash, source, latency_ms))
                self._conn.commit()
            except Exception as exc:
                LOG.warning("Audit: write error: %s", exc)
        return rec_id

    def log_feedback(self, url: str, true_label: int, source: str,
                      prob: Optional[float]) -> str:
        rec_id = uuid.uuid4().hex
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO feedback VALUES (?,?,?,?,?,?)",
                    (rec_id, ts, url, true_label, source, prob))
                self._conn.commit()
            except Exception as exc:
                LOG.warning("Audit: feedback error: %s", exc)
        return rec_id

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            try:
                cur = self._conn.execute(
                    "SELECT ts,url,prob,prediction,risk,source "
                    "FROM predictions ORDER BY ts DESC LIMIT ?", (limit,))
                cols = [c[0] for c in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
            except Exception as exc:
                LOG.warning("Audit: read error: %s", exc)
                return []

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

class ModelRegistry:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = root / "index.json"
        self._lock = threading.RLock()
    def _load_index(self) -> Dict[str, Any]:
        if not self.index_path.exists():
            return {"models": []}
        try:
            return json.loads(self.index_path.read_text(encoding="utf-8"))
        except Exception:
            return {"models": []}
    def _save_index(self, idx: Dict[str, Any]) -> None:
        try:
            self.index_path.write_text(
                json.dumps(idx, indent=2, ensure_ascii=False),
                encoding="utf-8")
        except Exception as exc:
            LOG.warning("Registry: not saved: %s", exc)
    def register(self, version: str, path: Path, cfg_hash: str,
                  metrics: Mapping[str, Any], notes: str = "") -> None:
        with self._lock:
            idx = self._load_index()
            idx["models"] = [m for m in idx["models"]
                             if m["version"] != version]
            idx["models"].append({
                "version": version,
                "path": str(path),
                "cfg_hash": cfg_hash,
                "metrics": {k: float(v) for k, v in metrics.items()
                            if isinstance(v, (int, float))},
                "notes": notes,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            idx["models"].sort(key=lambda m: m["ts"])
            self._save_index(idx)
    def list_models(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load_index().get("models", [])
    def latest(self) -> Optional[Dict[str, Any]]:
        models = self.list_models()
        return models[-1] if models else None

@dataclass(slots=True)
class Reason:
    text: str
    severity: str
    weight: float
    source: str = "heuristic"

@dataclass(slots=True)
class Result:
    url: str
    probability: float
    verdict: int
    risk: int
    reasons: List[Reason]
    features: Dict[str, float]
    flags: Dict[str, Any]
    tokens: List[Tuple[str, str, float]] = field(default_factory=list)
    contributions: Dict[str, float] = field(default_factory=dict)
    base_value: float = 0.0
    conformal_set: Tuple[bool, bool] = (True, True)
    conformal_p: float = 1.0
    abstain: bool = False
    online_prob: Optional[float] = None
    error: Optional[str] = None
    model_hash: str = ""
    latency_ms: float = 0.0
    cached: bool = False
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["reasons"] = [asdict(r) for r in self.reasons]
        d["features"] = dict(self.features)
        d["flags"] = dict(self.flags)
        return d

class ProgressCallback(Protocol):
    def __call__(self, msg: str, pct: float) -> None: ...

def _heuristic_explanations(parsed: ParsedURL) -> List[Reason]:
    features = parsed.features
    flags = parsed.flags
    out: List[Reason] = []
    def add(text: str, sev: str, w: float) -> None:
        out.append(Reason(text, sev, w, source="heuristic"))
    if features.get("has_at"):
        add("url contains '@' — real host is masked", "high", 0.9)
    if features.get("has_ip"):
        add("host is an IP address, not a domain", "high", 0.9)
    if features.get("suspicious_tld"):
        add(f"TLD .{flags.get('tld') or '?'} — dodgy zone", "medium", 0.6)
    if features.get("punycode"):
        add("punycode (xn--) — possible homograph attack", "high", 0.7)
    if features.get("homoglyph"):
        add("contains look-alike characters (homoglyphs)", "high", 0.8)
    if features.get("double_slash"):
        add("url contains '//' — redirect pattern", "low", 0.4)
    if features.get("hex_encoding"):
        add("contains hex-encoded characters (%XX)", "medium", 0.5)
    if features.get("subdomains", 0) >= 3:
        add(f"many subdomains ({int(features['subdomains'])})", "low", 0.3)
    if features.get("url_length", 0) >= 90:
        add(f"url too long ({int(features['url_length'])} chars)",
            "low", 0.3)
    if features.get("brand_in_subdomain"):
        brands = flags.get("brands") or []
        add("brand in subdomain — likely imitation"
            + (f": {', '.join(brands[:3])}" if brands else ""),
            "high", 0.8)
    if features.get("url_entropy", 0) >= 4.3:
        add("high entropy — looks like a random string", "low", 0.3)
    if features.get("https") == 0:
        add("no HTTPS", "medium", 0.4)
    if flags.get("shortener"):
        add(f"url shortener ({flags.get('host')})", "medium", 0.5)
    if features.get("port"):
        add(f"non-standard port ({flags.get('port')})", "medium", 0.5)
    kws = flags.get("suspicious_words") or []
    if kws:
        add(f"data-theft keywords: {', '.join(kws[:4])}",
            "medium", 0.4)
    if features.get("path_depth", 0) >= 6:
        add(f"deep path ({int(features['path_depth'])} segments)",
            "low", 0.2)
    if features.get("params", 0) >= 6:
        add(f"many query parameters ({int(features['params'])})",
            "low", 0.2)
    if features.get("double_extension"):
        add("double extension (e.g. .pdf.html) — evasion", "high", 0.8)
    if features.get("encoded_redirect"):
        add("contains encoded redirect", "medium", 0.5)
    if features.get("max_digit_run", 0) >= 6:
        add(f"long digit run ({int(features['max_digit_run'])})",
            "low", 0.3)
    if (features.get("brand_distance", 99) <= 1 and
            not features.get("brand_in_subdomain")):
        add("domain almost like a brand — typosquatting", "high", 0.85)
    if features.get("jaro_winkler_brand", 0) >= 0.9 and \
            features.get("brand_distance", 99) > 1:
        add("very similar to a brand (Jaro-Winkler ≥ 0.9)", "high", 0.75)
    if features.get("ip_in_hex"):
        add("IP address in hex format (0x...)", "high", 0.7)
    if features.get("too_many_dots"):
        add("too many dots in url", "low", 0.3)
    if features.get("ends_with_zip"):
        add("url ends with .zip — possible file lure", "medium", 0.5)
    if features.get("exclamation_marks", 0) >= 3:
        add("many exclamation marks — pressure on user", "low", 0.25)
    if not out:
        out.append(Reason("nothing suspicious found",
                            "info", 0.0, source="heuristic"))
    return out

class Analyzer:
    def __init__(self, model: Optional[BaseEstimator] = None,
                 threshold: float = 0.5) -> None:
        self._lock = threading.RLock()
        self.model: Optional[BaseEstimator] = model
        self.threshold: float = threshold
        self.feature_names: List[str] = list(FEATURES)
        self.last_report: Optional[Dict[str, Any]] = None
        self.risk_calibrator: Optional[RiskCalibrator] = None
        self.conformal: Optional[ConformalCalibrator] = None
        self.rules: RuleEngine = RuleEngine(APP_DIR / "rules.json")
        self.online: OnlineLearning = OnlineLearning(self.feature_names)
        self.active_queue: ActiveLearningQueue = ActiveLearningQueue()
        self.audit: Optional[AuditLog] = None
        self.model_hash: str = ""
        self._train_reference: Dict[str, np.ndarray] = {}
        self._cache: Dict[str, Result] = {}
        self._cache_order: deque = deque(maxlen=2048)
        self._cache_lock = threading.RLock()
        self._webhook_url: Optional[str] = None
    def train_pipeline(self, cfg: Config,
                       progress: Optional[ProgressCallback] = None,
                       extra_models: bool = False,
                       urls_for_ngrams: Optional[Sequence[str]] = None,
                       ) -> Dict[str, Any]:
        def emit(msg: str, pct: float) -> None:
            if progress:
                progress(msg, pct)
            LOG.info(msg)
        emit("Generating dataset…", 0.05)
        df = generate_dataset(cfg)
        y = df["label"].to_numpy()
        X = df[self.feature_names].copy()
        synth_urls = self._synthesize_urls(X, y, cfg)
        X = _add_url_column(X, synth_urls)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=cfg.test_size, random_state=cfg.random_state,
            stratify=y,
        )
        emit(f"Cross-validation ({cfg.cv_folds}-fold)…", 0.15)
        base = build_pipeline(cfg)
        cv = cross_validation(base, X_train, y_train, cfg)
        emit("Training final calibrated pipeline…", 0.45)
        calibrated = wrap_with_calibration(base, cfg)
        calibrated.fit(X_train, y_train)
        emit("Tuning threshold…", 0.62)
        y_prob = calibrated.predict_proba(X_test)[:, 1]
        scan = scan_thresholds(y_test, y_prob, cfg)
        cand = select_thresholds(scan)
        chosen = (cfg.decision_threshold
                  if cfg.decision_threshold is not None else cand.cost)
        emit("Training conformal calibrator…", 0.70)
        idx = np.arange(len(y_test))
        rng = np.random.default_rng(cfg.random_state)
        rng.shuffle(idx)
        half = len(idx) // 2
        cal_idx, eval_idx = idx[:half], idx[half:]
        conformal = ConformalCalibrator(alpha=cfg.conformal_alpha).fit(
            y_test[cal_idx], y_prob[cal_idx])
        y_eval, p_eval = y_test[eval_idx], y_prob[eval_idx]
        emit("Training risk calibrator…", 0.74)
        reason_sums = np.zeros(len(y_test))
        rule_sums = np.zeros(len(y_test))
        reason_sums[:] = np.clip(
            0.5 * X_test.get("has_at", 0).values
            + 0.6 * X_test.get("suspicious_tld", 0).values
            + 0.7 * X_test.get("punycode", 0).values
            + 0.8 * X_test.get("brand_in_subdomain", 0).values
            + 0.5 * X_test.get("homoglyph", 0).values, 0, None)
        risk_cal = RiskCalibrator().fit(
            y_prob, reason_sums, rule_sums, y_test)
        emit("Final metrics + bootstrap CI…", 0.80)
        metrics = metrics_with_ci(y_eval, p_eval, chosen, cfg)
        cov = 0.0
        size = 0.0
        if len(y_eval):
            for yy, pp in zip(y_eval, p_eval):
                inc0, inc1, _ = conformal.predict_set(float(pp))
                sz = int(inc0) + int(inc1)
                size += sz
                if (yy == 1 and inc1) or (yy == 0 and inc0):
                    cov += 1
            cov /= len(y_eval)
            size /= len(y_eval)
        metrics["conformal_coverage"] = cov
        metrics["conformal_set_size"] = size
        metrics["conformal_alpha"] = cfg.conformal_alpha
        try:
            frac_pos, mean_pred = calibration_curve(
                y_eval, p_eval, n_bins=12, strategy="quantile")
            calib_curve = list(zip(mean_pred.tolist(), frac_pos.tolist()))
        except Exception:
            calib_curve = []
        prec, rec, _ = precision_recall_curve(y_eval, p_eval)
        pr_points = list(zip(rec.tolist(), prec.tolist()))
        fpr, tpr, _ = roc_curve(y_eval, p_eval)
        roc_points = list(zip(fpr.tolist(), tpr.tolist()))
        emit("Feature importance (permutation)…", 0.88)
        perm_imp: List[Tuple[str, float, float]] = []
        try:
            sample_n = min(2000, len(X_test))
            rng2 = np.random.default_rng(cfg.random_state)
            idx2 = rng2.choice(len(X_test), sample_n, replace=False)
            Xs = X_test.iloc[idx2]
            ys = y_test[idx2]
            r = permutation_importance(
                calibrated, Xs, ys, n_repeats=cfg.permutation_repeats,
                random_state=cfg.random_state, n_jobs=-1,
                scoring="roc_auc",
            )
            perm_imp = sorted(
                zip(self.feature_names, r.importances_mean.tolist(),
                    r.importances_std.tolist()),
                key=lambda t: t[1], reverse=True,
            )
        except Exception as exc:
            LOG.warning("permutation_importance failed: %s", exc)
        emit("Saving reference for drift…", 0.92)
        self._train_reference = {
            col: X_train[col].to_numpy(dtype=float)
            for col in CONTINUOUS_FEATURES if col in X_train.columns
        }
        adv = None
        if cfg.adversarial_probe:
            emit("Adversarial probing…", 0.95)
            phish_urls = synth_urls[y == 1][:200].tolist()
            with self._lock:
                self.model = calibrated
                self.threshold = chosen
            adv = adversarial_probe(
                phish_urls, self, cfg.adversarial_mutations,
                cfg.random_state)
        with self._lock:
            self.model = calibrated
            self.threshold = chosen
            self.risk_calibrator = risk_cal
            self.conformal = conformal
            self.model_hash = hashlib.sha256(
                (cfg.hash() + str(metrics.get("roc_auc", 0))).encode()
            ).hexdigest()[:12]
            self._webhook_url = cfg.webhook_url
        emit("Done.", 1.0)
        report = {
            "config": asdict(cfg),
            "config_hash": cfg.hash(),
            "model_hash": self.model_hash,
            "dataset": {
                "rows": int(len(df)),
                "positive": int((df["label"] == 1).sum()),
                "negative": int((df["label"] == 0).sum()),
                "train_size": int(len(X_train)),
                "test_size": int(len(X_test)),
                "eval_size": int(len(y_eval)),
                "calib_size": int(len(cal_idx)),
            },
            "cross_validation": cv,
            "thresholds": {
                **cand.as_dict(),
                "chosen": chosen,
            },
            "metrics": metrics,
            "threshold_scan": scan.to_dict(orient="records"),
            "roc_points": roc_points,
            "pr_points": pr_points,
            "calibration_curve": calib_curve,
            "permutation_importance": perm_imp,
            "adversarial": adv,
            "conformal": conformal.to_dict(),
            "y_test": y_eval.tolist(),
            "y_prob": p_eval.tolist(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.last_report = report
        return report

    @staticmethod
    def _synthesize_urls(X: pd.DataFrame, y: np.ndarray,
                              cfg: Config) -> np.ndarray:
        rng = np.random.default_rng(cfg.random_state + 11)
        schemes = np.where(X["https"].values == 1, "https", "http")
        tlds = np.where(
            X["suspicious_tld"].values == 1,
            rng.choice(sorted(SUSPICIOUS_TLDS), len(X)),
            rng.choice(["com", "org", "net", "io", "co", "ru"], len(X)))
        hosts = []
        for i in range(len(X)):
            n = int(rng.integers(2, 5))
            parts = []
            for _ in range(n):
                ln = int(rng.integers(3, 12))
                parts.append("".join(rng.choice(list(string.ascii_lowercase),
                                                 ln)))
            hosts.append(".".join(parts))
        paths = []
        for i in range(len(X)):
            depth = int(X["path_depth"].values[i])
            toks = []
            for _ in range(depth):
                ln = int(rng.integers(2, 10))
                toks.append("".join(rng.choice(list(string.ascii_lowercase),
                                                ln)))
            paths.append("/".join(toks))
        urls = [
            f"{schemes[i]}://{hosts[i]}.{tlds[i]}/{paths[i]}"
            for i in range(len(X))
        ]
        return np.asarray(urls, dtype=object)

    def _check_schema(self, features: Mapping[str, float]) -> bool:
        missing = set(self.feature_names) - set(features)
        return not missing

    def scan_url(self, url: str, apply_rules: bool = True,
                      source: str = "api") -> Result:
        t0 = time.perf_counter()
        cache_key = f"{url}|{apply_rules}|{self.threshold:.4f}"
        with self._cache_lock:
            if cache_key in self._cache:
                cached = self._cache[cache_key]
                cached.latency_ms = (time.perf_counter() - t0) * 1000.0
                cached.cached = True
                return cached
        parsed = parse_url(url)
        if parsed.error:
            return Result(
                url=url, probability=0.0, verdict=0, risk=0,
                reasons=[Reason(f"could not parse: {parsed.error}",
                                  "high", 1.0)],
                features={}, flags={}, tokens=[], contributions={},
                error=parsed.error,
            )
        if not self._check_schema(parsed.features):
            missing = sorted(set(self.feature_names) - set(parsed.features))
            LOG.warning("Missing features: %s", missing)
            return Result(
                url=url, probability=0.0, verdict=0, risk=0,
                reasons=[Reason("feature schema mismatch", "high", 1.0)],
                features=parsed.features, flags=parsed.flags,
                error="feature schema incompatible",
            )
        with self._lock:
            model = self.model
            threshold = self.threshold
            conformal = self.conformal
            risk_cal = self.risk_calibrator
            model_hash = self.model_hash
        if model is None:
            prob = 0.5
            contributions: Dict[str, float] = {}
            base_value = 0.0
        else:
            row = pd.DataFrame([{k: parsed.features[k]
                                 for k in self.feature_names}])
            row = _add_url_column(row, [url])
            prob = float(model.predict_proba(row)[0, 1])
            contributions, base_value = self._local_contributions(row, model)
        pred = int(prob >= threshold)
        reasons = list(_heuristic_explanations(parsed))
        rule_reasons = self.rules.evaluate(parsed) if apply_rules else []
        reasons.extend(rule_reasons)
        reason_sum = sum(r.weight for r in reasons
                          if r.severity != "info")
        rule_sum = sum(r.weight for r in rule_reasons)
        risk = (risk_cal.score(prob, reason_sum, rule_sum)
                if risk_cal is not None
                else int(min(100, round(
                    100 * (0.6 * prob + 0.4 * math.tanh(reason_sum / 5.0))))))
        conf_set = (True, True)
        conf_p = 1.0
        abstain = False
        if conformal is not None and conformal.n_calib > 0:
            inc0, inc1, p_neg = conformal.predict_set(prob)
            conf_set = (bool(inc0), bool(inc1))
            conf_p = float(p_neg)
            abstain = bool(inc0 and inc1)
        online_prob = None
        if self.online is not None:
            online_prob = self.online.predict_proba(parsed.features)

        result = Result(
            url=url, probability=prob, verdict=pred, risk=risk,
            reasons=reasons, features=parsed.features, flags=parsed.flags,
            tokens=parsed.tokens, contributions=contributions,
            base_value=base_value, conformal_set=conf_set,
            conformal_p=conf_p, abstain=abstain,
            online_prob=online_prob, model_hash=model_hash,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
        with self._cache_lock:
            self._cache[cache_key] = result
            self._cache_order.append(cache_key)
            while len(self._cache) > 2048:
                old = self._cache_order.popleft()
                self._cache.pop(old, None)

        if self.active_queue is not None and 0.35 <= prob <= 0.65:
            try:
                self.active_queue.push(url, prob)
            except Exception:
                pass
        if self.audit is not None:
            try:
                self.audit.log_prediction(
                    url=url, prob=prob, prediction=pred, risk=risk,
                    threshold=threshold, model_hash=model_hash,
                    source=source, latency_ms=result.latency_ms)
            except Exception as exc:
                LOG.warning("Audit log failed: %s", exc)
        if self._webhook_url and risk >= 80:
            threading.Thread(
                target=self._send_webhook, args=(result,),
                daemon=True).start()
        return result

    def _send_webhook(self, res: Result) -> None:
        if not self._webhook_url:
            return
        try:
            import urllib.request
            body = json.dumps({
                "url": res.url,
                "probability": res.probability,
                "risk": res.risk,
                "prediction": res.verdict,
                "reasons": [r.text for r in res.reasons[:5]],
            }, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url, data=body,
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            LOG.warning("Webhook failed: %s", exc)

    def _local_contributions(self, row: pd.DataFrame,
                            model: BaseEstimator
                            ) -> Tuple[Dict[str, float], float]:
        base_model = getattr(model, "estimator", model)
        try:
            prep = base_model.named_steps["prep"]
            clf = base_model.named_steps["clf"]
        except Exception:
            return {}, 0.0
        try:
            Xt = prep.transform(row)
            names = list(prep.get_feature_names_out())
            Xv = np.asarray(Xt).ravel()
            contrib, base = shap_contributions(clf, Xv, names)
            return contrib, base
        except Exception as exc:
            LOG.debug("Contributions failed: %s", exc)
            return {}, 0.0

    def scan_many(self, urls: Sequence[str],
                       workers: int = 0) -> List[Result]:
        if workers <= 0:
            workers = min(8, os.cpu_count() or 4)
        if len(urls) <= 4 or workers <= 1:
            return [self.scan_url(u, source="batch") for u in urls]
        results: List[Optional[Result]] = [None] * len(urls)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.scan_url, u, True, "batch"): i
                    for i, u in enumerate(urls)}
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    results[i] = fut.result()
                except Exception as exc:
                    results[i] = Result(
                        url=urls[i], probability=0.0, verdict=0, risk=0,
                        reasons=[Reason(f"error: {exc}", "high", 1.0)],
                        features={}, flags={}, error=str(exc),
                    )
        return [r for r in results if r is not None]

    def feedback(self, url: str, true_label: int,
                source: str = "user") -> bool:
        parsed = parse_url(url)
        if parsed.error:
            return False
        self.online.partial_fit([parsed.features], [int(true_label)])
        if self.audit is not None:
            try:
                self.audit.log_feedback(url, int(true_label), source, None)
            except Exception:
                pass
        return True

    def save(self, path: str) -> None:
        if not _HAS_JOBLIB:
            raise RuntimeError("joblib not installed — cannot save")
        blob = {
            "model": self.model,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "schema_version": 3,
            "model_hash": self.model_hash,
            "conformal": (self.conformal.to_dict()
                          if self.conformal is not None else None),
            "risk_calibrator": (
                {"iso": self.risk_calibrator.iso}
                if self.risk_calibrator is not None else None
            ),
            "online_state": self.online.to_state(),
            "train_reference": {
                k: v.tolist() for k, v in self._train_reference.items()
            },
            "webhook_url": self._webhook_url,
        }
        joblib.dump(blob, path)

    @classmethod
    def load(cls, path: str) -> "Analyzer":
        if not _HAS_JOBLIB:
            raise RuntimeError("joblib not installed — cannot load")
        blob = joblib.load(path)
        version = blob.get("schema_version", 1)
        if version != 3:
            LOG.warning("Loading model schema_version=%s (current=3)", version)
        analyzer = cls(model=blob["model"],
                        threshold=blob["threshold"])
        analyzer.feature_names = list(blob.get("feature_names", FEATURES))
        analyzer.model_hash = blob.get("model_hash", "")
        analyzer._webhook_url = blob.get("webhook_url")
        if blob.get("conformal"):
            analyzer.conformal = ConformalCalibrator.from_dict(
                blob["conformal"])
        if blob.get("risk_calibrator"):
            rc = RiskCalibrator()
            rc.iso = blob["risk_calibrator"]["iso"]
            analyzer.risk_calibrator = rc
        if blob.get("online_state"):
            analyzer.online.load_state(blob["online_state"])
        if blob.get("train_reference"):
            analyzer._train_reference = {
                k: np.asarray(v) for k, v in
                blob["train_reference"].items()
            }
        return analyzer

    def drift_report(self, urls: Sequence[str]) -> Dict[str, Any]:
        if not self._train_reference:
            return {"error": "no reference for drift"}
        parsed = [parse_url(u) for u in urls]
        parsed = [p for p in parsed if not p.error]
        if not parsed:
            return {"error": "no valid urls"}
        current: Dict[str, np.ndarray] = {}
        for col in self._train_reference:
            current[col] = np.array(
                [p.features.get(col, 0.0) for p in parsed], dtype=float)
        out: Dict[str, Any] = {}
        worst = 0.0
        for col, ref in self._train_reference.items():
            psi_val = psi(ref, current[col])
            out[col] = psi_val
            worst = max(worst, psi_val)
        out["_max_psi"] = worst
        return out

    def write_model_card(self, path: str) -> None:
        if not self.last_report:
            raise RuntimeError("Train the pipeline first.")
        r = self.last_report
        m = r["metrics"]
        cv = r["cross_validation"]
        lines = [
            "# Model Card — Phishing URL Detector",
            f"_Generated {r.get('timestamp', '')}_",
            f"_Model hash: `{r.get('model_hash', '?')}`_",
            f"_Config hash: `{r.get('config_hash', '?')}`_",
            "",
            "## Purpose",
            "Triage individual URLs by phishing risk. Trained on a "
            "**synthetic** dataset; not validated on real traffic.",
            "",
            "## Config",
            "```json",
            json.dumps(r["config"], indent=2, ensure_ascii=False),
            "```",
            "",
            "## Dataset",
            f"- rows: {r['dataset']['rows']}",
            f"- positive: {r['dataset']['positive']}",
            f"- negative: {r['dataset']['negative']}",
            f"- train / calib / eval: {r['dataset']['train_size']} / "
            f"{r['dataset']['calib_size']} / {r['dataset']['eval_size']}",
            "",
            "## Metrics (95% bootstrap CI)",
        ]
        for k in ("accuracy", "balanced_accuracy", "precision",
                   "recall", "f1", "roc_auc", "pr_auc"):
            if f"{k}_lo" in m and not math.isnan(m[f"{k}_lo"]):
                lines.append(
                    f"- {k}: {m[k]:.4f} "
                    f"[{m[f'{k}_lo']:.4f}, {m[f'{k}_hi']:.4f}]")
            else:
                lines.append(f"- {k}: {m[k]:.4f}")
        lines += [
            f"- mcc: {m['mcc']:.4f}",
            f"- brier: {m['brier']:.4f}",
            f"- log_loss: {m['log_loss']:.4f}",
            f"- conformal coverage (1-α="
            f"{1-r['config']['conformal_alpha']:.2f}): "
            f"{m.get('conformal_coverage', float('nan')):.4f}",
            f"- average conformal set size: "
            f"{m.get('conformal_set_size', float('nan')):.3f}",
            "",
            "## Cross-validation",
            f"- {r['config']['cv_folds']}-fold F1: "
            f"{cv['f1']:.4f} ± {cv['f1_std']:.4f}",
            f"- ROC-AUC: {cv['roc_auc']:.4f} ± {cv['roc_auc_std']:.4f}",
            "",
            "## Thresholds",
        ]
        for k, v in r["thresholds"].items():
            lines.append(f"- {k}: {v:.4f}")
        lines.append("")
        if r.get("adversarial"):
            lines.append("## Adversarial probing (character mutations)")
            for k, v in r["adversarial"].items():
                lines.append(
                    f"- {k}: {v:+.4f}" if "drop" in k
                    else f"- {k}: {v:.4f}")
            lines.append("")
        lines += [
            "## Limitations",
            "- Trained on synthetic data; real-world performance unknown.",
            "- Feature extraction is lexical/structural (no DNS, WHOIS, "
            "content, or TLS).",
            "- Adversarial probing samples mutations; not exhaustive search.",
            "- Online model is linear; it complements but does not replace "
            "the pipeline.",
        ]
        Path(path).write_text("\n".join(lines), encoding="utf-8")

class _RateLimiter:
    def __init__(self, max_per_sec: float = 20.0) -> None:
        self.max_per_sec = max_per_sec
        self._tokens = max_per_sec
        self._last = time.monotonic()
        self._lock = threading.Lock()
    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self.max_per_sec,
                self._tokens + (now - self._last) * self.max_per_sec,
            )
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

_MAX_URL_LEN = 8192

def _sanitize_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    url = url.strip()
    if len(url) > _MAX_URL_LEN:
        raise ValueError(f"url longer than {_MAX_URL_LEN} characters")
    if "\x00" in url:
        raise ValueError("url contains NUL byte")
    return url

class _Handler(BaseHTTPRequestHandler):
    analyzer: "Analyzer" = None  # type: ignore
    limiter: _RateLimiter = _RateLimiter()
    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.debug("http: " + fmt, *args)
    def _send_json(self, code: int, obj: Mapping[str, Any]) -> None:
        body = json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self) -> None:
        if self.path in ("/health", "/healthz"):
            self._send_json(200, {"ok": True,
                                   "model_hash": self.analyzer.model_hash})
            return
        if self.path == "/metrics":
            self._send_json(200, {
                "model_hash": self.analyzer.model_hash,
                "online_samples": self.analyzer.online.n_samples,
                "active_queue": len(self.analyzer.active_queue),
                "threshold": self.analyzer.threshold,
            })
            return
        self._send_json(404, {"error": "not found"})
    def do_POST(self) -> None:
        if self.path != "/predict":
            self._send_json(404, {"error": "not found"})
            return
        if not self.limiter.allow():
            self._send_json(429, {"error": "too frequent"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "invalid length"})
            return
        if length <= 0 or length > 65536:
            self._send_json(400, {"error": "empty or too large body"})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except Exception:
            self._send_json(400, {"error": "invalid JSON"})
            return
        urls = payload.get("urls")
        if urls is None and "url" in payload:
            urls = [payload["url"]]
        if not isinstance(urls, list) or not urls:
            self._send_json(400, {"error": "need 'url' or 'urls'"})
            return
        try:
            clean = [_sanitize_url(u) for u in urls]
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        results = self.analyzer.scan_many(clean)
        self._send_json(200, {
            "model_hash": self.analyzer.model_hash,
            "results": [
                {
                    "url": r.url,
                    "probability": r.probability,
                    "prediction": r.verdict,
                    "risk": r.risk,
                    "abstain": r.abstain,
                    "conformal_set": list(r.conformal_set),
                    "top_reasons": [rr.text for rr in r.reasons[:5]],
                    "latency_ms": r.latency_ms,
                } for r in results
            ],
        })

def run_http(analyzer: "Analyzer", host: str = "127.0.0.1",
                    port: int = 8765) -> None:
    _Handler.analyzer = analyzer
    server = ThreadingHTTPServer((host, port), _Handler)
    LOG.info("HTTP server listening at http://%s:%d (POST /predict)", host, port)
    print(f"HTTP: http://{host}:{port}  POST /predict  "
          f'{{"urls": ["..."]}}', file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

def _color(txt: str, code: str) -> str:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"{code}{txt}{_C.RESET}"
    return txt

def _print_result(res: Result) -> None:
    if res.error:
        print(_color(f"[ERROR] {res.url}: {res.error}", _C.RED))
        return
    if res.abstain:
        verdict = _color("ABSTAIN", _C.YELLOW)
    elif res.verdict == 1:
        verdict = _color("PHISHING", _C.RED + _C.BOLD)
    else:
        verdict = _color("CLEAN", _C.GREEN + _C.BOLD)
    print(f"{verdict}  P={res.probability:.3f}  risk={res.risk}/100  "
          f"({res.latency_ms:.1f} ms)  {res.url}")
    if res.conformal_set != (True, True):
        print(f"   conformal set: "
              f"{'clean' if res.conformal_set[0] else ''}"
              f"{' and ' if res.conformal_set[0] and res.conformal_set[1] else ''}"
              f"{'phishing' if res.conformal_set[1] else ''}")
    for r in res.reasons[:8]:
        col = {"high": _C.RED, "critical": _C.RED + _C.BOLD,
               "medium": _C.YELLOW, "low": _C.DIM,
               "info": _C.DIM}.get(r.severity, _C.RESET)
        print(f"   • {_color('[' + r.severity + ']', col)} {r.text}")
    if res.contributions:
        top = sorted(res.contributions.items(), key=lambda kv: abs(kv[1]),
                     reverse=True)[:5]
        print("   contributions: " + ", ".join(
            f"{k}={v:+.3f}" for k, v in top))
    if res.online_prob is not None:
        print(f"   online model: P={res.online_prob:.3f}")

DARK = {
    "bg": "#0f1115", "panel": "#161a22", "panel_alt": "#1c222c",
    "fg": "#e6edf3", "fg_dim": "#8b949e", "accent": "#4ea1ff",
    "green": "#3fb950", "red": "#f85149", "yellow": "#d29922",
    "purple": "#a371f7", "border": "#30363d",
    "phish_bg": "#3a1517", "benign_bg": "#102a15",
}
LIGHT = {
    "bg": "#f6f8fa", "panel": "#ffffff", "panel_alt": "#eaeef2",
    "fg": "#1f2328", "fg_dim": "#57606a", "accent": "#0969da",
    "green": "#1a7f37", "red": "#cf222e", "yellow": "#9a6700",
    "purple": "#8250df", "border": "#d0d7de",
    "phish_bg": "#ffebe9", "benign_bg": "#dafbe1",
}

CONFIG_PATH = APP_DIR / "config.json"
RECENT_PATH = APP_DIR / "recent.json"
WATCHLIST_PATH = APP_DIR / "watchlist.json"
THEME_PATH = APP_DIR / "theme.json"
AUDIT_PATH = APP_DIR / "audit.db"

def _hex_lerp(a: str, b: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    ar, ag, ab = int(a[1:3], 16), int(a[3:5], 16), int(a[5:7], 16)
    br, bg, bb = int(b[1:3], 16), int(b[3:5], 16), int(b[5:7], 16)
    return "#{:02x}{:02x}{:02x}".format(
        int(ar + (br - ar) * t), int(ag + (bg - ag) * t),
        int(ab + (bb - ab) * t))

def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _save_json(path: Path, value: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, default=str,
                                    ensure_ascii=False),
                        encoding="utf-8")
    except Exception as exc:
        LOG.warning("Not saved %s: %s", path, exc)

class Application(tk.Tk if _HAS_TK else object):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__()
        self.title("AI Phishing URL Detector")
        self.geometry("1320x860")
        self.minsize(1100, 700)
        saved_cfg = _load_json(CONFIG_PATH, {})
        try:
            self.cfg = (Config.from_json(json.dumps(saved_cfg))
                        if saved_cfg else Config())
        except Exception:
            self.cfg = Config()
        self.theme_name = (_load_json(THEME_PATH, {"theme": "dark"})
                           .get("theme", "dark"))
        self.palette = DARK if self.theme_name == "dark" else LIGHT
        self.configure(bg=self.palette["bg"])
        self.analyzer = Analyzer(threshold=0.5)
        try:
            self.analyzer.audit = AuditLog(AUDIT_PATH)
        except Exception as exc:
            LOG.warning("Audit log unavailable: %s", exc)
        self.registry = ModelRegistry(APP_DIR / "registry")
        self.last_report: Optional[Dict[str, Any]] = None
        self.last_result: Optional[Result] = None
        self.recent: List[str] = _load_json(RECENT_PATH, [])[:30]
        self.watchlist: List[str] = _load_json(WATCHLIST_PATH, [])
        self._worker_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._training = False
        self._batch_results: List[Result] = []
        self._setup_style()
        self._create_menu()
        self._create_layout()
        self._bind_hotkeys()
        self._set_status("Ready. Train the pipeline or paste a URL.")

    def _setup_style(self) -> None:
        p = self.palette
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=p["bg"], foreground=p["fg"],
                        fieldbackground=p["panel"], borderwidth=0)
        opts_list = {
            "TFrame": {"background": p["bg"]},
            "Panel.TFrame": {"background": p["panel"]},
            "TLabel": {"background": p["bg"], "foreground": p["fg"]},
            "Dim.TLabel": {"background": p["bg"], "foreground": p["fg_dim"]},
            "Head.TLabel": {"background": p["bg"], "foreground": p["fg"],
                            "font": ("Segoe UI", 13, "bold")},
            "TButton": {"background": p["panel_alt"], "foreground": p["fg"],
                        "borderwidth": 0, "padding": 6},
            "Accent.TButton": {"background": p["accent"],
                                "foreground": "#000000",
                                "font": ("Segoe UI", 10, "bold")},
            "TNotebook": {"background": p["bg"], "borderwidth": 0},
            "TNotebook.Tab": {"background": p["panel"],
                              "foreground": p["fg_dim"],
                              "padding": [14, 8]},
            "Treeview": {"background": p["panel"],
                         "fieldbackground": p["panel"],
                         "foreground": p["fg"], "bordercolor": p["border"],
                         "rowheight": 22},
            "Treeview.Heading": {"background": p["panel_alt"],
                                  "foreground": p["fg"],
                                  "relief": "flat"},
            "TProgressbar": {"background": p["accent"],
                              "troughcolor": p["panel"]},
            "TEntry": {"fieldbackground": p["panel"],
                       "foreground": p["fg"]},
            "TCheckbutton": {"background": p["bg"], "foreground": p["fg"]},
            "TRadiobutton": {"background": p["bg"], "foreground": p["fg"]},
            "TLabelframe": {"background": p["bg"], "foreground": p["fg"],
                             "bordercolor": p["border"]},
            "TLabelframe.Label": {"background": p["bg"],
                                   "foreground": p["accent"],
                                   "font": ("Segoe UI", 10, "bold")},
        }
        for name, opts in opts_list.items():
            try:
                style.configure(name, **opts)
            except Exception:
                pass
        style.map("TButton",
                  background=[("active", p["border"])],
                  foreground=[("active", p["fg"])])
        style.map("Accent.TButton",
                  background=[("active",
                               _hex_lerp(p["accent"], "#ffffff", 0.2))])
        style.map("TNotebook.Tab",
                  background=[("selected", p["panel_alt"])],
                  foreground=[("selected", p["fg"])])
        style.map("Treeview",
                  background=[("selected", p["accent"])],
                  foreground=[("selected",
                               "#000000" if self.theme_name == "dark"
                               else "#ffffff")])

    def _toggle_theme(self) -> None:
        self.theme_name = ("light" if self.theme_name == "dark"
                            else "dark")
        self.palette = (DARK if self.theme_name == "dark"
                         else LIGHT)
        _save_json(THEME_PATH, {"theme": self.theme_name})
        self.configure(bg=self.palette["bg"])
        self._setup_style()
        for child in list(self.winfo_children()):
            if not isinstance(child, tk.Menu):
                child.destroy()
        self._create_menu()
        self._create_layout()
        self._bind_hotkeys()
        if self.last_report:
            self._on_trained(self.last_report, reapply_only=True)
        self._set_status(f"Theme: {self.theme_name}")

    def _create_menu(self) -> None:
        p = self.palette
        menubar = tk.Menu(self, tearoff=0, bg=p["panel"], fg=p["fg"],
                          activebackground=p["accent"],
                          activeforeground="#000000")
        fm = tk.Menu(menubar, tearoff=0, bg=p["panel"], fg=p["fg"],
                     activebackground=p["accent"],
                     activeforeground="#000000")
        fm.add_command(label="Load URLs from file…",
                       command=self._menu_load_urls, accelerator="Ctrl+O")
        fm.add_command(label="Save pipeline…",
                       command=self._menu_save_model, accelerator="Ctrl+S")
        fm.add_command(label="Load pipeline…",
                       command=self._menu_load_model)
        fm.add_separator()
        fm.add_command(label="Register pipeline…",
                       command=self._register_current_model)
        fm.add_command(label="Show registry…", command=self._list_registry)
        fm.add_separator()
        fm.add_command(label="Export report (HTML)…",
                       command=self._export_report_html)
        fm.add_command(label="Export report (JSON)…",
                       command=self._export_report_json)
        fm.add_command(label="Export model card…",
                       command=self._export_model_card)
        fm.add_command(label="Export indicators (STIX 2.1)…",
                       command=self._export_stix)
        fm.add_separator()
        fm.add_command(label="Save config…", command=self._save_config)
        fm.add_command(label="Load config…", command=self._load_config)
        fm.add_separator()
        fm.add_command(label="Exit", command=self.destroy,
                       accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=fm)

        vm = tk.Menu(menubar, tearoff=0, bg=p["panel"], fg=p["fg"],
                     activebackground=p["accent"],
                     activeforeground="#000000")
        vm.add_command(label="Toggle theme",
                       command=self._toggle_theme)
        vm.add_command(label="Manage watchlist…",
                       command=self._manage_watchlist)
        vm.add_command(label="Active learning queue…",
                       command=self._show_active_queue)
        vm.add_command(label="Recent predictions…",
                       command=self._show_audit_recent)
        menubar.add_cascade(label="View", menu=vm)

        hm = tk.Menu(menubar, tearoff=0, bg=p["panel"], fg=p["fg"],
                     activebackground=p["accent"],
                     activeforeground="#000000")
        hm.add_command(label="About", command=self._menu_about)
        menubar.add_cascade(label="Help", menu=hm)
        self.config(menu=menubar)

    def _bind_hotkeys(self) -> None:
        self.bind("<Control-Return>", lambda e: self._analyze_current_url())
        self.bind("<Control-t>", lambda e: self._train_model_async())
        self.bind("<Control-s>", lambda e: self._menu_save_model())
        self.bind("<Control-o>", lambda e: self._menu_load_urls())
        self.bind("<Control-q>", lambda e: self.destroy())

    def _create_layout(self) -> None:
        p = self.palette
        header = tk.Frame(self, bg=p["bg"])
        header.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(header, text="AI Phishing URL Detector",
                 bg=p["bg"], fg=p["fg"],
                 font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(header, text="   ensemble + stack + conformal + SHAP",
                 bg=p["bg"], fg=p["fg_dim"],
                 font=("Segoe UI", 10, "italic")).pack(side="left", padx=(4, 0))
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(4, 8))
        self.tab_analyze = ttk.Frame(self.notebook)
        self.tab_batch = ttk.Frame(self.notebook)
        self.tab_metrics = ttk.Frame(self.notebook)
        self.tab_dataset = ttk.Frame(self.notebook)
        self.tab_drift = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        for t, name in (
            (self.tab_analyze, "URL Analysis"),
            (self.tab_batch, "Batch Check"),
            (self.tab_metrics, "Pipeline Metrics"),
            (self.tab_dataset, "Dataset"),
            (self.tab_drift, "Drift"),
            (self.tab_settings, "Settings"),
        ):
            self.notebook.add(t, text=name)
        self._build_analyze_tab()
        self._build_batch_tab()
        self._build_metrics_tab()
        self._build_dataset_tab()
        self._build_drift_tab()
        self._build_settings_tab()
        status = tk.Frame(self, bg=p["panel"])
        status.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(status, textvariable=self.status_var, bg=p["panel"],
                 fg=p["fg_dim"], anchor="w", padx=10, pady=4
                 ).pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(status, orient="horizontal",
                                        length=240, mode="determinate")
        self.progress.pack(side="right", padx=10, pady=3)

    def _build_analyze_tab(self) -> None:
        p = self.palette
        f = self.tab_analyze
        top = tk.Frame(f, bg=p["bg"])
        top.pack(fill="x", padx=10, pady=(12, 6))
        tk.Label(top, text="URL:", bg=p["bg"], fg=p["fg"]).pack(side="left")
        self.url_var = tk.StringVar(
            value="http://paypal-login-secure.tk/verify?id=12345")
        entry = tk.Entry(top, textvariable=self.url_var, bg=p["panel"],
                         fg=p["fg"], insertbackground=p["fg"],
                         relief="flat", font=("Consolas", 11))
        entry.pack(side="left", fill="x", expand=True, padx=8, ipady=5)
        entry.bind("<Return>", lambda e: self._analyze_current_url())
        tk.Button(top, text="Scan", command=self._analyze_current_url,
                  bg=p["accent"], fg="#000000", relief="flat",
                  font=("Segoe UI", 10, "bold"), padx=14, pady=4,
                  cursor="hand2").pack(side="left")
        tk.Button(top, text="Example", command=self._insert_example,
                  bg=p["panel_alt"], fg=p["fg"], relief="flat",
                  padx=10, pady=4, cursor="hand2").pack(side="left", padx=6)
        tk.Button(top, text="👍 Correct",
                  command=lambda: self._give_feedback(1),
                  bg=p["panel_alt"], fg=p["green"], relief="flat",
                  padx=8, pady=4, cursor="hand2").pack(side="left",
                                                        padx=(12, 4))
        tk.Button(top, text="👎 Wrong",
                  command=lambda: self._give_feedback(0),
                  bg=p["panel_alt"], fg=p["red"], relief="flat",
                  padx=8, pady=4, cursor="hand2").pack(side="left")

        self.verdict_frame = tk.Frame(f, bg=p["panel"],
                                        highlightthickness=1,
                                        highlightbackground=p["border"])
        self.verdict_frame.pack(fill="x", padx=10, pady=8)
        self.verdict_label = tk.Label(self.verdict_frame, text="—",
                                        bg=p["panel"], fg=p["fg"],
                                        font=("Segoe UI", 22, "bold"),
                                        pady=14)
        self.verdict_label.pack(side="left", padx=16)
        self.verdict_detail = tk.Label(
            self.verdict_frame,
            text="Paste a URL above and press Scan.",
            bg=p["panel"], fg=p["fg_dim"], font=("Segoe UI", 10),
            justify="left", anchor="w")
        self.verdict_detail.pack(side="left", padx=8, fill="x", expand=True)

        bars = tk.Frame(f, bg=p["bg"])
        bars.pack(fill="x", padx=10, pady=(2, 8))
        self.prob_canvas = tk.Canvas(bars, height=70, bg=p["panel"],
                                      highlightthickness=1,
                                      highlightbackground=p["border"])
        self.prob_canvas.pack(fill="x")
        self.prob_canvas.bind("<Configure>",
                              lambda e: self._draw_probability_bars())

        diss = ttk.LabelFrame(f, text="URL breakdown")
        diss.pack(fill="x", padx=10, pady=4)
        self.dissect_canvas = tk.Canvas(diss, height=44, bg=p["panel"],
                                         highlightthickness=0)
        self.dissect_canvas.pack(fill="x", padx=6, pady=6)

        mid = tk.Frame(f, bg=p["bg"])
        mid.pack(fill="both", expand=True, padx=10, pady=4)
        left = ttk.LabelFrame(mid, text="Reasons")
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.reasons_text = tk.Text(left, bg=p["panel"], fg=p["fg"],
                                     relief="flat", font=("Segoe UI", 10),
                                     wrap="word", padx=10, pady=8, height=10)
        self.reasons_text.pack(fill="both", expand=True)
        self.reasons_text.configure(state="disabled")
        for sev, color in (("critical", p["red"]), ("high", p["red"]),
                            ("medium", p["yellow"]), ("low", p["fg_dim"]),
                            ("info", p["fg_dim"])):
            self.reasons_text.tag_configure(sev, foreground=color)
        right = ttk.LabelFrame(mid, text="Top contributions (SHAP-like)")
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.contrib_canvas = tk.Canvas(right, bg=p["panel"],
                                         highlightthickness=0, height=180)
        self.contrib_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.contrib_canvas.bind(
            "<Configure>", lambda e: self._draw_contributions())

        ftree_frame = ttk.LabelFrame(f, text="Extracted features")
        ftree_frame.pack(fill="both", expand=False, padx=10, pady=(4, 8))
        self.feature_tree = ttk.Treeview(ftree_frame,
                                           columns=("feature", "value"),
                                           show="headings", height=6)
        self.feature_tree.heading("feature", text="Feature")
        self.feature_tree.heading("value", text="Value")
        self.feature_tree.column("feature", width=260, anchor="w")
        self.feature_tree.column("value", width=120, anchor="e")
        vsb = ttk.Scrollbar(ftree_frame, orient="vertical",
                            command=self.feature_tree.yview)
        self.feature_tree.configure(yscrollcommand=vsb.set)
        self.feature_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _build_batch_tab(self) -> None:
        p = self.palette
        f = self.tab_batch
        top = tk.Frame(f, bg=p["bg"])
        top.pack(fill="x", padx=10, pady=(12, 6))
        tk.Label(top, text="Paste URLs (one per line):",
                 bg=p["bg"], fg=p["fg"]).pack(side="left")
        tk.Button(top, text="Load file…",
                  command=self._menu_load_urls,
                  bg=p["panel_alt"], fg=p["fg"], relief="flat",
                  padx=10, pady=2, cursor="hand2").pack(side="right")
        tk.Button(top, text="Export CSV…",
                  command=self._export_batch_csv,
                  bg=p["panel_alt"], fg=p["fg"], relief="flat",
                  padx=10, pady=2, cursor="hand2").pack(side="right", padx=6)
        tk.Button(top, text="Scan all",
                  command=self._batch_scan,
                  bg=p["accent"], fg="#000000", relief="flat",
                  font=("Segoe UI", 10, "bold"), padx=14, pady=2,
                  cursor="hand2").pack(side="right", padx=6)
        self.batch_input = tk.Text(f, bg=p["panel"], fg=p["fg"],
                                    relief="flat", height=8, wrap="none",
                                    font=("Consolas", 10),
                                    insertbackground=p["fg"])
        self.batch_input.pack(fill="x", padx=10, pady=4)
        self.batch_input.insert("1.0", "\n".join([
            "https://www.google.com/search?q=hello",
            "http://paypal-secure-login.tk/verify?user=victim",
            "http://192.168.10.55/admin/login.php",
            "https://amazon.com/orders/123",
            "http://xn--pypal-4ve.com/account/update",
            "http://bit.ly/3xYz9",
            "https://gosuslugi-vhod.ru/verify",
        ]))
        cols = ("url", "verdict", "probability", "risk", "conformal", "reason")
        self.batch_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w, a in zip(cols, [380, 100, 90, 60, 90, 340],
                            ["w", "center", "center", "center", "center", "w"]):
            self.batch_tree.heading(c, text=c.title())
            self.batch_tree.column(c, width=w, anchor=a)
        vsb = ttk.Scrollbar(f, orient="vertical",
                            command=self.batch_tree.yview)
        self.batch_tree.configure(yscrollcommand=vsb.set)
        self.batch_tree.pack(side="left", fill="both", expand=True,
                              padx=(10, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8, padx=(0, 10))
        self.batch_tree.tag_configure("phish", background=p["phish_bg"],
                                       foreground=p["red"])
        self.batch_tree.tag_configure("benign", background=p["benign_bg"],
                                       foreground=p["green"])
        self.batch_tree.tag_configure("abstain", background=p["panel_alt"],
                                       foreground=p["yellow"])

    def _build_metrics_tab(self) -> None:
        p = self.palette
        f = self.tab_metrics
        top = tk.Frame(f, bg=p["bg"])
        top.pack(fill="x", padx=10, pady=(12, 6))
        tk.Label(top, text="Train the pipeline to see metrics.",
                 bg=p["bg"], fg=p["fg_dim"]).pack(side="left")
        self.train_button = tk.Button(top, text="Train pipeline",
                                       command=self._train_model_async,
                                       bg=p["accent"], fg="#000000",
                                       relief="flat",
                                       font=("Segoe UI", 10, "bold"),
                                       padx=14, pady=3, cursor="hand2")
        self.train_button.pack(side="right")
        body = tk.Frame(f, bg=p["bg"])
        body.pack(fill="both", expand=True, padx=10, pady=6)
        left = tk.Frame(body, bg=p["bg"])
        left.pack(side="left", fill="both", expand=True)
        self.metric_cards_frame = tk.Frame(left, bg=p["bg"])
        self.metric_cards_frame.pack(fill="x")
        cm_frame = ttk.LabelFrame(left, text="Confusion matrix (eval)")
        cm_frame.pack(fill="x", pady=6)
        self.cm_canvas = tk.Canvas(cm_frame, height=170, bg=p["panel"],
                                     highlightthickness=0)
        self.cm_canvas.pack(fill="x", padx=6, pady=6)
        self.cm_canvas.bind(
            "<Configure>", lambda e: self._draw_confusion_matrix())
        scan_frame = ttk.LabelFrame(left, text="Threshold scan")
        scan_frame.pack(fill="both", expand=True, pady=6)
        scan_cols = ("threshold", "accuracy", "recall", "f1", "mcc",
                      "balanced", "youden", "fp", "fn", "cost")
        self.scan_tree = ttk.Treeview(scan_frame, columns=scan_cols,
                                        show="headings", height=8)
        for c, w in zip(scan_cols, [80, 80, 70, 70, 70, 80, 70, 50, 50, 80]):
            self.scan_tree.heading(c, text=c.title())
            self.scan_tree.column(c, width=w, anchor="center")
        self.scan_tree.pack(fill="both", expand=True, padx=6, pady=6)

        right = tk.Frame(body, bg=p["bg"])
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        imp_frame = ttk.LabelFrame(right, text="Feature importance (permutation)")
        imp_frame.pack(fill="both", expand=True)
        self.imp_canvas = tk.Canvas(imp_frame, bg=p["panel"],
                                      highlightthickness=0, height=200)
        self.imp_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.imp_canvas.bind("<Configure>",
                              lambda e: self._draw_importances())
        cal_frame = ttk.LabelFrame(right, text="Calibration curve")
        cal_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.cal_canvas = tk.Canvas(cal_frame, bg=p["panel"],
                                      highlightthickness=0, height=160)
        self.cal_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.cal_canvas.bind("<Configure>",
                              lambda e: self._draw_calibration())
        roc_frame = ttk.LabelFrame(right, text="ROC + PR curves")
        roc_frame.pack(fill="both", expand=True, pady=(6, 0))
        self.roc_canvas = tk.Canvas(roc_frame, bg=p["panel"],
                                      highlightthickness=0, height=200)
        self.roc_canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.roc_canvas.bind("<Configure>", lambda e: self._draw_roc())
        self._perm_importances: List[Tuple[str, float, float]] = []

    def _build_dataset_tab(self) -> None:
        p = self.palette
        f = self.tab_dataset
        top = tk.Frame(f, bg=p["bg"])
        top.pack(fill="x", padx=10, pady=(12, 6))
        tk.Label(top, text="Preview of the synthetic dataset.",
                 bg=p["bg"], fg=p["fg_dim"]).pack(side="left")
        tk.Button(top, text="Regenerate",
                  command=self._refresh_dataset_preview,
                  bg=p["panel_alt"], fg=p["fg"], relief="flat",
                  padx=10, pady=2, cursor="hand2").pack(side="right")
        self.dataset_tree = ttk.Treeview(f, show="headings")
        vsb = ttk.Scrollbar(f, orient="vertical",
                            command=self.dataset_tree.yview)
        hsb = ttk.Scrollbar(f, orient="horizontal",
                            command=self.dataset_tree.xview)
        self.dataset_tree.configure(yscrollcommand=vsb.set,
                                     xscrollcommand=hsb.set)
        self.dataset_tree.pack(side="top", fill="both", expand=True,
                                padx=(10, 0), pady=6)
        vsb.pack(side="right", fill="y", pady=6)
        hsb.pack(side="bottom", fill="x", padx=10)
        self._refresh_dataset_preview()

    def _build_drift_tab(self) -> None:
        p = self.palette
        f = self.tab_drift
        top = tk.Frame(f, bg=p["bg"])
        top.pack(fill="x", padx=10, pady=(12, 6))
        tk.Label(top, text="Paste fresh URLs to compute PSI against "
                            "the training set.",
                 bg=p["bg"], fg=p["fg_dim"]).pack(side="left")
        tk.Button(top, text="Compute PSI", command=self._compute_drift,
                  bg=p["accent"], fg="#000000", relief="flat",
                  padx=14, pady=3, cursor="hand2").pack(side="right")
        self.drift_input = tk.Text(f, bg=p["panel"], fg=p["fg"],
                                    relief="flat", height=8, wrap="none",
                                    font=("Consolas", 10))
        self.drift_input.pack(fill="x", padx=10, pady=4)
        cols = ("feature", "psi", "status")
        self.drift_tree = ttk.Treeview(f, columns=cols, show="headings",
                                         height=14)
        for c, w, a in zip(cols, [300, 100, 160], ["w", "center", "center"]):
            self.drift_tree.heading(c, text=c.title())
            self.drift_tree.column(c, width=w, anchor=a)
        self.drift_tree.pack(fill="both", expand=True, padx=10, pady=8)
        self.drift_tree.tag_configure("ok", foreground=p["green"])
        self.drift_tree.tag_configure("warn", foreground=p["yellow"])
        self.drift_tree.tag_configure("alert", foreground=p["red"])

    def _build_settings_tab(self) -> None:
        p = self.palette
        f = self.tab_settings
        wrap = tk.Frame(f, bg=p["bg"])
        wrap.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(wrap, text="Pipeline and training config",
                 bg=p["bg"], fg=p["fg"],
                 font=("Segoe UI", 13, "bold")
                 ).grid(row=0, column=0, columnspan=3, sticky="w",
                         pady=(0, 12))

        def label(row: int, text: str) -> None:
            tk.Label(wrap, text=text, bg=p["bg"], fg=p["fg"]
                     ).grid(row=row, column=0, sticky="w", pady=6)

        label(1, "Model type:")
        self.model_type_var = tk.StringVar(value=self.cfg.model_type)
        ttk.Combobox(wrap, textvariable=self.model_type_var,
                     values=["stack", "voting", "rf", "extratrees",
                              "hgb", "sgd"],
                     state="readonly", width=18).grid(
            row=1, column=1, sticky="w", pady=6)
        label(2, "Calibration:")
        self.calib_method_var = tk.StringVar(
            value=self.cfg.calibration_method
            if self.cfg.use_calibration else "none")
        ttk.Combobox(wrap, textvariable=self.calib_method_var,
                     values=["auto", "sigmoid", "isotonic", "none"],
                     state="readonly", width=18
                     ).grid(row=2, column=1, sticky="w", pady=6)
        label(3, "Decision threshold:")
        self.threshold_var = tk.DoubleVar(value=0.5)
        self.threshold_scale = ttk.Scale(wrap, from_=0.05, to=0.95,
                                           variable=self.threshold_var,
                                           orient="horizontal",
                                           length=320,
                                           command=self._on_threshold_change)
        self.threshold_scale.grid(row=3, column=1, sticky="w", pady=6)
        self.threshold_label = tk.Label(wrap, text="0.50", bg=p["bg"],
                                          fg=p["accent"],
                                          font=("Consolas", 11, "bold"))
        self.threshold_label.grid(row=3, column=2, sticky="w", padx=8)
        label(4, "Cost ratio (FN : FP):")
        self.cost_var = tk.IntVar(value=int(self.cfg.cost_fn))
        ttk.Spinbox(wrap, from_=1, to=100, textvariable=self.cost_var,
                    width=6).grid(row=4, column=1, sticky="w", pady=6)
        tk.Label(wrap,
                 text="Higher ⇒ tolerate false positives to catch more",
                 bg=p["bg"], fg=p["fg_dim"]).grid(
            row=4, column=2, sticky="w", padx=8)
        label(5, "Samples per class:")
        self.n_var = tk.IntVar(value=self.cfg.n_per_class)
        ttk.Spinbox(wrap, from_=100, to=20000, increment=100,
                    textvariable=self.n_var, width=8
                    ).grid(row=5, column=1, sticky="w", pady=6)
        label(6, "Random seed:")
        self.seed_var = tk.IntVar(value=self.cfg.random_state)
        ttk.Spinbox(wrap, from_=0, to=99999, textvariable=self.seed_var,
                    width=8).grid(row=6, column=1, sticky="w", pady=6)
        label(7, "Bootstrap CI iterations:")
        self.boot_var = tk.IntVar(value=self.cfg.bootstrap_iters)
        ttk.Spinbox(wrap, from_=0, to=2000, increment=50,
                    textvariable=self.boot_var, width=8
                    ).grid(row=7, column=1, sticky="w", pady=6)
        label(8, "Conformal alpha (miscoverage):")
        self.alpha_var = tk.DoubleVar(value=self.cfg.conformal_alpha)
        ttk.Spinbox(wrap, from_=0.01, to=0.5, increment=0.01,
                    textvariable=self.alpha_var, width=8
                    ).grid(row=8, column=1, sticky="w", pady=6)
        label(9, "Webhook on high risk:")
        self.webhook_var = tk.StringVar(value=self.cfg.webhook_url or "")
        tk.Entry(wrap, textvariable=self.webhook_var, width=48,
                 bg=p["panel"], fg=p["fg"], relief="flat",
                 insertbackground=p["fg"]).grid(
            row=9, column=1, columnspan=2, sticky="w", pady=6)
        self.ngram_var = tk.BooleanVar(value=self.cfg.use_ngram_embeddings)
        ttk.Checkbutton(wrap, text="Use hashed char-n-grams",
                        variable=self.ngram_var
                        ).grid(row=10, column=0, columnspan=2, sticky="w",
                                pady=6)
        self.adv_var = tk.BooleanVar(value=self.cfg.adversarial_probe)
        ttk.Checkbutton(wrap,
                        text="Run adversarial probing (URL mutations)",
                        variable=self.adv_var
                        ).grid(row=11, column=0, columnspan=2, sticky="w",
                                pady=6)
        tk.Button(wrap, text="Apply and retrain",
                  command=self._apply_settings,
                  bg=p["accent"], fg="#000000", relief="flat",
                  font=("Segoe UI", 10, "bold"), padx=16, pady=6,
                  cursor="hand2").grid(row=12, column=0, columnspan=3,
                                        pady=20, sticky="w")
        info = textwrap.dedent("""\
            Notes:
              • Stack = out-of-fold meta-learning over RF + ExtraTrees + HGB.
              • Calibration makes predict_proba reliable (sigmoid/isotonic).
              • Threshold candidates: F1, cost, Youden-J, balanced, MCC.
              • Conformal prediction returns a set with a 1-α guarantee;
                when both classes are included we show ABSTAIN.
              • Hashed char-n-grams add lexical texture.
              • Adversarial probing mutates URLs (homoglyphs, TLD swaps,
                subdomain injection, path noise) and re-parses them.
              • Webhook fires when risk ≥ 80.""")
        tk.Label(wrap, text=info, justify="left", bg=p["bg"],
                 fg=p["fg_dim"], font=("Segoe UI", 9)
                 ).grid(row=13, column=0, columnspan=3, sticky="w",
                         pady=(4, 0))

    def _on_threshold_change(self, _value: Any = None) -> None:
        v = float(self.threshold_var.get())
        try:
            self.threshold_label.configure(text=f"{v:.2f}")
        except Exception:
            pass
        with self.analyzer._lock:
            self.analyzer.threshold = v

    def _insert_example(self) -> None:
        examples = [
            "http://paypal-login-secure.tk/verify?id=12345",
            "https://www.google.com/search?q=hello+world",
            "http://192.168.1.10/admin/login.php?user=admin",
            "http://xn--pypal-4ve.com/account/update",
            "https://bit.ly/3xYz9",
            "https://github.com/features/actions",
            "http://amazon-security-update.ml/verify/account?token=ab12",
            "https://outlook-verify.000webhostapp.com/session/recover",
            "http://аpple.com/verify",
            "http://secure-paypal.com.evil.tk/login",
            "https://gosuslugi-vhod.ru/verify?token=abc",
            "http://сбербанк-онлайн.рф/войти",
        ]
        self.url_var.set(random.choice(examples))

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)
        try:
            self.update_idletasks()
        except Exception:
            pass

    def _push_recent(self, url: str) -> None:
        if url in self.recent:
            self.recent.remove(url)
        self.recent.insert(0, url)
        self.recent = self.recent[:30]
        _save_json(RECENT_PATH, self.recent)

    def _analyze_current_url(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showinfo("No URL", "Enter a URL.")
            return
        if self.analyzer.model is None:
            messagebox.showinfo(
                "Pipeline not trained",
                "The pipeline is not trained yet. Analysis will use rules "
                "and heuristics only.\nPress Ctrl+T to train.",
            )
        result = self.analyzer.scan_url(url, source="gui")
        wl_hit = any(w and w in url.lower() for w in self.watchlist)
        if wl_hit:
            result.reasons = list(result.reasons) + [
                Reason("watchlist match", "critical",
                        1.0, source="rule")]
            result.risk = 100
            result.verdict = 1
            result.abstain = False
        self.last_result = result
        self._push_recent(url)
        self._render_analysis(result)

    def _give_feedback(self, true_label: int) -> None:
        if self.last_result is None:
            messagebox.showinfo("No result", "Scan a URL first.")
            return
        ok = self.analyzer.feedback(self.last_result.url, true_label, "gui")
        if ok:
            self._set_status(
                f"Feedback recorded (online model n="
                f"{self.analyzer.online.n_samples}).")

    def _render_analysis(self, res: Result) -> None:
        p = self.palette
        if res.error:
            self.verdict_label.configure(text="ERROR", fg=p["yellow"])
            self.verdict_detail.configure(text=res.error)
        else:
            if res.abstain:
                color = p["yellow"]
                label = "ABSTAIN"
            else:
                color = p["red"] if res.verdict == 1 else p["green"]
                label = "PHISHING" if res.verdict == 1 else "CLEAN"
            self.verdict_label.configure(text=label, fg=color)
            detail = (
                f"P(phishing) = {res.probability:.3f}    "
                f"Risk = {res.risk}/100    "
                f"Threshold = {self.analyzer.threshold:.2f}\n"
                f"Host: {res.flags.get('host') or '(unknown)'}    "
                f"Scheme: {res.flags.get('scheme')}    "
                f"TLD: .{res.flags.get('tld') or '?'}    "
                f"Latency: {res.latency_ms:.1f} ms"
            )
            if res.flags.get("shortener"):
                detail += "    [shortener]"
            if res.conformal_set != (True, True):
                detail += (f"\nConformal set: "
                           f"{'clean ' if res.conformal_set[0] else ''}"
                           f"{'phishing' if res.conformal_set[1] else ''}")
            if res.online_prob is not None:
                detail += (f"    Online model P = "
                           f"{res.online_prob:.3f}")
            self.verdict_detail.configure(text=detail)
        self.reasons_text.configure(state="normal")
        self.reasons_text.delete("1.0", "end")
        for r in res.reasons:
            self.reasons_text.insert("end", f"• [{r.severity}] {r.text}\n",
                                      r.severity)
        self.reasons_text.configure(state="disabled")
        for row in self.feature_tree.get_children():
            self.feature_tree.delete(row)
        for k in self.analyzer.feature_names:
            v = res.features.get(k, "—")
            if isinstance(v, float):
                v = f"{v:.4f}" if "ratio" in k else f"{v:.2f}"
            self.feature_tree.insert("", "end", values=(k, v))
        self._draw_probability_bars()
        self._draw_dissection()
        self._draw_contributions()

    def _draw_probability_bars(self) -> None:
        c = self.prob_canvas
        p = self.palette
        c.delete("all")
        w = max(c.winfo_width(), 10)
        h = max(c.winfo_height(), 10)
        prob = self.last_result.probability if self.last_result else 0.0
        risk = self.last_result.risk if self.last_result else 0
        pad_x, bar_h = 20, 14
        bar_w = max(20, w - 2 * pad_x)
        c.create_text(pad_x, 12, anchor="w", text="P(phishing)",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_rectangle(pad_x, 22, pad_x + bar_w, 22 + bar_h,
                           outline=p["border"], fill=p["panel_alt"])
        fill_w = int(bar_w * prob)
        color = _hex_lerp(p["green"], p["red"], prob)
        c.create_rectangle(pad_x, 22, pad_x + fill_w, 22 + bar_h,
                           outline="", fill=color)
        with self.analyzer._lock:
            tx_thr = self.analyzer.threshold
        tx = pad_x + int(bar_w * tx_thr)
        c.create_line(tx, 18, tx, 22 + bar_h + 4,
                      fill=p["accent"], width=2)
        c.create_text(pad_x + bar_w, 22 + bar_h / 2, anchor="e",
                      text=f"{prob:.3f}", fill=p["fg"],
                      font=("Consolas", 9, "bold"))
        c.create_text(pad_x, 50, anchor="w", text="Risk score",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_rectangle(pad_x, 58, pad_x + bar_w, 58 + bar_h,
                           outline=p["border"], fill=p["panel_alt"])
        fill_w2 = int(bar_w * (risk / 100.0))
        color2 = _hex_lerp(p["green"], p["red"], risk / 100.0)
        c.create_rectangle(pad_x, 58, pad_x + fill_w2, 58 + bar_h,
                           outline="", fill=color2)
        c.create_text(pad_x + bar_w, 58 + bar_h / 2, anchor="e",
                      text=f"{risk}/100", fill=p["fg"],
                      font=("Consolas", 9, "bold"))

    def _draw_dissection(self) -> None:
        c = self.dissect_canvas
        p = self.palette
        c.delete("all")
        if not self.last_result or not self.last_result.tokens:
            c.create_text(10, 10, anchor="nw",
                          text="(URL tokens will appear here)",
                          fill=p["fg_dim"], font=("Segoe UI", 9))
            return
        kind_color = {
            "scheme": p["fg_dim"], "host": p["fg"], "sep": p["fg_dim"],
            "brand": p["red"], "risky_tld": p["red"], "punycode": p["purple"],
            "homoglyph": p["purple"], "digits": p["yellow"],
            "word": p["yellow"], "hex": p["purple"], "path": p["fg"],
        }
        x, y = 10, 12
        max_w = max(c.winfo_width(), 200) - 10
        for kind, text, weight in self.last_result.tokens:
            color = kind_color.get(kind, p["fg"])
            font = ("Consolas", 10, "bold" if weight >= 0.5 else "normal")
            item = c.create_text(x, y, anchor="nw", text=text,
                                  fill=color, font=font)
            bbox = c.bbox(item)
            if bbox:
                width = bbox[2] - bbox[0]
                if x + width > max_w:
                    x = 10
                    y += 20
                    c.coords(item, x, y)
                    bbox = c.bbox(item)
                    width = (bbox[2] - bbox[0]) if bbox else 0
                if weight >= 0.5 and bbox:
                    c.create_rectangle(bbox[0] - 2, bbox[1] - 1,
                                        bbox[2] + 2, bbox[3] + 1,
                                        outline=color, width=1)
                x += width + 4

    def _draw_contributions(self) -> None:
        c = self.contrib_canvas
        p = self.palette
        c.delete("all")
        if not self.last_result or not self.last_result.contributions:
            c.create_text(10, 10, anchor="nw",
                          text="Train the pipeline to see contributions.",
                          fill=p["fg_dim"], font=("Segoe UI", 9))
            return
        pairs = sorted(self.last_result.contributions.items(),
                       key=lambda kv: abs(kv[1]), reverse=True)[:12]
        max_v = max((abs(v) for _, v in pairs), default=1.0) or 1.0
        w = max(c.winfo_width(), 300)
        h = max(c.winfo_height(), 160)
        left = 200
        right = w - 60
        row_h = max(14, (h - 20) / max(1, len(pairs)))
        for i, (name, v) in enumerate(pairs):
            y = 10 + i * row_h
            c.create_text(left - 8, y + row_h / 2, anchor="e", text=name,
                          fill=p["fg_dim"], font=("Segoe UI", 9))
            bar_w = (right - left) * (abs(v) / max_v)
            color = p["red"] if v > 0 else p["green"]
            c.create_rectangle(left, y + 2, left + bar_w, y + row_h - 2,
                                fill=color, outline="")
            c.create_text(left + bar_w + 6, y + row_h / 2, anchor="w",
                          text=f"{v:+.3f}", fill=p["fg"],
                          font=("Consolas", 8))
        c.create_text(left, h - 6, anchor="w",
                      text=f"base value = {self.last_result.base_value:+.3f}",
                      fill=p["fg_dim"], font=("Consolas", 8))

    def _batch_scan(self) -> None:
        raw = self.batch_input.get("1.0", "end").strip()
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            messagebox.showinfo("No URLs", "Paste at least one URL.")
            return
        self._set_status(f"Scanning {len(urls)} URLs…")
        self.progress.configure(mode="determinate", maximum=len(urls),
                                 value=0)
        self._batch_results = []
        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)
        results = self.analyzer.scan_many(urls)
        for i, res in enumerate(results, 1):
            self._batch_results.append(res)
            tag = ("abstain" if res.abstain
                   else ("phish" if res.verdict == 1 else "benign"))
            top_reason = res.reasons[0].text if res.reasons else ""
            conf = ("both" if res.conformal_set == (True, True)
                    else ("phish" if res.conformal_set[1]
                          else ("clean" if res.conformal_set[0] else "∅")))
            self.batch_tree.insert("", "end", values=(
                res.url,
                "ABSTAIN" if res.abstain else
                ("PHISHING" if res.verdict == 1 else "CLEAN"),
                f"{res.probability:.3f}",
                res.risk,
                conf,
                top_reason,
            ), tags=(tag,))
            self.progress.configure(value=i)
            self.update_idletasks()
        self._set_status(f"Processed {len(urls)} URLs.")
        self.progress.configure(value=0)

    def _export_batch_csv(self) -> None:
        if not self._batch_results:
            messagebox.showinfo("Nothing to export",
                                 "Run a batch scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"phishing_scan_{datetime.now():%Y%m%d_%H%M%S}.csv",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["url", "verdict", "probability", "risk",
                            "abstain", "conformal_0", "conformal_1",
                            "reasons"])
                for r in self._batch_results:
                    w.writerow([
                        r.url,
                        "phishing" if r.verdict == 1 else "clean",
                        f"{r.probability:.4f}", r.risk, int(r.abstain),
                        int(r.conformal_set[0]),
                        int(r.conformal_set[1]),
                        " | ".join(f"[{x.severity}] {x.text}"
                                    for x in r.reasons),
                    ])
            self._set_status(f"Exported {len(self._batch_results)} "
                              f"rows → {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))

    def _train_model_async(self) -> None:
        if self._training:
            return
        self._training = True
        self.train_button.configure(state="disabled", text="Training…")
        self._set_status("Training pipeline in background…")
        self.progress.configure(mode="determinate", maximum=100, value=0)
        cfg = Config(
            random_state=int(self.seed_var.get()),
            n_per_class=int(self.n_var.get()),
            use_calibration=self.calib_method_var.get() != "none",
            calibration_method=self.calib_method_var.get(),
            model_type=self.model_type_var.get(),
            cost_fn=float(self.cost_var.get()),
            cost_fp=1.0,
            bootstrap_iters=int(self.boot_var.get()),
            adversarial_probe=bool(self.adv_var.get()),
            use_ngram_embeddings=bool(self.ngram_var.get()),
            conformal_alpha=float(self.alpha_var.get()),
            webhook_url=self.webhook_var.get().strip() or None,
        )
        self.cfg = cfg
        _save_json(CONFIG_PATH, asdict(cfg))

        def worker() -> None:
            try:
                report = self.analyzer.train_pipeline(
                    cfg,
                    progress=lambda msg, pct: self._worker_queue.put(
                        ("progress", (msg, pct))),
                )
                self._worker_queue.put(("trained", report))
            except Exception as exc:
                self._worker_queue.put(
                    ("train_error", (exc, traceback.format_exc())))
        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._poll_worker_queue)

    def _poll_worker_queue(self) -> None:
        try:
            while True:
                kind, payload = self._worker_queue.get_nowait()
                if kind == "progress":
                    msg, pct = payload
                    self._set_status(msg)
                    self.progress.configure(value=pct * 100)
                elif kind == "trained":
                    self._on_trained(payload)
                elif kind == "train_error":
                    exc, tb = payload
                    self._training = False
                    self.train_button.configure(state="normal",
                                                 text="Train pipeline")
                    self.progress.configure(value=0)
                    messagebox.showerror("Training error",
                                          f"{exc}\n\n{tb}")
                    self._set_status("Training failed.")
        except queue.Empty:
            pass
        if self._training:
            self.after(80, self._poll_worker_queue)

    def _on_trained(self, report: Dict[str, Any],
                     reapply_only: bool = False) -> None:
        self._training = False
        try:
            self.train_button.configure(state="normal",
                                         text="Train pipeline")
        except Exception:
            pass
        self.progress.configure(value=0)
        self.last_report = report
        chosen = report["thresholds"]["chosen"]
        self.threshold_var.set(chosen)
        self._on_threshold_change()
        self._render_metric_cards(report)
        for row in self.scan_tree.get_children():
            self.scan_tree.delete(row)
        for r in report["threshold_scan"]:
            self.scan_tree.insert("", "end", values=(
                f"{r['threshold']:.2f}",
                f"{r['accuracy']:.3f}",
                f"{r['recall']:.3f}",
                f"{r['f1']:.3f}",
                f"{r['mcc']:.3f}",
                f"{r['balanced_accuracy']:.3f}",
                f"{r['youden_j']:.3f}",
                r["fp"], r["fn"],
                f"{r['expected_cost']:.1f}",
            ))
        self._perm_importances = [
            (name, mean, std) for name, mean, std
            in report.get("permutation_importance", [])
        ]
        self._draw_confusion_matrix()
        self._draw_importances()
        self._draw_calibration()
        self._draw_roc()
        if not reapply_only:
            m = report["metrics"]
            self._set_status(
                f"Trained. F1={m['f1']:.4f} "
                f"[{m['f1_lo']:.3f},{m['f1_hi']:.3f}]  "
                f"ROC-AUC={m['roc_auc']:.4f}  threshold={chosen:.2f}  "
                f"conformal={m.get('conformal_coverage', 0):.3f}"
            )

    def _render_metric_cards(self, report: Dict[str, Any]) -> None:
        p = self.palette
        for w in self.metric_cards_frame.winfo_children():
            w.destroy()
        m = report["metrics"]
        cv = report["cross_validation"]

        def fmt(k: str) -> str:
            if f"{k}_lo" in m and not math.isnan(m[f"{k}_lo"]):
                return (f"{m[k]:.3f}\n"
                        f"[{m[k+'_lo']:.3f}, {m[k+'_hi']:.3f}]")
            return f"{m[k]:.3f}"
        cards = [
            ("Accuracy", fmt("accuracy"), p["fg"]),
            ("Balanced accuracy", fmt("balanced_accuracy"), p["fg"]),
            ("Precision", fmt("precision"), p["fg"]),
            ("Recall", fmt("recall"), p["fg"]),
            ("F1", fmt("f1"), p["green"]),
            ("MCC", f"{m['mcc']:.3f}", p["fg"]),
            ("ROC-AUC", fmt("roc_auc"), p["accent"]),
            ("PR-AUC", fmt("pr_auc"), p["accent"]),
            ("Brier", f"{m['brier']:.4f}", p["fg_dim"]),
            ("LogLoss", f"{m['log_loss']:.4f}", p["fg_dim"]),
            ("Conformal coverage",
             f"{m.get('conformal_coverage', 0):.3f} "
             f"(α={m.get('conformal_alpha', 0.1):.2f})", p["purple"]),
            ("Conformal set size",
             f"{m.get('conformal_set_size', 0):.3f}", p["purple"]),
            ("CV F1", f"{cv['f1']:.3f}±{cv['f1_std']:.3f}", p["purple"]),
            ("CV ROC-AUC",
             f"{cv['roc_auc']:.3f}±{cv['roc_auc_std']:.3f}", p["purple"]),
            ("Threshold", f"{report['thresholds']['chosen']:.3f}",
             p["yellow"]),
        ]
        per_row = 3
        for i, (label, value, color) in enumerate(cards):
            r, c = divmod(i, per_row)
            frame = tk.Frame(self.metric_cards_frame, bg=p["panel"],
                             highlightthickness=1,
                             highlightbackground=p["border"])
            frame.grid(row=r, column=c, padx=4, pady=4, sticky="nsew")
            tk.Label(frame, text=label, bg=p["panel"], fg=p["fg_dim"],
                     font=("Segoe UI", 9)).pack(anchor="w", padx=10,
                                                 pady=(6, 0))
            tk.Label(frame, text=value, bg=p["panel"], fg=color,
                     font=("Consolas", 10, "bold"), justify="left"
                     ).pack(anchor="w", padx=10, pady=(0, 6))
        for c in range(per_row):
            self.metric_cards_frame.grid_columnconfigure(c, weight=1)

    def _draw_confusion_matrix(self) -> None:
        c = self.cm_canvas
        p = self.palette
        c.delete("all")
        if not self.last_report:
            c.create_text(10, 10, anchor="nw",
                          text="Train the pipeline to see the matrix.",
                          fill=p["fg_dim"])
            return
        m = self.last_report["metrics"]
        tn, fp, fn, tp = m["tn"], m["fp"], m["fn"], m["tp"]
        total = max(1, tn + fp + fn + tp)
        w = max(c.winfo_width(), 400)
        h = max(c.winfo_height(), 170)
        pad = 34
        cw = (w - 2 * pad) / 2
        ch = (h - 2 * pad) / 2
        for col, row, val, label, color in (
            (0, 0, tn, "TN", p["green"]),
            (1, 0, fp, "FP", p["yellow"]),
            (0, 1, fn, "FN", p["red"]),
            (1, 1, tp, "TP", p["green"]),
        ):
            x0 = pad + col * cw
            y0 = pad + row * ch
            intensity = val / total
            fill = _hex_lerp(p["panel"], color, 0.15 + 0.55 * intensity)
            c.create_rectangle(x0, y0, x0 + cw, y0 + ch, fill=fill,
                                outline=p["border"])
            c.create_text(x0 + cw / 2, y0 + ch / 2 - 8, text=label,
                          fill=p["fg"], font=("Segoe UI", 10, "bold"))
            c.create_text(x0 + cw / 2, y0 + ch / 2 + 10, text=str(val),
                          fill=p["fg"], font=("Consolas", 14, "bold"))
        c.create_text(pad + cw, pad - 14, text="Predicted →",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_text(pad - 20, pad + ch, text="Actual\n↓",
                      fill=p["fg_dim"], font=("Segoe UI", 9),
                      justify="center")
        c.create_text(pad + cw * 0.5, h - 12, text="clean",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_text(pad + cw * 1.5, h - 12, text="phishing",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_text(pad - 22, pad + ch * 0.5, text="clean",
                      fill=p["fg_dim"], font=("Segoe UI", 9), angle=90)
        c.create_text(pad - 22, pad + ch * 1.5, text="phishing",
                      fill=p["fg_dim"], font=("Segoe UI", 9), angle=90)

    def _draw_importances(self) -> None:
        c = self.imp_canvas
        p = self.palette
        c.delete("all")
        if not self._perm_importances:
            c.create_text(10, 10, anchor="nw",
                          text="Train the pipeline to see importances.",
                          fill=p["fg_dim"])
            return
        w = max(c.winfo_width(), 300)
        h = max(c.winfo_height(), 180)
        pairs = self._perm_importances[:15]
        max_v = max((v for _, v, _ in pairs), default=1.0) or 1.0
        left = 200
        right = w - 40
        row_h = max(12, (h - 20) / max(1, len(pairs)))
        for i, (name, val, std) in enumerate(pairs):
            y = 10 + i * row_h
            c.create_text(left - 8, y + row_h / 2, anchor="e", text=name,
                          fill=p["fg_dim"], font=("Segoe UI", 9))
            bar_w = (right - left) * (val / max_v)
            c.create_rectangle(left, y + 2, left + bar_w, y + row_h - 2,
                                fill=p["accent"], outline="")
            if std > 0:
                e = (right - left) * (std / max_v)
                c.create_line(left + bar_w - e, y + row_h / 2,
                              left + bar_w + e, y + row_h / 2,
                              fill=p["fg"], width=1)
            c.create_text(left + bar_w + 6, y + row_h / 2, anchor="w",
                          text=f"{val:.3f}", fill=p["fg"],
                          font=("Consolas", 8))

    def _draw_calibration(self) -> None:
        c = self.cal_canvas
        p = self.palette
        c.delete("all")
        if not self.last_report or not \
                self.last_report.get("calibration_curve"):
            c.create_text(10, 10, anchor="nw",
                          text="Train the pipeline to see calibration.",
                          fill=p["fg_dim"])
            return
        pts = self.last_report["calibration_curve"]
        w = max(c.winfo_width(), 300)
        h = max(c.winfo_height(), 160)
        pad = 26
        c.create_line(pad, h - pad, w - pad, h - pad, fill=p["border"])
        c.create_line(pad, pad, pad, h - pad, fill=p["border"])
        c.create_line(pad, h - pad, w - pad, pad, fill=p["fg_dim"],
                      dash=(3, 3))
        for i in range(1, len(pts)):
            x0, y0 = pts[i - 1]
            x1, y1 = pts[i]
            c.create_line(
                pad + (w - 2 * pad) * x0, h - pad - (h - 2 * pad) * y0,
                pad + (w - 2 * pad) * x1, h - pad - (h - 2 * pad) * y1,
                fill=p["accent"], width=2)
        for x, y in pts:
            cx = pad + (w - 2 * pad) * x
            cy = h - pad - (h - 2 * pad) * y
            c.create_oval(cx - 2, cy - 2, cx + 2, cy + 2,
                          fill=p["accent"], outline="")
        c.create_text(pad, pad - 12, anchor="w",
                      text="Fraction positive",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_text(w - pad, h - pad + 14, anchor="e",
                      text="Mean predicted probability",
                      fill=p["fg_dim"], font=("Segoe UI", 9))

    def _draw_roc(self) -> None:
        c = self.roc_canvas
        p = self.palette
        c.delete("all")
        if not self.last_report:
            c.create_text(10, 10, anchor="nw",
                          text="Train the pipeline to see ROC/PR.",
                          fill=p["fg_dim"])
            return
        w = max(c.winfo_width(), 300)
        h = max(c.winfo_height(), 200)
        pad = 30
        c.create_line(pad, h - pad, w - pad, h - pad, fill=p["border"])
        c.create_line(pad, pad, pad, h - pad, fill=p["border"])
        c.create_line(pad, h - pad, w - pad, pad, fill=p["fg_dim"],
                      dash=(3, 3))
        roc = self.last_report.get("roc_points", [])
        for i in range(1, len(roc)):
            x0, y0 = roc[i - 1]
            x1, y1 = roc[i]
            c.create_line(
                pad + (w - 2 * pad) * x0, h - pad - (h - 2 * pad) * y0,
                pad + (w - 2 * pad) * x1, h - pad - (h - 2 * pad) * y1,
                fill=p["accent"], width=2)
        pr = self.last_report.get("pr_points", [])
        for i in range(1, len(pr)):
            x0, y0 = pr[i - 1]
            x1, y1 = pr[i]
            c.create_line(
                pad + (w - 2 * pad) * x0, h - pad - (h - 2 * pad) * y0,
                pad + (w - 2 * pad) * x1, h - pad - (h - 2 * pad) * y1,
                fill=p["green"], width=1, dash=(2, 2))
        m = self.last_report["metrics"]
        c.create_text(w - pad, pad - 12, anchor="e",
                      text=f"ROC-AUC = {m['roc_auc']:.4f}   "
                           f"PR-AUC = {m['pr_auc']:.4f}",
                      fill=p["accent"], font=("Consolas", 10, "bold"))
        c.create_text(pad, pad - 12, anchor="w",
                      text="TPR / Precision",
                      fill=p["fg_dim"], font=("Segoe UI", 9))
        c.create_text(w - pad, h - pad + 14, anchor="e",
                      text="FPR / Recall",
                      fill=p["fg_dim"], font=("Segoe UI", 9))

    def _refresh_dataset_preview(self) -> None:
        cfg = replace(self.cfg, n_per_class=150)
        df = generate_dataset(cfg)
        cols = list(df.columns)
        self.dataset_tree.configure(columns=cols)
        p = self.palette
        for col in cols:
            self.dataset_tree.heading(col, text=col)
            self.dataset_tree.column(col, width=110, anchor="center")
        for row in self.dataset_tree.get_children():
            self.dataset_tree.delete(row)
        self.dataset_tree.tag_configure("phish", background=p["phish_bg"])
        self.dataset_tree.tag_configure("benign", background=p["benign_bg"])
        for _, row in df.head(300).iterrows():
            values = [f"{v:.3f}" if isinstance(v, float) else v
                      for v in row]
            tag = "phish" if row["label"] == 1 else "benign"
            self.dataset_tree.insert("", "end", values=values, tags=(tag,))

    def _compute_drift(self) -> None:
        raw = self.drift_input.get("1.0", "end").strip()
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            messagebox.showinfo("No URLs", "Paste fresh URLs.")
            return
        report = self.analyzer.drift_report(urls)
        for row in self.drift_tree.get_children():
            self.drift_tree.delete(row)
        if "error" in report:
            messagebox.showerror("Drift", report["error"])
            return
        warn = self.cfg.drift_psi_warn
        alert = self.cfg.drift_psi_alert
        rows = sorted(((k, v) for k, v in report.items()
                        if not k.startswith("_")),
                       key=lambda kv: -kv[1])
        for feat, psi_val in rows:
            if psi_val >= alert:
                status, tag = "ALERT", "alert"
            elif psi_val >= warn:
                status, tag = "warn", "warn"
            else:
                status, tag = "ok", "ok"
            self.drift_tree.insert("", "end",
                                    values=(feat, f"{psi_val:.4f}", status),
                                    tags=(tag,))
        max_psi = report.get("_max_psi", 0.0)
        self._set_status(f"Drift: max PSI = {max_psi:.4f}")

    def _apply_settings(self) -> None:
        self.cfg.model_type = self.model_type_var.get()
        self.cfg.calibration_method = self.calib_method_var.get()
        self.cfg.use_calibration = self.cfg.calibration_method != "none"
        self.cfg.cost_fn = float(self.cost_var.get())
        self.cfg.n_per_class = int(self.n_var.get())
        self.cfg.random_state = int(self.seed_var.get())
        self.cfg.bootstrap_iters = int(self.boot_var.get())
        self.cfg.adversarial_probe = bool(self.adv_var.get())
        self.cfg.use_ngram_embeddings = bool(self.ngram_var.get())
        self.cfg.conformal_alpha = float(self.alpha_var.get())
        self.cfg.webhook_url = self.webhook_var.get().strip() or None
        _save_json(CONFIG_PATH, asdict(self.cfg))
        self._train_model_async()

    def _menu_load_urls(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"),
                        ("CSV", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8",
                                             errors="ignore")
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))
            return
        self.batch_input.delete("1.0", "end")
        self.batch_input.insert("1.0", content)
        self.notebook.select(self.tab_batch)
        self._set_status(f"Loaded URLs from {path}")

    def _menu_save_model(self) -> None:
        if self.analyzer.model is None:
            messagebox.showinfo("No pipeline", "Train the pipeline first.")
            return
        if not _HAS_JOBLIB:
            messagebox.showerror("Missing dependency",
                                  "joblib is required to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".joblib",
            filetypes=[("Joblib model", "*.joblib"),
                        ("All files", "*.*")],
            initialfile=f"phishing_model_"
                         f"{datetime.now():%Y%m%d_%H%M%S}.joblib",
        )
        if not path:
            return
        try:
            self.analyzer.save(path)
            self._set_status(f"Pipeline saved → {path}")
        except Exception as exc:
            messagebox.showerror("Save error", str(exc))

    def _menu_load_model(self) -> None:
        if not _HAS_JOBLIB:
            messagebox.showerror("Missing dependency",
                                  "joblib is required to load.")
            return
        path = filedialog.askopenfilename(
            filetypes=[("Joblib model", "*.joblib"),
                        ("All files", "*.*")])
        if not path:
            return
        try:
            self.analyzer = Analyzer.load(path)
            self.threshold_var.set(self.analyzer.threshold)
            self._on_threshold_change()
            self._set_status(f"Pipeline loaded ← {path}")
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))

    def _register_current_model(self) -> None:
        if not self.last_report:
            messagebox.showinfo("No pipeline", "Train the pipeline first.")
            return
        version = simpledialog.askstring(
            "Version (semver)", "Enter version:",
            initialvalue="1.0.0") if _HAS_TK else None
        if not version:
            return
        try:
            path = APP_DIR / "registry" / f"model_{version}.joblib"
            self.analyzer.save(str(path))
            self.registry.register(
                version, path, self.last_report["config_hash"],
                self.last_report["metrics"],
                notes="registered from GUI")
            self._set_status(f"Pipeline v{version} registered")
        except Exception as exc:
            messagebox.showerror("Registration error", str(exc))

    def _list_registry(self) -> None:
        models = self.registry.list_models()
        if not models:
            messagebox.showinfo("Registry", "No pipelines registered.")
            return
        lines = []
        for m in models:
            roc = m['metrics'].get('roc_auc', float('nan'))
            lines.append(f"v{m['version']}  {m['ts']}  "
                          f"hash={m['cfg_hash']}  roc_auc={roc:.4f}")
        messagebox.showinfo("Registry", "\n".join(lines))

    def _export_report_html(self) -> None:
        if not self.last_report:
            messagebox.showinfo("No report", "Train the pipeline first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML", "*.html")],
            initialfile=f"report_{datetime.now():%Y%m%d_%H%M%S}.html")
        if not path:
            return
        try:
            Path(path).write_text(self._render_html_report(),
                                    encoding="utf-8")
            self._set_status(f"HTML report → {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))

    def _render_html_report(self) -> str:
        r = self.last_report or {}
        m = r.get("metrics", {})
        cfg = r.get("config", {})
        rows = "\n".join(
            f"<tr><td>{html.escape(str(k))}</td><td>{v}</td></tr>"
            for k, v in m.items()
            if not k.endswith("_lo") and not k.endswith("_hi")
        )
        cv_rows = "\n".join(
            f"<tr><td>{html.escape(str(k))}</td>"
            f"<td>{v:.4f}</td></tr>"
            for k, v in r.get("cross_validation", {}).items()
        )
        cfg_rows = "\n".join(
            f"<tr><td>{html.escape(str(k))}</td>"
            f"<td>{html.escape(str(v))}</td></tr>"
            for k, v in cfg.items()
        )
        ts = html.escape(r.get("timestamp", ""))
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Phishing Pipeline Report</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 900px;
         margin: 2rem auto; }}
 table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
 th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
 th {{ background: #f6f8fa; }}
 h1, h2 {{ border-bottom: 1px solid #eee; padding-bottom: 4px; }}
</style></head><body>
<h1>Phishing Pipeline Report</h1>
<p><em>Generated {ts}</em></p>
<p>Model hash: <code>{html.escape(r.get('model_hash', '?'))}</code> &nbsp;
   Config hash: <code>{html.escape(r.get('config_hash', '?'))}</code></p>
<h2>Metrics (eval)</h2><table>{rows}</table>
<h2>Cross-validation</h2><table>{cv_rows}</table>
<h2>Config</h2><table>{cfg_rows}</table>
<h2>Thresholds</h2>
<pre>{html.escape(json.dumps(r.get("thresholds", {}),
                              indent=2, ensure_ascii=False))}</pre>
</body></html>"""

    def _export_report_json(self) -> None:
        if not self.last_report:
            messagebox.showinfo("No report", "Train the pipeline first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile=f"report_{datetime.now():%Y%m%d_%H%M%S}.json")
        if not path:
            return
        slim = {k: v for k, v in self.last_report.items()
                if k not in ("y_test", "y_prob", "roc_points", "pr_points")}
        try:
            Path(path).write_text(
                json.dumps(slim, indent=2, default=str,
                            ensure_ascii=False),
                encoding="utf-8")
            self._set_status(f"JSON report → {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))

    def _export_model_card(self) -> None:
        if not self.last_report:
            messagebox.showinfo("No report", "Train the pipeline first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".md", filetypes=[("Markdown", "*.md")],
            initialfile="model_card.md")
        if not path:
            return
        try:
            self.analyzer.write_model_card(path)
            self._set_status(f"Model card → {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))

    def _export_stix(self) -> None:
        if not self._batch_results:
            messagebox.showinfo("No data",
                                 "Run a batch scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("STIX 2.1", "*.json")],
            initialfile=f"indicators_{datetime.now():%Y%m%d_%H%M%S}.json")
        if not path:
            return
        try:
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": [],
            }
            for r in self._batch_results:
                if r.verdict != 1:
                    continue
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": f"Phishing URL: {r.url}",
                    "pattern": f"[url:value = '{r.url}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(timezone.utc).isoformat(),
                    "labels": ["malicious-activity"],
                    "confidence": int(r.probability * 100),
                    "description": "; ".join(
                        reason.text for reason in r.reasons[:5]),
                }
                bundle["objects"].append(obj)
            Path(path).write_text(
                json.dumps(bundle, indent=2, ensure_ascii=False),
                encoding="utf-8")
            self._set_status(f"STIX indicators → {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))

    def _save_config(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile="config.json")
        if not path:
            return
        try:
            Path(path).write_text(self.cfg.to_json(), encoding="utf-8")
            self._set_status(f"Config saved → {path}")
        except Exception as exc:
            messagebox.showerror("Save error", str(exc))

    def _load_config(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.cfg = Config.from_json(
                Path(path).read_text(encoding="utf-8"))
            try:
                self.model_type_var.set(self.cfg.model_type)
                self.calib_method_var.set(self.cfg.calibration_method)
                self.cost_var.set(int(self.cfg.cost_fn))
                self.n_var.set(int(self.cfg.n_per_class))
                self.seed_var.set(int(self.cfg.random_state))
                self.boot_var.set(int(self.cfg.bootstrap_iters))
                self.adv_var.set(bool(self.cfg.adversarial_probe))
                self.ngram_var.set(bool(self.cfg.use_ngram_embeddings))
                self.alpha_var.set(float(self.cfg.conformal_alpha))
                self.webhook_var.set(self.cfg.webhook_url or "")
            except Exception:
                pass
            self._set_status(f"Config loaded ← {path}")
        except Exception as exc:
            messagebox.showerror("Load error", str(exc))

    def _manage_watchlist(self) -> None:
        win = tk.Toplevel(self)
        win.title("Watchlist")
        win.configure(bg=self.palette["bg"])
        tk.Label(win, text="Substrings always flagged as phishing:",
                 bg=self.palette["bg"], fg=self.palette["fg"]
                 ).pack(anchor="w", padx=10, pady=(10, 4))
        text = tk.Text(win, width=60, height=12, bg=self.palette["panel"],
                       fg=self.palette["fg"], relief="flat",
                       insertbackground=self.palette["fg"])
        text.pack(padx=10, pady=4)
        text.insert("1.0", "\n".join(self.watchlist))

        def save() -> None:
            self.watchlist = [l.strip().lower() for l in
                              text.get("1.0", "end").splitlines() if l.strip()]
            _save_json(WATCHLIST_PATH, self.watchlist)
            win.destroy()
            self._set_status(f"Watchlist updated "
                              f"({len(self.watchlist)} entries)")

        tk.Button(win, text="Save", command=save,
                  bg=self.palette["accent"], fg="#000000",
                  relief="flat", padx=14, pady=4).pack(pady=8)

    def _show_active_queue(self) -> None:
        items = self.analyzer.active_queue.pop_batch(50)
        if not items:
            messagebox.showinfo("Active learning",
                                 "Queue is empty.")
            return
        win = tk.Toplevel(self)
        win.title("Active learning queue")
        win.geometry("800x400")
        win.configure(bg=self.palette["bg"])
        tree = ttk.Treeview(win, columns=("uncertainty", "url",
                                            "probability"),
                             show="headings")
        for c, w in zip(("uncertainty", "url", "probability"),
                         (120, 540, 100)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w)
        for unc, url, prob in items:
            tree.insert("", "end",
                        values=(f"{unc:.3f}", url, f"{prob:.3f}"))
        tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _show_audit_recent(self) -> None:
        if self.analyzer.audit is None:
            messagebox.showinfo("Audit", "Audit log unavailable.")
            return
        rows = self.analyzer.audit.recent(200)
        win = tk.Toplevel(self)
        win.title("Recent predictions (audit log)")
        win.geometry("1000x500")
        win.configure(bg=self.palette["bg"])
        tree = ttk.Treeview(win, columns=("ts", "url", "prob", "pred",
                                            "risk", "source"),
                             show="headings")
        for c, w in zip(("ts", "url", "prob", "pred", "risk", "source"),
                         (180, 460, 70, 60, 60, 90)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w)
        for r in rows:
            tree.insert("", "end", values=(
                r["ts"], r["url"], f"{r['prob']:.3f}",
                r["prediction"], r["risk"], r["source"]))
        tree.pack(fill="both", expand=True, padx=10, pady=10)

    def _menu_about(self) -> None:
        messagebox.showinfo(
            "About",
            "AI Phishing URL Detector\n\n"
            "Pipeline:\n"
            "  • Stacking ensemble (RF + ExtraTrees + HGB) → "
            "logistic meta\n"
            "  • Hashed char-n-grams (lexical texture)\n"
            "  • Probability calibration (sigmoid/isotonic)\n"
            "  • Multi-criteria threshold tuning with cost "
            "consideration\n"
            "  • Bootstrap confidence intervals\n"
            "  • Split-conformal + ABSTAIN band\n"
            "  • TreeSHAP-like additive explanations\n"
            "  • Permutation importance + local tree contributions\n"
            "  • Adversarial probing: character mutations of URLs\n"
            "  • Online learning from feedback (SGD partial_fit)\n"
            "  • Active learning queue for uncertain cases\n"
            "  • Drift monitoring (PSI)\n"
            "  • SQLite audit log + pipeline registry\n"
            "  • STIX 2.1 export + webhook\n\n"
            "Data: fully synthetic, generated on the fly.\n"
            "Hotkeys: Ctrl+Enter — scan, Ctrl+T — train, "
            "Ctrl+S — save, Ctrl+O — load, Ctrl+Q — exit.",
        )


def _cli_train(args: argparse.Namespace) -> None:
    cfg = Config()
    if args.config:
        cfg = Config.from_json(
            Path(args.config).read_text(encoding="utf-8"))
    if args.samples is not None:
        cfg.n_per_class = args.samples
    if args.model_type:
        cfg.model_type = args.model_type
    if args.no_ngrams:
        cfg.use_ngram_embeddings = False
    if args.alpha is not None:
        cfg.conformal_alpha = args.alpha
    cfg.bootstrap_iters = (args.bootstrap if args.bootstrap is not None
                            else cfg.bootstrap_iters)
    analyzer = Analyzer()
    report = analyzer.train_pipeline(cfg)
    m = report["metrics"]
    print(_color(f"F1={m['f1']:.4f} "
                 f"[{m['f1_lo']:.3f},{m['f1_hi']:.3f}]  "
                 f"ROC-AUC={m['roc_auc']:.4f}  MCC={m['mcc']:.4f}  "
                 f"threshold={report['thresholds']['chosen']:.2f}  "
                 f"conformal={m['conformal_coverage']:.3f}", _C.BOLD))
    if args.out:
        analyzer.save(args.out)
        print(f"Pipeline saved → {args.out}")
    if args.report:
        Path(args.report).write_text(
            json.dumps({k: v for k, v in report.items()
                        if k not in ("y_test", "y_prob",
                                      "roc_points", "pr_points")},
                       indent=2, default=str, ensure_ascii=False),
            encoding="utf-8")
        print(f"Report saved → {args.report}")

def _cli_scan(args: argparse.Namespace) -> None:
    if not args.model:
        print("--model is required for scan", file=sys.stderr)
        sys.exit(2)
    analyzer = Analyzer.load(args.model)
    if args.threshold is not None:
        analyzer.threshold = float(args.threshold)
    urls: List[str] = list(args.urls or [])
    if args.file:
        content = Path(args.file).read_text(encoding="utf-8",
                                              errors="ignore")
        urls.extend(u.strip() for u in content.splitlines() if u.strip())
    if not urls:
        print("No URLs provided.", file=sys.stderr)
        sys.exit(2)
    results = analyzer.scan_many(urls)
    if args.json:
        print(json.dumps([r.to_dict() for r in results],
                          indent=2, default=str, ensure_ascii=False))
        return
    for res in results:
        _print_result(res)

def _cli_serve(args: argparse.Namespace) -> None:
    if not args.model:
        print("--model is required for serve", file=sys.stderr)
        sys.exit(2)
    analyzer = Analyzer.load(args.model)
    analyzer.audit = AuditLog(AUDIT_PATH)
    run_http(analyzer, host=args.host, port=args.port)

def _cli_repl(args: argparse.Namespace) -> None:
    analyzer = Analyzer()
    if args.model:
        analyzer = Analyzer.load(args.model)
    else:
        print("Training a fresh pipeline…")
        analyzer.train_pipeline(Config())
    print("Enter a URL to scan or 'q' to quit.")
    while True:
        try:
            u = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if u.lower() in ("q", "quit", "exit", ""):
            break
        _print_result(analyzer.scan_url(u, source="cli"))

def _cli_watch(args: argparse.Namespace) -> None:
    if not args.model:
        print("--model is required for watch", file=sys.stderr)
        sys.exit(2)
    if not args.file:
        print("--file is required for watch", file=sys.stderr)
        sys.exit(2)
    analyzer = Analyzer.load(args.model)
    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)
    seen: set = set()
    print(f"Watching {path} (Ctrl+C to exit)…")
    try:
        while True:
            try:
                lines = path.read_text(encoding="utf-8",
                                        errors="ignore").splitlines()
            except Exception:
                lines = []
            for line in lines:
                line = line.strip()
                if not line or line in seen:
                    continue
                seen.add(line)
                _print_result(analyzer.scan_url(line, source="watch"))
            time.sleep(1.5)
    except KeyboardInterrupt:
        pass

def _cli_gui(_args: argparse.Namespace) -> None:
    if not _HAS_TK:
        print("Tkinter is unavailable.", file=sys.stderr)
        sys.exit(1)
    app = Application()
    app.after(200, app._train_model_async)
    app.mainloop()

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing",
        description="Phishing URL detector (single file).")
    sub = p.add_subparsers(dest="cmd")
    g = sub.add_parser("gui", help="Launch the Tkinter GUI.")
    g.set_defaults(func=_cli_gui)
    t = sub.add_parser("train", help="Train the pipeline and save.")
    t.add_argument("--config", type=str, default=None)
    t.add_argument("--samples", type=int, default=None)
    t.add_argument("--model-type", type=str, default=None,
                    choices=["stack", "voting", "rf", "extratrees",
                              "hgb", "sgd"])
    t.add_argument("--bootstrap", type=int, default=None)
    t.add_argument("--alpha", type=float, default=None)
    t.add_argument("--no-ngrams", action="store_true")
    t.add_argument("--out", type=str, default=None)
    t.add_argument("--report", type=str, default=None)
    t.set_defaults(func=_cli_train)
    s = sub.add_parser("scan", help="Scan URLs with a saved pipeline.")
    s.add_argument("--model", type=str, required=True)
    s.add_argument("--file", type=str, default=None)
    s.add_argument("--threshold", type=float, default=None)
    s.add_argument("--json", action="store_true")
    s.add_argument("urls", nargs="*")
    s.set_defaults(func=_cli_scan)
    v = sub.add_parser("serve", help="Launch a local HTTP server.")
    v.add_argument("--model", type=str, required=True)
    v.add_argument("--host", type=str, default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.set_defaults(func=_cli_serve)
    r = sub.add_parser("repl", help="Interactive REPL.")
    r.add_argument("--model", type=str, default=None)
    r.set_defaults(func=_cli_repl)
    w = sub.add_parser("watch", help="Watch a file and scan new lines.")
    w.add_argument("--model", type=str, required=True)
    w.add_argument("--file", type=str, required=True)
    w.set_defaults(func=_cli_watch)
    return p

def main(argv: Optional[Sequence[str]] = None) -> None:
    args = build_argparser().parse_args(argv)
    if not getattr(args, "cmd", None):
        if _HAS_TK:
            _cli_gui(args)
        else:
            _cli_repl(args)
        return
    args.func(args)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
