"""Bounded, non-executing material reads with explicit visibility receipts."""
import codecs
import hashlib
import json
import unicodedata
import uuid
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024
BYTECODE = {'.pyc', '.pyo', '.pyd'}
# Directories whose contents are usually dependency caches or build output. Flagged as
# inventory data, never excluded here: the skill's own rule is that artefacts loaded at
# runtime do live in such directories, so only the auditor may rule them out.
FLAG_DIRS = {'__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build', '.next', '.nuxt'}


def flags(path):
    """Inventory markers for a material. Kept through the pruning: zero of 1891 materials
    on one real target carried either marker, but `tests/test_audit_extensions.py`
    compiles a genuinely importable `.pyc` with a side effect in it and asserts the skill
    treats it as data — "no hits on this target" is not "no hits ever", which is the same
    reasoning that kept `opaque` and `artifacts`."""
    result = []
    if set(path.parts) & FLAG_DIRS:
        result.append('dependency_cache_or_build')
    if path.suffix.lower() in BYTECODE:
        result.append('bytecode_or_extension')
    return result


# Character classes as deletion tables, so each predicate below is one C-level pass
# instead of a Python loop over every character. Profiled on a 2-file unit: those loops
# ran 115M, 51M and 32M times and cost 43 of the preflight's 120 seconds, while the
# sha256 everyone assumed was the bottleneck cost 4.8. The classes are enumerated from
# `unicodedata.category` and asserted equal to the old predicates in the tests — these
# decide whether a material is readable at all, so a silent change in what counts as a
# control character silently changes what gets audited.
_CONTROL = dict.fromkeys(
    list(range(0x00, 0x09)) + [0x0b, 0x0c] + list(range(0x0e, 0x20))
    + list(range(0x7f, 0xa0)) + list(range(0xd800, 0xe000)))
_PRINTABLE = frozenset(b'\n\r\t') | frozenset(range(0x20, 0x7f))


def _count(text, table):
    """How many characters of `text` fall in `table`, in one pass."""
    return len(text) - len(text.translate(table))


def _unprintable(text):
    """Characters outside \n \r \t and U+0020-U+007E, counted without a table over the
    whole code space: the text is first reduced to its distinct characters."""
    return sum(text.count(c) for c in set(text) if ord(c) not in _PRINTABLE)


def _format_controls(text):
    """Whether any character is category Cf, checked on the distinct characters only."""
    return any(unicodedata.category(c) == 'Cf' for c in set(text))


def decode(raw, encoding=None):
    if len(raw) > MAX_BYTES:
        raise ValueError('Material exceeds bounded decoding size')
    if encoding:
        try:
            encoding = codecs.lookup(encoding).name
        except LookupError as exc:
            raise ValueError('Unknown text encoding') from exc
        if encoding not in {'utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be',
                            'utf-32', 'utf-32-le', 'utf-32-be', 'gb18030', 'gbk', 'big5', 'cp1252', 'iso8859-1'}:
            raise ValueError('Unsupported text encoding')
    elif raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = 'utf-32'
    elif raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = 'utf-16'
    else:
        encoding = 'utf-8-sig'
    text = raw.decode(encoding, errors='strict')
    # Via `_count`, not a per-character loop. The helpers and their exhaustive
    # equivalence tests were added earlier without this line being changed to call them,
    # so the loop stayed on the production path and the 83M `unicodedata.category` calls
    # it makes still dominated `validate` — the tests passed because they exercised the
    # helpers directly.
    if '\x00' in text or _count(text, _CONTROL) > max(1, len(text) * .02):
        raise ValueError('Binary control characters; a text view is unavailable')
    return text, encoding


def recovered_view(text):
    """Expose one reversible interpretation as a candidate, never replace source."""
    if not text or text.isascii():
        return None
    ratio = lambda s: sum(c in '\n\r\t' or ' ' <= c <= '~' for c in s) / max(1, len(s))
    for encoding in ('utf-16-le', 'utf-16-be'):
        try:
            candidate = text.encode(encoding).decode('utf-8')
        except UnicodeError:
            continue
        if candidate != text and ratio(candidate) - ratio(text) >= .25 and '\x00' not in candidate:
            return {'transform': encoding + ' -> utf-8', 'text': candidate}
    return None


def inspect(path, raw=None):
    """Classify a material's visibility. `raw` lets the caller pass bytes it already
    read: `inventory` needs both this and the file's sha256, and opening the file twice
    cost one of the two reads per material across 1891 of them."""
    result = {'flags': flags(path), 'visibility': 'text', 'encoding': None, 'visibility_reason': ''}
    try:
        if raw is None:
            with path.open('rb') as handle:
                raw = handle.read(MAX_BYTES + 1)
        if path.suffix.lower() in BYTECODE:
            result.update(visibility='opaque', visibility_reason='Executable artifact; inspect its loader and provenance without executing it')
        elif len(raw) > MAX_BYTES:
            result.update(visibility='oversized', visibility_reason='Requires scoped extraction; no full decoded view')
        else:
            # Only the decode verdict and the encoding are kept. The two flags this used
            # to add (`format_control_characters`, `reversible_encoding_candidate`) were
            # read by nothing but the report's material list and never fired once across
            # 1891 materials, while computing them walked every character of every file
            # twice. `recovered_view` itself stays — `records.py` re-derives it when an
            # evidence row claims the recovered view.
            text, encoding = decode(raw)
            result['encoding'] = encoding
    except (UnicodeError, ValueError) as exc:
        result.update(visibility='undecodable', visibility_reason=str(exc))
    except OSError as exc:
        result.update(visibility='unreadable', visibility_reason=type(exc).__name__)
    return result


