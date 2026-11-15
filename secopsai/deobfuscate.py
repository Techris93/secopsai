"""Unpack hidden payloads in package source so the rules can see them (frontier phase 3).

Malicious packages hide their real code: a base64 or hex string handed to
``eval``/``exec``/``Function``, a zlib- or gzip-compressed blob, an obfuscator
string table, ``marshal``/``codecs`` tricks. The YARA and behaviour rules only
read the files as published, so the payload's network calls and credential
reads are invisible to them.

``expand`` decodes such literals in code files (two levels deep, within byte
budgets) and returns the original members plus each decoded payload as a
virtual member named ``<file>.decoded-<n><ext>``. Only decodes that come out as
readable text that looks like code are kept, so embedded images, fonts and
data blobs are not turned into noise. Nothing is executed.
"""
from __future__ import annotations

import base64
import os
import binascii
import codecs
import gzip
import re
import zlib
from typing import Iterable, List, Optional, Tuple

CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".py", ".pyw", ".sh", ".ps1", ".rb", ".php")
MIN_LITERAL = 40
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_DECODED_BYTES = 1024 * 1024
MAX_TOTAL_DECODED = 8 * 1024 * 1024
MAX_PAYLOADS = 40
MAX_DEPTH = 2
PRINTABLE_SHARE = 0.85
CODE_HINT = re.compile(
    rb"(require\(|import |from \w+ import|function|=>|\beval\b|\bexec\b|child_process|subprocess|socket|http[s]?://|"
    rb"process\.env|os\.environ|Buffer\.from|fetch\(|XMLHttpRequest|powershell|/bin/(?:ba)?sh|curl |wget |\bvar |\bconst |\blet |def |class )")
STRING_LITERAL = re.compile(rb"""(?:"([^"\\\n]{%d,})"|'([^'\\\n]{%d,})'|`([^`\\]{%d,})`)""" % (MIN_LITERAL, MIN_LITERAL, MIN_LITERAL))
BASE64 = re.compile(rb"^[A-Za-z0-9+/_-]+={0,2}$")
HEX = re.compile(rb"^(?:[0-9a-fA-F]{2})+$")
ESCAPED_HEX = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){%d,}" % (MIN_LITERAL // 2))
CHAR_CODES = re.compile(rb"fromCharCode\(((?:\s*\d{2,3}\s*,){%d,}\s*\d{2,3}\s*)\)" % (MIN_LITERAL // 4))
ROT13_CALL = re.compile(rb"""codecs\.decode\(\s*['"]([^'"]{%d,})['"]\s*,\s*['"]rot[_-]?13['"]""" % MIN_LITERAL)


def _readable(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(sample) >= PRINTABLE_SHARE


def _inflate(data: bytes) -> Optional[bytes]:
    """zlib / gzip / raw-deflate payloads, bounded."""
    for opener in (lambda raw: zlib.decompressobj().decompress(raw, MAX_DECODED_BYTES),
                   lambda raw: zlib.decompressobj(-15).decompress(raw, MAX_DECODED_BYTES),
                   lambda raw: gzip.decompress(raw)[:MAX_DECODED_BYTES]):
        try:
            out = opener(data)
        except (zlib.error, OSError, EOFError):
            continue
        if out:
            return out
    return None


def _decode_literal(text: bytes) -> Optional[bytes]:
    """The plain bytes behind one string literal, when it decodes to something."""
    candidate = text.strip()
    decoded: Optional[bytes] = None
    if HEX.match(candidate) and len(candidate) >= MIN_LITERAL:
        decoded = binascii.unhexlify(candidate)
    elif BASE64.match(candidate) and len(candidate) % 4 in (0, 2, 3):
        try:
            padded = candidate + b"=" * (-len(candidate) % 4)
            decoded = base64.urlsafe_b64decode(padded.replace(b"+", b"-").replace(b"/", b"_"))
        except (binascii.Error, ValueError):
            decoded = None
    if decoded is None:
        return None
    inflated = _inflate(decoded)
    return (inflated if inflated is not None else decoded)[:MAX_DECODED_BYTES]


def _payloads(content: bytes) -> Iterable[bytes]:
    for match in STRING_LITERAL.finditer(content):
        literal = match.group(1) or match.group(2) or match.group(3) or b""
        decoded = _decode_literal(literal)
        if decoded is not None:
            yield decoded
    for match in ESCAPED_HEX.finditer(content):
        yield binascii.unhexlify(match.group(0).replace(b"\\x", b""))
    for match in CHAR_CODES.finditer(content):
        try:
            yield bytes(int(code) for code in match.group(1).split(b",") if code.strip())
        except ValueError:
            continue
    for match in ROT13_CALL.finditer(content):
        yield codecs.decode(match.group(1).decode("latin-1"), "rot13").encode("latin-1")


def expand(members: List[Tuple[str, bytes]]) -> List[Tuple[str, bytes]]:
    """``members`` plus decoded payloads that read as code (never executed).

    ``SECOPSAI_DEOBFUSCATE=0`` turns it off (used to measure its effect).
    """
    if os.environ.get("SECOPSAI_DEOBFUSCATE", "1") == "0":
        return list(members)
    out = list(members)
    total = 0
    count = 0
    queue = [(name, content, 0) for name, content in members
             if name.lower().endswith(CODE_SUFFIXES) and isinstance(content, (bytes, bytearray)) and len(content) <= MAX_MEMBER_BYTES]
    seen = set()
    while queue and count < MAX_PAYLOADS and total < MAX_TOTAL_DECODED:
        name, content, depth = queue.pop(0)
        for index, payload in enumerate(_payloads(bytes(content)), start=1):
            if count >= MAX_PAYLOADS or total >= MAX_TOTAL_DECODED:
                break
            digest = hash(payload)
            if digest in seen or not _readable(payload) or not CODE_HINT.search(payload):
                continue
            seen.add(digest)
            # Keep the original extension: the behaviour rules select files by it.
            suffix = next((ext for ext in CODE_SUFFIXES if name.lower().endswith(ext)), ".js")
            virtual = f"{name}.decoded-{index}{suffix}"
            out.append((virtual, payload))
            total += len(payload)
            count += 1
            if depth + 1 < MAX_DEPTH:
                queue.append((virtual, payload, depth + 1))
    return out
