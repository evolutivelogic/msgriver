#!/usr/bin/env python3
"""Verify the public-safe observable identifier migration contract.

This is a source-integrity guard, not a runtime behavior test. The product
catalog remains the authority; the guard makes the one disclosure-driven
identifier replacement explicit and preserves the catalog-wide identifier
format contract.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "specs" / "atomic-observables.toml"
PUBLIC_SAFE_ID = "TRAILING_WRAPPER_PROVENANCE_CANDIDATE_LIMIT"
OBSERVABLE_ID = re.compile(r"[A-Z][A-Z0-9_-]{2,63}")
STATEMENT = (
    "Trailing Markdown-wrapper/outer-HTML provenance accepts at most 256 "
    "combined candidates per line before suffix interpretation;"
)


def fail(message: str) -> None:
    print(f"Task0313 RED: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    text = CATALOG.read_text(encoding="utf-8")
    identifiers = re.findall(r'^observable_id = "([^"]+)"$', text, re.MULTILINE)
    malformed = [identifier for identifier in identifiers if not OBSERVABLE_ID.fullmatch(identifier)]
    if malformed:
        fail(f"catalog has {len(malformed)} malformed observable identifier(s)")
    records = [record for record in text.split("[[observable]]") if record.strip()]
    matching = [record for record in records if f'statement = "{STATEMENT}"' in record]
    if len(matching) != 1:
        fail(f"expected one targeted observable record, found {len(matching)}")
    if matching[0].count(f'observable_id = "{PUBLIC_SAFE_ID}"') != 1:
        fail("targeted observable has not received the public-safe identifier")
    if text.count(f'observable_id = "{PUBLIC_SAFE_ID}"') != 1:
        fail("public-safe identifier is not unique in the catalog")
    print("Task0313 GREEN: public-safe observable identifier is unique and bound")


if __name__ == "__main__":
    main()
