"""Lossless on-demand Markdown representation."""

from __future__ import annotations

import json
import re

from .errors import GateError

META_START = "<!-- arcturion-gate:metadata"
FIELDS_START = "<!-- arcturion-gate:fields"
BLOCK_END = "-->"


def render(record: dict) -> str:
    metadata = {
        "id": record["id"],
        "category": record["category"],
        "version": record["version"],
        "aliases": record.get("aliases", []),
        "tags": record.get("tags", []),
    }
    return (
        f"{META_START}\n{json.dumps(metadata, ensure_ascii=False, indent=2)}\n{BLOCK_END}\n\n"
        f"# {record['title']}\n\n"
        f"## Fields\n\n{FIELDS_START}\n{json.dumps(record.get('fields', {}), ensure_ascii=False, indent=2)}\n{BLOCK_END}\n\n"
        f"## Notes\n\n{record.get('notes_markdown', '')}\n"
    )


def _json_block(text: str, marker: str) -> dict:
    pattern = re.escape(marker) + r"\n(.*?)\n" + re.escape(BLOCK_END)
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        raise GateError("INVALID", f"Missing Markdown block: {marker}")
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise GateError("INVALID", f"Invalid JSON inside {marker}") from exc
    if not isinstance(value, dict):
        raise GateError("INVALID", f"Expected object inside {marker}")
    return value


def parse(text: str) -> dict:
    metadata = _json_block(text, META_START)
    fields = _json_block(text, FIELDS_START)
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    notes_match = re.search(r"^## Notes\s*\n(.*)\Z", text, re.MULTILINE | re.DOTALL)
    if not title_match:
        raise GateError("INVALID", "Markdown record is missing a title")
    return {
        "id": str(metadata.get("id", "")),
        "category": str(metadata.get("category", "Secret")),
        "version": int(metadata.get("version", 0)),
        "title": title_match.group(1).strip(),
        "aliases": list(metadata.get("aliases", [])),
        "tags": list(metadata.get("tags", [])),
        "fields": fields,
        "notes_markdown": (notes_match.group(1).rstrip() if notes_match else ""),
    }

