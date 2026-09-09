from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.1.0"
DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}
DEFAULT_EXCLUDED_FILE_NAMES = {".env", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
MAX_FILE_BYTES = 2_000_000
TEXT_EXTENSIONS = {
    ".c", ".cfg", ".conf", ".cpp", ".cs", ".css", ".csv", ".go", ".h", ".html", ".ini", ".java",
    ".js", ".json", ".jsx", ".kt", ".md", ".php", ".properties", ".py", ".rb", ".rs", ".sh", ".sql",
    ".tf", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml",
}
DOMAIN_RE = re.compile(r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-])")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
PASCAL_RE = re.compile(r"\b[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)+\b")
SNAKE_RE = re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+){1,}\b")
KEBAB_RE = re.compile(r"\b[a-z][a-z0-9]+(?:-[a-z0-9]+){1,}\b")
PHRASE_RE = re.compile(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"File does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def initial_fingerprint() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "entries": [],
    }


def normalise_variant(value: str) -> str:
    return value.strip()


def validate_fingerprint(fingerprint: dict[str, Any]) -> list[dict[str, Any]]:
    if fingerprint.get("schema_version") != 1:
        raise ValueError("Unsupported or missing fingerprint schema_version (expected 1)")
    entries = fingerprint.get("entries")
    if not isinstance(entries, list):
        raise ValueError("fingerprint.entries must be a list")
    seen: set[str] = set()
    result = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"entries[{index}] must be an object")
        canonical = entry.get("canonical")
        category = entry.get("category")
        status = entry.get("status")
        variants = entry.get("variants")
        if not isinstance(canonical, str) or not canonical.strip():
            raise ValueError(f"entries[{index}].canonical must be a non-empty string")
        if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", category):
            raise ValueError(f"entries[{index}].category must be lowercase snake_case")
        if status not in {"candidate", "approved", "ignored"}:
            raise ValueError(f"entries[{index}].status must be candidate, approved, or ignored")
        if not isinstance(variants, list) or not all(isinstance(v, str) and v.strip() for v in variants):
            raise ValueError(f"entries[{index}].variants must be a list of non-empty strings")
        key = canonical.casefold()
        if key in seen:
            raise ValueError(f"Duplicate canonical entry: {canonical}")
        seen.add(key)
        result.append(entry)
    return result


def should_exclude(relative: Path) -> str | None:
    if any(part in DEFAULT_EXCLUDED_DIRS for part in relative.parts[:-1]):
        return "excluded directory"
    name = relative.name
    if name in DEFAULT_EXCLUDED_FILE_NAMES or name.startswith(".env."):
        return "excluded sensitive filename"
    if name.endswith((".pem", ".key", ".p12", ".pfx")):
        return "excluded key material filename"
    return None


def iter_source_files(root: Path) -> Iterable[tuple[Path, Path, str | None]]:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDED_DIRS]
        for filename in files:
            full_path = current_path / filename
            relative = full_path.relative_to(root)
            yield full_path, relative, should_exclude(relative)


def read_text_file(path: Path) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"unreadable: {exc.strerror or exc}"
    if size > MAX_FILE_BYTES:
        return None, f"file exceeds {MAX_FILE_BYTES} bytes"
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile", "LICENSE", "NOTICE"}:
        return None, "unsupported or binary-prone extension"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"unreadable: {exc.strerror or exc}"
    if b"\x00" in raw:
        return None, "binary content"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not UTF-8 text"


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def extract_candidates(text: str, relative: Path) -> list[dict[str, Any]]:
    patterns = [
        ("domain_or_host", DOMAIN_RE),
        ("url", URL_RE),
        ("pascal_identifier", PASCAL_RE),
        ("constant_identifier", SNAKE_RE),
        ("kebab_identifier", KEBAB_RE),
        ("proper_name_phrase", PHRASE_RE),
    ]
    candidates = []
    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            term = match.group(0).rstrip(".,;:)")
            if len(term) < 4 or term.lower() in {"true", "false", "null", "none", "http", "https", "json", "yaml"}:
                continue
            candidates.append({"term": term, "kind": kind, "path": relative.as_posix(), "line": line_for_offset(text, match.start())})
    return candidates


def scan(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Source must be a directory: {root}")
    candidates: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    scanned_files = 0
    for full_path, relative, reason in iter_source_files(root):
        if reason:
            excluded.append({"path": relative.as_posix(), "reason": reason})
            continue
        text, reason = read_text_file(full_path)
        if reason:
            excluded.append({"path": relative.as_posix(), "reason": reason})
            continue
        scanned_files += 1
        candidates.extend(extract_candidates(text, relative))

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        grouped[(candidate["term"].casefold(), candidate["kind"])].append(candidate)
    inventory = []
    for (_, kind), occurrences in grouped.items():
        sample = occurrences[:5]
        inventory.append({
            "term": occurrences[0]["term"],
            "kind": kind,
            "occurrences": len(occurrences),
            "evidence": [{"path": item["path"], "line": item["line"]} for item in sample],
        })
    inventory.sort(key=lambda x: (-x["occurrences"], x["term"].casefold(), x["kind"]))
    return {
        "schema_version": 1,
        "tool_version": VERSION,
        "created_at": utc_now(),
        "source": {"path": str(root), "scanned_file_count": scanned_files},
        "candidate_inventory": inventory,
        "excluded_files": excluded,
    }


def copilot_request(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "purpose": "Internal-only organisation fingerprint discovery. Do not transform source and do not mark entries approved.",
        "instructions": (
            "Review the candidate inventory. Identify terms or naming patterns that could enable an external engineer "
            "to infer the organisation, customer, product, internal system, programme, or business domain. "
            "Return only JSON matching the response_schema. Each proposed entry needs a rationale and evidence. "
            "Do not invent facts or include source content beyond the supplied evidence."
        ),
        "candidate_inventory": report["candidate_inventory"],
        "response_schema": {
            "entries": [{
                "canonical": "string",
                "category": "company|internal_product|customer|internal_system|project|other",
                "variants": ["string"],
                "confidence": "low|medium|high",
                "rationale": "string",
                "evidence": [{"path": "string", "line": 1}],
            }]
        },
    }


def import_review(fingerprint: dict[str, Any], review: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
    entries = review.get("entries")
    if not isinstance(entries, list):
        raise ValueError("review.entries must be a list")
    current_entries = validate_fingerprint(fingerprint)
    by_canonical = {entry["canonical"].casefold(): entry for entry in current_entries}
    added = updated = 0
    for index, proposal in enumerate(entries):
        if not isinstance(proposal, dict):
            raise ValueError(f"review.entries[{index}] must be an object")
        canonical = proposal.get("canonical")
        category = proposal.get("category")
        variants = proposal.get("variants")
        confidence = proposal.get("confidence", "medium")
        rationale = proposal.get("rationale", "")
        evidence = proposal.get("evidence", [])
        if not isinstance(canonical, str) or not canonical.strip():
            raise ValueError(f"review.entries[{index}].canonical must be a non-empty string")
        if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", category):
            raise ValueError(f"review.entries[{index}].category must be lowercase snake_case")
        if not isinstance(variants, list) or not all(isinstance(v, str) and v.strip() for v in variants):
            raise ValueError(f"review.entries[{index}].variants must be a list of strings")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError(f"review.entries[{index}].confidence must be low, medium, or high")
        key = canonical.casefold()
        if key in by_canonical:
            entry = by_canonical[key]
            merged = {normalise_variant(v) for v in entry["variants"]} | {normalise_variant(v) for v in variants}
            entry["variants"] = sorted(merged, key=str.casefold)
            entry.setdefault("evidence", []).extend(evidence if isinstance(evidence, list) else [])
            entry.setdefault("rationales", []).append(str(rationale))
            entry["last_seen"] = utc_now()
            updated += 1
            continue
        entry = {
            "canonical": canonical.strip(),
            "category": category,
            "variants": sorted({normalise_variant(v) for v in variants} | {canonical.strip()}, key=str.casefold),
            "status": "candidate",
            "confidence": confidence,
            "rationales": [str(rationale)],
            "evidence": evidence if isinstance(evidence, list) else [],
            "first_seen": utc_now(),
            "last_seen": utc_now(),
        }
        current_entries.append(entry)
        by_canonical[key] = entry
        added += 1
    fingerprint["entries"] = sorted(current_entries, key=lambda entry: entry["canonical"].casefold())
    fingerprint["updated_at"] = utc_now()
    validate_fingerprint(fingerprint)
    return fingerprint, added, updated


def approved_replacements(fingerprint: dict[str, Any]) -> list[tuple[str, str, str]]:
    entries = [entry for entry in validate_fingerprint(fingerprint) if entry["status"] == "approved"]
    counters: Counter[str] = Counter()
    replacements: list[tuple[str, str, str]] = []
    for entry in sorted(entries, key=lambda item: (item["category"], item["canonical"].casefold())):
        counters[entry["category"]] += 1
        token = f"<{entry['category'].upper()}_{counters[entry['category']]:03d}>"
        for variant in sorted(set(entry["variants"]), key=len, reverse=True):
            replacements.append((variant, token, entry["canonical"]))
    return sorted(replacements, key=lambda item: len(item[0]), reverse=True)


def replace_text(text: str, replacements: list[tuple[str, str, str]]) -> tuple[str, set[str]]:
    applied: set[str] = set()
    result = text
    for variant, token, canonical in replacements:
        pattern = re.compile(re.escape(variant), re.IGNORECASE)
        result, count = pattern.subn(token, result)
        if count:
            applied.add(canonical)
    return result, applied


def safe_archive_name(path: Path) -> str:
    # The output path deliberately does not include the source directory name, which may identify an organisation.
    return path.as_posix()


def build(source: Path, fingerprint: dict[str, Any], output: Path) -> dict[str, Any]:
    source = source.resolve()
    if not source.is_dir():
        raise ValueError(f"Source must be a directory: {source}")
    replacements = approved_replacements(fingerprint)
    if not replacements:
        raise ValueError("No approved fingerprint entries. Review the fingerprint before building.")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    excluded: list[dict[str, str]] = []
    transformed_files = 0
    copied_files = 0
    applied_canonicals: set[str] = set()
    final_occurrences: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="deidentify-") as staging_name:
        staging = Path(staging_name)
        for full_path, relative, reason in iter_source_files(source):
            if reason:
                excluded.append({"path": relative.as_posix(), "reason": reason})
                continue
            text, reason = read_text_file(full_path)
            if reason:
                excluded.append({"path": relative.as_posix(), "reason": reason})
                continue
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            transformed, applied = replace_text(text, replacements)
            destination.write_text(transformed, encoding="utf-8")
            transformed_files += 1
            applied_canonicals.update(applied)

        # Independent final check: no approved input variant can remain in any staged text file.
        for full_path, relative, _ in iter_source_files(staging):
            text, reason = read_text_file(full_path)
            if reason or text is None:
                continue
            for variant, _, canonical in replacements:
                if re.search(re.escape(variant), text, re.IGNORECASE):
                    final_occurrences.append({"path": relative.as_posix(), "canonical": canonical})
        if final_occurrences:
            raise ValueError(f"Final check found {len(final_occurrences)} unresolved approved variants; no archive created")

        with tarfile.open(output, "w:gz") as archive:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=safe_archive_name(path.relative_to(staging)), recursive=False)
                    copied_files += 1

    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {
        "schema_version": 1,
        "tool_version": VERSION,
        "created_at": utc_now(),
        "archive": {"filename": output.name, "sha256": checksum, "file_count": copied_files},
        "source": {"file_count_transformed": transformed_files},
        "fingerprint": {
            "approved_entry_count": sum(1 for entry in fingerprint["entries"] if entry["status"] == "approved"),
            "entries_applied": len(applied_canonicals),
        },
        "excluded_files": excluded,
        "final_check": {"passed": True, "unresolved_approved_variants": 0},
        "notes": ["No original-to-replacement map is stored in this manifest."],
    }
    write_json(output.with_suffix(output.suffix + ".manifest.json"), manifest)
    return manifest
