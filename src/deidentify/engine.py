from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
from base64 import urlsafe_b64decode, urlsafe_b64encode
from io import BytesIO
from pathlib import PurePosixPath
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VERSION = "0.2.0"
DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}
DEFAULT_EXCLUDED_FILE_NAMES = {".env", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
GENERIC_PATH_COMPONENTS = {"src", "test", "tests", "docs", "doc", "main", "config", "configs", "assets", "scripts", "lib", "app", "api", "service", "services", "terraform"}
MAX_FILE_BYTES = 2_000_000
TEXT_EXTENSIONS = {".c", ".cfg", ".conf", ".cpp", ".cs", ".css", ".csv", ".go", ".h", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".kt", ".md", ".php", ".properties", ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".tf", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml"}
EXTENSIONLESS_TEXT = {"Dockerfile", "Makefile", "LICENSE", "NOTICE", "README"}
DOMAIN_RE = re.compile(r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?![\w-])")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:]+(?![\w:])")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
AWS_ARN_RE = re.compile(r"\barn:aws[a-z-]*:[^\s'\"]+", re.IGNORECASE)
AZURE_RESOURCE_RE = re.compile(r"(?i)/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/\s]+(?:/providers/[^\s'\"]+)?")
PASCAL_RE = re.compile(r"\b[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)+\b")
CAMEL_RE = re.compile(r"\b[a-z]+(?:[A-Z][A-Za-z0-9]+){1,}\b")
SNAKE_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9]+(?:_[a-zA-Z0-9]+){1,}\b")
UPPER_SNAKE_RE = re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+){1,}\b")
KEBAB_RE = re.compile(r"\b[a-z][a-z0-9]+(?:-[a-z0-9]+){1,}\b")
PHRASE_RE = re.compile(r"\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,3}\b")


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"File does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def initial_fingerprint() -> dict[str, Any]:
    return {"schema_version": 1, "created_at": utc_now(), "entries": []}


def validate_fingerprint(fingerprint: dict[str, Any]) -> list[dict[str, Any]]:
    if fingerprint.get("schema_version") != 1 or not isinstance(fingerprint.get("entries"), list):
        raise ValueError("Unsupported fingerprint; expected schema_version 1 with an entries list")
    seen: set[str] = set()
    for index, entry in enumerate(fingerprint["entries"]):
        if not isinstance(entry, dict):
            raise ValueError(f"entries[{index}] must be an object")
        if not isinstance(entry.get("canonical"), str) or not entry["canonical"].strip():
            raise ValueError(f"entries[{index}].canonical must be a non-empty string")
        if not isinstance(entry.get("category"), str) or not re.fullmatch(r"[a-z][a-z0-9_]*", entry["category"]):
            raise ValueError(f"entries[{index}].category must be lowercase snake_case")
        if entry.get("status") not in {"candidate", "approved", "ignored"}:
            raise ValueError(f"entries[{index}].status must be candidate, approved, or ignored")
        variants = entry.get("variants")
        if not isinstance(variants, list) or not all(isinstance(v, str) and v.strip() for v in variants):
            raise ValueError(f"entries[{index}].variants must be non-empty strings")
        key = entry["canonical"].casefold()
        if key in seen:
            raise ValueError(f"Duplicate canonical entry: {entry['canonical']}")
        seen.add(key)
    return fingerprint["entries"]


def source_root(source: Path) -> Path:
    absolute = source.absolute()
    if absolute.is_symlink():
        raise ValueError("Source root must not be a symlink")
    root = absolute.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Source must be a directory: {source}")
    return root


def under_root(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root)
        return True
    except ValueError:
        return False


def require_outside_source(source: Path, artifact: Path, label: str) -> None:
    """Prevent sensitive workflow artifacts from being packaged with their source."""
    if under_root(source_root(source), artifact.absolute()):
        raise ValueError(f"{label} must be outside the selected source directory")


def excluded_reason(relative: Path) -> str | None:
    if any(part in DEFAULT_EXCLUDED_DIRS for part in relative.parts):
        return "policy: excluded directory"
    name = relative.name
    if name in DEFAULT_EXCLUDED_FILE_NAMES or name.startswith(".env."):
        return "policy: excluded sensitive filename"
    if name.endswith((".pem", ".key", ".p12", ".pfx")):
        return "policy: excluded key-material filename"
    return None


def iter_source_files(root: Path) -> Iterable[tuple[Path, Path, str | None]]:
    """Yield direct regular-file candidates only; symlinks are never followed."""
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained_dirs = []
        for dirname in dirs:
            directory = current_path / dirname
            relative = directory.relative_to(root)
            reason = "security: symlink directory skipped" if directory.is_symlink() else excluded_reason(relative)
            if reason:
                yield directory, relative, reason
            else:
                retained_dirs.append(dirname)
        dirs[:] = retained_dirs
        for filename in files:
            full_path = current_path / filename
            relative = full_path.relative_to(root)
            if full_path.is_symlink():
                yield full_path, relative, "security: symlink file skipped"
            elif not under_root(root, full_path):
                yield full_path, relative, "security: path resolves outside source root"
            else:
                yield full_path, relative, excluded_reason(relative)


def secure_read_bytes(root: Path, path: Path) -> tuple[bytes | None, str | None]:
    if path.is_symlink() or not under_root(root, path):
        return None, "security: symlink or out-of-tree path"
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "security: not a regular file"
        if metadata.st_size > MAX_FILE_BYTES:
            return None, f"file exceeds {MAX_FILE_BYTES} bytes"
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            return stream.read(), None
    except OSError as exc:
        return None, f"unreadable: {exc.strerror or exc}"
    finally:
        if descriptor != -1:
            os.close(descriptor)


def read_text_file(root: Path, path: Path) -> tuple[str | None, str | None]:
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in EXTENSIONLESS_TEXT:
        return None, "unsupported file type"
    raw, reason = secure_read_bytes(root, path)
    if reason:
        return None, reason
    assert raw is not None
    if b"\x00" in raw:
        return None, "binary content"
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "not UTF-8 text"


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def patterns() -> list[tuple[str, re.Pattern[str], int]]:
    return [("azure_resource_id", AZURE_RESOURCE_RE, 100), ("aws_arn", AWS_ARN_RE, 100), ("email", EMAIL_RE, 90), ("url", URL_RE, 80), ("domain_or_host", DOMAIN_RE, 80), ("ipv4", IPV4_RE, 65), ("ipv6", IPV6_RE, 65), ("uuid", UUID_RE, 50), ("pascal_identifier", PASCAL_RE, 45), ("proper_name_phrase", PHRASE_RE, 45), ("upper_snake_identifier", UPPER_SNAKE_RE, 35), ("lower_camel_identifier", CAMEL_RE, 25), ("snake_identifier", SNAKE_RE, 25), ("kebab_identifier", KEBAB_RE, 25)]


def extract_candidates(text: str, relative: Path, source: str) -> list[dict[str, Any]]:
    result = []
    for kind, pattern, score in patterns():
        for match in pattern.finditer(text):
            term = match.group(0).rstrip(".,;:)")
            if len(term) < 4 or term.casefold() in {"true", "false", "null", "none", "http", "https", "json", "yaml", "readme"}:
                continue
            item = {"term": term, "kind": kind, "score": score, "source": source, "path": relative.as_posix()}
            if source == "content":
                item["line"] = line_for_offset(text, match.start())
            result.append(item)
    return result


def path_candidates(relative: Path) -> list[dict[str, Any]]:
    result = []
    for component in relative.parts:
        if component.casefold() not in GENERIC_PATH_COMPONENTS:
            result.extend(extract_candidates(component, relative, "path"))
    return result


def snippets(text: str, relative: Path, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lines = text.splitlines()
    starts = sorted({max(1, item["line"] - 3) for item in candidates if "line" in item})[:3] or [1]
    return [{"path": relative.as_posix(), "start_line": start, "end_line": min(len(lines), start + 29), "file_type": relative.suffix.lower() or "extensionless", "text": "\n".join(lines[start - 1:start + 29])} for start in starts]


def scan(source: Path) -> dict[str, Any]:
    root = source_root(source); candidates: list[dict[str, Any]] = []; excluded: list[dict[str, str]] = []; chunks: list[dict[str, Any]] = []; scanned_files = 0
    for full_path, relative, reason in iter_source_files(root):
        if reason:
            excluded.append({"path": relative.as_posix(), "reason": reason}); continue
        candidates.extend(path_candidates(relative))
        text, reason = read_text_file(root, full_path)
        if reason:
            excluded.append({"path": relative.as_posix(), "reason": reason}); continue
        scanned_files += 1
        file_candidates = extract_candidates(text, relative, "content")
        candidates.extend(file_candidates); chunks.extend(snippets(text, relative, file_candidates))
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates: grouped[(candidate["term"].casefold(), candidate["kind"])].append(candidate)
    inventory = [{"term": values[0]["term"], "kind": kind, "score": max(v["score"] for v in values) + min(len(values), 10), "occurrences": len(values), "evidence": [{"source": v["source"], "path": v["path"], **({"line": v["line"]} if "line" in v else {})} for v in values[:5]]} for (_, kind), values in grouped.items()]
    inventory.sort(key=lambda item: (-item["score"], -item["occurrences"], item["term"].casefold()))
    return {"schema_version": 2, "tool_version": VERSION, "created_at": utc_now(), "source": {"path": str(root), "scanned_file_count": scanned_files}, "candidate_inventory": inventory, "semantic_chunks": chunks[:200], "excluded_files": excluded}


def ai_review_request(report: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "purpose": "Internal-only organisation fingerprint discovery; proposals remain candidates and cannot approve replacements.", "instructions": "Review the bounded snippets and candidate inventory. Discover employer/company, customer, project/program, internal product/system, hostname/domain, repository organisation, cloud tenant/account, alias, acronym, or meaningful identifier that could fingerprint the source. Return only response_schema JSON. Do not transform content, approve entries, or invent evidence.", "candidate_inventory": report["candidate_inventory"], "semantic_chunks": report["semantic_chunks"], "response_schema": {"entries": [{"canonical": "string", "category": "company|internal_product|customer|internal_system|project|other", "variants": ["string"], "confidence": "low|medium|high", "rationale": "string", "evidence": [{"path": "string", "line": 1}]}]}}


def import_review(fingerprint: dict[str, Any], review: dict[str, Any]) -> tuple[dict[str, Any], int, int]:
    entries = review.get("entries")
    if not isinstance(entries, list): raise ValueError("review.entries must be a list")
    current = validate_fingerprint(fingerprint); by_name = {entry["canonical"].casefold(): entry for entry in current}; added = updated = 0
    for index, proposal in enumerate(entries):
        if not isinstance(proposal, dict): raise ValueError(f"review.entries[{index}] must be an object")
        canonical, category, variants, confidence = proposal.get("canonical"), proposal.get("category"), proposal.get("variants"), proposal.get("confidence", "medium")
        if not isinstance(canonical, str) or not canonical.strip() or not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", category) or not isinstance(variants, list) or not all(isinstance(v, str) and v.strip() for v in variants) or confidence not in {"low", "medium", "high"}: raise ValueError(f"review.entries[{index}] has invalid canonical, category, variants, or confidence")
        key = canonical.casefold()
        if key in by_name:
            target = by_name[key]; target["variants"] = sorted(set(target["variants"]) | set(variants) | {canonical.strip()}, key=str.casefold); target.setdefault("evidence", []).extend(proposal.get("evidence", []) if isinstance(proposal.get("evidence", []), list) else []); target.setdefault("rationales", []).append(str(proposal.get("rationale", ""))); target["last_seen"] = utc_now(); updated += 1
        else:
            target = {"canonical": canonical.strip(), "category": category, "variants": sorted(set(variants) | {canonical.strip()}, key=str.casefold), "status": "candidate", "confidence": confidence, "rationales": [str(proposal.get("rationale", ""))], "evidence": proposal.get("evidence", []) if isinstance(proposal.get("evidence", []), list) else [], "first_seen": utc_now(), "last_seen": utc_now()}; current.append(target); by_name[key] = target; added += 1
    fingerprint["entries"] = sorted(current, key=lambda item: item["canonical"].casefold()); fingerprint["updated_at"] = utc_now(); validate_fingerprint(fingerprint)
    return fingerprint, added, updated


def approved_replacements(fingerprint: dict[str, Any]) -> list[tuple[str, str, str]]:
    counters: Counter[str] = Counter(); replacements = []
    for entry in sorted((e for e in validate_fingerprint(fingerprint) if e["status"] == "approved"), key=lambda e: (e["category"], e["canonical"].casefold())):
        counters[entry["category"]] += 1; token = f"<{entry['category'].upper()}_{counters[entry['category']]:03d}>"
        replacements.extend((variant, token, entry["canonical"]) for variant in entry["variants"])
    return sorted(replacements, key=lambda item: len(item[0]), reverse=True)


def mapping_vault(fingerprint: dict[str, Any], passphrase: str) -> dict[str, Any]:
    if not passphrase:
        raise ValueError("Mapping-vault passphrase must not be empty")
    token_map: dict[str, str] = {}
    for _, token, canonical in approved_replacements(fingerprint):
        token_map[token] = canonical
    if not token_map:
        raise ValueError("No approved mappings available for a vault")
    salt = os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000).derive(passphrase.encode("utf-8"))
    plaintext = json.dumps({"schema_version": 1, "token_map": token_map}, sort_keys=True).encode("utf-8")
    return {"schema_version": 1, "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": 600_000, "salt": urlsafe_b64encode(salt).decode("ascii")}, "ciphertext": Fernet(urlsafe_b64encode(key)).encrypt(plaintext).decode("ascii")}


def write_mapping_vault(path: Path, fingerprint: dict[str, Any], passphrase: str) -> None:
    if path.exists():
        raise ValueError(f"Refusing to overwrite existing mapping vault: {path}")
    write_json(path, mapping_vault(fingerprint, passphrase))


def decrypt_mapping_vault(path: Path, passphrase: str) -> dict[str, str]:
    vault = load_json(path)
    kdf = vault.get("kdf", {})
    if vault.get("schema_version") != 1 or kdf.get("name") != "PBKDF2-HMAC-SHA256" or not isinstance(kdf.get("iterations"), int) or not isinstance(kdf.get("salt"), str) or not isinstance(vault.get("ciphertext"), str):
        raise ValueError("Unsupported mapping vault")
    try:
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=urlsafe_b64decode(kdf["salt"]), iterations=kdf["iterations"]).derive(passphrase.encode("utf-8"))
        data = json.loads(Fernet(urlsafe_b64encode(key)).decrypt(vault["ciphertext"].encode("ascii")))
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError) as exc:
        raise ValueError("Could not decrypt mapping vault; check the passphrase and vault file") from exc
    token_map = data.get("token_map") if isinstance(data, dict) else None
    if not isinstance(token_map, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in token_map.items()):
        raise ValueError("Mapping vault contains an invalid token map")
    return token_map


def replace_text(text: str, replacements: list[tuple[str, str, str]]) -> tuple[str, set[str], int]:
    applied: set[str] = set(); count = 0
    for variant, token, canonical in replacements:
        text, replaced = re.subn(re.escape(variant), token, text, flags=re.IGNORECASE)
        if replaced: applied.add(canonical); count += replaced
    return text, applied, count


def transformed_relative(relative: Path, replacements: list[tuple[str, str, str]]) -> tuple[Path, set[str], int]:
    parts = []; applied: set[str] = set(); count = 0
    for component in relative.parts:
        value, names, occurrences = replace_text(component, replacements)
        if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value: raise ValueError(f"Unsafe transformed path component from {relative}")
        parts.append(value); applied.update(names); count += occurrences
    target = Path(*parts)
    if target.is_absolute() or any(part in {".", ".."} for part in target.parts): raise ValueError(f"Unsafe transformed path: {relative}")
    return target, applied, count


def build_plan(source: Path, fingerprint: dict[str, Any], unsupported_policy: str = "reject") -> tuple[list[dict[str, Any]], list[dict[str, str]], list[tuple[str, str, str]]]:
    if unsupported_policy not in {"reject", "exclude"}: raise ValueError("unsupported_policy must be reject or exclude")
    root = source_root(source); replacements = approved_replacements(fingerprint)
    if not replacements: raise ValueError("No approved fingerprint entries. Review the fingerprint before building.")
    plan = []; omitted = []; destinations: dict[str, str] = {}
    for full_path, relative, reason in iter_source_files(root):
        if reason: omitted.append({"path": relative.as_posix(), "reason": reason}); continue
        text, reason = read_text_file(root, full_path)
        if reason:
            if unsupported_policy == "reject": raise ValueError(f"Refusing incomplete export: {relative}: {reason}")
            omitted.append({"path": relative.as_posix(), "reason": f"policy: excluded unsupported file ({reason})"}); continue
        target, path_applied, path_count = transformed_relative(relative, replacements); target_name = target.as_posix()
        collision = next((existing for existing in destinations if target_name == existing or target_name.startswith(existing + "/") or existing.startswith(target_name + "/")), None)
        if collision: raise ValueError(f"Path collision after transformation: {destinations[collision]} and {relative} overlap at {target_name}")
        destinations[target_name] = relative.as_posix(); changed, content_applied, content_count = replace_text(text, replacements)
        plan.append({"relative": relative, "target": target, "text": changed, "applied": path_applied | content_applied, "path_occurrences": path_count, "content_occurrences": content_count})
    return plan, omitted, replacements


def preview(source: Path, fingerprint: dict[str, Any], unsupported_policy: str = "reject") -> dict[str, Any]:
    plan, omitted, _ = build_plan(source, fingerprint, unsupported_policy)
    changes = [{"source_path": item["relative"].as_posix(), "output_path": item["target"].as_posix(), "path_changed": item["relative"] != item["target"], "content_changed": bool(item["content_occurrences"]), "occurrences": item["path_occurrences"] + item["content_occurrences"], "fingerprint_entries": sorted(item["applied"])} for item in plan if item["path_occurrences"] or item["content_occurrences"]]
    return {"schema_version": 1, "created_at": utc_now(), "changes": changes, "omitted_files": omitted, "output_file_count": len(plan)}


def remaining_approved(text: str, replacements: list[tuple[str, str, str]]) -> set[str]:
    return {canonical for variant, _, canonical in replacements if re.search(re.escape(variant), text, re.IGNORECASE)}


def audit_request(source: Path, fingerprint: dict[str, Any], unsupported_policy: str = "reject") -> dict[str, Any]:
    plan, _, _ = build_plan(source, fingerprint, unsupported_policy)
    chunks = [{"path": item["target"].as_posix(), "start_line": 1, "end_line": min(len(item["text"].splitlines()), 80), "text": "\n".join(item["text"].splitlines()[:80])} for item in plan[:200]]
    return {"schema_version": 1, "purpose": "Adversarial post-transformation audit only; do not transform files or approve mappings.", "instructions": "Examine this deidentified repository as an adversarial reviewer. Identify clues that could reveal the original organisation, customer, project, programme, environment, or internal system. Return only response_schema JSON.", "semantic_chunks": chunks, "response_schema": {"findings": [{"clue": "string", "category": "string", "path": "string", "line": 1, "explanation": "string", "confidence": "low|medium|high", "status": "open|dismissed"}]}}


def substantive_audit_findings(audit: dict[str, Any]) -> list[dict[str, Any]]:
    findings = audit.get("findings")
    if not isinstance(findings, list): raise ValueError("audit.findings must be a list")
    result = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not isinstance(finding.get("clue"), str) or finding.get("confidence") not in {"low", "medium", "high"} or finding.get("status", "open") not in {"open", "dismissed"}: raise ValueError(f"audit.findings[{index}] is invalid")
        if finding.get("status", "open") == "open" and finding["confidence"] in {"medium", "high"}: result.append(finding)
    return result


def build(source: Path, fingerprint: dict[str, Any], output: Path, unsupported_policy: str = "reject", audit: dict[str, Any] | None = None, fail_on_ai_findings: bool = False, vault_path: Path | None = None, vault_passphrase: str | None = None) -> dict[str, Any]:
    if fail_on_ai_findings and audit is None: raise ValueError("--fail-on-ai-findings requires an audit findings file")
    if (vault_path is None) != (vault_passphrase is None): raise ValueError("A mapping vault path and passphrase must be supplied together")
    substantive = substantive_audit_findings(audit) if audit is not None else []
    if fail_on_ai_findings and substantive: raise ValueError(f"Adversarial AI audit has {len(substantive)} open medium/high findings; archive blocked")
    require_outside_source(source, output, "Archive output")
    if output.exists() or output.with_suffix(output.suffix + ".manifest.json").exists():
        raise ValueError("Refusing to overwrite an existing archive or manifest")
    plan, omitted, replacements = build_plan(source, fingerprint, unsupported_policy); output = output.absolute(); output.parent.mkdir(parents=True, exist_ok=True); final_occurrences = []
    with tempfile.TemporaryDirectory(prefix="deidentify-") as staging_name:
        staging = Path(staging_name)
        for item in plan:
            destination = staging / item["target"]; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(item["text"], encoding="utf-8", newline="")
        for item in plan:
            staged_text = (staging / item["target"]).read_text(encoding="utf-8")
            remaining = remaining_approved(item["target"].as_posix(), replacements) | remaining_approved(staged_text, replacements)
            if remaining: final_occurrences.append({"path": item["target"].as_posix(), "canonicals": sorted(remaining)})
        if final_occurrences: raise ValueError(f"Final check found approved variants in {len(final_occurrences)} staged paths or files")
        with tarfile.open(output, "w:gz") as archive:
            for item in plan:
                destination = staging / item["target"]; info = archive.gettarinfo(str(destination), arcname=item["target"].as_posix()); info.uid = info.gid = 0; info.uname = info.gname = ""; info.mtime = 0
                with destination.open("rb") as stream: archive.addfile(info, stream)
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {"schema_version": 2, "tool_version": VERSION, "created_at": utc_now(), "archive": {"filename": output.name, "sha256": checksum, "file_count": len(plan), "metadata_normalised": True}, "fingerprint": {"approved_entry_count": sum(e["status"] == "approved" for e in fingerprint["entries"]), "entries_applied": len({name for item in plan for name in item["applied"]})}, "omitted_files": omitted, "final_check": {"passed": True, "unresolved_approved_variants": 0, "paths_checked": True}, "ai_audit": {"performed": audit is not None, "open_medium_or_high_findings": len(substantive)}, "notes": ["No original-to-replacement map is stored in this manifest."]}
    write_json(output.with_suffix(output.suffix + ".manifest.json"), manifest)
    if vault_path is not None:
        write_mapping_vault(vault_path, fingerprint, vault_passphrase or "")
    return manifest


def safe_archive_relative(name: str) -> Path:
    raw = PurePosixPath(name)
    if raw.is_absolute() or not raw.parts or any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError(f"Unsafe path in returned archive: {name}")
    return Path(*raw.parts)


def reidentify(returned_archive: Path, vault_path: Path, output: Path, passphrase: str) -> dict[str, Any]:
    """Restore canonical values from an encrypted vault into a new local tarball."""
    if output.exists() or output.with_suffix(output.suffix + ".manifest.json").exists():
        raise ValueError("Refusing to overwrite an existing reidentified archive or manifest")
    token_map = decrypt_mapping_vault(vault_path, passphrase)
    replacements = sorted([(token, canonical, token) for token, canonical in token_map.items()], key=lambda item: len(item[0]), reverse=True)
    restored: list[tuple[Path, bytes, int]] = []; targets: dict[str, str] = {}
    try:
        archive = tarfile.open(returned_archive, "r:*")
    except (OSError, tarfile.TarError) as exc:
        raise ValueError(f"Cannot read returned archive: {exc}") from exc
    with archive:
        for member in archive.getmembers():
            if not member.isfile():
                raise ValueError(f"Returned archive contains non-regular member: {member.name}")
            relative = safe_archive_relative(member.name)
            if member.size > MAX_FILE_BYTES:
                raise ValueError(f"Returned archive member exceeds {MAX_FILE_BYTES} bytes: {member.name}")
            stream = archive.extractfile(member)
            raw = stream.read() if stream else b""
            if relative.suffix.lower() not in TEXT_EXTENSIONS and relative.name not in EXTENSIONLESS_TEXT:
                raise ValueError(f"Returned archive has unsupported file type: {member.name}")
            if b"\x00" in raw:
                raise ValueError(f"Returned archive has binary content: {member.name}")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"Returned archive is not UTF-8 text: {member.name}") from exc
            target, _, path_count = transformed_relative(relative, replacements)
            target_name = target.as_posix()
            collision = next((existing for existing in targets if target_name == existing or target_name.startswith(existing + "/") or existing.startswith(target_name + "/")), None)
            if collision:
                raise ValueError(f"Path collision while reidentifying: {targets[collision]} and {member.name}")
            targets[target_name] = member.name
            restored_text, _, content_count = replace_text(text, replacements)
            if remaining_approved(target.as_posix(), replacements) or remaining_approved(restored_text, replacements):
                raise ValueError(f"Reidentification left vault tokens in {member.name}")
            restored.append((target, restored_text.encode("utf-8"), path_count + content_count))
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for target, raw, _ in sorted(restored, key=lambda item: item[0].as_posix()):
            info = tarfile.TarInfo(target.as_posix()); info.size = len(raw); info.mode = 0o644; info.uid = info.gid = 0; info.uname = info.gname = ""; info.mtime = 0
            archive.addfile(info, BytesIO(raw))
    manifest = {"schema_version": 1, "tool_version": VERSION, "created_at": utc_now(), "archive": {"filename": output.name, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "file_count": len(restored), "metadata_normalised": True}, "reidentified_token_occurrences": sum(count for _, _, count in restored), "notes": ["Canonical values were restored from an encrypted mapping vault; original spelling variants are not reconstructed."]}
    write_json(output.with_suffix(output.suffix + ".manifest.json"), manifest)
    return manifest
