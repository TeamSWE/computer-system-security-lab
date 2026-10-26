#!/usr/bin/env python3
"""
integrity.py - File Integrity Monitoring System

Calculates cryptographic SHA-256 checksums, establishes baseline profiles
for authorized lab files, and detects unauthorized modifications.

EDUCATIONAL DISTINCTION:
An integrity check detects WHETHER a file changed (modification detection).
It does NOT determine WHY it changed or prove the presence of malware.
Benign edits, reformatting, and malicious infections all produce checksum changes.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class IntegrityStatus(str, Enum):
    """Integrity verification status categories."""
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    ERROR = "ERROR"
    BASELINE_CREATED = "BASELINE_CREATED"


@dataclass
class BaselineEntry:
    """Metadata recorded for an authorized baseline file."""
    relative_path: str
    sha256: str
    size_bytes: int
    recorded_at: str


def get_project_root() -> Path:
    """Resolve project root directory reliably."""
    return Path(__file__).resolve().parent


def get_default_targets_dir() -> Path:
    """Resolve the default authorized lab/targets directory."""
    return (get_project_root() / "lab" / "targets").resolve()


def get_default_baselines_dir() -> Path:
    """Resolve the default lab/baselines directory."""
    return (get_project_root() / "lab" / "baselines").resolve()


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash using streaming chunks."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_lab_target(
    target_input: str | Path,
    allowed_targets_dir: Optional[Path] = None
) -> Tuple[Path, str]:
    """
    Resolve and validate that the target resides safely inside the lab directory.

    Returns:
        Tuple of (resolved_path, relative_key)
    """
    if allowed_targets_dir is None:
        allowed_dir = get_default_targets_dir()
    else:
        allowed_dir = allowed_targets_dir.resolve()

    raw_path = Path(target_input)

    # Check candidates
    if raw_path.is_absolute():
        candidate = raw_path
    elif (Path.cwd() / raw_path).exists():
        candidate = Path.cwd() / raw_path
    elif (get_project_root() / raw_path).exists():
        candidate = get_project_root() / raw_path
    else:
        candidate = Path.cwd() / raw_path

    if candidate.is_symlink():
        sym_target = candidate.resolve()
        if not sym_target.is_relative_to(allowed_dir):
            raise PermissionError(f"Symlink points outside authorized directory: {sym_target}")

    resolved = candidate.resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")

    if not resolved.is_file():
        raise ValueError(f"Path is not a regular file: {resolved}")

    if not resolved.is_relative_to(allowed_dir):
        raise PermissionError(
            f"Access Denied: Path escapes authorized lab directory.\n"
            f"  Authorized: {allowed_dir}\n"
            f"  Target:     {resolved}"
        )

    # Use relative path inside allowed_dir as unique catalog key
    rel_key = resolved.relative_to(allowed_dir).as_posix()
    return resolved, rel_key


def get_baseline_store_path(baselines_dir: Optional[Path] = None) -> Path:
    """Return path to JSON baseline database file."""
    if baselines_dir is None:
        b_dir = get_default_baselines_dir()
    else:
        b_dir = baselines_dir.resolve()
    b_dir.mkdir(parents=True, exist_ok=True)
    return b_dir / "integrity_baselines.json"


def load_baselines(baselines_dir: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Load existing baseline profiles from JSON store."""
    store_file = get_baseline_store_path(baselines_dir)
    if not store_file.exists():
        return {}
    try:
        data = json.loads(store_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_baselines(
    data: Dict[str, Dict[str, Any]],
    baselines_dir: Optional[Path] = None
) -> None:
    """Save baseline profiles to JSON store atomically."""
    store_file = get_baseline_store_path(baselines_dir)
    serialized = json.dumps(data, indent=2, sort_keys=True)
    temp_file = store_file.with_suffix(".tmp")
    temp_file.write_text(serialized, encoding="utf-8")
    temp_file.replace(store_file)


def record_baseline(
    target_input: str | Path,
    force: bool = False,
    allowed_targets_dir: Optional[Path] = None,
    baselines_dir: Optional[Path] = None
) -> Tuple[bool, str, Optional[BaselineEntry]]:
    """
    Establish a new integrity baseline for a designated file.

    Guards against accidental overwriting unless force=True.
    """
    resolved_path, rel_key = resolve_lab_target(target_input, allowed_targets_dir)
    current_baselines = load_baselines(baselines_dir)

    if rel_key in current_baselines and not force:
        existing = current_baselines[rel_key]
        return False, (
            f"Baseline already exists for '{rel_key}'.\n"
            f"  Recorded SHA-256: {existing.get('sha256')}\n"
            f"  Recorded At:     {existing.get('recorded_at')}\n"
            f"Refusing to overwrite without explicit authorization. Use --force to replace."
        ), None

    file_size = resolved_path.stat().st_size
    digest = compute_sha256(resolved_path)
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    entry = BaselineEntry(
        relative_path=rel_key,
        sha256=digest,
        size_bytes=file_size,
        recorded_at=now_utc
    )

    current_baselines[rel_key] = asdict(entry)
    save_baselines(current_baselines, baselines_dir)

    return True, f"Baseline successfully recorded for '{rel_key}'.", entry


def check_integrity(
    target_input: str | Path,
    allowed_targets_dir: Optional[Path] = None,
    baselines_dir: Optional[Path] = None
) -> Tuple[IntegrityStatus, Dict[str, Any]]:
    """
    Compare current file checksum against the saved baseline.

    Returns:
        Tuple of (IntegrityStatus, report_dict)
    """
    resolved_path, rel_key = resolve_lab_target(target_input, allowed_targets_dir)
    current_baselines = load_baselines(baselines_dir)

    if rel_key not in current_baselines:
        return IntegrityStatus.ERROR, {
            "file": rel_key,
            "path": str(resolved_path),
            "error": f"No baseline record found for '{rel_key}'. Create one with: baseline <file>"
        }

    baseline_data = current_baselines[rel_key]
    expected_digest = baseline_data["sha256"]
    expected_size = baseline_data.get("size_bytes", -1)

    actual_digest = compute_sha256(resolved_path)
    actual_size = resolved_path.stat().st_size

    matches = (actual_digest == expected_digest)
    status = IntegrityStatus.MATCH if matches else IntegrityStatus.MISMATCH

    return status, {
        "file": rel_key,
        "path": str(resolved_path),
        "matches": matches,
        "baseline_sha256": expected_digest,
        "current_sha256": actual_digest,
        "baseline_size": expected_size,
        "current_size": actual_size,
        "recorded_at": baseline_data.get("recorded_at")
    }


def print_check_report(status: IntegrityStatus, details: Dict[str, Any]) -> None:
    """Print structured integrity report."""
    print("=" * 70)
    print("         FILE INTEGRITY MONITORING REPORT")
    print("=" * 70)
    print(f"Target:           {details.get('file', 'Unknown')}")
    print(f"Path:             {details.get('path', 'Unknown')}")
    print(f"Verification:     [{status.value}]")
    print("-" * 70)

    if status == IntegrityStatus.ERROR:
        print(f"Error: {details.get('error')}")
    elif status == IntegrityStatus.MATCH:
        print(f"Status:           VERIFIED - FILE IS UNCHANGED")
        print(f"SHA-256 Digest:   {details.get('current_sha256')}")
        print(f"File Size:        {details.get('current_size')} bytes")
        print(f"Baseline Date:    {details.get('recorded_at')}")
    elif status == IntegrityStatus.MISMATCH:
        print(f"Status:           WARNING - INTEGRITY COMPROMISED (CHANGED)")
        print(f"Baseline SHA-256: {details.get('baseline_sha256')}")
        print(f"Current SHA-256:  {details.get('current_sha256')}")
        print(f"Baseline Size:    {details.get('baseline_size')} bytes")
        print(f"Current Size:     {details.get('current_size')} bytes")
        print("-" * 70)
        print("Important Educational Context:")
        print("  * Cryptographic hash difference confirms the file's bits have altered.")
        print("  * An integrity change does NOT prove malicious infection by itself.")
        print("  * Benign user edits, system patches, and malware modifications all alter hashes.")
    print("=" * 70)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for integrity tool."""
    parser = argparse.ArgumentParser(
        description="Educational File Integrity Monitoring Tool (SHA-256)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: baseline
    baseline_parser = subparsers.add_parser("baseline", help="Record initial integrity baseline")
    baseline_parser.add_argument("target", help="Target file within lab/targets/")
    baseline_parser.add_argument("--force", action="store_true", help="Overwrite existing baseline explicitly")

    # Subcommand: check
    check_parser = subparsers.add_parser("check", help="Compare file checksum against recorded baseline")
    check_parser.add_argument("target", help="Target file to inspect")

    # Subcommand: list
    subparsers.add_parser("list", help="List all recorded baseline profiles")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "baseline":
            success, msg, entry = record_baseline(args.target, force=args.force)
            if success and entry:
                print(f"[✓] SUCCESS: {msg}")
                print(f"    File:     {entry.relative_path}")
                print(f"    SHA-256:  {entry.sha256}")
                print(f"    Size:     {entry.size_bytes} bytes")
                return 0
            else:
                print(f"[!] REFUSAL: {msg}", file=sys.stderr)
                return 2

        elif args.command == "check":
            status, details = check_integrity(args.target)
            print_check_report(status, details)
            if status == IntegrityStatus.MATCH:
                return 0
            elif status == IntegrityStatus.MISMATCH:
                return 1
            else:
                return 2

        elif args.command == "list":
            baselines = load_baselines()
            print("=" * 70)
            print("         STORED INTEGRITY BASELINE PROFILES")
            print("=" * 70)
            if not baselines:
                print("No baseline profiles currently registered.")
            for key, info in sorted(baselines.items()):
                print(f"File:        {key}")
                print(f"  SHA-256:   {info.get('sha256')}")
                print(f"  Size:      {info.get('size_bytes')} bytes")
                print(f"  Timestamp: {info.get('recorded_at')}")
                print("-" * 70)
            return 0

        return 0

    except (PermissionError, ValueError, FileNotFoundError) as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
