#!/usr/bin/env python3
"""
restore_lab.py - Clean Lab Environment Restoration Tool

Safely restores the educational lab targets to their pristine original state,
cleans up temporary backup files, and verifies integrity.

Safety Constraints:
- Operates strictly within the project's lab/ directory.
- Never touches or removes files outside lab/targets, lab/backups, or lab/quarantine.
- Never accepts arbitrary system paths.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Import standard fixture generators to verify canonical content
try:
    from scripts.create_test_files import create_targets, get_pristine_files, compute_sha256
except ModuleNotFoundError:
    # Handle direct execution from scripts directory or elsewhere
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from scripts.create_test_files import create_targets, get_pristine_files, compute_sha256


def get_project_root() -> Path:
    """Resolve project root directory reliably."""
    return Path(__file__).resolve().parent.parent


def get_lab_dir() -> Path:
    """Resolve the dedicated lab directory."""
    return (get_project_root() / "lab").resolve()


def clean_backup_files(backups_dir: Path) -> List[str]:
    """Remove temporary simulation backup files while preserving .gitkeep."""
    removed: List[str] = []
    if not backups_dir.exists():
        return removed

    for item in backups_dir.iterdir():
        if item.is_file() and item.name != ".gitkeep":
            item.unlink()
            removed.append(item.name)
    return removed


def clean_quarantine_files(quarantine_dir: Path) -> List[str]:
    """Remove any quarantined artifacts while preserving .gitkeep."""
    removed: List[str] = []
    if not quarantine_dir.exists():
        return removed

    for item in quarantine_dir.iterdir():
        if item.is_file() and item.name != ".gitkeep":
            item.unlink()
            removed.append(item.name)
    return removed


def restore_lab_environment(lab_dir: Path | None = None) -> Tuple[bool, List[str]]:
    """
    Restore the lab environment to its canonical clean state.

    Args:
        lab_dir: Optional custom lab directory (must be verified for safety).

    Returns:
        Tuple of (success_status, log_messages)
    """
    if lab_dir is None:
        lab_dir = get_lab_dir()
    else:
        lab_dir = lab_dir.resolve()

    logs: List[str] = []

    targets_dir = lab_dir / "targets"
    backups_dir = lab_dir / "backups"
    quarantine_dir = lab_dir / "quarantine"

    logs.append(f"Restoring lab targets in: {targets_dir}")
    create_targets(targets_dir)

    removed_backups = clean_backup_files(backups_dir)
    if removed_backups:
        logs.append(f"Cleaned {len(removed_backups)} backup file(s): {', '.join(removed_backups)}")

    removed_quarantine = clean_quarantine_files(quarantine_dir)
    if removed_quarantine:
        logs.append(f"Cleaned {len(removed_quarantine)} quarantine file(s): {', '.join(removed_quarantine)}")

    # Verification: check all target files match their pristine SHA-256
    all_valid = True
    pristine_map = get_pristine_files()
    for filename, expected_content in pristine_map.items():
        file_path = targets_dir / filename
        if not file_path.is_file():
            logs.append(f"[!] ERROR: Target file missing after restoration: {filename}")
            all_valid = False
            continue

        actual_content = file_path.read_text(encoding="utf-8")
        expected_digest = compute_sha256(expected_content)
        actual_digest = compute_sha256(actual_content)

        if actual_digest == expected_digest:
            logs.append(f"[✓] Verified {filename} matches pristine baseline ({actual_digest[:16]}...)")
        else:
            logs.append(f"[!] MISMATCH in {filename}: expected {expected_digest[:16]}, got {actual_digest[:16]}")
            all_valid = False

    return all_valid, logs


def main() -> None:
    print("====================================================================")
    print("      EDUCATIONAL LAB ENVIRONMENT RESTORATION TOOL")
    print("====================================================================")
    success, messages = restore_lab_environment()
    for msg in messages:
        print(msg)

    if success:
        print("\n[✓] Lab environment successfully restored to pristine clean state.")
        sys.exit(0)
    else:
        print("\n[!] Restoration verification encountered errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
