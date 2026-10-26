#!/usr/bin/env python3
"""
virus_simulator.py - Educational File Infection Simulator

Demonstrates how a classic file virus appends a recognizable marker signature
to an authorized test file in a safe, controlled, and reversible manner.

CRITICAL SAFETY & EDUCATIONAL CONSTRAINTS:
1. Controlled Simulation Only: This is NOT a real or self-replicating virus.
2. Strict Confinement: Only operates on .txt files strictly inside lab/targets/.
3. Directory Traversal & Symlink Defense: Resolves and verifies canonical paths.
4. Code Execution Prohibition: Never executes, imports, or runs target files.
5. Single-File Idempotent: Never scans or infects multiple files; appends marker once.
6. Reversible: Automatically generates backups in lab/backups/ prior to modification.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

# Unique inert simulation marker representing a known virus signature
SIMULATION_MARKER: str = "EDU_VIRUS_SIMULATION_MARKER_V1"

# Inert payload appended to the target file
SIMULATION_PAYLOAD: str = (
    "\n\n"
    "--- [BEGIN SIMULATED VIRUS PAYLOAD: INERT EDUCATIONAL ARTIFACT] ---\n"
    f"[SIMULATED_INFECTION_MARKER: {SIMULATION_MARKER}]\n"
    "Notice: This is a controlled university cybersecurity lab demonstration.\n"
    "No malicious actions, propagation, or system execution will occur.\n"
    "--- [END SIMULATED VIRUS PAYLOAD] ---\n"
)


class SecurityValidationError(Exception):
    """Raised when a file path violates security confinement constraints."""


class AlreadyInfectedError(Exception):
    """Raised when the target already contains the simulation marker."""


@dataclass
class SimulationResult:
    """Encapsulates the outcome of a simulation attempt."""
    success: bool
    status: str
    target_path: Path
    original_sha256: str
    original_size: int
    new_sha256: Optional[str] = None
    new_size: Optional[int] = None
    backup_path: Optional[Path] = None
    dry_run: bool = False
    message: str = ""


def get_project_root() -> Path:
    """Resolve the project root directory reliably regardless of cwd."""
    return Path(__file__).resolve().parent


def get_default_targets_dir() -> Path:
    """Resolve the authorized lab/targets directory."""
    return (get_project_root() / "lab" / "targets").resolve()


def get_default_backups_dir() -> Path:
    """Resolve the lab/backups directory."""
    return (get_project_root() / "lab" / "backups").resolve()


def compute_file_sha256(path: Path) -> str:
    """Compute the SHA-256 hexadecimal digest of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_and_validate_target(
    target_input: str | Path,
    allowed_targets_dir: Optional[Path] = None
) -> Path:
    """
    Safely resolve and validate that the target file is an approved .txt file
    strictly within the authorized lab/targets directory.

    Enforces strict security checks:
    - Path traversal prevention (e.g., ../../../)
    - Symlink escape prevention (symlinks resolving outside lab)
    - File extension restriction (only .txt files allowed)
    - Rejection of source code, executables, directories, and non-regular files.
    """
    if allowed_targets_dir is None:
        allowed_dir = get_default_targets_dir()
    else:
        allowed_dir = allowed_targets_dir.resolve()

    raw_path = Path(target_input)

    # Resolve candidate relative to cwd first, then project root if needed
    if raw_path.is_absolute():
        candidate = raw_path
    elif (Path.cwd() / raw_path).exists():
        candidate = Path.cwd() / raw_path
    elif (get_project_root() / raw_path).exists():
        candidate = get_project_root() / raw_path
    else:
        candidate = Path.cwd() / raw_path

    # Check for symbolic links pointing outside authorized directory
    if candidate.is_symlink():
        symlink_target = candidate.resolve()
        if not symlink_target.is_relative_to(allowed_dir):
            raise SecurityValidationError(
                f"Security Violation: Target is a symbolic link pointing outside the authorized lab directory.\n"
                f"  Link:   {candidate}\n"
                f"  Target: {symlink_target}\n"
                f"  Allowed: {allowed_dir}"
            )

    # Fully resolve canonical path
    resolved_path = candidate.resolve()

    # Check if target exists
    if not resolved_path.exists():
        raise SecurityValidationError(f"Target file does not exist: {resolved_path}")

    # Must be a regular file, not a directory or special device
    if not resolved_path.is_file():
        raise SecurityValidationError(
            f"Security Violation: Target must be a regular file, not a directory or device: {resolved_path}"
        )

    # Strict containment check within allowed_dir
    if not resolved_path.is_relative_to(allowed_dir):
        raise SecurityValidationError(
            f"Security Violation: Path traversal detected. Target must reside strictly within:\n"
            f"  Authorized: {allowed_dir}\n"
            f"  Attempted:  {resolved_path}"
        )

    # Extension validation: strictly allow only .txt files
    # Reject python files, shell scripts, binaries, and unsupported extensions
    if resolved_path.suffix.lower() != ".txt":
        raise SecurityValidationError(
            f"Security Violation: Target extension '{resolved_path.suffix}' is disallowed.\n"
            f"For safety, this simulator modifies only '.txt' files."
        )

    return resolved_path


def create_backup(target_path: Path, backups_dir: Optional[Path] = None) -> Path:
    """Create a verified backup copy of the target file before modification."""
    if backups_dir is None:
        backups_dir = get_default_backups_dir()
    else:
        backups_dir = backups_dir.resolve()

    backups_dir.mkdir(parents=True, exist_ok=True)

    # Standard clean backup name for restoration tool
    standard_bak = backups_dir / f"{target_path.name}.bak"
    shutil.copy2(target_path, standard_bak)

    # Timestamped backup for audit trail
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_bak = backups_dir / f"{target_path.stem}_{timestamp_str}{target_path.suffix}.bak"
    shutil.copy2(target_path, timestamped_bak)

    return standard_bak


def simulate_infection(
    target_input: str | Path,
    dry_run: bool = False,
    allowed_targets_dir: Optional[Path] = None,
    backups_dir: Optional[Path] = None,
) -> SimulationResult:
    """
    Execute controlled simulated infection on a single authorized target file.

    Returns:
        SimulationResult containing execution details and status.
    """
    # 1. Path resolution & security containment check
    target_path = resolve_and_validate_target(target_input, allowed_targets_dir)

    # 2. Record initial file metrics
    original_size = target_path.stat().st_size
    original_sha256 = compute_file_sha256(target_path)

    # 3. Read content and check for existing infection marker (Idempotency)
    content = target_path.read_text(encoding="utf-8", errors="replace")
    if SIMULATION_MARKER in content:
        raise AlreadyInfectedError(
            f"File '{target_path.name}' already contains the simulation marker '{SIMULATION_MARKER}'.\n"
            f"Infection refused: The simulator is idempotent and will not re-infect files."
        )

    # 4. Handle Dry-Run option
    if dry_run:
        return SimulationResult(
            success=True,
            status="DRY_RUN_SUCCESS",
            target_path=target_path,
            original_sha256=original_sha256,
            original_size=original_size,
            new_sha256=original_sha256,
            new_size=original_size,
            backup_path=None,
            dry_run=True,
            message="Dry run complete. No modifications or backups were written to disk."
        )

    # 5. Create backup prior to modification
    backup_file = create_backup(target_path, backups_dir)

    # 6. Apply harmless simulation payload
    with target_path.open("a", encoding="utf-8") as f:
        f.write(SIMULATION_PAYLOAD)

    # 7. Record post-modification metrics
    new_size = target_path.stat().st_size
    new_sha256 = compute_file_sha256(target_path)

    return SimulationResult(
        success=True,
        status="SIMULATION_APPLIED",
        target_path=target_path,
        original_sha256=original_sha256,
        original_size=original_size,
        new_sha256=new_sha256,
        new_size=new_size,
        backup_path=backup_file,
        dry_run=False,
        message=f"Simulated infection marker appended successfully. Backup stored at {backup_file.name}."
    )


def print_simulation_report(result: SimulationResult) -> None:
    """Print an educational, user-friendly report of the simulation outcome."""
    print("=" * 70)
    print("      EDUCATIONAL FILE VIRUS SIMULATION REPORT")
    print("=" * 70)
    print(f"Target File:      {result.target_path.name}")
    print(f"Full Path:        {result.target_path}")
    print(f"Action:           {'DRY RUN (PROPOSED ACTION ONLY)' if result.dry_run else 'APPEND SIMULATION MARKER'}")
    print(f"Status:           {result.status}")
    print("-" * 70)
    print(f"Original Size:    {result.original_size} bytes")
    print(f"Original SHA-256: {result.original_sha256}")
    if not result.dry_run and result.new_sha256:
        print(f"Modified Size:    {result.new_size} bytes (+{result.new_size - result.original_size} bytes)")
        print(f"Modified SHA-256: {result.new_sha256}")
        if result.backup_path:
            print(f"Backup Location:  {result.backup_path}")
    print("-" * 70)
    print(f"Summary: {result.message}")
    print("=" * 70)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for virus_simulator.py."""
    parser = argparse.ArgumentParser(
        description="Educational File Virus Simulator - Append harmless signature marker to lab test files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Safety Warning:\n"
            "  This utility is strictly for educational security coursework.\n"
            "  It operates ONLY on .txt files within the lab/targets/ directory.\n"
            "  It does NOT replicate, execute payloads, or modify system files."
        )
    )
    parser.add_argument(
        "target",
        help="Path to the approved target file (must reside in lab/targets/ and end with .txt)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the action and display proposed modifications without writing to disk"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        result = simulate_infection(args.target, dry_run=args.dry_run)
        print_simulation_report(result)
        return 0
    except SecurityValidationError as e:
        print("\n" + "!" * 70, file=sys.stderr)
        print(f"[!] SECURITY VALIDATION REFUSAL:\n{e}", file=sys.stderr)
        print("!" * 70 + "\n", file=sys.stderr)
        return 1
    except AlreadyInfectedError as e:
        print("\n" + "!" * 70, file=sys.stderr)
        print(f"[!] IDEMPOTENCY REFUSAL:\n{e}", file=sys.stderr)
        print("!" * 70 + "\n", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"\n[!] Unexpected Error during simulation: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
