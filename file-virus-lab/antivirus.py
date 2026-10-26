#!/usr/bin/env python3
"""
antivirus.py - Educational Antivirus Signature Scanner

Implements signature-based detection for the educational cybersecurity lab.
Scans explicitly supplied test files for the known simulation marker signature.

EDUCATIONAL & SAFETY CONSTRAINTS:
1. Purely Passive: Strictly read-only; never deletes, alters, or executes target files.
2. Controlled Target Scope: Checks authorized files within lab/targets/.
3. Signature Specificity: Explicitly documents that marker-based scanning
   detects only the known simulation marker and cannot detect unknown malware.
4. Deterministic Reporting: Outputs clean status (CLEAN, DETECTED, ERROR) with
   accurate SHA-256 digests, file sizes, and timestamps.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

# Known simulation signature targeted by this educational detector
TARGET_SIGNATURE: str = "EDU_VIRUS_SIMULATION_MARKER_V1"


class ScanStatus(str, Enum):
    """Scan result status categories."""
    CLEAN = "CLEAN"
    DETECTED = "DETECTED"
    ERROR = "ERROR"


@dataclass
class ScanResult:
    """Encapsulates scan findings and metadata for a single file."""
    status: ScanStatus
    target_path: Path
    file_size_bytes: int = 0
    modified_timestamp: str = "N/A"
    sha256_hash: str = "N/A"
    marker_detected: bool = False
    message: str = ""


def get_project_root() -> Path:
    """Resolve project root directory reliably regardless of cwd."""
    return Path(__file__).resolve().parent


def get_default_targets_dir() -> Path:
    """Resolve the default authorized lab/targets directory."""
    return (get_project_root() / "lab" / "targets").resolve()


def compute_sha256(file_path: Path) -> str:
    """Calculate SHA-256 hexadecimal hash in a read-only stream."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def scan_file(
    target_input: str | Path,
    allowed_targets_dir: Optional[Path] = None
) -> ScanResult:
    """
    Perform passive signature scanning and metadata collection on a target file.

    Args:
        target_input: Path to file to scan.
        allowed_targets_dir: Directory boundary. Defaults to lab/targets/.

    Returns:
        ScanResult object with status CLEAN, DETECTED, or ERROR.
    """
    if allowed_targets_dir is None:
        allowed_dir = get_default_targets_dir()
    else:
        allowed_dir = allowed_targets_dir.resolve()

    raw_path = Path(target_input)

    # Resolve candidate path relative to cwd or project root
    if raw_path.is_absolute():
        candidate = raw_path
    elif (Path.cwd() / raw_path).exists():
        candidate = Path.cwd() / raw_path
    elif (get_project_root() / raw_path).exists():
        candidate = get_project_root() / raw_path
    else:
        candidate = Path.cwd() / raw_path

    # Check symlinks pointing outside allowed directory
    if candidate.is_symlink():
        symlink_target = candidate.resolve()
        if not symlink_target.is_relative_to(allowed_dir):
            return ScanResult(
                status=ScanStatus.ERROR,
                target_path=candidate,
                message=f"Access Denied: Symlink points outside allowed directory ({symlink_target})."
            )

    resolved_path = candidate.resolve()

    # Safety and existence checks
    if not resolved_path.exists():
        return ScanResult(
            status=ScanStatus.ERROR,
            target_path=resolved_path,
            message=f"Target file does not exist: {resolved_path}"
        )

    if not resolved_path.is_file():
        return ScanResult(
            status=ScanStatus.ERROR,
            target_path=resolved_path,
            message=f"Target is not a regular file (directory or special device): {resolved_path}"
        )

    if not resolved_path.is_relative_to(allowed_dir):
        return ScanResult(
            status=ScanStatus.ERROR,
            target_path=resolved_path,
            message=(
                f"Security Validation Refusal: Scans are restricted to the authorized lab directory.\n"
                f"  Authorized: {allowed_dir}\n"
                f"  Attempted:  {resolved_path}"
            )
        )

    # Read metadata
    try:
        stat_info = resolved_path.stat()
        file_size = stat_info.st_size
        mod_time = datetime.datetime.fromtimestamp(
            stat_info.st_mtime, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
        digest = compute_sha256(resolved_path)

        # Passive signature search
        content = resolved_path.read_text(encoding="utf-8", errors="replace")
        marker_present = TARGET_SIGNATURE in content

        if marker_present:
            return ScanResult(
                status=ScanStatus.DETECTED,
                target_path=resolved_path,
                file_size_bytes=file_size,
                modified_timestamp=mod_time,
                sha256_hash=digest,
                marker_detected=True,
                message=f"Educational signature match: '{TARGET_SIGNATURE}' identified."
            )
        else:
            return ScanResult(
                status=ScanStatus.CLEAN,
                target_path=resolved_path,
                file_size_bytes=file_size,
                modified_timestamp=mod_time,
                sha256_hash=digest,
                marker_detected=False,
                message="No known simulation signatures identified in target file."
            )

    except (PermissionError, OSError) as exc:
        return ScanResult(
            status=ScanStatus.ERROR,
            target_path=resolved_path,
            message=f"I/O Error while inspecting file: {exc}"
        )


def print_scan_report(result: ScanResult) -> None:
    """Print formatted antivirus inspection report with educational notes."""
    print("=" * 70)
    print("      EDUCATIONAL ANTIVIRUS SIGNATURE SCANNER")
    print("=" * 70)
    print(f"Target File:      {result.target_path.name}")
    print(f"Path:             {result.target_path}")
    print(f"Scan Result:      [{result.status.value}]")
    print("-" * 70)
    if result.status != ScanStatus.ERROR:
        print(f"File Size:        {result.file_size_bytes} bytes")
        print(f"Last Modified:    {result.modified_timestamp}")
        print(f"SHA-256 Digest:   {result.sha256_hash}")
        print(f"Marker Detected:  {result.marker_detected}")
    print(f"Scan Details:     {result.message}")
    print("-" * 70)
    print("Security Notice & Academic Disclaimer:")
    print("  * Signature-based scanning detects ONLY known, static markers.")
    print("  * This educational detector checks exclusively for the lab's simulation tag.")
    print("  * It is not a general-purpose antivirus engine and cannot detect")
    print("    unknown, polymorphic, or zero-day malicious software.")
    print("=" * 70)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for antivirus.py."""
    parser = argparse.ArgumentParser(
        description="Educational Antivirus Scanner - Detects simulation markers in authorized test files."
    )
    parser.add_argument(
        "target",
        help="Path to the test file to inspect (must reside in lab/targets/)"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    result = scan_file(args.target)
    print_scan_report(result)

    # Standard exit code mapping:
    # 0 = CLEAN
    # 1 = DETECTED
    # 2 = ERROR
    if result.status == ScanStatus.CLEAN:
        return 0
    elif result.status == ScanStatus.DETECTED:
        return 1
    else:
        return 2


if __name__ == "__main__":
    sys.exit(main())
