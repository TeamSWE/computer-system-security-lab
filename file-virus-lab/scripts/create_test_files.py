#!/usr/bin/env python3
"""
create_test_files.py - Educational Fixture Generator

This script initializes the safe, controlled target text files used for
demonstrating file infection and antivirus signature detection.
All files are strictly inert text and contain no executable code or malicious logic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict

# Simulation signature constant used across the lab
SIMULATION_MARKER: str = "EDU_VIRUS_SIMULATION_MARKER_V1"

# Pristine contents for target fixtures
CLEAN_SAMPLE_CONTENT: str = (
    "====================================================================\n"
    "EDUCATIONAL SECURITY LAB: CLEAN SAMPLE DOCUMENT\n"
    "====================================================================\n"
    "File Status: Clean (Uninfected)\n"
    "Topic: Principles of Secure Computing\n"
    "\n"
    "Computer security fundamentally relies on the CIA triad:\n"
    "1. Confidentiality: Ensuring that information is accessible only to\n"
    "   authorized individuals and systems.\n"
    "2. Integrity: Guarding the accuracy, completeness, and authenticity\n"
    "   of data by safeguarding against unauthorized modification or deletion.\n"
    "3. Availability: Ensuring authorized users have reliable and timely access\n"
    "   to critical data and system resources.\n"
    "\n"
    "This document serves as an authorized test file for controlled lab exercises.\n"
    "It contains only ordinary educational prose.\n"
)

SAMPLE_DOCUMENT_CONTENT: str = (
    "====================================================================\n"
    "EDUCATIONAL SECURITY LAB: TECHNICAL REFERENCE NOTE\n"
    "====================================================================\n"
    "File Status: Clean (Uninfected)\n"
    "Topic: Malware Architecture & Attack Vectors (COMP 561 Chapter 1)\n"
    "\n"
    "In computer security taxonomy, a virus is distinguished from a worm primarily\n"
    "by its dependency on a host entity. A traditional file virus requires an\n"
    "existing host file or executable program to attach itself to. When the user\n"
    "transfers or executes the infected host, the virus payload is also carried.\n"
    "\n"
    "In contrast, a computer worm is a standalone, self-replicating program that\n"
    "propagates across networks independently by exploiting security flaws or weak\n"
    "configurations without requiring host file modification or human intervention.\n"
    "\n"
    "Common vectors for file virus transmission include:\n"
    "- Malicious email attachments disguised as benign documents\n"
    "- Removable physical media (e.g., infected USB drives with autorun)\n"
    "- Compromised software download portals and trojanized installers\n"
    "- Network file shares configured with permissive write permissions\n"
    "\n"
    "Defense-in-depth strategies incorporate cryptographic hash verification,\n"
    "signature scanning, heuristic behavioral analysis, and strict access controls.\n"
)

SIMULATED_INFECTED_CONTENT: str = (
    "====================================================================\n"
    "EDUCATIONAL SECURITY LAB: STATIC INFECTION FIXTURE\n"
    "====================================================================\n"
    "File Status: Inert Simulation Fixture (Non-Executable)\n"
    "Notice: This file contains the educational simulation marker for static testing.\n"
    "It contains NO executable code, NO payloads, and CANNOT cause system harm.\n"
    "\n"
    "Security analysis systems use signature detection to locate known patterns.\n"
    "Below is the harmless simulation signature marker:\n"
    "\n"
    f"[SIMULATED_INFECTION_MARKER: {SIMULATION_MARKER}]\n"
    "\n"
    "End of simulation fixture.\n"
)


def get_project_root() -> Path:
    """Resolve the project root directory reliably regardless of cwd."""
    # scripts/ is one level beneath project root
    return Path(__file__).resolve().parent.parent


def get_pristine_files() -> Dict[str, str]:
    """Return a mapping of fixture filenames to their canonical contents."""
    return {
        "clean_sample.txt": CLEAN_SAMPLE_CONTENT,
        "sample_document.txt": SAMPLE_DOCUMENT_CONTENT,
        "simulated_infected_sample.txt": SIMULATED_INFECTED_CONTENT,
    }


def compute_sha256(data: str) -> str:
    """Compute SHA-256 hexadecimal digest of string data (UTF-8)."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def create_targets(targets_dir: Path | None = None) -> Dict[str, str]:
    """
    Write pristine test files to the specified targets directory.

    Args:
        targets_dir: Directory where files should be created. Defaults to lab/targets.

    Returns:
        Dict mapping filename to computed SHA-256 digest.
    """
    if targets_dir is None:
        targets_dir = get_project_root() / "lab" / "targets"

    targets_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, str] = {}

    for filename, content in get_pristine_files().items():
        file_path = targets_dir / filename
        file_path.write_text(content, encoding="utf-8")
        digest = compute_sha256(content)
        results[filename] = digest
        print(f"[+] Created {file_path.name} ({len(content)} bytes) | SHA-256: {digest[:16]}...")

    return results


def main() -> None:
    print("=== Initializing Educational Lab Test Files ===")
    targets_dir = get_project_root() / "lab" / "targets"
    print(f"Target directory: {targets_dir}")
    create_targets(targets_dir)
    print("=== Fixtures successfully initialized. ===\n")


if __name__ == "__main__":
    main()
