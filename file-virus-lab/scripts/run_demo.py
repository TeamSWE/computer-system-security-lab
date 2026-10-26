#!/usr/bin/env python3
"""
run_demo.py - End-to-End Educational Demonstration Script

Demonstrates the full cybersecurity lifecycle:
1. Clean environment initialization & baseline recording.
2. Initial Antivirus scan verifying CLEAN status.
3. Controlled file-virus simulation appending a recognizable marker.
4. Antivirus scan detecting the signature (DETECTED status).
5. File Integrity Monitor detecting bit alterations (MISMATCH status).
6. Safe restoration of the target to pristine state.
7. Antivirus scan on restored target (CLEAN status).
8. Integrity verification confirming original cryptographic hash.

Academic Context: COMP 561 Chapter 1 - File Infection & Detection.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project modules can be loaded regardless of current working directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from antivirus import ScanStatus, scan_file
from integrity import IntegrityStatus, check_integrity, record_baseline
from scripts.create_test_files import compute_sha256, create_targets
from scripts.restore_lab import restore_lab_environment
from virus_simulator import simulate_infection


def print_stage_banner(stage_num: int, title: str, expected: str) -> None:
    """Print standard visual stage header."""
    print("\n" + "=" * 75)
    print(f"  STAGE {stage_num}: {title.upper()}")
    print("=" * 75)
    print(f"[*] Expected Outcome: {expected}")
    print("-" * 75)


def run_full_demonstration() -> bool:
    """Execute the multi-stage educational cybersecurity demonstration."""
    print("***************************************************************************")
    print("      CYBERSECURITY LAB: FILE VIRUS SIMULATION & ANTIVIRUS DETECTION")
    print("      Course Reference: COMP 561 Chapter 1 - Malware Taxonomy & Defense")
    print("***************************************************************************")

    lab_dir = PROJECT_ROOT / "lab"
    targets_dir = lab_dir / "targets"
    target_filename = "clean_sample.txt"
    target_path = targets_dir / target_filename

    # -------------------------------------------------------------------------
    # STAGE 1: Initialize clean test environment
    # -------------------------------------------------------------------------
    print_stage_banner(1, "Initialize Clean Test File", "Fresh, pristine file with zero markers")
    create_targets(targets_dir)
    if not target_path.exists():
        print(f"[!] FAILED: Target file {target_path} was not created.")
        return False
    print(f"[✓] Initialized {target_filename} inside {targets_dir}")

    # -------------------------------------------------------------------------
    # STAGE 2: Record initial cryptographic checksum & establish baseline
    # -------------------------------------------------------------------------
    print_stage_banner(2, "Record Cryptographic Baseline (SHA-256)", "Baseline hash registered")
    initial_content = target_path.read_text(encoding="utf-8")
    initial_hash = compute_sha256(initial_content)
    print(f"[*] Target File:    {target_filename}")
    print(f"[*] Initial SHA-256: {initial_hash}")
    print(f"[*] Initial Size:   {len(initial_content)} bytes")

    ok, msg, entry = record_baseline(target_path, force=True)
    if not ok:
        print(f"[!] Baseline recording failed: {msg}")
        return False
    print(f"[✓] {msg}")

    # -------------------------------------------------------------------------
    # STAGE 3: Run Antivirus scan on clean target
    # -------------------------------------------------------------------------
    print_stage_banner(3, "Antivirus Signature Scan (Clean Target)", "Status: CLEAN")
    scan_res_clean = scan_file(target_path)
    print(f"[*] Target:          {scan_res_clean.target_path.name}")
    print(f"[*] Status:          {scan_res_clean.status.value}")
    print(f"[*] Marker Detected: {scan_res_clean.marker_detected}")
    print(f"[*] Details:         {scan_res_clean.message}")

    if scan_res_clean.status != ScanStatus.CLEAN:
        print(f"[!] Unexpected status on clean file: {scan_res_clean.status}")
        return False
    print("[✓] PASS: Antivirus verified file as CLEAN.")

    # -------------------------------------------------------------------------
    # STAGE 4: Simulate File Infection
    # -------------------------------------------------------------------------
    print_stage_banner(4, "Execute File Virus Simulator", "Marker appended safely, backup saved")
    sim_res = simulate_infection(target_path)
    print(f"[*] Target Modified: {sim_res.target_path.name}")
    print(f"[*] Backup Stored:   {sim_res.backup_path.name if sim_res.backup_path else 'None'}")
    print(f"[*] Pre-Hash:        {sim_res.original_sha256}")
    print(f"[*] Post-Hash:       {sim_res.new_sha256}")
    print(f"[*] Size Change:     {sim_res.original_size} -> {sim_res.new_size} bytes")

    if not sim_res.success or sim_res.original_sha256 == sim_res.new_sha256:
        print("[!] Simulation modification failed.")
        return False
    print("[✓] PASS: Harmless simulation signature appended to target.")

    # -------------------------------------------------------------------------
    # STAGE 5: Antivirus scan on infected target
    # -------------------------------------------------------------------------
    print_stage_banner(5, "Antivirus Signature Scan (Infected Target)", "Status: DETECTED")
    scan_res_infected = scan_file(target_path)
    print(f"[*] Target:          {scan_res_infected.target_path.name}")
    print(f"[*] Status:          {scan_res_infected.status.value}")
    print(f"[*] Marker Detected: {scan_res_infected.marker_detected}")
    print(f"[*] Details:         {scan_res_infected.message}")

    if scan_res_infected.status != ScanStatus.DETECTED:
        print(f"[!] FAILED: Antivirus failed to detect marker: {scan_res_infected.status}")
        return False
    print("[✓] PASS: Antivirus successfully DETECTED known virus signature.")

    # -------------------------------------------------------------------------
    # STAGE 6: File Integrity Monitoring Check
    # -------------------------------------------------------------------------
    print_stage_banner(6, "File Integrity Verification", "Status: MISMATCH (Integrity Altered)")
    integ_status, integ_details = check_integrity(target_path)
    print(f"[*] Target:          {integ_details.get('file')}")
    print(f"[*] Status:          {integ_status.value}")
    print(f"[*] Baseline SHA256: {integ_details.get('baseline_sha256')}")
    print(f"[*] Current SHA256:  {integ_details.get('current_sha256')}")

    if integ_status != IntegrityStatus.MISMATCH:
        print(f"[!] Integrity check did not report MISMATCH: {integ_status}")
        return False
    print("[✓] PASS: Integrity monitor successfully identified unauthorized modification.")

    # -------------------------------------------------------------------------
    # STAGE 7: Restore clean test file
    # -------------------------------------------------------------------------
    print_stage_banner(7, "Restore Environment from Pristine Backup", "Target restored cleanly")
    restore_ok, restore_msgs = restore_lab_environment()
    for m in restore_msgs:
        print(f"  {m}")

    if not restore_ok:
        print("[!] Lab restoration encountered errors.")
        return False
    print("[✓] PASS: Environment restored cleanly.")

    # -------------------------------------------------------------------------
    # STAGE 8: Antivirus scan on restored target
    # -------------------------------------------------------------------------
    print_stage_banner(8, "Antivirus Scan (Post-Restoration)", "Status: CLEAN")
    scan_res_restored = scan_file(target_path)
    print(f"[*] Target:          {scan_res_restored.target_path.name}")
    print(f"[*] Status:          {scan_res_restored.status.value}")
    print(f"[*] Marker Detected: {scan_res_restored.marker_detected}")

    if scan_res_restored.status != ScanStatus.CLEAN:
        print(f"[!] FAILED: Restored target still contains marker: {scan_res_restored.status}")
        return False
    print("[✓] PASS: Restored target scanned as CLEAN.")

    # -------------------------------------------------------------------------
    # STAGE 9: Verify restored file matches original cryptographic checksum
    # -------------------------------------------------------------------------
    print_stage_banner(9, "Integrity Verification (Post-Restoration)", "Status: MATCH (Hashes Match)")
    integ_status_restored, integ_details_restored = check_integrity(target_path)
    print(f"[*] Target:          {integ_details_restored.get('file')}")
    print(f"[*] Status:          {integ_status_restored.value}")
    print(f"[*] Baseline SHA256: {integ_details_restored.get('baseline_sha256')}")
    print(f"[*] Restored SHA256: {integ_details_restored.get('current_sha256')}")

    if integ_status_restored != IntegrityStatus.MATCH:
        print(f"[!] Integrity check failed on restored file: {integ_status_restored}")
        return False
    print("[✓] PASS: Restored file matches pristine baseline perfectly.")

    print("\n" + "*" * 75)
    print("      ALL 9 DEMONSTRATION PHASES COMPLETED AND VERIFIED SUCCESSFULLY!")
    print("***************************************************************************\n")
    return True


def main() -> None:
    success = run_full_demonstration()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
