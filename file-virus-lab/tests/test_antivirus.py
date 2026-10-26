#!/usr/bin/env python3
"""
test_antivirus.py - Automated Unit Tests for antivirus.py

Tests:
1. Clean target file is reported with status CLEAN (exit code 0).
2. Target containing simulation marker is reported with status DETECTED (exit code 1).
3. Missing file is reported with status ERROR (exit code 2).
4. Out-of-scope or path traversal target is rejected with status ERROR.
5. The detector does not alter or modify file contents (passive read-only verification).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from antivirus import ScanStatus, compute_sha256, scan_file
from virus_simulator import SIMULATION_MARKER


class TestAntivirusScanner(unittest.TestCase):
    """Test suite for antivirus.py passive scanning functionality."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sandbox_root = Path(self.temp_dir.name)
        self.targets_dir = self.sandbox_root / "lab" / "targets"
        self.external_dir = self.sandbox_root / "external"

        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.external_dir.mkdir(parents=True, exist_ok=True)

        # Create clean target
        self.clean_file = self.targets_dir / "clean_document.txt"
        self.clean_content = "This is a clean document with no simulation markers.\n"
        self.clean_file.write_text(self.clean_content, encoding="utf-8")

        # Create infected target
        self.infected_file = self.targets_dir / "infected_document.txt"
        self.infected_content = (
            "File header.\n"
            f"[SIMULATED_INFECTION_MARKER: {SIMULATION_MARKER}]\n"
            "File footer.\n"
        )
        self.infected_file.write_text(self.infected_content, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_clean_target_reported_clean(self) -> None:
        """Verify that an uninfected file is reported as CLEAN."""
        result = scan_file(self.clean_file, allowed_targets_dir=self.targets_dir)

        self.assertEqual(result.status, ScanStatus.CLEAN)
        self.assertFalse(result.marker_detected)
        self.assertEqual(result.file_size_bytes, len(self.clean_content.encode("utf-8")))
        self.assertEqual(result.sha256_hash, compute_sha256(self.clean_file))

    def test_marker_target_reported_detected(self) -> None:
        """Verify that a file containing the simulation marker is reported as DETECTED."""
        result = scan_file(self.infected_file, allowed_targets_dir=self.targets_dir)

        self.assertEqual(result.status, ScanStatus.DETECTED)
        self.assertTrue(result.marker_detected)
        self.assertIn(SIMULATION_MARKER, result.message)

    def test_missing_file_reported_error(self) -> None:
        """Verify that scanning a non-existent file returns ERROR."""
        missing = self.targets_dir / "ghost_file.txt"
        result = scan_file(missing, allowed_targets_dir=self.targets_dir)

        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertIn("does not exist", result.message)

    def test_out_of_scope_target_rejected(self) -> None:
        """Verify that scanning files outside the lab target boundary returns ERROR."""
        outside_file = self.external_dir / "clean_outside.txt"
        outside_file.write_text("Outside text", encoding="utf-8")

        result = scan_file(outside_file, allowed_targets_dir=self.targets_dir)

        self.assertEqual(result.status, ScanStatus.ERROR)
        self.assertIn("restricted", result.message.lower())

    def test_antivirus_is_strictly_read_only(self) -> None:
        """Verify that scanning does not modify bytes, mtime, or size of the target."""
        pre_hash = compute_sha256(self.infected_file)
        pre_mtime = self.infected_file.stat().st_mtime_ns
        pre_size = self.infected_file.stat().st_size

        # Perform multiple scans
        res1 = scan_file(self.infected_file, allowed_targets_dir=self.targets_dir)
        res2 = scan_file(self.infected_file, allowed_targets_dir=self.targets_dir)

        post_hash = compute_sha256(self.infected_file)
        post_mtime = self.infected_file.stat().st_mtime_ns
        post_size = self.infected_file.stat().st_size

        self.assertEqual(pre_hash, post_hash)
        self.assertEqual(pre_mtime, post_mtime)
        self.assertEqual(pre_size, post_size)
        self.assertEqual(res1.status, ScanStatus.DETECTED)
        self.assertEqual(res2.status, ScanStatus.DETECTED)


if __name__ == "__main__":
    unittest.main()
