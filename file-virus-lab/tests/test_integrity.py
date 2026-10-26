#!/usr/bin/env python3
"""
test_integrity.py - Automated Unit Tests for integrity.py

Tests:
1. Checksum calculation is consistent and deterministic.
2. Baseline creation and check for an unchanged file returns MATCH.
3. Modifying a file produces an integrity warning (MISMATCH).
4. Replacing a baseline requires explicit authorization (force=True).
5. Baseline registration rejects paths escaping the authorized lab directory.
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

from integrity import (
    IntegrityStatus,
    check_integrity,
    compute_sha256,
    load_baselines,
    record_baseline,
)


class TestIntegrityMonitoring(unittest.TestCase):
    """Test suite for integrity monitoring and baseline verification."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sandbox_root = Path(self.temp_dir.name)
        self.targets_dir = self.sandbox_root / "lab" / "targets"
        self.baselines_dir = self.sandbox_root / "lab" / "baselines"
        self.external_dir = self.sandbox_root / "external"

        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self.external_dir.mkdir(parents=True, exist_ok=True)

        self.test_file = self.targets_dir / "monitored_file.txt"
        self.test_content = "Critical configuration and educational data.\nLine 2.\n"
        self.test_file.write_text(self.test_content, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_checksum_consistency(self) -> None:
        """Verify that identical file content produces identical SHA-256 digests."""
        hash1 = compute_sha256(self.test_file)
        hash2 = compute_sha256(self.test_file)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_baseline_creation_and_check_match(self) -> None:
        """Verify that establishing a baseline and checking an unchanged file yields MATCH."""
        success, msg, entry = record_baseline(
            self.test_file,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertTrue(success)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.sha256, compute_sha256(self.test_file))

        # Check integrity
        status, details = check_integrity(
            self.test_file,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertEqual(status, IntegrityStatus.MATCH)
        self.assertTrue(details["matches"])
        self.assertEqual(details["baseline_sha256"], details["current_sha256"])

    def test_changed_file_produces_integrity_warning(self) -> None:
        """Verify that any modification triggers MISMATCH warning."""
        record_baseline(
            self.test_file,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )

        # Alter the file content
        with self.test_file.open("a", encoding="utf-8") as f:
            f.write("Unauthorized appended alteration.\n")

        status, details = check_integrity(
            self.test_file,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertEqual(status, IntegrityStatus.MISMATCH)
        self.assertFalse(details["matches"])
        self.assertNotEqual(details["baseline_sha256"], details["current_sha256"])

    def test_overwrite_baseline_requires_explicit_authorization(self) -> None:
        """Verify that baseline creation refuses to overwrite without force=True."""
        # First creation
        ok1, msg1, entry1 = record_baseline(
            self.test_file,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertTrue(ok1)

        # Second attempt without force must fail
        ok2, msg2, entry2 = record_baseline(
            self.test_file,
            force=False,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertFalse(ok2)
        self.assertIsNone(entry2)
        self.assertIn("Refusing to overwrite without explicit authorization", msg2)

        # Third attempt with force must succeed
        ok3, msg3, entry3 = record_baseline(
            self.test_file,
            force=True,
            allowed_targets_dir=self.targets_dir,
            baselines_dir=self.baselines_dir,
        )
        self.assertTrue(ok3)
        self.assertIsNotNone(entry3)

    def test_baseline_cannot_escape_lab_directory(self) -> None:
        """Verify that files outside the lab target boundary cannot be baselined."""
        external_file = self.external_dir / "external_system_file.txt"
        external_file.write_text("System file", encoding="utf-8")

        with self.assertRaises(PermissionError):
            record_baseline(
                external_file,
                allowed_targets_dir=self.targets_dir,
                baselines_dir=self.baselines_dir,
            )

        with self.assertRaises(PermissionError):
            check_integrity(
                external_file,
                allowed_targets_dir=self.targets_dir,
                baselines_dir=self.baselines_dir,
            )


if __name__ == "__main__":
    unittest.main()
