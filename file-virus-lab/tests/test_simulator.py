#!/usr/bin/env python3
"""
test_simulator.py - Automated Unit Tests for virus_simulator.py

Tests:
1. Valid clean text target is simulated safely.
2. Marker is appended exactly once.
3. Repeated attempts do not append another marker (idempotency).
4. Original file can be restored from backup.
5. Dry-run does not modify the target file.
6. Unsupported file extensions (.py, .exe, .bin, .sh) are rejected.
7. Paths outside lab/targets/ are strictly rejected (directory traversal).
8. Symbolic links pointing outside the lab are rejected.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from virus_simulator import (
    SIMULATION_MARKER,
    AlreadyInfectedError,
    SecurityValidationError,
    compute_file_sha256,
    simulate_infection,
)


class TestVirusSimulator(unittest.TestCase):
    """Test suite for virus_simulator.py in an isolated temporary sandbox."""

    def setUp(self) -> None:
        """Create an isolated sandbox mimicking project structure."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sandbox_root = Path(self.temp_dir.name)
        self.targets_dir = self.sandbox_root / "lab" / "targets"
        self.backups_dir = self.sandbox_root / "lab" / "backups"
        self.external_dir = self.sandbox_root / "external"

        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.external_dir.mkdir(parents=True, exist_ok=True)

        # Create standard test fixture
        self.sample_file = self.targets_dir / "test_target.txt"
        self.sample_initial_text = "Clean educational test file contents.\nSafe line 1.\nSafe line 2.\n"
        self.sample_file.write_text(self.sample_initial_text, encoding="utf-8")

    def tearDown(self) -> None:
        """Clean up the isolated temporary sandbox."""
        self.temp_dir.cleanup()

    def test_valid_clean_target_infection(self) -> None:
        """Verify that a valid .txt target is simulated safely and marker is present."""
        initial_hash = compute_file_sha256(self.sample_file)
        initial_size = self.sample_file.stat().st_size

        result = simulate_infection(
            self.sample_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.status, "SIMULATION_APPLIED")
        self.assertNotEqual(initial_hash, result.new_sha256)
        self.assertGreater(result.new_size, initial_size)

        # Check content
        content = self.sample_file.read_text(encoding="utf-8")
        self.assertIn(SIMULATION_MARKER, content)
        self.assertTrue(content.startswith(self.sample_initial_text))

    def test_marker_appended_exactly_once(self) -> None:
        """Verify that the marker string appears exactly once in the infected file."""
        simulate_infection(
            self.sample_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )
        content = self.sample_file.read_text(encoding="utf-8")
        self.assertEqual(content.count(SIMULATION_MARKER), 1)

    def test_idempotency_prevents_reinfection(self) -> None:
        """Verify repeated execution refuses to append marker multiple times."""
        # First infection
        res1 = simulate_infection(
            self.sample_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )
        self.assertTrue(res1.success)
        hash_after_first = compute_file_sha256(self.sample_file)

        # Second attempt must raise AlreadyInfectedError
        with self.assertRaises(AlreadyInfectedError):
            simulate_infection(
                self.sample_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

        # File content and hash must remain unchanged
        hash_after_second = compute_file_sha256(self.sample_file)
        self.assertEqual(hash_after_first, hash_after_second)
        content = self.sample_file.read_text(encoding="utf-8")
        self.assertEqual(content.count(SIMULATION_MARKER), 1)

    def test_backup_created_before_modification(self) -> None:
        """Verify that a backup copy is stored in backups directory before modification."""
        initial_hash = compute_file_sha256(self.sample_file)

        result = simulate_infection(
            self.sample_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )

        self.assertIsNotNone(result.backup_path)
        self.assertTrue(result.backup_path.exists())
        # Backup must have the original content and original hash
        backup_hash = compute_file_sha256(result.backup_path)
        self.assertEqual(initial_hash, backup_hash)

        # Test restoring from backup
        shutil.copy2(result.backup_path, self.sample_file)
        restored_hash = compute_file_sha256(self.sample_file)
        self.assertEqual(initial_hash, restored_hash)

    def test_dry_run_leaves_file_unmodified(self) -> None:
        """Verify dry-run describes actions without modifying file or writing backups."""
        initial_hash = compute_file_sha256(self.sample_file)
        initial_size = self.sample_file.stat().st_size

        result = simulate_infection(
            self.sample_file,
            dry_run=True,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )

        self.assertTrue(result.success)
        self.assertTrue(result.dry_run)
        self.assertEqual(result.status, "DRY_RUN_SUCCESS")
        self.assertEqual(initial_hash, compute_file_sha256(self.sample_file))
        self.assertEqual(initial_size, self.sample_file.stat().st_size)

        # Verify no backup was created
        backups = [f for f in self.backups_dir.iterdir() if f.is_file()]
        self.assertEqual(len(backups), 0)

    def test_unsupported_extensions_rejected(self) -> None:
        """Verify that .py, .exe, .sh, .bin files are rejected even inside targets dir."""
        bad_extensions = ["script.py", "malware.exe", "tool.sh", "firmware.bin", "document.docx"]

        for filename in bad_extensions:
            bad_file = self.targets_dir / filename
            bad_file.write_text("dummy binary or script data", encoding="utf-8")
            with self.subTest(filename=filename):
                with self.assertRaises(SecurityValidationError):
                    simulate_infection(
                        bad_file,
                        allowed_targets_dir=self.targets_dir,
                        backups_dir=self.backups_dir,
                    )

    def test_path_outside_allowed_dir_rejected(self) -> None:
        """Verify that paths outside lab/targets/ (directory traversal) are rejected."""
        external_file = self.external_dir / "external_target.txt"
        external_file.write_text("Important outside file", encoding="utf-8")

        with self.assertRaises(SecurityValidationError):
            simulate_infection(
                external_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

        # Verify relative directory traversal "../external/external_target.txt" is rejected
        traversal_path = self.targets_dir / ".." / ".." / "external" / "external_target.txt"
        with self.assertRaises(SecurityValidationError):
            simulate_infection(
                traversal_path,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

    def test_symlink_pointing_outside_rejected(self) -> None:
        """Verify that a symlink inside lab/targets/ pointing outside is rejected."""
        external_file = self.external_dir / "secret.txt"
        external_file.write_text("Top secret outside file", encoding="utf-8")

        symlink_file = self.targets_dir / "innocent_looking_link.txt"
        try:
            symlink_file.symlink_to(external_file)
        except OSError:
            self.skipTest("Filesystem does not support symbolic links in test environment.")

        with self.assertRaises(SecurityValidationError):
            simulate_infection(
                symlink_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

        # Verify the external file was never touched
        self.assertEqual(external_file.read_text(encoding="utf-8"), "Top secret outside file")


if __name__ == "__main__":
    unittest.main()
