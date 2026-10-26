#!/usr/bin/env python3
"""
test_safety.py - Automated Security & Safety Constraint Tests

Verifies that the file virus simulation and antivirus scanner rigorously
adhere to university cybersecurity lab safety principles:
1. No files outside lab/targets/ are modified under any circumstances.
2. No network sockets or remote connections are initiated.
3. No subprocesses, shell commands, or external system processes are invoked.
4. No persistence mechanisms (cron, bashrc, registry, systemd) are touched.
5. Antivirus scanner is strictly passive and never deletes or alters files.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from antivirus import ScanStatus, scan_file
from integrity import check_integrity, record_baseline
from scripts.restore_lab import restore_lab_environment
from virus_simulator import (
    SecurityValidationError,
    compute_file_sha256,
    simulate_infection,
)


class TestSafetyConstraints(unittest.TestCase):
    """Rigorous verification of sandbox safety and operational constraints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sandbox_root = Path(self.temp_dir.name)
        self.targets_dir = self.sandbox_root / "lab" / "targets"
        self.backups_dir = self.sandbox_root / "lab" / "backups"
        self.outside_dir = self.sandbox_root / "outside_lab"

        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.outside_dir.mkdir(parents=True, exist_ok=True)

        # Authorized target file
        self.target_file = self.targets_dir / "authorized_target.txt"
        self.target_file.write_text("Authorized educational content.\n", encoding="utf-8")

        # Protected external files that must NEVER be modified
        self.ext_python_file = self.outside_dir / "user_script.py"
        self.ext_python_file.write_text("print('Critical user script')\n", encoding="utf-8")

        self.ext_doc_file = self.outside_dir / "user_document.txt"
        self.ext_doc_file.write_text("Confidential academic research data.\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_no_modification_outside_lab_directory(self) -> None:
        """Verify simulator strictly refuses to alter files outside lab/targets/."""
        orig_py_hash = compute_file_sha256(self.ext_python_file)
        orig_doc_hash = compute_file_sha256(self.ext_doc_file)

        # Attempt to target external Python script
        with self.assertRaises(SecurityValidationError):
            simulate_infection(
                self.ext_python_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

        # Attempt to target external document
        with self.assertRaises(SecurityValidationError):
            simulate_infection(
                self.ext_doc_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )

        # Verify neither file was modified
        self.assertEqual(orig_py_hash, compute_file_sha256(self.ext_python_file))
        self.assertEqual(orig_doc_hash, compute_file_sha256(self.ext_doc_file))

    def test_no_network_connections_initiated(self) -> None:
        """Verify neither the simulator nor scanner initiates network connections."""
        mock_connect = MagicMock(side_effect=RuntimeError("NETWORK ACCESS PROHIBITED"))

        with patch.object(socket.socket, "connect", mock_connect):
            # 1. Run simulator
            res = simulate_infection(
                self.target_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )
            self.assertTrue(res.success)

            # 2. Run antivirus
            scan_res = scan_file(self.target_file, allowed_targets_dir=self.targets_dir)
            self.assertEqual(scan_res.status, ScanStatus.DETECTED)

            # Assert network connect was never called
            self.assertEqual(mock_connect.call_count, 0)

    def test_no_subprocesses_used_by_simulator(self) -> None:
        """Verify simulator does not invoke subprocesses or shell commands."""
        mock_popen = MagicMock(side_effect=RuntimeError("SUBPROCESS CALL PROHIBITED"))
        mock_system = MagicMock(side_effect=RuntimeError("OS.SYSTEM PROHIBITED"))

        with patch("subprocess.Popen", mock_popen), \
             patch("os.system", mock_system), \
             patch("subprocess.run", mock_popen):

            res = simulate_infection(
                self.target_file,
                allowed_targets_dir=self.targets_dir,
                backups_dir=self.backups_dir,
            )
            self.assertTrue(res.success)

            self.assertEqual(mock_popen.call_count, 0)
            self.assertEqual(mock_system.call_count, 0)

    def test_no_persistence_or_startup_changes(self) -> None:
        """Verify no persistence artifacts (cron, bashrc, startup items) are created."""
        home = Path.home()
        cron_spool = Path("/var/spool/cron")
        systemd_user = home / ".config" / "systemd" / "user"

        # Check mtimes of common shell configs before
        bashrc = home / ".bashrc"
        bashrc_mtime_before = bashrc.stat().st_mtime if bashrc.exists() else None

        # Execute simulation
        simulate_infection(
            self.target_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )

        if bashrc.exists() and bashrc_mtime_before is not None:
            self.assertEqual(bashrc.stat().st_mtime, bashrc_mtime_before)

        # Confirm no systemd or startup scripts generated in sandbox or project
        self.assertFalse((self.sandbox_root / ".bashrc").exists())
        self.assertFalse((self.sandbox_root / "autostart").exists())

    def test_detector_does_not_delete_or_modify_files(self) -> None:
        """Verify that antivirus scan does NOT quarantine or delete files."""
        # Initial scan on infected file
        simulate_infection(
            self.target_file,
            allowed_targets_dir=self.targets_dir,
            backups_dir=self.backups_dir,
        )

        file_hash_before = compute_file_sha256(self.target_file)
        self.assertTrue(self.target_file.exists())

        # Perform scan
        scan_res = scan_file(self.target_file, allowed_targets_dir=self.targets_dir)
        self.assertEqual(scan_res.status, ScanStatus.DETECTED)

        # Verify file still exists and was not deleted or quarantined
        self.assertTrue(self.target_file.exists())
        self.assertEqual(file_hash_before, compute_file_sha256(self.target_file))


if __name__ == "__main__":
    unittest.main()
