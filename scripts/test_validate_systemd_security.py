#!/usr/bin/env python3
"""Unit tests for validate_systemd_security.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from validate_systemd_security import validate_unit

DEPLOY_SYSTEMD_DIR = Path(__file__).resolve().parent.parent / "deploy" / "systemd"
VALIDATOR_SCRIPT = Path(__file__).resolve().parent / "validate_systemd_security.py"


class SystemdSecurityValidatorTests(unittest.TestCase):
    def test_production_identity_service_passes(self):
        path = DEPLOY_SYSTEMD_DIR / "camellia-remote-identity.service"
        errors = validate_unit(path)
        self.assertEqual(errors, [], f"Identity service failed validation: {errors}")

    def test_production_relay_service_passes(self):
        path = DEPLOY_SYSTEMD_DIR / "camellia-remote-relay.service"
        errors = validate_unit(path)
        self.assertEqual(errors, [], f"Relay service failed validation: {errors}")

    def test_missing_user_fails(self):
        content = (DEPLOY_SYSTEMD_DIR / "camellia-remote-identity.service").read_text()
        corrupted = "\n".join(line for line in content.splitlines() if not line.startswith("User="))
        with tempfile.NamedTemporaryFile("w", suffix=".service") as tmp:
            tmp.write(corrupted)
            tmp.flush()
            errors = validate_unit(Path(tmp.name))
            self.assertTrue(
                any("User=" in err or "UserOrDynamicUser" in err for err in errors),
                f"Expected error for missing User, got: {errors}",
            )

    def test_missing_protect_system_fails(self):
        content = (DEPLOY_SYSTEMD_DIR / "camellia-remote-identity.service").read_text()
        corrupted = "\n".join(line for line in content.splitlines() if not line.startswith("ProtectSystem="))
        with tempfile.NamedTemporaryFile("w", suffix=".service") as tmp:
            tmp.write(corrupted)
            tmp.flush()
            errors = validate_unit(Path(tmp.name))
            self.assertTrue(
                any("ProtectSystem" in err for err in errors),
                f"Expected error for missing ProtectSystem, got: {errors}",
            )

    def test_missing_state_directory_fails(self):
        content = (DEPLOY_SYSTEMD_DIR / "camellia-remote-identity.service").read_text()
        corrupted = "\n".join(line for line in content.splitlines() if not line.startswith("StateDirectory="))
        with tempfile.NamedTemporaryFile("w", suffix=".service") as tmp:
            tmp.write(corrupted)
            tmp.flush()
            errors = validate_unit(Path(tmp.name))
            self.assertTrue(
                any("StateDirectory=" in err for err in errors),
                f"Expected error for missing StateDirectory, got: {errors}",
            )

    def test_insecure_unit_high_exposure_fails(self):
        insecure = """[Unit]
Description=Insecure test service

[Service]
ExecStart=/bin/sh -c "echo running"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".service") as tmp:
            tmp.write(insecure)
            tmp.flush()
            errors = validate_unit(Path(tmp.name))
            self.assertTrue(len(errors) > 0, "Expected errors for completely unhardened service")
            self.assertTrue(
                any("exceeds threshold" in err or "UserOrDynamicUser" in err for err in errors),
                f"Expected exposure threshold or directive errors, got: {errors}",
            )

    def test_cli_execution_success_and_failure(self):
        identity_path = DEPLOY_SYSTEMD_DIR / "camellia-remote-identity.service"
        relay_path = DEPLOY_SYSTEMD_DIR / "camellia-remote-relay.service"

        # Success case
        proc_ok = subprocess.run(
            [sys.executable, str(VALIDATOR_SCRIPT), str(identity_path), str(relay_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc_ok.returncode, 0, f"CLI validation failed: {proc_ok.stderr}")

        # Failure case with corrupted service
        content = identity_path.read_text()
        corrupted = "\n".join(line for line in content.splitlines() if not line.startswith("User="))
        with tempfile.NamedTemporaryFile("w", suffix=".service") as tmp:
            tmp.write(corrupted)
            tmp.flush()
            proc_fail = subprocess.run(
                [sys.executable, str(VALIDATOR_SCRIPT), tmp.name],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_fail.returncode, 1, "CLI should fail on corrupted service")
            self.assertIn("VALIDATION FAILED", proc_fail.stderr)


if __name__ == "__main__":
    unittest.main()
