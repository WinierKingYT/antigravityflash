"""
Strict Engineering Kernel V1.2.3 - Final Distribution Integrity Hotfix Test Suite
Tests all audit findings A through I:
- UPCHECK-123: 404 response handling, non-SemVer remote tags, 500 error handling, valid SemVer comparisons
- ARCH-123: TAR symlink, TAR hardlink, ZIP path traversal, TAR path traversal rejection
- STATUS-123: inspect_completion_readiness read-only purity, fail-closed circuit breaker handling
- MAN-123: config.json SHA-256 integrity, package version vs manifest check, obsolete module & agent reconciliation, config.json snapshot and rollback
"""

import os
import sys
import json
import shutil
import tarfile
import zipfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch, MagicMock

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir / "src") not in sys.path:
    sys.path.insert(0, str(root_dir / "src"))

import strict_engineering
from strict_engineering import __version__
from strict_engineering import distribution
from strict_engineering import gate
from strict_engineering import kernel
from strict_engineering import runtime_safety


class TestV123DistributionHotfix(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="strict_v123_test_")
        self.workspace = Path(self.temp_dir) / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.gemini_dir = Path(self.temp_dir) / "gemini_home"
        self.gemini_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -----------------------------------------------------------------------
    # UPCHECK-123: Update Discovery & SemVer Validation (Findings A & B)
    # -----------------------------------------------------------------------
    def test_upcheck_strict_semver_parser(self):
        """Audit Finding B: parse_version_tuple strictly parses SemVer and rejects invalid formats."""
        self.assertEqual(distribution.parse_version_tuple("1.2.3"), (1, 2, 3))
        self.assertEqual(distribution.parse_version_tuple("v1.2.3"), (1, 2, 3))
        self.assertEqual(distribution.parse_version_tuple("0.1.0"), (0, 1, 0))

        invalid_versions = ["latest", "abc", "1.2", "1.2.3-beta", "v1.2.3.4", "", None, 123]
        for inv in invalid_versions:
            with self.subTest(version=inv):
                with self.assertRaises(ValueError):
                    distribution.parse_version_tuple(inv)

    def test_upcheck_http_404_returns_check_failed(self):
        """Audit Finding A: HTTP 404 from GitHub API must return CHECK_FAILED with clear error, never UP_TO_DATE."""
        import urllib.error
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.side_effect = urllib.error.HTTPError(
                url="https://api.github.com/repos/WinierKingYT/antigravityflash/releases/latest",
                code=404,
                msg="Not Found",
                hdrs={},
                fp=None,
            )
            res = distribution.check_for_updates(current_version="1.2.3")
            self.assertEqual(res.status, distribution.UpdateCheckStatus.CHECK_FAILED)
            self.assertFalse(res.update_available)
            self.assertIsNone(res.latest_version)
            self.assertIn("HTTP 404", res.error)

    def test_upcheck_malformed_remote_tag_returns_check_failed(self):
        """Audit Finding B: Non-SemVer remote tags (latest, dev, 1.2, 1.2.3-rc1) return CHECK_FAILED."""
        malformed_payloads = [
            {"tag_name": "latest"},
            {"tag_name": "dev"},
            {"tag_name": "1.2"},
            {"tag_name": "v1.2.3-beta"},
            {"tag_name": "release-1.2.3"},
        ]
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
                mock_resp.__enter__.return_value = mock_resp
                with patch("urllib.request.urlopen", return_value=mock_resp):
                    res = distribution.check_for_updates(current_version="1.2.3")
                    self.assertEqual(res.status, distribution.UpdateCheckStatus.CHECK_FAILED)
                    self.assertFalse(res.update_available)
                    self.assertIsNone(res.latest_version)
                    self.assertIn("INVALID_REMOTE_METADATA", res.error)

    def test_upcheck_http_500_or_timeout_returns_check_failed(self):
        """Audit Finding A & B: HTTP 500 or network timeout returns CHECK_FAILED."""
        import urllib.error
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.side_effect = urllib.error.HTTPError(
                url="https://api.github.com/repos/WinierKingYT/antigravityflash/releases/latest",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=None,
            )
            res = distribution.check_for_updates(current_version="1.2.3")
            self.assertEqual(res.status, distribution.UpdateCheckStatus.CHECK_FAILED)
            self.assertFalse(res.update_available)

    def test_upcheck_valid_newer_and_older_semver(self):
        """Audit Finding B: Valid SemVer returns UPDATE_AVAILABLE when newer and UP_TO_DATE when equal/older."""
        mock_resp_newer = MagicMock()
        mock_resp_newer.status = 200
        mock_resp_newer.read.return_value = json.dumps({
            "tag_name": "v1.2.4",
            "zipball_url": "https://example.com/archive.zip",
        }).encode("utf-8")
        mock_resp_newer.__enter__.return_value = mock_resp_newer
        with patch("urllib.request.urlopen", return_value=mock_resp_newer):
            res = distribution.check_for_updates(current_version="1.2.3")
            self.assertEqual(res.status, distribution.UpdateCheckStatus.UPDATE_AVAILABLE)
            self.assertTrue(res.update_available)
            self.assertEqual(res.latest_version, "1.2.4")

        mock_resp_equal = MagicMock()
        mock_resp_equal.status = 200
        mock_resp_equal.read.return_value = json.dumps({
            "tag_name": "v1.2.3",
            "zipball_url": "https://example.com/archive.zip",
        }).encode("utf-8")
        mock_resp_equal.__enter__.return_value = mock_resp_equal
        with patch("urllib.request.urlopen", return_value=mock_resp_equal):
            res = distribution.check_for_updates(current_version="1.2.3")
            self.assertEqual(res.status, distribution.UpdateCheckStatus.UP_TO_DATE)
            self.assertFalse(res.update_available)
            self.assertEqual(res.latest_version, "1.2.3")

    # -----------------------------------------------------------------------
    # ARCH-123: Archive Extraction & Link Safety (Finding C)
    # -----------------------------------------------------------------------
    def test_arch_tar_symlink_rejected(self):
        """Audit Finding C: TAR archive containing a symlink must be rejected with ValueError."""
        tar_path = Path(self.temp_dir) / "symlink_test.tar"
        extract_dir = Path(self.temp_dir) / "tar_extract"

        with tarfile.open(tar_path, "w") as tf:
            ti = tarfile.TarInfo(name="malicious_symlink")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)

        with self.assertRaises(ValueError) as ctx:
            distribution.safe_extract_archive(tar_path, extract_dir)
        self.assertIn("symlink rejected", str(ctx.exception).lower())

    def test_arch_tar_hardlink_rejected(self):
        """Audit Finding C: TAR archive containing a hardlink must be rejected with ValueError."""
        tar_path = Path(self.temp_dir) / "hardlink_test.tar"
        extract_dir = Path(self.temp_dir) / "tar_extract"

        with tarfile.open(tar_path, "w") as tf:
            ti = tarfile.TarInfo(name="malicious_hardlink")
            ti.type = tarfile.LNKTYPE
            ti.linkname = "some_target"
            tf.addfile(ti)

        with self.assertRaises(ValueError) as ctx:
            distribution.safe_extract_archive(tar_path, extract_dir)
        self.assertIn("hardlink rejected", str(ctx.exception).lower())

    def test_arch_zip_path_traversal_rejected(self):
        """Audit Finding C: ZIP archive with path traversal ('../') must be rejected with ValueError."""
        zip_path = Path(self.temp_dir) / "traversal.zip"
        extract_dir = Path(self.temp_dir) / "zip_extract"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../evil.txt", "malicious payload")

        with self.assertRaises(ValueError) as ctx:
            distribution.safe_extract_archive(zip_path, extract_dir)
        self.assertIn("path traversal", str(ctx.exception).lower())

    def test_arch_tar_path_traversal_rejected(self):
        """Audit Finding C: TAR archive with path traversal ('../') must be rejected with ValueError."""
        tar_path = Path(self.temp_dir) / "traversal.tar"
        extract_dir = Path(self.temp_dir) / "tar_extract"

        with tarfile.open(tar_path, "w") as tf:
            ti = tarfile.TarInfo(name="../evil.txt")
            ti.size = 4
            tf.addfile(ti, BytesIO(b"evil"))

        with self.assertRaises(ValueError) as ctx:
            distribution.safe_extract_archive(tar_path, extract_dir)
        self.assertIn("path traversal", str(ctx.exception).lower())

    # -----------------------------------------------------------------------
    # STATUS-123: Read-Only Purity & Circuit Breaker Robustness (Findings D & E)
    # -----------------------------------------------------------------------
    def test_status_inspect_completion_readiness_is_100_percent_pure(self):
        """Audit Finding D: inspect_completion_readiness must be 100% pure read-only with zero disk mutation."""
        kernel.initialize_harness(self.workspace, "Pure inspection test")
        harness_dir = kernel.get_harness_dir(self.workspace)

        before_hashes = {}
        for f in harness_dir.rglob("*"):
            if f.is_file():
                before_hashes[str(f.relative_to(harness_dir))] = distribution.compute_file_sha256(f)

        ready, issues = gate.inspect_completion_readiness(self.workspace)
        self.assertFalse(ready)

        after_hashes = {}
        for f in harness_dir.rglob("*"):
            if f.is_file():
                after_hashes[str(f.relative_to(harness_dir))] = distribution.compute_file_sha256(f)

        self.assertEqual(before_hashes, after_hashes, "inspect_completion_readiness mutated harness artifacts!")

    def test_status_circuit_breaker_corrupt_fails_closed(self):
        """Audit Finding E: Corrupt or unreadable circuit-breaker.json must report CIRCUIT_BREAKER_STATE_UNREADABLE and fail closed."""
        kernel.initialize_harness(self.workspace, "Circuit breaker corruption test")
        harness_dir = kernel.get_harness_dir(self.workspace)
        cb_file = harness_dir / "circuit-breaker.json"
        cb_file.write_text("{CORRUPT_JSON_DATA!@#$", encoding="utf-8")

        ready, issues = gate.inspect_completion_readiness(self.workspace)
        self.assertFalse(ready)
        unreadable_issues = [i for i in issues if "CIRCUIT_BREAKER_STATE_UNREADABLE" in i]
        self.assertTrue(len(unreadable_issues) > 0, f"Expected CIRCUIT_BREAKER_STATE_UNREADABLE in issues, got: {issues}")

    # -----------------------------------------------------------------------
    # MAN-123: Manifest Scope, Drift, Package Check & Rollback (Findings F, G, H, I)
    # -----------------------------------------------------------------------
    def test_manifest_verifies_config_sha_and_corruption(self):
        """Audit Finding F: verify_manifest_integrity checks config.json existence, valid JSON, and SHA match."""
        cfg_dir = distribution.get_config_dir(self.gemini_dir)
        cfg_file = cfg_dir / distribution.CONFIG_FILENAME
        cfg_data = {"schemaVersion": "1.2.0", "maxAutomaticContinues": 3}
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f)

        hooks_file = self.gemini_dir / "config" / "hooks.json"
        gemini_md = self.gemini_dir / "GEMINI.md"
        agents_dir = self.gemini_dir / "config" / "agents"

        for ag in distribution.MANAGED_CORE_AGENTS:
            ad = agents_dir / ag
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {ag}", encoding="utf-8")

        manifest = distribution.generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md,
            agents_dir=agents_dir,
            version=__version__,
            gemini_dir=self.gemini_dir,
        )
        distribution.save_installation_manifest(manifest, gemini_dir=self.gemini_dir)

        ok, issues = distribution.verify_manifest_integrity(self.gemini_dir)
        self.assertTrue(ok, f"Expected manifest verification to pass, issues: {issues}")

        # Modify config.json -> drift detected
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump({"schemaVersion": "1.2.0", "maxAutomaticContinues": 99}, f)
        ok, issues = distribution.verify_manifest_integrity(self.gemini_dir)
        self.assertFalse(ok)
        self.assertTrue(any("Global configuration modified in config.json" in i for i in issues))

        # Corrupt config.json -> corrupted detected
        cfg_file.write_text("{BAD_JSON_CONTENT", encoding="utf-8")
        ok, issues = distribution.verify_manifest_integrity(self.gemini_dir)
        self.assertFalse(ok)
        self.assertTrue(any("Global configuration corrupted" in i for i in issues))

        # Delete config.json -> missing detected
        cfg_file.unlink()
        ok, issues = distribution.verify_manifest_integrity(self.gemini_dir)
        self.assertFalse(ok)
        self.assertTrue(any("Global configuration missing" in i for i in issues))

    def test_manifest_verifies_package_version_mismatch(self):
        """Audit Finding G: verify_manifest_integrity checks strict_engineering.__version__ == manifest.version."""
        cfg_dir = distribution.get_config_dir(self.gemini_dir)
        cfg_file = cfg_dir / distribution.CONFIG_FILENAME
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump({"schemaVersion": "1.2.0"}, f)

        hooks_file = self.gemini_dir / "config" / "hooks.json"
        gemini_md = self.gemini_dir / "GEMINI.md"
        agents_dir = self.gemini_dir / "config" / "agents"
        for ag in distribution.MANAGED_CORE_AGENTS:
            ad = agents_dir / ag
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {ag}", encoding="utf-8")

        manifest = distribution.generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md,
            agents_dir=agents_dir,
            version="9.9.9",
            gemini_dir=self.gemini_dir,
        )
        distribution.save_installation_manifest(manifest, gemini_dir=self.gemini_dir)

        ok, issues = distribution.verify_manifest_integrity(self.gemini_dir)
        self.assertFalse(ok)
        self.assertTrue(
            any("Installed package version" in i and "does not match manifest version" in i for i in issues),
            f"Expected package version mismatch issue, got: {issues}"
        )

    def test_update_reconciles_obsolete_modules_and_agents(self):
        """Audit Finding H & Section 13: update_installation removes obsolete modules and agents."""
        cfg_dir = distribution.get_config_dir(self.gemini_dir)
        agents_dir = self.gemini_dir / "config" / "agents"

        (cfg_dir / "kernel.py").write_text("# kernel", encoding="utf-8")
        (cfg_dir / "obsolete_old_module.py").write_text("# obsolete", encoding="utf-8")

        for ag in distribution.MANAGED_CORE_AGENTS:
            ad = agents_dir / ag
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {ag}", encoding="utf-8")

        initial_manifest = distribution.generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=self.gemini_dir / "config" / "hooks.json",
            gemini_md_file=self.gemini_dir / "GEMINI.md",
            agents_dir=agents_dir,
            version="1.2.2",
            gemini_dir=self.gemini_dir,
        )
        distribution.save_installation_manifest(initial_manifest, gemini_dir=self.gemini_dir)
        self.assertIn("obsolete_old_module.py", initial_manifest["managedFiles"]["modules"])

        new_source = Path(self.temp_dir) / "source_123"
        new_src_pkg = new_source / "src" / "strict_engineering"
        new_src_pkg.mkdir(parents=True, exist_ok=True)
        (new_src_pkg / "__init__.py").write_text('__version__ = "1.2.3"', encoding="utf-8")
        (new_src_pkg / "kernel.py").write_text("# new kernel v1.2.3", encoding="utf-8")
        (new_src_pkg / "gate.py").write_text("# gate v1.2.3", encoding="utf-8")
        (new_src_pkg / "distribution.py").write_text("# dist v1.2.3", encoding="utf-8")
        (new_src_pkg / "installer.py").write_text("# installer v1.2.3", encoding="utf-8")
        (new_src_pkg / "cli.py").write_text("# cli v1.2.3", encoding="utf-8")

        new_agents = new_source / "agents"
        for ag in distribution.MANAGED_CORE_AGENTS:
            ad = new_agents / ag
            ad.mkdir(parents=True, exist_ok=True)
            (ad / "agent.md").write_text(f"# Agent {ag} v1.2.3", encoding="utf-8")

        ok, msg, manifest = distribution.update_installation(
            source_dir=new_source,
            target_version="1.2.3",
            gemini_dir=self.gemini_dir,
            force=True,
        )
        self.assertTrue(ok, f"Update failed: {msg}")

        self.assertFalse((cfg_dir / "obsolete_old_module.py").exists(), "Obsolete module was not deleted from disk!")
        self.assertNotIn("obsolete_old_module.py", manifest["managedFiles"]["modules"])
        self.assertEqual(manifest["version"], "1.2.3")

    def test_rollback_restores_and_removes_config_json(self):
        """Audit Finding I: rollback_from_snapshot restores previous config.json or deletes introduced config.json."""
        cfg_dir = distribution.get_config_dir(self.gemini_dir)
        snapshot_dir = cfg_dir / ".backups" / "snap1"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        with open(snapshot_dir / distribution.CONFIG_FILENAME, "w", encoding="utf-8") as f:
            json.dump({"original": True}, f)
        (snapshot_dir / "kernel.py").write_text("# snap kernel", encoding="utf-8")

        with open(cfg_dir / distribution.CONFIG_FILENAME, "w", encoding="utf-8") as f:
            json.dump({"mutated": True}, f)

        ok, notes = distribution.rollback_from_snapshot(snapshot_dir, cfg_dir, self.gemini_dir)
        self.assertTrue(ok)
        with open(cfg_dir / distribution.CONFIG_FILENAME, "r", encoding="utf-8") as f:
            restored = json.load(f)
        self.assertTrue(restored.get("original"))

        (snapshot_dir / distribution.CONFIG_FILENAME).unlink()
        (cfg_dir / distribution.CONFIG_FILENAME).write_text("{}", encoding="utf-8")
        ok, notes = distribution.rollback_from_snapshot(snapshot_dir, cfg_dir, self.gemini_dir)
        self.assertTrue(ok)
        self.assertFalse((cfg_dir / distribution.CONFIG_FILENAME).exists(), "Introduced config.json should be removed!")


if __name__ == "__main__":
    unittest.main()
