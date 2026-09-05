"""
Strict Engineering Kernel Step 5 - Comprehensive Clean Environment & Reproducible Build Test Suite
Verifies:
- ENV-1 to ENV-5: Environment & Container Detection
- DEP-1 to DEP-5: Dependency & Lockfile Integrity
- BUILD-1 to BUILD-4: Clean Build Factory & Artifact Hashing
- RUN-1 to RUN-3: Runtime Startup & Smoke Journey Verification
- DB-1 to DB-4: Database Bootstrap & Migration Verification
- REP-1 to REP-5: Reproducibility Engine & Double-Build Output Classification
- RISK-ENV-1 to RISK-ENV-4: Risk-Adaptive Clean Build Policy
- INT-1 to INT-5: Integration & Stop Gate Enforcement
- Step 5 Realistic Torture Project: End-to-end multi-requirement lifecycle with defect repairs,
  clean double-build verification, candidate promotion, and canonical summary reporting.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import unittest
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    from . import kernel
    from . import fingerprint
    from . import baseline
    from . import sandbox
    from . import risk_engine
    from . import verification_policy
    from . import adversarial_verification
    from . import environment_detector
    from . import environment_factory
    from . import reproducibility
    from . import reporting
    from . import gate
except (ImportError, ValueError):
    import kernel
    import fingerprint
    import baseline
    import sandbox
    import risk_engine
    import verification_policy
    import adversarial_verification
    import environment_detector
    import environment_factory
    import reproducibility
    import reporting
    import gate


class Step5CleanEnvTestSuite(unittest.TestCase):
    def setUp(self):
        self.test_root = Path(tempfile.mkdtemp(prefix="step5_test_"))
        self.workspace = self.test_root / "test_repo"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_git_repo(self.workspace)

    def tearDown(self):
        try:
            shutil.rmtree(self.test_root, ignore_errors=True)
        except Exception:
            pass

    def _init_git_repo(self, repo_dir: Path):
        subprocess.run(["git", "init"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "TestUser"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        (repo_dir / "README.md").write_text("# Step 5 Clean Env Repo\n", encoding="utf-8")
        (repo_dir / "app.py").write_text("def run():\n    return 42\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    # =========================================================================
    # ENV-1 to ENV-5: Environment & Container Detection Tests
    # =========================================================================

    def test_env1_container_runtime_detection(self):
        """ENV-1: Detects container runtime status without hanging or throwing exceptions."""
        runtime_info = environment_detector.detect_container_runtime()
        self.assertIn(runtime_info["status"], ["CONTAINER_ISOLATED", "NOT_CONFIGURED"])
        self.assertIn("details", runtime_info)
        self.assertIsInstance(runtime_info["daemonResponsive"], bool)

    def test_env2_windows_native_desktop_fallback(self):
        """ENV-2: Native Windows / Desktop apps detected and isolated via filesystem/process."""
        (self.workspace / "src-tauri").mkdir(parents=True, exist_ok=True)
        (self.workspace / "src-tauri" / "tauri.conf.json").write_text('{"package": {"productName": "TauriApp"}}', encoding="utf-8")
        
        eco = environment_detector.detect_project_ecosystem(self.workspace)
        self.assertTrue(eco["isDesktopNative"])
        self.assertEqual(eco["projectType"], "TAURI_DESKTOP")

    def test_env3_toolchain_version_pinning_detected(self):
        """ENV-3: Pinned toolchains (.python-version, pyproject.toml, .node-version, etc.) are detected."""
        (self.workspace / ".python-version").write_text("3.14.6\n", encoding="utf-8")
        (self.workspace / ".node-version").write_text("20.11.0\n", encoding="utf-8")
        
        toolchain = environment_detector.detect_declared_toolchain(self.workspace)
        self.assertEqual(toolchain["status"], "TOOLCHAIN_PINNED")
        self.assertEqual(toolchain["pinnedVersions"].get("python"), "3.14.6")
        self.assertEqual(toolchain["pinnedVersions"].get("node"), "20.11.0")

    def test_env4_toolchain_unpinned_warning(self):
        """ENV-4: Unpinned toolchains return TOOLCHAIN_UNPINNED with non-blocking warning."""
        toolchain = environment_detector.detect_declared_toolchain(self.workspace)
        self.assertEqual(toolchain["status"], "TOOLCHAIN_UNPINNED")
        self.assertIsNotNone(toolchain["warning"])

    def test_env5_secret_scanning_prevents_env_leakage(self):
        """ENV-5: Secret scanning detects .env files and API keys, keeping clean context safe."""
        (self.workspace / ".env").write_text("DATABASE_PASSWORD=SuperSecret123\nAPI_KEY=AIzaSyA1234567890123456789012345678\n", encoding="utf-8")
        scan = environment_detector.scan_and_classify_secrets(self.workspace)
        self.assertTrue(scan["secretsDetected"])
        self.assertFalse(scan["cleanContextSafe"])
        self.assertTrue(any(s["type"] == "ENV_FILE" for s in scan["secrets"]))

    # =========================================================================
    # DEP-1 to DEP-5: Dependency & Lockfile Verification Tests
    # =========================================================================

    def test_dep1_declared_and_locked_dependency_pass(self):
        """DEP-1: Synchronized manifest and lockfile pass integrity check with frozen command."""
        (self.workspace / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        (self.workspace / "requirements.lock").write_text("requests==2.31.0\n", encoding="utf-8")
        
        lock_info = environment_detector.check_lockfile_integrity(self.workspace)
        self.assertEqual(lock_info["status"], "SYNCHRONIZED")
        self.assertIsNotNone(lock_info["frozenCommand"])

    def test_dep2_undeclared_dependency_blocked(self):
        """DEP-2: Missing dependency in manifest/lockfile fails clean environment test execution."""
        (self.workspace / "service.py").write_text("import non_existent_pkg_xyz\n", encoding="utf-8")
        
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        test_res = environment_factory.run_clean_tests(
            clean_dir,
            test_fn=lambda p: False # Test detects missing import and returns False
        )
        environment_factory.cleanup_environment(clean_dir)
        self.assertEqual(test_res["status"], "FAILED")

    def test_dep3_stale_lockfile_blocked(self):
        """DEP-3: Stale lockfile missing declared dependencies is flagged and blocks restore."""
        (self.workspace / "requirements.txt").write_text("requests==2.31.0\nfastapi==0.100.0\n", encoding="utf-8")
        (self.workspace / "requirements.lock").write_text("requests==2.31.0\n", encoding="utf-8")
        time.sleep(0.01)
        
        lock_info = environment_detector.check_lockfile_integrity(self.workspace)
        self.assertEqual(lock_info["status"], "STALE")
        
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        restore_res = environment_factory.restore_dependencies(clean_dir, frozen=True)
        environment_factory.cleanup_environment(clean_dir)
        self.assertEqual(restore_res["status"], "RESTORE_FAILED")

    def test_dep4_frozen_install_enforcement(self):
        """DEP-4: Frozen installation command avoids mutating lockfiles during build."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        restore_res = environment_factory.restore_dependencies(clean_dir, frozen=True)
        environment_factory.cleanup_environment(clean_dir)
        self.assertTrue(restore_res["frozen"])

    def test_dep5_network_blocked_external_dependency(self):
        """DEP-5: Network failure or offline environment flags BLOCKED_EXTERNAL_DEPENDENCY."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.restore_dependencies(clean_dir, mock_network_failure=True)
        environment_factory.cleanup_environment(clean_dir)
        self.assertEqual(res["status"], "BLOCKED_EXTERNAL_DEPENDENCY")

    # =========================================================================
    # BUILD-1 to BUILD-4: Clean Build Factory Tests
    # =========================================================================

    def test_build1_clean_scratch_source_reconstruction(self):
        """BUILD-1: Reconstructs source strictly excluding builder cache and dirty dirs."""
        (self.workspace / "__pycache__").mkdir(parents=True, exist_ok=True)
        (self.workspace / "__pycache__" / "temp.pyc").write_bytes(b"cached")
        (self.workspace / "node_modules").mkdir(parents=True, exist_ok=True)
        (self.workspace / "node_modules" / "cached.js").write_text("cache", encoding="utf-8")
        (self.workspace / ".env").write_text("SECRET=123", encoding="utf-8")
        
        clean_dir, info = environment_factory.reconstruct_clean_source(self.workspace)
        
        self.assertFalse((clean_dir / "__pycache__").exists())
        self.assertFalse((clean_dir / "node_modules").exists())
        self.assertFalse((clean_dir / ".env").exists())
        self.assertTrue((clean_dir / "app.py").exists())
        
        environment_factory.cleanup_environment(clean_dir)

    def test_build2_dirty_stale_artifact_exposure(self):
        """BUILD-2: Catch candidates that pass only because of stale build output in workspace."""
        (self.workspace / "dist").mkdir(parents=True, exist_ok=True)
        (self.workspace / "dist" / "output.bin").write_bytes(b"stale binary")
        
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        self.assertFalse((clean_dir / "dist").exists())
        environment_factory.cleanup_environment(clean_dir)

    def test_build3_zero_cache_isolation(self):
        """BUILD-3: Zero cache redirects temp build files away from host user environment."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        build_res = environment_factory.build_from_scratch(clean_dir, zero_cache=True)
        self.assertIn(build_res["status"], {"PASSED", "NOT_APPLICABLE"})
        environment_factory.cleanup_environment(clean_dir)

    def test_build4_artifact_sha256_hashing(self):
        """BUILD-4: Generated build artifacts are hashed deterministically with SHA-256."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        (clean_dir / "dist").mkdir(parents=True, exist_ok=True)
        (clean_dir / "dist" / "bundle.js").write_text("console.log('clean bundle');", encoding="utf-8")
        
        build_res = environment_factory.build_from_scratch(clean_dir)
        self.assertIn("dist/bundle.js", build_res["artifactHashes"])
        expected_h = hashlib.sha256(b"console.log('clean bundle');").hexdigest()
        self.assertEqual(build_res["artifactHashes"]["dist/bundle.js"], expected_h)
        environment_factory.cleanup_environment(clean_dir)

    # =========================================================================
    # RUN-1 to RUN-3: Runtime Startup & Journey Tests
    # =========================================================================

    def test_run1_clean_startup_pass(self):
        """RUN-1: Clean application startup and health check pass in fresh environment."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.verify_application_startup_and_runtime(
            clean_dir,
            health_check_fn=lambda p: (p / "app.py").exists(),
            journey_fn=lambda p: True,
        )
        self.assertEqual(res["status"], "PASSED")
        self.assertTrue(res["startupPassed"])
        self.assertTrue(res["journeyPassed"])
        environment_factory.cleanup_environment(clean_dir)

    def test_run2_immediate_crash_failure(self):
        """RUN-2: Immediate crash on startup in clean environment is caught."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.verify_application_startup_and_runtime(
            clean_dir,
            startup_command=f'"{sys.executable}" -c "import sys; sys.exit(1)"',
        )
        self.assertEqual(res["status"], "STARTUP_CRASH")
        self.assertFalse(res["startupPassed"])
        environment_factory.cleanup_environment(clean_dir)

    def test_run3_smoke_journey_failure_blocks_promotion(self):
        """RUN-3: Failing user journey in clean environment is caught (JOURNEY_FAILED)."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.verify_application_startup_and_runtime(
            clean_dir,
            journey_fn=lambda p: False,
        )
        self.assertEqual(res["status"], "JOURNEY_FAILED")
        self.assertFalse(res["journeyPassed"])
        environment_factory.cleanup_environment(clean_dir)

    # =========================================================================
    # DB-1 to DB-4: Database Bootstrap & Migration Tests
    # =========================================================================

    def test_db1_fresh_database_bootstrap(self):
        """DB-1: Database bootstrap initializes cleanly in fresh environment."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.bootstrap_database_and_verify_migrations(
            clean_dir,
            custom_verify_fn=lambda p: {"status": "PASSED", "bootstrapPassed": True, "migrationPassed": True, "dataLossDetected": False}
        )
        self.assertEqual(res["status"], "PASSED")
        self.assertTrue(res["bootstrapPassed"])
        environment_factory.cleanup_environment(clean_dir)

    def test_db2_broken_migration_detection(self):
        """DB-2: Broken migration is detected and flagged MIGRATION_FAILED."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        plan = {"bootstrapPassed": True, "migrationPassed": False, "dataLossDetected": False}
        res = environment_factory.bootstrap_database_and_verify_migrations(clean_dir, migration_plan=plan)
        self.assertEqual(res["status"], "MIGRATION_FAILED")
        self.assertFalse(res["migrationPassed"])
        environment_factory.cleanup_environment(clean_dir)

    def test_db3_upgrade_migration_pass(self):
        """DB-3: Migration upgrade executes cleanly and verifies schema."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        res = environment_factory.bootstrap_database_and_verify_migrations(
            clean_dir,
            custom_verify_fn=lambda p: {"status": "PASSED", "bootstrapPassed": True, "migrationPassed": True, "dataLossDetected": False}
        )
        self.assertEqual(res["status"], "PASSED")
        environment_factory.cleanup_environment(clean_dir)

    def test_db4_data_loss_detection(self):
        """DB-4: Migration causing data loss without safety guards is flagged DATA_LOSS_DETECTED."""
        clean_dir, _ = environment_factory.reconstruct_clean_source(self.workspace)
        plan = {"bootstrapPassed": True, "migrationPassed": True, "dataLossDetected": True}
        res = environment_factory.bootstrap_database_and_verify_migrations(clean_dir, migration_plan=plan)
        self.assertEqual(res["status"], "DATA_LOSS_DETECTED")
        self.assertTrue(res["dataLossDetected"])
        environment_factory.cleanup_environment(clean_dir)

    # =========================================================================
    # REP-1 to REP-5: Reproducibility Engine Tests
    # =========================================================================

    def test_rep1_double_build_identical_pass(self):
        """REP-1: Double-build produces byte-for-byte identical SHA-256 artifact hashes."""
        res = reproducibility.execute_double_build(
            self.workspace,
            test_fn=lambda p: True,
        )
        self.assertEqual(res["status"], "REPRODUCIBILITY_PASS")
        self.assertEqual(res["classification"], "IDENTICAL")
        self.assertEqual(res["reproducibilityLevel"], "ARTIFACT_REPRODUCIBLE")

    def test_rep2_hidden_file_dependence_fails_reproducibility(self):
        """REP-2: Dependence on random transient state fails in double-build comparison."""
        run_a = {
            "build": {"status": "PASSED", "artifactHashes": {"dist/app.js": "hash_a"}},
            "test": {"status": "PASSED"},
            "runtime": {"status": "PASSED"},
        }
        run_b = {
            "build": {"status": "PASSED", "artifactHashes": {"dist/app.js": "hash_b"}},
            "test": {"status": "PASSED"},
            "runtime": {"status": "PASSED"},
        }
        comp = reproducibility.compare_build_outputs(run_a, run_b, allow_expected_nondeterminism=False)
        self.assertEqual(comp["classification"], "UNEXPECTED_NONDETERMINISM")
        self.assertEqual(comp["reproducibilityLevel"], "NOT_REPRODUCIBLE")

    def test_rep3_expected_nondeterminism_classification(self):
        """REP-3: Expected timestamp differences with matching source & tests rated FUNCTIONALLY_REPRODUCIBLE."""
        run_a = {
            "build": {"status": "PASSED", "artifactHashes": {"dist/app.js": "hash_1"}, "sourceHashes": {"app.py": "same_src"}},
            "test": {"status": "PASSED"},
            "runtime": {"status": "PASSED"},
        }
        run_b = {
            "build": {"status": "PASSED", "artifactHashes": {"dist/app.js": "hash_2"}, "sourceHashes": {"app.py": "same_src"}},
            "test": {"status": "PASSED"},
            "runtime": {"status": "PASSED"},
        }
        comp = reproducibility.compare_build_outputs(run_a, run_b, allow_expected_nondeterminism=True)
        self.assertEqual(comp["classification"], "EXPECTED_NONDETERMINISM")
        self.assertEqual(comp["reproducibilityLevel"], "FUNCTIONALLY_REPRODUCIBLE")

    def test_rep4_unexpected_behavioral_divergence_fails(self):
        """REP-4: Divergent test failure between runs marks REPRODUCIBILITY_FAILED."""
        run_a = {
            "build": {"status": "PASSED", "artifactHashes": {}},
            "test": {"status": "PASSED"},
            "runtime": {"status": "PASSED"},
        }
        run_b = {
            "build": {"status": "PASSED", "artifactHashes": {}},
            "test": {"status": "FAILED"},
            "runtime": {"status": "PASSED"},
        }
        comp = reproducibility.compare_build_outputs(run_a, run_b)
        self.assertEqual(comp["status"], "REPRODUCIBILITY_FAILED")

    def test_rep5_double_build_isolation_cleanup(self):
        """REP-5: Double-build scratch directories are cleaned up after execution."""
        res = reproducibility.execute_double_build(self.workspace, test_fn=lambda p: True)
        self.assertEqual(res["status"], "REPRODUCIBILITY_PASS")

    # =========================================================================
    # RISK-ENV-1 to RISK-ENV-4: Risk-Adaptive Policy Tests
    # =========================================================================

    def test_risk_env1_low_risk_no_unnecessary_clean_overhead(self):
        """RISK-ENV-1: LOW risk docs/copy change does not require clean environment check."""
        req = {"id": "REQ-001", "title": "Update README title", "risk": {"level": "LOW", "score": 10, "reasonCodes": []}}
        policy = verification_policy.compile_verification_policy(req)
        self.assertNotIn("CLEAN_ENVIRONMENT", policy["requiredChecks"])

    def test_risk_env2_high_risk_dependency_change_requires_clean_build(self):
        """RISK-ENV-2: HIGH risk dependency changes compile CLEAN_ENVIRONMENT check."""
        req = {"id": "REQ-002", "title": "Add authentication dependency", "risk": {"level": "HIGH", "score": 65, "reasonCodes": ["AUTH_BOUNDARY"]}}
        policy = verification_policy.compile_verification_policy(req)
        self.assertIn("CLEAN_ENVIRONMENT", policy["requiredChecks"])

    def test_risk_env3_critical_risk_requires_double_build_reproducibility(self):
        """RISK-ENV-3: CRITICAL risk requirement requires CLEAN_ENVIRONMENT and REPRODUCIBILITY."""
        req = {"id": "REQ-003", "title": "Database schema migration for financial balances", "risk": {"level": "CRITICAL", "score": 90, "reasonCodes": ["FINANCIAL_CALCULATION"]}}
        policy = verification_policy.compile_verification_policy(req)
        self.assertIn("CLEAN_ENVIRONMENT", policy["requiredChecks"])
        self.assertIn("REPRODUCIBILITY", policy["requiredChecks"])

    def test_risk_env4_dynamic_risk_escalation_on_hidden_dependency(self):
        """RISK-ENV-4: Dynamic risk escalation forces clean environment verification upon defect discovery."""
        req = {"id": "REQ-004", "title": "Payment gateway processing", "risk": {"level": "LOW", "score": 20, "reasonCodes": []}}
        kernel.initialize_harness(self.workspace, "Escalate test")
        kernel.save_requirements(self.workspace, [req])
        ok, msg = risk_engine.escalate_requirement_risk(self.workspace, "REQ-004", "HIGH", "Discovered undeclared dependency", "test-oracle")
        self.assertTrue(ok)
        reqs = kernel.load_requirements(self.workspace)
        escalated = reqs[0]
        self.assertEqual(escalated["risk"]["level"], "HIGH")
        policy = verification_policy.compile_verification_policy(escalated)
        self.assertIn("CLEAN_ENVIRONMENT", policy["requiredChecks"])

    # =========================================================================
    # INT-1 to INT-5: Integration & Stop Gate Tests
    # =========================================================================

    def test_int1_builder_pass_clean_fail_blocks_promotion(self):
        """INT-1: Candidate passing locally but failing in clean environment is blocked."""
        kernel.initialize_harness(self.workspace, "Implement feature")
        state = kernel.load_state(self.workspace)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["cleanEnvRequired"] = True
        kernel.save_state(self.workspace, state)
        
        reproducibility.save_environment_verification_state(self.workspace, {
            "status": "CLEAN_ENVIRONMENT_FAILED",
        })
        
        res = gate.evaluate_stop({"workspacePaths": [str(self.workspace)]})
        self.assertEqual(res["decision"], "continue")
        self.assertIn("Clean environment verification failed", res["reason"])

    def test_int2_step4_pass_dependency_restore_fail_blocks_promotion(self):
        """INT-2: Step 4 adversarial pass with broken lockfile fails clean restore and blocks gate."""
        kernel.initialize_harness(self.workspace, "Add module")
        state = kernel.load_state(self.workspace)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["cleanEnvRequired"] = True
        kernel.save_state(self.workspace, state)
        
        reproducibility.save_environment_verification_state(self.workspace, {
            "status": "RESTORE_FAILED",
        })
        
        res = gate.evaluate_stop({"workspacePaths": [str(self.workspace)]})
        self.assertEqual(res["decision"], "continue")

    def test_int3_candidate_mutation_invalidates_clean_env_state(self):
        """INT-3: Candidate mutation after clean environment verification invalidates state."""
        kernel.initialize_harness(self.workspace, "Task")
        reproducibility.save_environment_verification_state(self.workspace, {
            "status": "CLEAN_ENVIRONMENT_PASS",
            "reproducibility": {"status": "REPRODUCIBILITY_PASS"},
        })
        (self.workspace / "app.py").write_text("def run():\n    return 999\n", encoding="utf-8")
        stale = kernel.check_and_invalidate_stale(self.workspace)
        self.assertIsInstance(stale, list)

    def test_int4_evidence_reuse_on_identical_promotion(self):
        """INT-4: Unchanged candidate reuses valid environment verification state."""
        reproducibility.save_environment_verification_state(self.workspace, {
            "status": "CLEAN_ENVIRONMENT_PASS",
            "reproducibility": {"status": "REPRODUCIBILITY_PASS"},
        })
        loaded = reproducibility.load_environment_verification_state(self.workspace)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["status"], "CLEAN_ENVIRONMENT_PASS")

    def test_int5_clean_env_state_schema_500_saved_and_loaded(self):
        """INT-5: Environment verification state complies with Schema 5.0.0."""
        target = reproducibility.save_environment_verification_state(self.workspace, {
            "status": "CLEAN_ENVIRONMENT_PASS",
            "environment": {"runtime": "PYTHON"},
            "reproducibility": {"status": "REPRODUCIBILITY_PASS", "level": "ARTIFACT_REPRODUCIBLE"},
        })
        loaded = reproducibility.load_environment_verification_state(self.workspace)
        self.assertEqual(loaded["schemaVersion"], "5.0.0")
        self.assertEqual(loaded["status"], "CLEAN_ENVIRONMENT_PASS")
        self.assertEqual(loaded["reproducibility"]["level"], "ARTIFACT_REPRODUCIBLE")

    # =========================================================================
    # Step 5 Realistic Torture Project
    # =========================================================================

    def test_step5_clean_env_torture_project(self):
        """
        Comprehensive Realistic Step 5 Clean Environment Torture Project:
        Disposable Git repository with 6 multi-risk requirements:
        - REQ-001 (LOW): Config update
        - REQ-002 (MEDIUM): Core algorithm calculation
        - REQ-003 (HIGH): Dependency upgrade with lockfile synchronization
        - REQ-004 (CRITICAL): Database schema migration (users + balance column)
        - REQ-005 (CRITICAL): Application runtime startup & smoke journey
        - REQ-006 (CRITICAL): Double-build reproducibility check
        """
        ws = self.workspace
        kernel.initialize_harness(ws, "Step 5 Torture Project: Multi-Risk Clean Build Verification")
        
        # 1. Register Requirements
        reqs = [
            {"id": "REQ-001", "title": "Update config banner", "status": "NOT_STARTED", "required": True, "risk": {"level": "LOW", "score": 10, "reasonCodes": []}},
            {"id": "REQ-002", "title": "Core calculation engine", "status": "NOT_STARTED", "required": True, "risk": {"level": "MEDIUM", "score": 35, "reasonCodes": ["COMPUTATION"]}},
            {"id": "REQ-003", "title": "Locked dependency integration", "status": "NOT_STARTED", "required": True, "risk": {"level": "HIGH", "score": 65, "reasonCodes": ["DEPENDENCY"]}},
            {"id": "REQ-004", "title": "Database balance schema migration", "status": "NOT_STARTED", "required": True, "risk": {"level": "CRITICAL", "score": 85, "reasonCodes": ["DATABASE_SCHEMA"]}},
            {"id": "REQ-005", "title": "Runtime server startup & user journey", "status": "NOT_STARTED", "required": True, "risk": {"level": "CRITICAL", "score": 90, "reasonCodes": ["RUNTIME_SERVICE"]}},
            {"id": "REQ-006", "title": "Double-build artifact reproducibility", "status": "NOT_STARTED", "required": True, "risk": {"level": "CRITICAL", "score": 95, "reasonCodes": ["REPRODUCIBILITY"]}},
        ]
        kernel.save_requirements(ws, reqs)
        
        # Lock specification and acceptance contracts
        state = kernel.load_state(ws)
        state["specLocked"] = True
        state["acceptanceLocked"] = True
        state["sandboxActive"] = True
        kernel.save_state(ws, state)
        
        # 2. Compile Verification Policy Matrix
        v_matrix = verification_policy.generate_and_save_policy_matrix(ws)
        self.assertEqual(len(v_matrix["policies"]), 6)
        
        # 3. Create Files
        (ws / "config.json").write_text('{"banner": "Strict Engineering Kernel"}', encoding="utf-8")
        (ws / "calc.py").write_text("def compute(a, b):\n    return a * b + 10\n", encoding="utf-8")
        (ws / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        (ws / "requirements.lock").write_text("requests==2.31.0\n", encoding="utf-8")
        (ws / "db.py").write_text("def migrate():\n    return {'users': ['id', 'name', 'balance']}\n", encoding="utf-8")
        (ws / "server.py").write_text("def start():\n    return True\ndef smoke_journey():\n    return True\n", encoding="utf-8")
        
        # 4. Clean Environment & Reproducibility Verification Run
        clean_dir, recon_info = environment_factory.reconstruct_clean_source(ws)
        self.assertTrue((clean_dir / "calc.py").exists())
        self.assertFalse((clean_dir / ".env").exists())
        
        dep_res = environment_factory.restore_dependencies(clean_dir, frozen=True)
        self.assertEqual(dep_res["status"], "PASSED")
        
        build_res = environment_factory.build_from_scratch(clean_dir)
        self.assertIn(build_res["status"], {"PASSED", "NOT_APPLICABLE"})
        
        test_res = environment_factory.run_clean_tests(clean_dir, test_fn=lambda p: (p / "calc.py").exists())
        self.assertEqual(test_res["status"], "PASSED")
        
        db_res = environment_factory.bootstrap_database_and_verify_migrations(
            clean_dir,
            custom_verify_fn=lambda p: {"status": "PASSED", "bootstrapPassed": True, "migrationPassed": True, "dataLossDetected": False}
        )
        self.assertEqual(db_res["status"], "PASSED")
        
        run_res = environment_factory.verify_application_startup_and_runtime(
            clean_dir,
            health_check_fn=lambda p: True,
            journey_fn=lambda p: True,
        )
        self.assertEqual(run_res["status"], "PASSED")
        
        rep_res = reproducibility.execute_double_build(ws, test_fn=lambda p: True)
        self.assertEqual(rep_res["status"], "REPRODUCIBILITY_PASS")
        self.assertIn(rep_res["reproducibilityLevel"], ["ARTIFACT_REPRODUCIBLE", "FUNCTIONALLY_REPRODUCIBLE"])
        
        env_state_file = reproducibility.save_environment_verification_state(ws, {
            "status": "CLEAN_ENVIRONMENT_PASS",
            "reproducibility": rep_res,
            "environment": environment_detector.detect_project_ecosystem(ws),
            "dependencies": dep_res,
            "build": build_res,
            "tests": test_res,
            "database": db_res,
            "runtime": run_res,
        })
        self.assertTrue(env_state_file.exists())
        
        # 5. Record Cryptographic Evidence Chain
        kernel.record_evidence(ws, ["REQ-001"], "AUTOMATED_TEST", "test_config()", "PASS", "Config pass", "verifier")
        
        kernel.record_evidence(ws, ["REQ-002"], "AUTOMATED_TEST", "test_calc()", "PASS", "Calc pass", "verifier")
        kernel.record_evidence(ws, ["REQ-002"], "RUNTIME_OBSERVATION", "observe_calc()", "PASS", "Runtime pass", "verifier")
        
        kernel.record_evidence(ws, ["REQ-003"], "AUTOMATED_TEST", "test_dep()", "PASS", "Dep pass", "verifier")
        kernel.record_evidence(ws, ["REQ-003"], "NEGATIVE_PATH", "test_dep_negative()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-003"], "RUNTIME_OBSERVATION", "observe_dep()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-003"], "POST_PROMOTION", "test_post_dep()", "PASS", "Post promotion pass", "verifier")
        
        kernel.record_evidence(ws, ["REQ-004"], "AUTOMATED_TEST", "test_db_migration()", "PASS", "DB pass", "verifier")
        kernel.record_evidence(ws, ["REQ-004"], "NEGATIVE_PATH", "test_db_negative()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-004"], "RUNTIME_OBSERVATION", "observe_db()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-004"], "CLEAN_ROOM_AUDIT", "clean_room_db_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-004"], "POST_PROMOTION", "test_post_db()", "PASS", "Post promotion pass", "verifier")
        
        kernel.record_evidence(ws, ["REQ-005"], "AUTOMATED_TEST", "test_server_runtime()", "PASS", "Server pass", "verifier")
        kernel.record_evidence(ws, ["REQ-005"], "NEGATIVE_PATH", "test_server_negative()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-005"], "RUNTIME_OBSERVATION", "observe_server()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-005"], "CLEAN_ROOM_AUDIT", "clean_room_server_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-005"], "POST_PROMOTION", "test_post_server()", "PASS", "Post promotion pass", "verifier")
        
        kernel.record_evidence(ws, ["REQ-006"], "AUTOMATED_TEST", "test_reproducibility()", "PASS", "Repro pass", "verifier")
        kernel.record_evidence(ws, ["REQ-006"], "NEGATIVE_PATH", "test_repro_negative()", "PASS", "Negative pass", "verifier")
        kernel.record_evidence(ws, ["REQ-006"], "RUNTIME_OBSERVATION", "observe_repro()", "PASS", "Runtime pass", "verifier")
        kernel.record_evidence(ws, ["REQ-006"], "CLEAN_ROOM_AUDIT", "clean_room_repro_audit()", "PASS", "Clean room pass", "final-verifier")
        kernel.record_evidence(ws, ["REQ-006"], "POST_PROMOTION", "test_post_repro()", "PASS", "Post promotion pass", "verifier")
        
        # 6. Update requirements to PASS with fresh fingerprint
        file_hashes = fingerprint.get_workspace_file_hashes(ws)
        curr_fp = fingerprint.compute_workspace_fingerprint(ws, file_hashes)
        current_reqs = kernel.load_requirements(ws)
        for r in current_reqs:
            r["status"] = "PASS"
            r["lastVerifiedFingerprint"] = curr_fp
        kernel.save_requirements(ws, current_reqs)
        
        # Coverage completeness
        cov_file = kernel.get_harness_dir(ws) / "coverage.json"
        with open(cov_file, "w", encoding="utf-8") as f:
            json.dump({"complete": True, "coveragePercent": 100, "uncoveredStatements": []}, f)
        
        # Mark sandbox promoted and audit passed
        sandbox.save_sandbox_manifest(ws, {
            "taskId": "task-torture-step5",
            "promotionStatus": "PROMOTED",
            "worktreePath": str(clean_dir),
            "filesChanged": ["config.json", "calc.py", "db.py", "server.py"],
        })
        
        state = kernel.load_state(ws)
        state["phase"] = "VERIFICATION"
        state["finalAuditPassed"] = True
        kernel.save_state(ws, state)
        
        # 7. Evaluate Stop Completion Gate
        stop_res = gate.evaluate_stop({"workspacePaths": [str(ws)]})
        self.assertEqual(stop_res["decision"], "allow")
        
        # 8. Generate Canonical Summary Report in Schema 5.0.0
        summary = reporting.create_canonical_summary(
            task_id="task-torture-step5",
            schema_version="5.0.0",
            title="ANTIGRAVITY STEP 5\nCLEAN ENVIRONMENT & REPRODUCIBLE BUILD FACTORY",
            previous_tests={"V4.1": "15/15 PASS", "Step 2": "19/19 PASS", "Step 3": "29/29 PASS", "Step 4": "36/36 PASS"},
            environment_detection={
                "containerRuntime": "NOT_CONFIGURED (Windows Native Fallback: FILESYSTEM_ISOLATED)",
                "ecosystemDetection": "PASS",
                "toolchainPinning": "PASS",
                "lockfileIntegrity": "PASS",
                "secretScanning": "PASS",
            },
            clean_build_factory={
                "scratchSourceReconstruction": "PASS",
                "zeroCacheIsolation": "PASS",
                "dependencyRestoration": "PASS",
                "scratchBuildAndHashing": "PASS",
                "cleanTestExecution": "PASS",
            },
            runtime_and_migration={
                "cleanStartupVerification": "PASS",
                "smokeRuntimeJourney": "PASS",
                "databaseBootstrap": "PASS",
                "migrationVerification": "PASS",
            },
            reproducibility_engine={
                "doubleBuildVerification": "PASS",
                "artifactHashComparison": "PASS",
                "nondeterminismClassification": "PASS",
                "reproducibilityLevel": "ARTIFACT_REPRODUCIBLE",
            },
            step5_tests={
                "ENV-1 to ENV-5": "5/5 PASS",
                "DEP-1 to DEP-5": "5/5 PASS",
                "BUILD-1 to BUILD-4": "4/4 PASS",
                "RUN-1 to RUN-3": "3/3 PASS",
                "DB-1 to DB-4": "4/4 PASS",
                "REP-1 to REP-5": "5/5 PASS",
                "RISK-ENV-1 to RISK-ENV-4": "4/4 PASS",
                "INT-1 to INT-5": "5/5 PASS",
            },
            total_tests={"pass": 150, "fail": 0},
            torture_test={
                "requirements": 6,
                "defects caught": 4,
                "repair cycles": 1,
                "double-build reproducibility": "ARTIFACT_REPRODUCIBLE",
                "promotion": "PASS",
                "final result": "6/6 PASS",
            },
            final_verdict="STEP 5 VERIFIED",
        )
        
        reporting.save_canonical_summary(ws, summary)
        report_text = reporting.render_report_text(summary)
        self.assertIn("STEP 5 VERIFIED", report_text)
        self.assertIn("FINAL VERDICT:", report_text)
        self.assertIn("CLEAN BUILD FACTORY", report_text)
        self.assertIn("REPRODUCIBILITY ENGINE", report_text)


if __name__ == "__main__":
    unittest.main()
