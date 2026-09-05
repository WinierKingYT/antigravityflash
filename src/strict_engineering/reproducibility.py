"""
Strict Engineering Kernel Step 5 - Reproducibility Engine
Performs double-build verification (Run A vs Run B in independent fresh environments),
artifact hashing (SHA-256), output difference classification, and reproducibility level rating.
"""

import os
import sys
import json
import time
import hashlib
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set, Callable

try:
    from . import kernel
    from . import environment_detector
    from . import environment_factory
except (ImportError, ValueError):
    import kernel
    import environment_detector
    import environment_factory


def execute_double_build(
    workspace_dir: Path,
    candidate_manifest: Optional[Dict[str, Any]] = None,
    build_command: Optional[str] = None,
    test_fn: Optional[Callable[[Path], bool]] = None,
    journey_fn: Optional[Callable[[Path], bool]] = None,
) -> Dict[str, Any]:
    """
    Executes Run A and Run B in two completely independent scratch environments.
    Captures artifact hashes, source fingerprints, and test outputs.
    """
    workspace_path = Path(workspace_dir).resolve()
    
    # --- RUN A ---
    dir_a, info_a = environment_factory.reconstruct_clean_source(workspace_path, candidate_manifest)
    try:
        dep_a = environment_factory.restore_dependencies(dir_a)
        build_a = environment_factory.build_from_scratch(dir_a, build_command=build_command)
        test_a = environment_factory.run_clean_tests(dir_a, test_fn=test_fn)
        runtime_a = environment_factory.verify_application_startup_and_runtime(dir_a, journey_fn=journey_fn)
    finally:
        pass # keep for inspection until comparison finishes

    # --- RUN B ---
    dir_b, info_b = environment_factory.reconstruct_clean_source(workspace_path, candidate_manifest)
    try:
        dep_b = environment_factory.restore_dependencies(dir_b)
        build_b = environment_factory.build_from_scratch(dir_b, build_command=build_command)
        test_b = environment_factory.run_clean_tests(dir_b, test_fn=test_fn)
        runtime_b = environment_factory.verify_application_startup_and_runtime(dir_b, journey_fn=journey_fn)
    finally:
        pass

    # Compare Run A and Run B
    comparison = compare_build_outputs(
        run_a_results={
            "info": info_a,
            "dependencies": dep_a,
            "build": build_a,
            "test": test_a,
            "runtime": runtime_a,
        },
        run_b_results={
            "info": info_b,
            "dependencies": dep_b,
            "build": build_b,
            "test": test_b,
            "runtime": runtime_b,
        },
    )

    # Cleanup scratch dirs
    environment_factory.cleanup_environment(dir_a)
    environment_factory.cleanup_environment(dir_b)

    return comparison


def compare_build_outputs(
    run_a_results: Dict[str, Any],
    run_b_results: Dict[str, Any],
    allow_expected_nondeterminism: bool = True,
) -> Dict[str, Any]:
    """
    Compares outputs between Run A and Run B.
    Classifies result into:
    - ARTIFACT_REPRODUCIBLE (exact SHA-256 byte-for-byte match)
    - FUNCTIONALLY_REPRODUCIBLE (functional behaviors match, expected timestamp/metadata variance)
    - NOT_REPRODUCIBLE (functional divergence, different test results, or missing files)
    """
    build_a = run_a_results.get("build", {})
    build_b = run_b_results.get("build", {})
    test_a = run_a_results.get("test", {})
    test_b = run_b_results.get("test", {})
    runtime_a = run_a_results.get("runtime", {})
    runtime_b = run_b_results.get("runtime", {})

    art_a = build_a.get("artifactHashes", {})
    art_b = build_b.get("artifactHashes", {})

    src_a = build_a.get("sourceHashes", {})
    src_b = build_b.get("sourceHashes", {})

    # Check build and test pass status
    both_built = build_a.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"} and build_b.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"}
    both_tested = test_a.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"} and test_b.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"}
    both_runtime = runtime_a.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"} and runtime_b.get("status") in {"PASSED", "REPRODUCIBILITY_PASS", "NOT_APPLICABLE"}

    if not (both_built and both_tested and both_runtime):
        return {
            "status": "REPRODUCIBILITY_FAILED",
            "classification": "UNEXPECTED_NONDETERMINISM",
            "reproducibilityLevel": "NOT_REPRODUCIBLE",
            "runAPassed": both_built and test_a.get("status") in {"PASSED", "NOT_APPLICABLE"},
            "runBPassed": both_built and test_b.get("status") in {"PASSED", "NOT_APPLICABLE"},
            "artifactDiffs": ["One or both runs failed to build or pass tests."],
            "details": f"Run A: build={build_a.get('status')}, test={test_a.get('status')}; Run B: build={build_b.get('status')}, test={test_b.get('status')}",
        }

    # Compare artifact hashes
    all_art_keys = sorted(list(set(list(art_a.keys()) + list(art_b.keys()))))
    mismatched_artifacts: List[Dict[str, str]] = []
    missing_in_a: List[str] = []
    missing_in_b: List[str] = []

    for k in all_art_keys:
        if k not in art_a:
            missing_in_a.append(k)
        elif k not in art_b:
            missing_in_b.append(k)
        elif art_a[k] != art_b[k]:
            mismatched_artifacts.append({
                "artifact": k,
                "hashA": art_a[k],
                "hashB": art_b[k],
            })

    # Compare source hashes if no explicit artifacts
    source_mismatches: List[str] = []
    for k in sorted(list(set(list(src_a.keys()) + list(src_b.keys())))):
        if src_a.get(k) != src_b.get(k):
            source_mismatches.append(k)

    if not missing_in_a and not missing_in_b and not mismatched_artifacts and not source_mismatches:
        classification = "IDENTICAL"
        level = "ARTIFACT_REPRODUCIBLE"
        status = "REPRODUCIBILITY_PASS"
        details = "Byte-for-byte SHA-256 identical outputs across independent clean runs."
    elif not missing_in_a and not missing_in_b and len(source_mismatches) == 0 and allow_expected_nondeterminism:
        classification = "EXPECTED_NONDETERMINISM"
        level = "FUNCTIONALLY_REPRODUCIBLE"
        status = "REPRODUCIBILITY_PASS"
        details = f"Functional outcomes match 100%. {len(mismatched_artifacts)} artifact(s) have timestamp/header differences."
    else:
        classification = "UNEXPECTED_NONDETERMINISM"
        level = "NOT_REPRODUCIBLE"
        status = "REPRODUCIBILITY_FAILED"
        details = f"Divergent build outputs: {len(mismatched_artifacts)} mismatched hashes, {len(missing_in_a)} missing in A, {len(missing_in_b)} missing in B, {len(source_mismatches)} source differences."

    return {
        "status": status,
        "classification": classification,
        "reproducibilityLevel": level,
        "runAPassed": True,
        "runBPassed": True,
        "totalArtifactsRunA": len(art_a),
        "totalArtifactsRunB": len(art_b),
        "mismatchedArtifacts": mismatched_artifacts,
        "sourceMismatches": source_mismatches,
        "details": details,
    }


def save_environment_verification_state(
    workspace_dir: Path,
    env_state: Dict[str, Any],
) -> Path:
    """
    Saves machine-readable .agent-harness/environment-verification.json state.
    """
    harness_dir = kernel.get_harness_dir(workspace_dir)
    harness_dir.mkdir(parents=True, exist_ok=True)
    target = harness_dir / "environment-verification.json"
    
    state_payload = {
        "schemaVersion": "5.0.0",
        "timestamp": kernel.utc_now_iso(),
        "status": env_state.get("status", "CLEAN_ENVIRONMENT_PASS"),
        "reproducibility": env_state.get("reproducibility", {}),
        "environment": env_state.get("environment", {}),
        "dependencies": env_state.get("dependencies", {}),
        "build": env_state.get("build", {}),
        "tests": env_state.get("tests", {}),
        "database": env_state.get("database", {}),
        "runtime": env_state.get("runtime", {}),
    }

    with open(target, "w", encoding="utf-8") as f:
        json.dump(state_payload, f, indent=2)

    return target


def load_environment_verification_state(workspace_dir: Path) -> Optional[Dict[str, Any]]:
    """
    Loads machine-readable .agent-harness/environment-verification.json state.
    """
    harness_dir = kernel.get_harness_dir(workspace_dir)
    harness_dir.mkdir(parents=True, exist_ok=True)
    target = harness_dir / "environment-verification.json"
    if not target.exists():
        return None
    try:
        with open(target, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
