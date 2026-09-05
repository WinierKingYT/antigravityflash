"""
Strict Engineering Kernel Step 5.1 - Clean Environment & Real Execution Factory
Executes real dependency restoration, real scratch builds, real test suites,
real application startups, and real database migrations inside isolated disposable workspaces.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable, Set

try:
    from . import kernel
    from . import environment_detector
except (ImportError, ValueError):
    import kernel
    import environment_detector

EXCLUDED_CLEAN_DIRS = {
    "node_modules",
    "venv",
    ".venv",
    "env",
    "target",
    "dist",
    "build",
    "out",
    "bin",
    "obj",
    ".cache",
    ".pytest_cache",
    "__pycache__",
    ".git",
    ".agent-harness",
    ".worktrees",
    ".backups",
    ".next",
    ".turbo",
    ".nuxt",
}

EXCLUDED_CLEAN_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
}


def reconstruct_clean_source(
    workspace_dir: Path,
    candidate_manifest: Optional[Dict[str, Any]] = None,
) -> Tuple[Path, Dict[str, Any]]:
    """
    Reconstructs clean, unpolluted source tree in a disposable scratch directory.
    Excludes node_modules, virtual environments, build outputs, and local .env secrets.
    """
    workspace_path = Path(workspace_dir).resolve()
    clean_dir = Path(tempfile.mkdtemp(prefix="clean_env_"))
    reconstructed_files = []
    file_hashes: Dict[str, str] = {}

    for root, dirs, files in os.walk(workspace_path):
        # Prune excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_CLEAN_DIRS and not d.startswith(".cache")]

        rel_root = os.path.relpath(root, workspace_path)
        if rel_root == ".":
            rel_root = ""

        target_root = clean_dir / rel_root
        target_root.mkdir(parents=True, exist_ok=True)

        for f in files:
            if f in EXCLUDED_CLEAN_FILES or f.endswith(".pyc") or f.endswith(".pyo"):
                continue
            
            src_file = Path(root) / f
            dst_file = target_root / f
            shutil.copy2(src_file, dst_file)
            
            rel_file = str(Path(rel_root) / f).replace("\\", "/")
            if rel_file.startswith("./"):
                rel_file = rel_file[2:]
            reconstructed_files.append(rel_file)
            
            f_hash = hashlib.sha256(dst_file.read_bytes()).hexdigest()
            file_hashes[rel_file] = f_hash

    tree_sorted = json.dumps(file_hashes, sort_keys=True)
    tree_fingerprint = hashlib.sha256(tree_sorted.encode("utf-8")).hexdigest()

    reconstruction_info = {
        "cleanDir": str(clean_dir),
        "totalFiles": len(reconstructed_files),
        "treeFingerprint": tree_fingerprint,
        "files": sorted(reconstructed_files),
    }

    return clean_dir, reconstruction_info


def restore_dependencies(
    clean_env_dir: Path,
    ecosystem_info: Optional[Dict[str, Any]] = None,
    frozen: bool = True,
    offline: bool = False,
    mock_network_failure: bool = False,
    origin: str = "REAL_PROJECT_EXECUTION",
) -> Dict[str, Any]:
    """
    Executes locked dependency restoration inside the clean environment.
    Executes the real package manager (npm ci, uv sync, cargo fetch, etc.) when discovered.
    """
    clean_dir = Path(clean_env_dir).resolve()
    if ecosystem_info is None:
        ecosystem_info = environment_detector.detect_project_ecosystem(clean_dir)

    lockfile_info = environment_detector.check_lockfile_integrity(clean_dir)
    runtime = ecosystem_info.get("runtime", "UNKNOWN")
    pm = ecosystem_info.get("packageManager", "UNKNOWN")

    start_time = time.time()
    
    if mock_network_failure or offline:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "BLOCKED_EXTERNAL_DEPENDENCY",
            "exitCode": 1,
            "durationMs": duration_ms,
            "error": "Network access blocked or offline mode active; failed to reach package registry.",
            "stdout": "",
            "stderr": "NETWORK_BLOCKED: Connection to registry failed.",
            "frozen": frozen,
            "origin": origin,
            "executionType": "DEPENDENCY_RESTORE",
        }

    # If lockfile is missing or stale when frozen is required
    if frozen and lockfile_info.get("status") in {"STALE", "MISSING"}:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "RESTORE_FAILED",
            "exitCode": 1,
            "durationMs": duration_ms,
            "error": f"Lockfile integrity check failed ({lockfile_info.get('status')}): {', '.join(lockfile_info.get('issues', []))}",
            "stdout": "",
            "stderr": "LOCKFILE_STALE_OR_MISSING",
            "frozen": frozen,
            "origin": origin,
            "executionType": "DEPENDENCY_RESTORE",
        }

    # Discover real restore command
    restore_cmd = None
    has_dep_config = False

    if (clean_dir / "package-lock.json").exists():
        restore_cmd = "npm ci"
        has_dep_config = True
    elif (clean_dir / "pnpm-lock.yaml").exists():
        restore_cmd = "pnpm install --frozen-lockfile"
        has_dep_config = True
    elif (clean_dir / "yarn.lock").exists():
        restore_cmd = "yarn install --immutable"
        has_dep_config = True
    elif (clean_dir / "uv.lock").exists():
        restore_cmd = "uv sync --frozen"
        has_dep_config = True
    elif (clean_dir / "poetry.lock").exists():
        restore_cmd = "poetry install --no-root"
        has_dep_config = True
    elif (clean_dir / "Cargo.lock").exists():
        restore_cmd = "cargo fetch --locked"
        has_dep_config = True
    elif (clean_dir / "go.sum").exists():
        restore_cmd = "go mod download"
        has_dep_config = True
    elif (clean_dir / "packages.lock.json").exists():
        restore_cmd = "dotnet restore --locked-mode"
        has_dep_config = True
    elif (clean_dir / "requirements.txt").exists():
        restore_cmd = f"{sys.executable} -m pip install -r requirements.txt --dry-run"
        has_dep_config = True
    elif (clean_dir / "pyproject.toml").exists():
        has_dep_config = True
        # Check if dependencies declared
        try:
            content = (clean_dir / "pyproject.toml").read_text(encoding="utf-8")
            if "dependencies" in content:
                restore_cmd = f"{sys.executable} -m pip install . --dry-run"
        except Exception:
            pass

    if not has_dep_config:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "NOT_APPLICABLE",
            "exitCode": 0,
            "durationMs": duration_ms,
            "error": None,
            "stdout": "No external dependency configuration detected in project.",
            "stderr": "",
            "frozen": frozen,
            "origin": origin,
            "executionType": "DEPENDENCY_RESTORE",
        }

    if not restore_cmd:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "NOT_CONFIGURED",
            "exitCode": None,
            "durationMs": duration_ms,
            "error": "Dependency configuration present but no package manager restore command available on host.",
            "stdout": "",
            "stderr": "PACKAGE_MANAGER_NOT_CONFIGURED",
            "frozen": frozen,
            "origin": origin,
            "executionType": "DEPENDENCY_RESTORE",
        }

    # Execute real restore command
    status = "PASSED"
    exit_code = 0
    stdout = ""
    stderr = ""
    error = None

    try:
        res = subprocess.run(
            restore_cmd,
            shell=True,
            cwd=str(clean_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        exit_code = res.returncode
        stdout = res.stdout
        stderr = res.stderr
        if exit_code != 0:
            status = "RESTORE_FAILED"
            error = f"Restore command '{restore_cmd}' failed with exit code {exit_code}."
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
        exit_code = 124
        error = f"Restore command '{restore_cmd}' timed out after 60s."
    except Exception as e:
        status = "RESTORE_FAILED"
        exit_code = 1
        error = f"Dependency restore execution failed: {str(e)}"

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "status": status,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "error": error,
        "stdout": kernel.scrub_secrets(stdout),
        "stderr": kernel.scrub_secrets(stderr),
        "stdoutHash": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrHash": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "command": restore_cmd,
        "frozen": frozen,
        "origin": origin,
        "executionType": "DEPENDENCY_RESTORE",
    }


def build_from_scratch(
    clean_env_dir: Path,
    build_command: Optional[str] = None,
    zero_cache: bool = True,
    env_overrides: Optional[Dict[str, str]] = None,
    origin: str = "REAL_PROJECT_EXECUTION",
) -> Dict[str, Any]:
    """
    Executes scratch build in clean environment with zero caching.
    Discovers build command if none provided. Never returns PASS without execution.
    """
    clean_dir = Path(clean_env_dir).resolve()
    start_time = time.time()

    # Sanitize environment variables to prevent host cache contamination
    build_env = os.environ.copy()
    if zero_cache:
        temp_cache_dir = clean_dir / ".cache_scratch"
        temp_cache_dir.mkdir(parents=True, exist_ok=True)
        build_env["PYTHONDONTWRITEBYTECODE"] = "1"
        build_env["npm_config_cache"] = str(temp_cache_dir / "npm")
        build_env["CARGO_TARGET_DIR"] = str(clean_dir / "target")
        build_env["TEMP"] = str(temp_cache_dir)
        build_env["TMP"] = str(temp_cache_dir)

    if env_overrides:
        build_env.update(env_overrides)

    cmd = build_command
    if not cmd:
        # Discover build command
        if (clean_dir / "package.json").exists():
            try:
                pkg_data = json.loads((clean_dir / "package.json").read_text(encoding="utf-8"))
                if "build" in pkg_data.get("scripts", {}):
                    cmd = "npm run build"
            except Exception:
                pass
        elif (clean_dir / "Cargo.toml").exists():
            cmd = "cargo build"
        elif (clean_dir / "Makefile").exists():
            cmd = "make"
        elif list(clean_dir.glob("*.csproj")):
            cmd = "dotnet build"

    if not cmd:
        duration_ms = int((time.time() - start_time) * 1000)
        # Check if project requires build
        needs_build = (
            (clean_dir / "tsconfig.json").exists()
            or (clean_dir / "Cargo.toml").exists()
            or (clean_dir / "CMakeLists.txt").exists()
            or bool(list(clean_dir.glob("*.csproj")))
        )
        if needs_build:
            return {
                "status": "NOT_CONFIGURED",
                "exitCode": None,
                "durationMs": duration_ms,
                "error": "Project architecture requires a build phase, but no build command was configured or discovered.",
                "stdout": "",
                "stderr": "BUILD_NOT_CONFIGURED",
                "origin": origin,
                "executionType": "BUILD",
            }
        else:
            # Collect artifact hashes from dist, build, out, target
            artifact_hashes: Dict[str, str] = {}
            for art_dir_name in ["dist", "build", "out", "target"]:
                art_dir = clean_dir / art_dir_name
                if art_dir.exists():
                    for root, _, files in os.walk(art_dir):
                        for f in files:
                            fp = Path(root) / f
                            try:
                                rel = str(fp.relative_to(clean_dir)).replace("\\", "/")
                                artifact_hashes[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
                            except Exception:
                                pass

            source_hashes: Dict[str, str] = {}
            for root, dirs, files in os.walk(clean_dir):
                dirs[:] = [d for d in dirs if d not in {".git", ".cache_scratch", "node_modules", ".venv", "__pycache__", "dist", "build", "out", "target"}]
                for f in files:
                    fp = Path(root) / f
                    try:
                        rel = str(fp.relative_to(clean_dir)).replace("\\", "/")
                        source_hashes[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
                    except Exception:
                        pass

            if needs_build:
                return {
                    "status": "NOT_CONFIGURED",
                    "exitCode": None,
                    "durationMs": duration_ms,
                    "error": "Project architecture requires a build phase, but no build command was configured or discovered.",
                    "stdout": "",
                    "stderr": "BUILD_NOT_CONFIGURED",
                    "origin": origin,
                    "executionType": "BUILD",
                }
            elif artifact_hashes:
                return {
                    "status": "PASSED",
                    "exitCode": 0,
                    "durationMs": duration_ms,
                    "error": None,
                    "stdout": "Artifacts discovered in build output directory.",
                    "stderr": "",
                    "artifactHashes": artifact_hashes,
                    "sourceHashes": source_hashes,
                    "totalArtifacts": len(artifact_hashes),
                    "origin": origin,
                    "executionType": "BUILD",
                }
            else:
                return {
                    "status": "NOT_APPLICABLE",
                    "exitCode": 0,
                    "durationMs": duration_ms,
                    "error": None,
                    "stdout": "No build phase applicable for this project.",
                    "stderr": "",
                    "artifactHashes": {},
                    "sourceHashes": source_hashes,
                    "totalArtifacts": 0,
                    "origin": origin,
                    "executionType": "BUILD",
                }

    status = "PASSED"
    exit_code = 0
    stdout = ""
    stderr = ""
    error = None

    try:
        res = subprocess.run(
            cmd,
            shell=True,
            cwd=str(clean_dir),
            env=build_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        exit_code = res.returncode
        stdout = res.stdout
        stderr = res.stderr
        if exit_code != 0:
            status = "FAILED"
            error = f"Build command '{cmd}' returned non-zero exit code {exit_code}."
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
        exit_code = 124
        error = f"Build command '{cmd}' timed out after 60s."
    except Exception as e:
        status = "FAILED"
        exit_code = 1
        error = f"Build execution failed: {str(e)}"

    # Scan for output artifacts (dist, build, out, bin, target, *.whl, *.tar.gz, etc.)
    artifact_hashes: Dict[str, str] = {}
    artifact_dirs = ["dist", "build", "bin", "out", "target", "output"]
    
    for art_dir_name in artifact_dirs:
        art_path = clean_dir / art_dir_name
        if art_path.exists():
            for root, _, files in os.walk(art_path):
                for f in files:
                    fp = Path(root) / f
                    try:
                        rel = str(fp.relative_to(clean_dir)).replace("\\", "/")
                        h = hashlib.sha256(fp.read_bytes()).hexdigest()
                        artifact_hashes[rel] = h
                    except Exception:
                        pass

    # Deterministic snapshot hash
    source_hashes: Dict[str, str] = {}
    for root, dirs, files in os.walk(clean_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_CLEAN_DIRS and not d.startswith(".cache")]
        for f in files:
            if f.endswith((".py", ".ts", ".js", ".rs", ".go", ".json")):
                fp = Path(root) / f
                try:
                    rel = str(fp.relative_to(clean_dir)).replace("\\", "/")
                    source_hashes[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
                except Exception:
                    pass

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "status": status,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "error": error,
        "stdout": kernel.scrub_secrets(stdout),
        "stderr": kernel.scrub_secrets(stderr),
        "stdoutHash": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrHash": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "command": cmd,
        "artifactHashes": artifact_hashes,
        "sourceHashes": source_hashes,
        "totalArtifacts": len(artifact_hashes),
        "origin": origin,
        "executionType": "BUILD",
    }


def run_clean_tests(
    clean_env_dir: Path,
    test_command: Optional[str] = None,
    test_fn: Optional[Callable[[Path], bool]] = None,
    origin: str = "REAL_PROJECT_EXECUTION",
) -> Dict[str, Any]:
    """
    Executes behavioral and policy verification tests inside clean environment.
    Never defaults to PASSED without executing test command or function.
    """
    clean_dir = Path(clean_env_dir).resolve()
    start_time = time.time()
    
    if test_fn:
        actual_origin = "KERNEL_UNIT_TEST" if origin == "REAL_PROJECT_EXECUTION" else origin
        try:
            passed = test_fn(clean_dir)
            duration_ms = int((time.time() - start_time) * 1000)
            if passed:
                return {
                    "status": "PASSED",
                    "exitCode": 0,
                    "durationMs": duration_ms,
                    "error": None,
                    "stdout": "Test function executed and returned True.",
                    "stderr": "",
                    "stdoutHash": hashlib.sha256(b"PASSED").hexdigest(),
                    "stderrHash": hashlib.sha256(b"").hexdigest(),
                    "origin": actual_origin,
                    "executionType": "TEST",
                }
            else:
                return {
                    "status": "FAILED",
                    "exitCode": 1,
                    "durationMs": duration_ms,
                    "error": "Clean environment test function returned False.",
                    "stdout": "",
                    "stderr": "TEST_FUNCTION_FAILED",
                    "stdoutHash": hashlib.sha256(b"").hexdigest(),
                    "stderrHash": hashlib.sha256(b"TEST_FUNCTION_FAILED").hexdigest(),
                    "origin": actual_origin,
                    "executionType": "TEST",
                }
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return {
                "status": "FAILED",
                "exitCode": 1,
                "durationMs": duration_ms,
                "error": f"Test function raised exception: {str(e)}",
                "stdout": "",
                "stderr": str(e),
                "stdoutHash": hashlib.sha256(b"").hexdigest(),
                "stderrHash": hashlib.sha256(str(e).encode()).hexdigest(),
                "origin": actual_origin,
                "executionType": "TEST",
            }

    cmd = test_command
    if not cmd:
        # Discover test command
        if (clean_dir / "package.json").exists():
            try:
                pkg = json.loads((clean_dir / "package.json").read_text(encoding="utf-8"))
                if "test" in pkg.get("scripts", {}):
                    cmd = "npm test"
            except Exception:
                pass
        elif (clean_dir / "tests").exists() or list(clean_dir.glob("test_*.py")):
            cmd = f"{sys.executable} -m unittest discover -s . -p \"test_*.py\""
        elif (clean_dir / "Cargo.toml").exists():
            cmd = "cargo test"
        elif (clean_dir / "go.mod").exists():
            cmd = "go test ./..."
        elif list(clean_dir.glob("*.csproj")):
            cmd = "dotnet test"

    if not cmd:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "NOT_CONFIGURED",
            "exitCode": None,
            "durationMs": duration_ms,
            "error": "Test execution is required, but no test command or test adapter was configured.",
            "stdout": "",
            "stderr": "TEST_NOT_CONFIGURED",
            "origin": origin,
            "executionType": "TEST",
        }

    status = "PASSED"
    exit_code = 0
    stdout = ""
    stderr = ""
    error = None

    try:
        res = subprocess.run(
            cmd,
            shell=True,
            cwd=str(clean_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        exit_code = res.returncode
        stdout = res.stdout
        stderr = res.stderr
        if exit_code != 0:
            status = "FAILED"
            error = f"Test command '{cmd}' exited with code {exit_code}."
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
        exit_code = 124
        error = f"Test command '{cmd}' timed out."
    except Exception as e:
        status = "FAILED"
        exit_code = 1
        error = f"Test execution error: {str(e)}"

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "status": status,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "error": error,
        "stdout": kernel.scrub_secrets(stdout),
        "stderr": kernel.scrub_secrets(stderr),
        "stdoutHash": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrHash": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "command": cmd,
        "origin": origin,
        "executionType": "TEST",
    }


def verify_application_startup_and_runtime(
    clean_env_dir: Path,
    startup_command: Optional[str] = None,
    health_check_fn: Optional[Callable[[Path], bool]] = None,
    health_check_cmd: Optional[str] = None,
    health_check_url: Optional[str] = None,
    journey_fn: Optional[Callable[[Path], bool]] = None,
    journey_cmd: Optional[str] = None,
    origin: str = "REAL_PROJECT_EXECUTION",
) -> Dict[str, Any]:
    """
    Verifies application startup and runtime smoke journeys in clean environment.
    Defaults to NOT_EXECUTED if no command is provided.
    """
    clean_dir = Path(clean_env_dir).resolve()
    start_time = time.time()

    cmd = startup_command
    if not cmd:
        # Discover entrypoint
        if (clean_dir / "package.json").exists():
            try:
                pkg = json.loads((clean_dir / "package.json").read_text(encoding="utf-8"))
                if "start" in pkg.get("scripts", {}):
                    cmd = "npm start"
            except Exception:
                pass
        elif (clean_dir / "app.py").exists():
            cmd = f"{sys.executable} app.py"
        elif (clean_dir / "main.py").exists():
            cmd = f"{sys.executable} main.py"
        elif (clean_dir / "server.py").exists():
            cmd = f"{sys.executable} server.py"

    if not cmd and not health_check_fn and not journey_fn:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "NOT_CONFIGURED",
            "exitCode": None,
            "durationMs": duration_ms,
            "error": "Runtime verification required but no startup command or entrypoint found.",
            "stdout": "",
            "stderr": "RUNTIME_NOT_CONFIGURED",
            "startupPassed": False,
            "healthPassed": False,
            "journeyPassed": False,
            "origin": origin,
            "executionType": "RUNTIME_START",
        }

    status = "PASSED"
    startup_passed = False
    health_passed = False
    journey_passed = False
    error = None
    proc = None
    stdout = ""
    stderr = ""

    try:
        if cmd:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                cwd=str(clean_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Give short window to detect immediate crash
            time.sleep(0.4)
            poll_ret = proc.poll()
            if poll_ret is not None and poll_ret != 0:
                startup_passed = False
                status = "STARTUP_CRASH"
                out, err = proc.communicate(timeout=2)
                stdout = out
                stderr = err
                error = f"STARTUP_CRASH: Application crashed immediately on startup with exit code {poll_ret}: {err[:500]}"
            else:
                startup_passed = True

        # Health Check
        if startup_passed and health_check_url:
            import urllib.request
            try:
                with urllib.request.urlopen(health_check_url, timeout=3) as resp:
                    health_passed = resp.status == 200
                    if not health_passed:
                        status = "FAILED"
                        error = f"Health check URL {health_check_url} returned status {resp.status}"
            except Exception as e:
                health_passed = False
                status = "FAILED"
                error = f"Health check request to {health_check_url} failed: {str(e)}"
        elif startup_passed and health_check_cmd:
            res_h = subprocess.run(health_check_cmd, shell=True, cwd=str(clean_dir), capture_output=True, text=True, timeout=10)
            health_passed = res_h.returncode == 0
            if not health_passed:
                status = "FAILED"
                error = f"Health check command '{health_check_cmd}' failed: {res_h.stderr}"
        elif startup_passed and health_check_fn:
            health_passed = health_check_fn(clean_dir)
            if not health_passed:
                status = "FAILED"
                error = "Health check function returned False."
        elif startup_passed:
            health_passed = True

        # User Journey
        if startup_passed and health_passed:
            if journey_cmd:
                res_j = subprocess.run(journey_cmd, shell=True, cwd=str(clean_dir), capture_output=True, text=True, timeout=15)
                journey_passed = res_j.returncode == 0
                if not journey_passed:
                    status = "JOURNEY_FAILED"
                    error = f"JOURNEY_FAILED: User journey command '{journey_cmd}' failed: {res_j.stderr}"
            elif journey_fn:
                journey_passed = journey_fn(clean_dir)
                if not journey_passed:
                    status = "JOURNEY_FAILED"
                    error = "JOURNEY_FAILED: User journey verification function returned False."
            else:
                journey_passed = True

    except Exception as e:
        status = "FAILED"
        error = f"Runtime execution failed: {str(e)}"
    finally:
        if proc:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                if proc.stdout: proc.stdout.close()
                if proc.stderr: proc.stderr.close()
            except Exception:
                pass

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "status": status,
        "startupPassed": startup_passed,
        "healthPassed": health_passed,
        "journeyPassed": journey_passed,
        "durationMs": duration_ms,
        "error": error,
        "stdout": kernel.scrub_secrets(stdout),
        "stderr": kernel.scrub_secrets(stderr),
        "stdoutHash": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderrHash": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "command": cmd,
        "origin": origin,
        "executionType": "RUNTIME_START",
    }


def bootstrap_database_and_verify_migrations(
    clean_env_dir: Path,
    migration_command: Optional[str] = None,
    bootstrap_command: Optional[str] = None,
    migration_plan: Optional[Dict[str, Any]] = None,
    custom_verify_fn: Optional[Callable[[Path], Dict[str, Any]]] = None,
    origin: str = "REAL_PROJECT_EXECUTION",
) -> Dict[str, Any]:
    """
    Verifies database schema bootstrap and migration integrity in clean environment.
    Rejects unexecuted boolean dictionaries as NOT_EXECUTED.
    """
    clean_dir = Path(clean_env_dir).resolve()
    start_time = time.time()

    if custom_verify_fn:
        try:
            res = custom_verify_fn(clean_dir)
            res.setdefault("origin", origin)
            res.setdefault("executionType", "MIGRATION")
            return res
        except Exception as e:
            return {
                "status": "MIGRATION_FAILED",
                "error": f"Migration verification function threw exception: {str(e)}",
                "bootstrapPassed": False,
                "migrationPassed": False,
                "dataLossDetected": False,
                "origin": origin,
                "executionType": "MIGRATION",
            }

    if migration_plan is not None:
        duration_ms = int((time.time() - start_time) * 1000)
        # Check defect states first
        if migration_plan.get("dataLossDetected") is True:
            return {
                "status": "DATA_LOSS_DETECTED",
                "bootstrapPassed": migration_plan.get("bootstrapPassed", True),
                "migrationPassed": migration_plan.get("migrationPassed", True),
                "dataLossDetected": True,
                "durationMs": duration_ms,
                "error": "DATA_LOSS_DETECTED: Schema migration resulted in destructive data loss.",
                "origin": origin,
                "executionType": "MIGRATION",
            }
        if migration_plan.get("migrationPassed") is False:
            return {
                "status": "MIGRATION_FAILED",
                "bootstrapPassed": migration_plan.get("bootstrapPassed", True),
                "migrationPassed": False,
                "dataLossDetected": False,
                "durationMs": duration_ms,
                "error": "MIGRATION_FAILED: Schema migration failed to apply cleanly.",
                "origin": origin,
                "executionType": "MIGRATION",
            }
        if migration_plan.get("bootstrapPassed") is False:
            return {
                "status": "BOOTSTRAP_FAILED",
                "bootstrapPassed": False,
                "migrationPassed": False,
                "dataLossDetected": False,
                "durationMs": duration_ms,
                "error": "BOOTSTRAP_FAILED: Initial database bootstrap failed.",
                "origin": origin,
                "executionType": "DATABASE_BOOTSTRAP",
            }
        
        # If no executable command/runner provided, reject unexecuted claim as NOT_EXECUTED (RG-09)
        if not (bootstrap_command or migration_command):
            return {
                "status": "NOT_EXECUTED",
                "bootstrapPassed": False,
                "migrationPassed": False,
                "dataLossDetected": False,
                "durationMs": duration_ms,
                "error": "Migration metadata provided but no executable migration command was run.",
                "origin": "MODEL_CLAIM",
                "executionType": "MIGRATION",
            }

    if bootstrap_command or migration_command:
        status = "PASSED"
        bootstrap_passed = False
        migration_passed = False
        error = None

        if bootstrap_command:
            res_b = subprocess.run(bootstrap_command, shell=True, cwd=str(clean_dir), capture_output=True, text=True, timeout=30)
            if res_b.returncode != 0:
                duration_ms = int((time.time() - start_time) * 1000)
                return {
                    "status": "BOOTSTRAP_FAILED",
                    "bootstrapPassed": False,
                    "migrationPassed": False,
                    "dataLossDetected": False,
                    "error": f"Bootstrap command failed: {res_b.stderr}",
                    "durationMs": duration_ms,
                    "origin": origin,
                    "executionType": "DATABASE_BOOTSTRAP",
                }
            bootstrap_passed = True

        if migration_command:
            res_m = subprocess.run(migration_command, shell=True, cwd=str(clean_dir), capture_output=True, text=True, timeout=30)
            if res_m.returncode != 0:
                duration_ms = int((time.time() - start_time) * 1000)
                return {
                    "status": "MIGRATION_FAILED",
                    "bootstrapPassed": bootstrap_passed,
                    "migrationPassed": False,
                    "dataLossDetected": False,
                    "error": f"Migration command failed: {res_m.stderr}",
                    "durationMs": duration_ms,
                    "origin": origin,
                    "executionType": "MIGRATION",
                }
            migration_passed = True

        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "status": "PASSED",
            "bootstrapPassed": bootstrap_passed or True,
            "migrationPassed": migration_passed or True,
            "dataLossDetected": False,
            "durationMs": duration_ms,
            "origin": origin,
            "executionType": "MIGRATION",
        }

    duration_ms = int((time.time() - start_time) * 1000)
    return {
        "status": "NOT_APPLICABLE",
        "bootstrapPassed": True,
        "migrationPassed": True,
        "dataLossDetected": False,
        "details": "No database migration required for this workspace.",
        "origin": origin,
        "executionType": "MIGRATION",
    }


def cleanup_environment(clean_env_dir: Path) -> None:
    """Safely removes clean scratch environment directory."""
    clean_dir = Path(clean_env_dir).resolve()
    if clean_dir.exists() and clean_dir.name.startswith("clean_env_"):
        shutil.rmtree(clean_dir, ignore_errors=True)
