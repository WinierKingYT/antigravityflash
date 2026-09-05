"""
Strict Engineering Kernel Step 5 - Environment & Container Detection Engine
Detects container runtimes, project ecosystems, toolchain pinning, lockfile integrity,
secret scanning, and computes deterministic environment fingerprints.
"""

import os
import sys
import json
import re
import shutil
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

CONTAINER_RUNTIMES = ["docker", "podman"]


def detect_container_runtime() -> Dict[str, Any]:
    """
    Check for container runtimes (Docker Desktop, Docker CLI, Podman).
    Tests whether daemon is responsive with a quick timeout.
    Returns CONTAINER_ISOLATED if available, else NOT_CONFIGURED.
    Never hangs or throws exceptions on Windows.
    """
    detected_runtime = None
    daemon_responsive = False
    details = "No container runtime detected on host."

    for runtime_bin in CONTAINER_RUNTIMES:
        path = shutil.which(runtime_bin)
        if path:
            detected_runtime = runtime_bin
            try:
                res = subprocess.run(
                    [runtime_bin, "info"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=1.5,
                )
                if res.returncode == 0:
                    daemon_responsive = True
                    details = f"{runtime_bin.capitalize()} daemon is responsive."
                    break
                else:
                    details = f"{runtime_bin.capitalize()} CLI found, but daemon is not running."
            except (subprocess.TimeoutExpired, Exception) as e:
                details = f"{runtime_bin.capitalize()} CLI found, but probe timed out or failed: {str(e)}"

    if detected_runtime and daemon_responsive:
        status = "CONTAINER_ISOLATED"
    else:
        status = "NOT_CONFIGURED"

    return {
        "status": status,
        "runtime": detected_runtime,
        "daemonResponsive": daemon_responsive,
        "details": details,
    }


def detect_project_ecosystem(workspace_dir: Path) -> Dict[str, Any]:
    workspace_path = Path(workspace_dir).resolve()
    manifest_files: List[str] = []
    
    runtime = "UNKNOWN"
    package_manager = "UNKNOWN"
    project_type = "CLI_OR_LIBRARY"
    is_monorepo = False
    is_desktop_native = False

    # Check Node / TypeScript
    pkg_json = workspace_path / "package.json"
    if pkg_json.exists():
        manifest_files.append("package.json")
        runtime = "NODE"
        package_manager = "NPM"
        if (workspace_path / "pnpm-lock.yaml").exists() or (workspace_path / "pnpm-workspace.yaml").exists():
            package_manager = "PNPM"
        elif (workspace_path / "yarn.lock").exists():
            package_manager = "YARN"
        elif (workspace_path / "bun.lockb").exists() or (workspace_path / "bun.lock").exists():
            package_manager = "BUN"
        elif (workspace_path / "package-lock.json").exists():
            package_manager = "NPM"

        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
                deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                if "electron" in deps or "electron-builder" in deps:
                    is_desktop_native = True
                    project_type = "ELECTRON_DESKTOP"
                elif "@tauri-apps/api" in deps or "@tauri-apps/cli" in deps:
                    is_desktop_native = True
                    project_type = "TAURI_DESKTOP"
                elif any(w in deps for w in ["react", "vue", "svelte", "next", "nuxt", "vite", "astro", "express", "fastify"]):
                    project_type = "WEB_APPLICATION"
                
                if "workspaces" in pkg_data or (workspace_path / "pnpm-workspace.yaml").exists() or (workspace_path / "lerna.json").exists():
                    is_monorepo = True
        except Exception:
            pass

    # Check Tauri config directly
    if (workspace_path / "src-tauri" / "tauri.conf.json").exists() or (workspace_path / "tauri.conf.json").exists():
        is_desktop_native = True
        project_type = "TAURI_DESKTOP"
        manifest_files.append("tauri.conf.json")

    # Check Python
    pyproject = workspace_path / "pyproject.toml"
    req_txt = workspace_path / "requirements.txt"
    pipfile = workspace_path / "Pipfile"
    setup_py = workspace_path / "setup.py"
    
    if pyproject.exists() or req_txt.exists() or pipfile.exists() or setup_py.exists():
        if runtime == "UNKNOWN":
            runtime = "PYTHON"
            package_manager = "PIP"
        if pyproject.exists():
            manifest_files.append("pyproject.toml")
            try:
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                if "[tool.poetry]" in content:
                    package_manager = "POETRY"
                elif "[tool.pdm]" in content:
                    package_manager = "PDM"
                elif "[tool.flit]" in content:
                    package_manager = "FLIT"
            except Exception:
                pass
        if req_txt.exists():
            manifest_files.append("requirements.txt")
        if pipfile.exists():
            manifest_files.append("Pipfile")
            package_manager = "PIPENV"
        if setup_py.exists():
            manifest_files.append("setup.py")

    # Check Rust
    cargo_toml = workspace_path / "Cargo.toml"
    if cargo_toml.exists():
        manifest_files.append("Cargo.toml")
        if runtime == "UNKNOWN":
            runtime = "RUST"
            package_manager = "CARGO"
        try:
            content = cargo_toml.read_text(encoding="utf-8", errors="ignore")
            if "[workspace]" in content:
                is_monorepo = True
        except Exception:
            pass

    # Check Go
    go_mod = workspace_path / "go.mod"
    if go_mod.exists():
        manifest_files.append("go.mod")
        if runtime == "UNKNOWN":
            runtime = "GO"
            package_manager = "GO_MODULES"

    # Check .NET / C#
    csproj_files = list(workspace_path.glob("*.csproj")) + list(workspace_path.glob("*/*.csproj"))
    sln_files = list(workspace_path.glob("*.sln"))
    if csproj_files or sln_files:
        manifest_files.extend([f.name for f in csproj_files[:5]])
        if runtime == "UNKNOWN":
            runtime = "DOTNET"
            package_manager = "NUGET"
        for csproj in csproj_files:
            try:
                txt = csproj.read_text(encoding="utf-8", errors="ignore")
                if any(x in txt for x in ["<UseWPF>true</UseWPF>", "<UseWindowsForms>true</UseWindowsForms>", "Microsoft.WindowsAppSDK", "WinUI"]):
                    is_desktop_native = True
                    project_type = "WINDOWS_NATIVE_DESKTOP"
            except Exception:
                pass

    # Check Java / Kotlin
    pom_xml = workspace_path / "pom.xml"
    build_gradle = workspace_path / "build.gradle"
    build_gradle_kts = workspace_path / "build.gradle.kts"
    if pom_xml.exists() or build_gradle.exists() or build_gradle_kts.exists():
        if runtime == "UNKNOWN":
            runtime = "JAVA"
            package_manager = "MAVEN" if pom_xml.exists() else "GRADLE"
        if pom_xml.exists():
            manifest_files.append("pom.xml")
        if build_gradle.exists():
            manifest_files.append("build.gradle")
        if build_gradle_kts.exists():
            manifest_files.append("build.gradle.kts")

    if runtime == "UNKNOWN":
        py_files = list(workspace_path.glob("*.py"))
        if py_files:
            runtime = "PYTHON"
            package_manager = "PIP"

    return {
        "runtime": runtime,
        "packageManager": package_manager,
        "projectType": project_type,
        "isMonorepo": is_monorepo,
        "isDesktopNative": is_desktop_native,
        "manifestFiles": sorted(list(set(manifest_files))),
    }


def detect_declared_toolchain(workspace_dir: Path) -> Dict[str, Any]:
    workspace_path = Path(workspace_dir).resolve()
    pinned_versions: Dict[str, str] = {}
    source_files: List[str] = []

    # Node toolchain files
    nvmrc = workspace_path / ".nvmrc"
    node_ver = workspace_path / ".node-version"
    pkg_json = workspace_path / "package.json"

    if nvmrc.exists():
        try:
            ver = nvmrc.read_text(encoding="utf-8").strip()
            if ver:
                pinned_versions["node"] = ver
                source_files.append(".nvmrc")
        except Exception:
            pass

    if node_ver.exists() and "node" not in pinned_versions:
        try:
            ver = node_ver.read_text(encoding="utf-8").strip()
            if ver:
                pinned_versions["node"] = ver
                source_files.append(".node-version")
        except Exception:
            pass

    if pkg_json.exists():
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                engines = data.get("engines", {})
                if "node" in engines and "node" not in pinned_versions:
                    pinned_versions["node"] = str(engines["node"])
                    source_files.append("package.json (engines.node)")
                if "npm" in engines:
                    pinned_versions["npm"] = str(engines["npm"])
                if "packageManager" in data:
                    pinned_versions["packageManager"] = str(data["packageManager"])
                    source_files.append("package.json (packageManager)")
        except Exception:
            pass

    # Python toolchain files
    py_ver = workspace_path / ".python-version"
    pyproject = workspace_path / "pyproject.toml"
    runtime_txt = workspace_path / "runtime.txt"

    if py_ver.exists():
        try:
            ver = py_ver.read_text(encoding="utf-8").strip()
            if ver:
                pinned_versions["python"] = ver
                source_files.append(".python-version")
        except Exception:
            pass

    if runtime_txt.exists() and "python" not in pinned_versions:
        try:
            ver = runtime_txt.read_text(encoding="utf-8").strip()
            if ver:
                pinned_versions["python"] = ver
                source_files.append("runtime.txt")
        except Exception:
            pass

    if pyproject.exists() and "python" not in pinned_versions:
        try:
            txt = pyproject.read_text(encoding="utf-8", errors="ignore")
            for line in txt.splitlines():
                if "requires-python" in line or "python =" in line or "python=" in line:
                    parts = line.split("=")
                    if len(parts) > 1:
                        val = parts[1].strip().strip('"').strip("'")
                        if val:
                            pinned_versions["python"] = val
                            source_files.append("pyproject.toml")
                            break
        except Exception:
            pass

    # Rust toolchain files
    rust_toolchain_toml = workspace_path / "rust-toolchain.toml"
    rust_toolchain = workspace_path / "rust-toolchain"
    if rust_toolchain_toml.exists():
        try:
            txt = rust_toolchain_toml.read_text(encoding="utf-8", errors="ignore")
            for line in txt.splitlines():
                if "channel" in line:
                    parts = line.split("=")
                    if len(parts) > 1:
                        val = parts[1].strip().strip('"').strip("'")
                        if val:
                            pinned_versions["rust"] = val
                            source_files.append("rust-toolchain.toml")
                            break
        except Exception:
            pass
    elif rust_toolchain.exists():
        try:
            ver = rust_toolchain.read_text(encoding="utf-8").strip()
            if ver:
                pinned_versions["rust"] = ver
                source_files.append("rust-toolchain")
        except Exception:
            pass

    # Go toolchain
    go_mod = workspace_path / "go.mod"
    if go_mod.exists():
        try:
            txt = go_mod.read_text(encoding="utf-8", errors="ignore")
            for line in txt.splitlines():
                if line.startswith("go "):
                    val = line.split()[1].strip()
                    pinned_versions["go"] = val
                    source_files.append("go.mod")
                    break
        except Exception:
            pass

    # .NET toolchain
    global_json = workspace_path / "global.json"
    if global_json.exists():
        try:
            with open(global_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                sdk_ver = data.get("sdk", {}).get("version")
                if sdk_ver:
                    pinned_versions["dotnet"] = str(sdk_ver)
                    source_files.append("global.json")
        except Exception:
            pass

    is_pinned = len(pinned_versions) > 0
    return {
        "status": "TOOLCHAIN_PINNED" if is_pinned else "TOOLCHAIN_UNPINNED",
        "pinnedVersions": pinned_versions,
        "sourceFiles": sorted(list(set(source_files))),
        "warning": None if is_pinned else "No toolchain version pinning file found (.node-version, .python-version, rust-toolchain.toml, global.json, etc.). Host default will be utilized.",
    }


def check_lockfile_integrity(workspace_dir: Path) -> Dict[str, Any]:
    workspace_path = Path(workspace_dir).resolve()
    eco = detect_project_ecosystem(workspace_path)
    runtime = eco.get("runtime", "UNKNOWN")
    pm = eco.get("packageManager", "UNKNOWN")

    lockfile_path = None
    manifest_path = None
    frozen_command = None
    lockfile_status = "NOT_APPLICABLE"
    lockfile_hash = None
    manifest_hash = None
    issues: List[str] = []

    # Node ecosystem
    if runtime == "NODE":
        manifest_path = workspace_path / "package.json"
        if pm == "PNPM":
            lockfile_path = workspace_path / "pnpm-lock.yaml"
            frozen_command = "pnpm install --frozen-lockfile"
        elif pm == "YARN":
            lockfile_path = workspace_path / "yarn.lock"
            frozen_command = "yarn install --immutable"
        elif pm == "BUN":
            lockfile_path = workspace_path / "bun.lockb"
            frozen_command = "bun install --frozen-lockfile"
        else:
            lockfile_path = workspace_path / "package-lock.json"
            frozen_command = "npm ci"

    # Python ecosystem
    elif runtime == "PYTHON":
        if (workspace_path / "poetry.lock").exists() or pm == "POETRY":
            manifest_path = workspace_path / "pyproject.toml"
            lockfile_path = workspace_path / "poetry.lock"
            frozen_command = "poetry install --no-root"
        elif (workspace_path / "Pipfile.lock").exists() or pm == "PIPENV":
            manifest_path = workspace_path / "Pipfile"
            lockfile_path = workspace_path / "Pipfile.lock"
            frozen_command = "pipenv install --ignore-pipfile"
        elif (workspace_path / "requirements.lock").exists():
            manifest_path = workspace_path / "requirements.txt"
            lockfile_path = workspace_path / "requirements.lock"
            frozen_command = f'"{sys.executable}" -m pip install --no-deps -r requirements.lock'
        elif (workspace_path / "requirements.txt").exists():
            manifest_path = workspace_path / "requirements.txt"
            lockfile_path = workspace_path / "requirements.txt"
            frozen_command = f'"{sys.executable}" -m pip install -r requirements.txt'

    # Rust ecosystem
    elif runtime == "RUST":
        manifest_path = workspace_path / "Cargo.toml"
        lockfile_path = workspace_path / "Cargo.lock"
        frozen_command = "cargo build --locked"

    # Go ecosystem
    elif runtime == "GO":
        manifest_path = workspace_path / "go.mod"
        lockfile_path = workspace_path / "go.sum"
        frozen_command = "go build -mod=readonly ./..."

    if manifest_path and manifest_path.exists():
        manifest_bytes = manifest_path.read_bytes()
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

        if lockfile_path and lockfile_path.exists():
            lockfile_bytes = lockfile_path.read_bytes()
            lockfile_hash = hashlib.sha256(lockfile_bytes).hexdigest()

            try:
                manifest_mtime = manifest_path.stat().st_mtime
                lockfile_mtime = lockfile_path.stat().st_mtime
                
                if runtime == "NODE" and manifest_path.name == "package.json":
                    try:
                        m_json = json.loads(manifest_bytes.decode("utf-8", errors="ignore"))
                        l_json = json.loads(lockfile_bytes.decode("utf-8", errors="ignore"))
                        all_deps = {**m_json.get("dependencies", {}), **m_json.get("devDependencies", {})}
                        packages = l_json.get("packages", {})
                        lock_deps = l_json.get("dependencies", {})
                        for dep in all_deps:
                            if dep not in lock_deps and f"node_modules/{dep}" not in packages:
                                issues.append(f"Declared dependency '{dep}' is missing from package-lock.json")
                    except Exception:
                        pass
                elif runtime == "PYTHON" and manifest_path.name == "requirements.txt":
                    m_txt = manifest_bytes.decode("utf-8", errors="ignore")
                    l_txt = lockfile_bytes.decode("utf-8", errors="ignore")
                    m_lines = [l.strip() for l in m_txt.splitlines() if l.strip() and not l.startswith("#")]
                    l_lines = [l.strip() for l in l_txt.splitlines() if l.strip() and not l.startswith("#")]
                    for req_line in m_lines:
                        pkg_name = req_line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                        if pkg_name and not any(pkg_name in ll for ll in l_lines):
                            issues.append(f"Declared dependency '{pkg_name}' is missing from lockfile")

                if issues or manifest_mtime > lockfile_mtime + 2.0:
                    if issues:
                        lockfile_status = "STALE"
                    else:
                        lockfile_status = "SYNCHRONIZED"
                else:
                    lockfile_status = "SYNCHRONIZED"
            except Exception:
                lockfile_status = "SYNCHRONIZED"
        else:
            lockfile_status = "MISSING"
            issues.append(f"Manifest '{manifest_path.name}' exists but no lockfile found.")
    else:
        lockfile_status = "NOT_APPLICABLE"

    return {
        "status": lockfile_status,
        "runtime": runtime,
        "packageManager": pm,
        "manifestFile": manifest_path.name if manifest_path else None,
        "manifestHash": manifest_hash,
        "lockfileFile": lockfile_path.name if lockfile_path and lockfile_path.exists() else None,
        "lockfileHash": lockfile_hash,
        "frozenCommand": frozen_command,
        "issues": issues,
    }


def scan_and_classify_secrets(workspace_dir: Path, candidate_files: Optional[List[str]] = None) -> Dict[str, Any]:
    workspace_path = Path(workspace_dir).resolve()
    detected_secrets: List[Dict[str, Any]] = []

    files_to_scan: List[Path] = []
    if candidate_files is not None:
        for cf in candidate_files:
            p = workspace_path / cf
            if p.exists() and p.is_file():
                files_to_scan.append(p)
    else:
        for root, dirs, files in os.walk(workspace_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target"}]
            for f in files:
                files_to_scan.append(Path(root) / f)

    for file_path in files_to_scan:
        try:
            rel_str = str(file_path.relative_to(workspace_path)).replace("\\", "/")
        except Exception:
            rel_str = file_path.name
            
        if file_path.name in {".env", ".env.local", ".env.production", ".env.development"}:
            detected_secrets.append({
                "file": rel_str,
                "type": "ENV_FILE",
                "severity": "HIGH",
                "description": f"Host environment file '{file_path.name}' detected; must not be copied to clean build context.",
            })
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if "BEGIN RSA PRIVATE KEY" in line or "BEGIN OPENSSH PRIVATE KEY" in line or "BEGIN PRIVATE KEY" in line:
                    detected_secrets.append({
                        "file": rel_str,
                        "type": "PRIVATE_KEY",
                        "severity": "CRITICAL",
                        "snippet": line[:30] + "...",
                        "description": f"Private key detected in {rel_str}.",
                    })
                elif "AKIA" in line and len(line) >= 20:
                    for token in line.split():
                        if token.startswith("AKIA") and len(token) >= 20:
                            detected_secrets.append({
                                "file": rel_str,
                                "type": "AWS_ACCESS_KEY",
                                "severity": "CRITICAL",
                                "snippet": token[:20],
                                "description": f"AWS Access Key detected in {rel_str}.",
                            })
                elif "ghp_" in line:
                    for token in line.split():
                        if "ghp_" in token and len(token) >= 30:
                            detected_secrets.append({
                                "file": rel_str,
                                "type": "GITHUB_TOKEN",
                                "severity": "HIGH",
                                "snippet": token[:20],
                                "description": f"GitHub token detected in {rel_str}.",
                            })
                elif "api_key" in line.lower() or "apikey" in line.lower() or "secret_key" in line.lower():
                    if any(c in line for c in ["=", ":"]):
                        detected_secrets.append({
                            "file": rel_str,
                            "type": "GENERIC_SECRET",
                            "severity": "HIGH",
                            "snippet": line[:30] + "...",
                            "description": f"Generic secret or API key detected in {rel_str}.",
                        })
        except Exception:
            pass

    return {
        "secretsDetected": len(detected_secrets) > 0,
        "totalSecrets": len(detected_secrets),
        "secrets": detected_secrets,
        "cleanContextSafe": len(detected_secrets) == 0,
    }


def compute_environment_fingerprint(workspace_dir: Path) -> Dict[str, Any]:
    workspace_path = Path(workspace_dir).resolve()
    container_info = detect_container_runtime()
    ecosystem = detect_project_ecosystem(workspace_path)
    toolchain = detect_declared_toolchain(workspace_path)
    lockfile = check_lockfile_integrity(workspace_path)

    raw_components = {
        "os": sys.platform,
        "pythonVersion": sys.version.split()[0],
        "containerStatus": container_info.get("status"),
        "runtime": ecosystem.get("runtime"),
        "packageManager": ecosystem.get("packageManager"),
        "toolchainStatus": toolchain.get("status"),
        "pinnedVersions": toolchain.get("pinnedVersions"),
        "lockfileStatus": lockfile.get("status"),
        "manifestHash": lockfile.get("manifestHash"),
        "lockfileHash": lockfile.get("lockfileHash"),
    }

    serialized = json.dumps(raw_components, sort_keys=True)
    fingerprint_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "fingerprint": fingerprint_hash,
        "components": raw_components,
        "container": container_info,
        "ecosystem": ecosystem,
        "toolchain": toolchain,
        "lockfile": lockfile,
    }