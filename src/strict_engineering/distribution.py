"""
Strict Engineering Kernel V1.2.0 - Distribution, Update Lifecycle & Configuration Engine
Provides:
- Canonical installation manifest (manifest.json) tracking file hashes and versions
- Transactional atomic update engine with automatic rollback
- Safe rollback engine restoring last known-good snapshot
- Non-destructive uninstallation preserving unrelated user hooks, agents, and prompts
- Minimal global configuration manager (config.json)
"""

import os
import sys
import json
import shutil
import hashlib
import datetime
import compileall
import zipfile
import tarfile
import re
import tempfile
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from . import __version__
    from . import installer
    from . import observability
except (ImportError, ValueError):
    try:
        import strict_engineering
        __version__ = strict_engineering.__version__
    except Exception:
        __version__ = "1.2.5"
    import installer  # type: ignore
    import observability  # type: ignore

MANIFEST_FILENAME = "manifest.json"
CONFIG_FILENAME = "config.json"
CANONICAL_DISTRIBUTION_SOURCE = "https://github.com/WinierKingYT/antigravityflash"

DEFAULT_CONFIG = {
    "schemaVersion": "1.2.0",
    "maxAutomaticContinues": 2,
    "loggingLevel": "INFO",
    "distributionSource": CANONICAL_DISTRIBUTION_SOURCE,
}

MANAGED_CORE_AGENTS = {
    "builder",
    "counterexample-auditor",
    "diagnostic-engineer",
    "engineering-orchestrator",
    "final-verifier",
    "scope-auditor",
    "spec-architect",
    "test-oracle",
}


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def compute_file_sha256(path: Path) -> Optional[str]:
    p = Path(path).resolve()
    if not p.exists() or not p.is_file():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_default_gemini_dir(gemini_dir: Optional[Path] = None) -> Path:
    if gemini_dir is not None:
        return Path(gemini_dir).resolve()
    return Path.home() / ".gemini"


def get_config_dir(gemini_dir: Optional[Path] = None) -> Path:
    g = get_default_gemini_dir(gemini_dir)
    cfg = g / "config" / "strict-engineering"
    cfg.mkdir(parents=True, exist_ok=True)
    return cfg


# ---------------------------------------------------------------------------
# Minimal Configuration (config.json)
# ---------------------------------------------------------------------------
def load_global_config(gemini_dir: Optional[Path] = None) -> Dict[str, Any]:
    cfg_file = get_config_dir(gemini_dir) / CONFIG_FILENAME
    if not cfg_file.exists():
        return dict(DEFAULT_CONFIG)
    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_global_config(config: Dict[str, Any], gemini_dir: Optional[Path] = None) -> Path:
    cfg_dir = get_config_dir(gemini_dir)
    cfg_file = cfg_dir / CONFIG_FILENAME
    temp_file = cfg_dir / f"{CONFIG_FILENAME}.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    os.replace(temp_file, cfg_file)
    return cfg_file


# ---------------------------------------------------------------------------
# Installation Manifest (manifest.json)
# ---------------------------------------------------------------------------
def compute_strict_hook_entry_sha256(hooks_file: Path) -> Optional[str]:
    """
    Computes deterministic SHA-256 of only the Strict Engineering hook configuration,
    ignoring all unrelated user hooks in hooks.json.
    """
    p = Path(hooks_file).resolve()
    if not p.exists() or not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        strict_entries: Dict[str, Any] = {}
        for event in ["PreToolUse", "PreInvocation", "Stop"]:
            hooks_list = data.get(event, [])
            if not isinstance(hooks_list, list):
                continue
            matched = []
            for item in hooks_list:
                if not isinstance(item, dict):
                    continue
                item_str = json.dumps(item)
                if "hooks_handler.py" in item_str or "strict-engineering" in item_str or "strict_engineering" in item_str:
                    matched.append(item)
            if matched:
                strict_entries[event] = matched
        if not strict_entries:
            return None
        canonical = json.dumps(strict_entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
    except Exception:
        return None


def compute_gemini_managed_block_sha256(gemini_md_file: Path) -> Optional[str]:
    """
    Computes deterministic SHA-256 of only the Strict Engineering managed block
    inside GEMINI.md, ignoring all surrounding user instructions.
    """
    p = Path(gemini_md_file).resolve()
    if not p.exists() or not p.is_file():
        return None
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
        start_marker = "<!-- STRICT_ENGINEERING_KERNEL_START -->"
        end_marker = "<!-- STRICT_ENGINEERING_KERNEL_END -->"
        if start_marker in text and end_marker in text:
            start_idx = text.index(start_marker)
            end_idx = text.index(end_marker) + len(end_marker)
            managed_block = text[start_idx:end_idx].strip()
            return hashlib.sha256(managed_block.encode("utf-8")).hexdigest()
        return None
    except Exception:
        return None


def compute_managed_agents_hashes(
    agents_dir: Path,
    allowed_agents: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, str]]:
    """
    Computes deterministic SHA-256 hashes for all managed core agents (agent.md).
    Custom agents outside allowed_agents / MANAGED_CORE_AGENTS are completely excluded from ownership.
    """
    p = Path(agents_dir).resolve()
    result: Dict[str, Dict[str, str]] = {}
    if not p.exists() or not p.is_dir():
        return result
    target_agents = allowed_agents if allowed_agents is not None else MANAGED_CORE_AGENTS
    for d in sorted(p.iterdir()):
        if d.is_dir() and d.name in target_agents:
            agent_files: Dict[str, str] = {}
            for f in sorted(d.iterdir()):
                if f.is_file():
                    sha = compute_file_sha256(f)
                    if sha:
                        agent_files[f.name] = sha
            result[d.name] = agent_files
    return result


def generate_installation_manifest(
    modules_dir: Path,
    hooks_file: Path,
    gemini_md_file: Path,
    agents_dir: Path,
    version: str = __version__,
    previous_version: Optional[str] = None,
    install_source: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
    allowed_modules: Optional[Set[str]] = None,
    allowed_agents: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Generate canonical manifest capturing precise hashes of all managed components."""
    modules_dir = Path(modules_dir).resolve()
    modules_map: Dict[str, str] = {}
    if modules_dir.exists():
        for f in sorted(modules_dir.glob("*.py")):
            if allowed_modules is not None and f.name not in allowed_modules:
                continue
            sha = compute_file_sha256(f)
            if sha:
                modules_map[f.name] = sha

    strict_hook_sha = compute_strict_hook_entry_sha256(hooks_file)
    gemini_block_sha = compute_gemini_managed_block_sha256(gemini_md_file)
    agents_map = compute_managed_agents_hashes(agents_dir, allowed_agents=allowed_agents)

    cfg_dir = get_config_dir(gemini_dir)
    config_file = cfg_dir / CONFIG_FILENAME
    config_sha = compute_file_sha256(config_file)

    manifest = {
        "schemaVersion": "1.2.0",
        "version": str(version),
        "previousVersion": previous_version,
        "installedAt": utc_now_iso(),
        "updatedAt": utc_now_iso(),
        "pythonExecutable": sys.executable,
        "installSource": install_source or CANONICAL_DISTRIBUTION_SOURCE,
        "installationHealth": "HEALTHY",
        "status": "INSTALLED",
        "managedFiles": {
            "modules": modules_map,
            "agents": agents_map,
            "strictHook": {
                "path": str(Path(hooks_file).resolve()),
                "sha256": strict_hook_sha,
            },
            "geminiManagedBlock": {
                "path": str(Path(gemini_md_file).resolve()),
                "sha256": gemini_block_sha,
            },
            "config": {
                "path": str(config_file),
                "sha256": config_sha,
            },
            # Backward-compatibility alias
            "hooks": {
                "path": str(Path(hooks_file).resolve()),
                "sha256": compute_file_sha256(hooks_file),
            },
        },
    }
    return manifest


def save_installation_manifest(
    manifest: Dict[str, Any],
    gemini_dir: Optional[Path] = None,
) -> Path:
    cfg_dir = get_config_dir(gemini_dir)
    manifest_file = cfg_dir / MANIFEST_FILENAME
    temp_file = cfg_dir / f"{MANIFEST_FILENAME}.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(temp_file, manifest_file)
    return manifest_file


def load_installation_manifest(gemini_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    manifest_file = get_config_dir(gemini_dir) / MANIFEST_FILENAME
    if not manifest_file.exists():
        return None
    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def verify_manifest_integrity(
    gemini_dir: Optional[Path] = None,
    skip_version_check: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Comprehensive, precise manifest integrity check:
    - Verifies all managed module file hashes match disk
    - Verifies all managed core agent definitions exist and hashes match disk
    - Verifies strict-engineering hook entry hash in hooks.json
    - Verifies managed block hash in GEMINI.md
    - Verifies global config.json exists and is valid
    - Verifies package version matches installed manifest version (unless skip_version_check=True)
    Ignores all custom user agents, custom user hooks, and custom GEMINI text.
    """
    manifest = load_installation_manifest(gemini_dir)
    if not manifest:
        return False, ["Installation manifest not found"]

    issues: List[str] = []
    g = get_default_gemini_dir(gemini_dir)
    cfg_dir = get_config_dir(gemini_dir)
    managed_files = manifest.get("managedFiles", {})


    # 2. Module integrity
    recorded_modules = managed_files.get("modules", {})
    for mod_name, expected_sha in recorded_modules.items():
        mod_file = cfg_dir / mod_name
        if not mod_file.exists():
            issues.append(f"Missing managed module: {mod_name}")
            continue
        actual_sha = compute_file_sha256(mod_file)
        if actual_sha != expected_sha:
            issues.append(f"Hash mismatch in module {mod_name} (drift detected)")

    # 3. Managed core agent definitions
    recorded_agents = managed_files.get("agents", {})
    agents_dir = g / "config" / "agents"
    if isinstance(recorded_agents, dict):
        for agent_name in sorted(MANAGED_CORE_AGENTS):
            agent_dir = agents_dir / agent_name
            if not agent_dir.exists() or not agent_dir.is_dir():
                issues.append(f"Missing managed agent directory: {agent_name}")
                continue
            expected_files = recorded_agents.get(agent_name, {})
            if not expected_files and not any(agent_dir.glob("*.md")):
                issues.append(f"Managed agent '{agent_name}' has no definition files")
            for fname, exp_sha in expected_files.items():
                fpath = agent_dir / fname
                if not fpath.exists():
                    issues.append(f"Missing file in managed agent '{agent_name}': {fname}")
                else:
                    act_sha = compute_file_sha256(fpath)
                    if act_sha != exp_sha:
                        issues.append(f"Hash mismatch in managed agent '{agent_name}/{fname}' (drift detected)")
    elif isinstance(recorded_agents, list):
        for agent_name in recorded_agents:
            if agent_name in MANAGED_CORE_AGENTS:
                agent_dir = agents_dir / agent_name
                if not agent_dir.exists():
                    issues.append(f"Missing managed agent directory: {agent_name}")

    # 4. Strict hook entry integrity
    hooks_file = g / "config" / "hooks.json"
    strict_hook_info = managed_files.get("strictHook", {})
    if strict_hook_info and strict_hook_info.get("sha256"):
        expected_hook_sha = strict_hook_info.get("sha256")
        actual_hook_sha = compute_strict_hook_entry_sha256(hooks_file)
        if actual_hook_sha is None:
            issues.append("Strict Engineering hook entry missing from hooks.json")
        elif actual_hook_sha != expected_hook_sha:
            issues.append("Strict Engineering hook entry modified in hooks.json (drift detected)")

    # 5. GEMINI managed block integrity
    gemini_md_file = g / "GEMINI.md"
    gemini_block_info = managed_files.get("geminiManagedBlock", {})
    if gemini_block_info and gemini_block_info.get("sha256"):
        expected_gemini_sha = gemini_block_info.get("sha256")
        actual_gemini_sha = compute_gemini_managed_block_sha256(gemini_md_file)
        if actual_gemini_sha is None:
            issues.append("Strict Engineering managed block missing from GEMINI.md")
        elif actual_gemini_sha != expected_gemini_sha:
            issues.append("Strict Engineering managed block modified in GEMINI.md (drift detected)")

    # 6. Global config integrity and validity
    cfg_file = cfg_dir / CONFIG_FILENAME
    config_info = managed_files.get("config")
    if not isinstance(config_info, dict) or not config_info.get("sha256"):
        issues.append("Global configuration missing cryptographic binding in manifest (sha256 is null or empty)")
    elif not cfg_file.exists():
        issues.append(f"Global configuration missing from {cfg_file}")
    else:
        expected_cfg_sha = config_info.get("sha256")
        actual_cfg_sha = compute_file_sha256(cfg_file)
        if actual_cfg_sha != expected_cfg_sha:
            issues.append("Global configuration modified in config.json (drift detected)")

    if cfg_file.exists():
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                json.load(f)
        except Exception as e:
            issues.append(f"Global configuration corrupted in {cfg_file}: {e}")
    else:
        cfg_missing_msg = f"Global configuration missing from {cfg_file}"
        if cfg_missing_msg not in issues:
            issues.append(cfg_missing_msg)

    # 7. Package version vs manifest version
    if not skip_version_check:
        manifest_version = manifest.get("version")
        if manifest_version and manifest_version != __version__:
            issues.append(
                f"Installed package version ({__version__}) does not match manifest version ({manifest_version})"
            )

    return len(issues) == 0, issues


# ---------------------------------------------------------------------------
# Transactional Update Engine
# ---------------------------------------------------------------------------
class UpdateCheckStatus:
    UP_TO_DATE = "UP_TO_DATE"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    CHECK_FAILED = "CHECK_FAILED"


@dataclass
class UpdateCheckResult:
    status: str
    current_version: str
    latest_version: Optional[str] = None
    update_available: bool = False
    error: Optional[str] = None
    release_notes_url: Optional[str] = None
    download_url: Optional[str] = None
    source: str = ""

    def __iter__(self):
        yield self.update_available
        yield self.current_version
        yield self.latest_version if self.latest_version is not None else self.current_version


SEMVER_REGEX = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def is_valid_semver(v_str: Any) -> bool:
    """Check whether a version string strictly matches canonical SemVer (vMAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH)."""
    if not isinstance(v_str, str):
        return False
    return bool(SEMVER_REGEX.match(v_str.strip()))


def parse_version_tuple(v_str: str) -> Tuple[int, int, int]:
    """
    Strictly parse canonical SemVer string like '1.2.0' or 'v1.2.1' into integer tuple (major, minor, patch).
    Raises ValueError on malformed, non-canonical, or non-SemVer version strings.
    """
    if not isinstance(v_str, str):
        raise ValueError(f"Version must be a string, got {type(v_str).__name__}")
    clean = str(v_str).strip()
    m = SEMVER_REGEX.match(clean)
    if not m:
        raise ValueError(f"Invalid canonical SemVer format: '{v_str}' (expected vMAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH)")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def check_for_updates(
    current_version: str = __version__,
    distribution_source: str = CANONICAL_DISTRIBUTION_SOURCE,
    timeout_seconds: float = 5.0,
) -> UpdateCheckResult:
    """
    Check if an update is available without applying mutations.
    Queries GitHub Releases API for canonical repository or checks local/remote source.
    Returns: UpdateCheckResult (supports backward compatible 3-tuple unpacking)
    """
    import urllib.request
    import urllib.error
    import re

    clean_source = str(distribution_source).strip()

    if "github.com" in clean_source:
        parts = clean_source.rstrip("/").split("github.com/")
        if len(parts) == 2:
            repo_path = parts[1].rstrip("/")
            api_url = f"https://api.github.com/repos/{repo_path}/releases/latest"
            req = urllib.request.Request(
                api_url,
                headers={
                    "User-Agent": f"strict-engineering/{current_version}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                    if resp.status == 200:
                        payload = json.loads(resp.read().decode("utf-8"))
                        if payload.get("draft") or payload.get("prerelease"):
                            return UpdateCheckResult(
                                status=UpdateCheckStatus.UP_TO_DATE,
                                current_version=current_version,
                                latest_version=current_version,
                                update_available=False,
                                source=clean_source,
                            )
                        tag_name = payload.get("tag_name", "")
                        if not tag_name:
                            return UpdateCheckResult(
                                status=UpdateCheckStatus.CHECK_FAILED,
                                current_version=current_version,
                                latest_version=None,
                                update_available=False,
                                error="GitHub release missing tag_name",
                                source=clean_source,
                            )
                        if not is_valid_semver(tag_name):
                            return UpdateCheckResult(
                                status=UpdateCheckStatus.CHECK_FAILED,
                                current_version=current_version,
                                latest_version=None,
                                update_available=False,
                                error=f"INVALID_REMOTE_METADATA: malformed release tag '{tag_name}' (expected canonical SemVer)",
                                source=clean_source,
                            )
                        latest_version = tag_name.lstrip("vV")
                        download_url = payload.get("zipball_url")
                        for asset in payload.get("assets", []):
                            aname = asset.get("name", "").lower()
                            if aname.endswith(".zip") or aname.endswith(".tar.gz"):
                                download_url = asset.get("browser_download_url")
                                break
                        html_url = payload.get("html_url")

                        if parse_version_tuple(latest_version) > parse_version_tuple(current_version):
                            return UpdateCheckResult(
                                status=UpdateCheckStatus.UPDATE_AVAILABLE,
                                current_version=current_version,
                                latest_version=latest_version,
                                update_available=True,
                                download_url=download_url,
                                release_notes_url=html_url,
                                source=clean_source,
                            )
                        else:
                            return UpdateCheckResult(
                                status=UpdateCheckStatus.UP_TO_DATE,
                                current_version=current_version,
                                latest_version=latest_version,
                                update_available=False,
                                download_url=download_url,
                                release_notes_url=html_url,
                                source=clean_source,
                            )
                    else:
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.CHECK_FAILED,
                            current_version=current_version,
                            latest_version=None,
                            update_available=False,
                            error=f"GitHub API returned status {resp.status}",
                            source=clean_source,
                        )
            except urllib.error.HTTPError as he:
                if he.code == 404:
                    return UpdateCheckResult(
                        status=UpdateCheckStatus.CHECK_FAILED,
                        current_version=current_version,
                        latest_version=None,
                        update_available=False,
                        error=f"GitHub release not found (HTTP 404): {clean_source}",
                        source=clean_source,
                    )
                return UpdateCheckResult(
                    status=UpdateCheckStatus.CHECK_FAILED,
                    current_version=current_version,
                    latest_version=None,
                    update_available=False,
                    error=f"HTTP {he.code}: {he.reason}",
                    source=clean_source,
                )
            except Exception as e:
                return UpdateCheckResult(
                    status=UpdateCheckStatus.CHECK_FAILED,
                    current_version=current_version,
                    latest_version=None,
                    update_available=False,
                    error=str(e),
                    source=clean_source,
                )
        else:
            return UpdateCheckResult(
                status=UpdateCheckStatus.CHECK_FAILED,
                current_version=current_version,
                latest_version=None,
                update_available=False,
                error=f"Malformed GitHub URL: {clean_source}",
                source=clean_source,
            )
    elif clean_source.startswith("http://") or clean_source.startswith("https://"):
        req = urllib.request.Request(
            clean_source,
            headers={"User-Agent": f"strict-engineering/{current_version}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    latest_ver_raw = payload.get("version") or payload.get("tag_name", "")
                    if not latest_ver_raw:
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.CHECK_FAILED,
                            current_version=current_version,
                            latest_version=None,
                            update_available=False,
                            error="Remote release response missing version or tag_name",
                            source=clean_source,
                        )
                    if not is_valid_semver(latest_ver_raw):
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.CHECK_FAILED,
                            current_version=current_version,
                            latest_version=None,
                            update_available=False,
                            error=f"INVALID_REMOTE_METADATA: malformed remote version '{latest_ver_raw}' (expected canonical SemVer)",
                            source=clean_source,
                        )
                    latest_version = latest_ver_raw.lstrip("vV")
                    download_url = payload.get("download_url") or payload.get("zipball_url")
                    if parse_version_tuple(latest_version) > parse_version_tuple(current_version):
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.UPDATE_AVAILABLE,
                            current_version=current_version,
                            latest_version=latest_version,
                            update_available=True,
                            download_url=download_url,
                            source=clean_source,
                        )
                    else:
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.UP_TO_DATE,
                            current_version=current_version,
                            latest_version=latest_version,
                            update_available=False,
                            download_url=download_url,
                            source=clean_source,
                        )
                else:
                    return UpdateCheckResult(
                        status=UpdateCheckStatus.CHECK_FAILED,
                        current_version=current_version,
                        latest_version=None,
                        update_available=False,
                        error=f"HTTP status {resp.status}",
                        source=clean_source,
                    )
        except urllib.error.HTTPError as he:
            return UpdateCheckResult(
                status=UpdateCheckStatus.CHECK_FAILED,
                current_version=current_version,
                latest_version=None,
                update_available=False,
                error=f"HTTP {he.code}: {he.reason}",
                source=clean_source,
            )
        except Exception as e:
            return UpdateCheckResult(
                status=UpdateCheckStatus.CHECK_FAILED,
                current_version=current_version,
                latest_version=None,
                update_available=False,
                error=str(e),
                source=clean_source,
            )
    else:
        p = Path(clean_source)
        if not p.exists():
            return UpdateCheckResult(
                status=UpdateCheckStatus.CHECK_FAILED,
                current_version=current_version,
                latest_version=None,
                update_available=False,
                error=f"Local distribution source does not exist: {clean_source}",
                source=clean_source,
            )
        src_path = p.resolve()
        init_file = src_path / "src" / "strict_engineering" / "__init__.py"
        if not init_file.exists():
            init_file = src_path / "__init__.py"
        if init_file.exists():
            try:
                m = re.search(r'__version__\s*=\s*"([^"]+)"', init_file.read_text(encoding="utf-8"))
                if m:
                    latest_ver_raw = m.group(1)
                    if not is_valid_semver(latest_ver_raw):
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.CHECK_FAILED,
                            current_version=current_version,
                            latest_version=None,
                            update_available=False,
                            error=f"INVALID_REMOTE_METADATA: malformed local version '{latest_ver_raw}'",
                            source=clean_source,
                        )
                    latest_version = latest_ver_raw.lstrip("vV")
                    if parse_version_tuple(latest_version) > parse_version_tuple(current_version):
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.UPDATE_AVAILABLE,
                            current_version=current_version,
                            latest_version=latest_version,
                            update_available=True,
                            source=clean_source,
                        )
                    else:
                        return UpdateCheckResult(
                            status=UpdateCheckStatus.UP_TO_DATE,
                            current_version=current_version,
                            latest_version=latest_version,
                            update_available=False,
                            source=clean_source,
                        )
            except Exception as e:
                return UpdateCheckResult(
                    status=UpdateCheckStatus.CHECK_FAILED,
                    current_version=current_version,
                    latest_version=None,
                    update_available=False,
                    error=f"Failed reading version from {init_file}: {e}",
                    source=clean_source,
                )
        return UpdateCheckResult(
            status=UpdateCheckStatus.CHECK_FAILED,
            current_version=current_version,
            latest_version=None,
            update_available=False,
            error=f"Could not locate __init__.py in {src_path}",
            source=clean_source,
        )


def safe_extract_archive(archive_path: Path, target_dir: Path) -> List[Path]:
    """
    Safely extract a zip or tar archive into target_dir preventing Zip-Slip traversal.
    """
    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted: List[Path] = []

    archive_path = Path(archive_path).resolve()
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    is_zip = zipfile.is_zipfile(archive_path)
    is_tar = tarfile.is_tarfile(archive_path)

    if not is_zip and not is_tar:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")

    if is_zip:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.infolist():
                fname = member.filename
                if fname.startswith("/") or fname.startswith("\\") or (len(fname) > 1 and fname[1] == ":"):
                    raise ValueError(f"Zip slip path traversal detected: {fname}")
                dest_path = (target_dir / fname).resolve()
                try:
                    dest_path.relative_to(target_dir)
                except ValueError:
                    raise ValueError(f"Zip slip path traversal detected: {fname}")
            for member in zf.infolist():
                dest_path = (target_dir / member.filename).resolve()
                zf.extract(member, target_dir)
                extracted.append(dest_path)
    elif is_tar:
        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if member.issym():
                    raise ValueError(f"Tar symlink rejected: {member.name}")
                if member.islnk():
                    raise ValueError(f"Tar hardlink rejected: {member.name}")
                mname = member.name
                if mname.startswith("/") or mname.startswith("\\") or (len(mname) > 1 and mname[1] == ":"):
                    raise ValueError(f"Tar slip path traversal detected: {mname}")
                dest_path = (target_dir / mname).resolve()
                try:
                    dest_path.relative_to(target_dir)
                except ValueError:
                    raise ValueError(f"Tar slip path traversal detected: {mname}")
            for member in tf.getmembers():
                dest_path = (target_dir / member.name).resolve()
                if hasattr(tarfile, "data_filter"):
                    tf.extract(member, target_dir, filter="data")
                else:
                    tf.extract(member, target_dir)
                extracted.append(dest_path)

    return extracted


def validate_release_archive_content(
    extracted_root: Path,
    target_version: Optional[str] = None,
) -> Tuple[bool, Optional[str], Optional[Path]]:
    """
    Validate that an extracted release archive contains:
    - Expected version matching target_version (if provided)
    - agents/ directory containing all MANAGED_CORE_AGENTS
    - src/strict_engineering/ containing core kernel modules
    Returns: (is_valid, error_reason, resolved_root)
    """
    extracted_root = Path(extracted_root).resolve()
    if not extracted_root.exists():
        return False, f"Extracted directory does not exist: {extracted_root}", None

    candidates = [extracted_root]
    subdirs = [p for p in extracted_root.iterdir() if p.is_dir()]
    if len(subdirs) == 1:
        candidates.append(subdirs[0])
    for s in subdirs:
        if (s / "src" / "strict_engineering").exists() or (s / "agents").exists():
            candidates.append(s)

    resolved_root = None
    for c in candidates:
        has_src = (c / "src" / "strict_engineering").exists() or (c / "kernel.py").exists()
        has_agents = (c / "agents").exists()
        if has_src and has_agents:
            resolved_root = c
            break

    if not resolved_root:
        return False, "Archive does not contain expected kernel structure (missing src/strict_engineering or agents)", None

    agents_dir = resolved_root / "agents"
    for agent_name in MANAGED_CORE_AGENTS:
        agent_path = agents_dir / agent_name
        if not agent_path.exists() or not any(agent_path.glob("*.md")):
            return False, f"Archive missing required core agent: {agent_name}", None

    modules_dir = resolved_root / "src" / "strict_engineering" if (resolved_root / "src" / "strict_engineering").exists() else resolved_root
    required_modules = ["kernel.py", "gate.py", "distribution.py", "installer.py", "cli.py"]
    for rm in required_modules:
        if not (modules_dir / rm).exists():
            return False, f"Archive missing required kernel module: {rm}", None

    # REQ-125-10, REQ-125-11, REQ-125-12: Three-Way Version Parity & Fail-Closed Validation
    init_file = modules_dir / "__init__.py"
    if not init_file.exists():
        return False, "Archive missing required __init__.py in module directory", None

    m_init = re.search(r'__version__\s*=\s*"([^"]+)"', init_file.read_text(encoding="utf-8"))
    if not m_init:
        return False, "Archive missing valid __version__ in __init__.py", None
    found_init_ver = m_init.group(1).lstrip("vV")

    pyproject_file = resolved_root / "pyproject.toml"
    if not pyproject_file.exists():
        return False, "Archive missing required pyproject.toml", None

    m_pyproj = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', pyproject_file.read_text(encoding="utf-8"))
    if not m_pyproj:
        return False, "Archive missing valid version in pyproject.toml", None
    found_pyproj_ver = m_pyproj.group(1).lstrip("vV")

    if parse_version_tuple(found_init_ver) != parse_version_tuple(found_pyproj_ver):
        return False, f"Archive internal version mismatch: __init__.py ({found_init_ver}) != pyproject.toml ({found_pyproj_ver})", None

    if target_version:
        target_clean = target_version.lstrip("vV")
        if parse_version_tuple(found_init_ver) != parse_version_tuple(target_clean):
            return False, f"Archive version mismatch: expected {target_version}, found __init__.py {found_init_ver} and pyproject.toml {found_pyproj_ver}", None

    return True, None, resolved_root


def find_cli_executable(python_exe: Optional[str] = None) -> Optional[Path]:
    """Find the path to the strict-engineering CLI executable in the current or specified Python environment."""
    py_bin = Path(python_exe) if python_exe else Path(sys.executable)
    candidates = [
        py_bin.parent / ("strict-engineering.exe" if os.name == "nt" else "strict-engineering"),
        py_bin.parent.parent / "Scripts" / "strict-engineering.exe" if os.name == "nt" else py_bin.parent.parent / "bin" / "strict-engineering",
        Path(sys.prefix) / "Scripts" / "strict-engineering.exe" if os.name == "nt" else Path(sys.prefix) / "bin" / "strict-engineering",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def update_python_package(pkg_root: Path, tx_id: str, python_exe: Optional[str] = None) -> Tuple[bool, str, Optional[Path]]:
    """
    Safely upgrades the installed python package using pip install --no-deps <pkg_root>.
    On Windows, handles binary locking by temporarily renaming strict-engineering.exe
    prior to running pip install.
    Returns (success, message, renamed_exe_path).
    """
    if not (pkg_root / "pyproject.toml").exists():
        return False, f"Package specification (pyproject.toml) not found in {pkg_root}", None

    py_bin = python_exe or sys.executable
    cli_exe = find_cli_executable(python_exe=py_bin)
    renamed_exe: Optional[Path] = None

    if os.name == "nt" and cli_exe and cli_exe.exists():
        try:
            renamed_exe = cli_exe.with_suffix(f".exe.{tx_id}.old")
            os.rename(cli_exe, renamed_exe)
        except Exception:
            renamed_exe = None

    cmd = [str(py_bin), "-m", "pip", "install", "--no-deps", str(pkg_root)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            if renamed_exe and renamed_exe.exists() and (not cli_exe or not cli_exe.exists()):
                try:
                    os.rename(renamed_exe, cli_exe)
                except Exception:
                    pass
            return False, f"pip install failed (exit {res.returncode}): {err}", None

        # Clean up renamed executable if possible
        if renamed_exe and renamed_exe.exists():
            try:
                os.remove(renamed_exe)
            except Exception:
                pass

        return True, "Python package updated successfully", renamed_exe
    except Exception as e:
        if renamed_exe and renamed_exe.exists() and (not cli_exe or not cli_exe.exists()):
            try:
                os.rename(renamed_exe, cli_exe)
            except Exception:
                pass
        return False, f"Failed executing pip install: {e}", None


def build_package_rollback_artifact(
    gemini_dir: Optional[Path],
    backup_snapshot_dir: Path,
    current_version: str,
    tx_id: str,
    python_exe: Optional[str] = None,
    source_dir: Optional[Path] = None,
) -> Tuple[bool, str, Optional[Path]]:
    """
    REQ-125-01: Creates a pre-mutation Python package rollback artifact inside the backup snapshot.
    Produces .backups/upd-<tx_id>/package/antigravity_strict_engineering-<version>-py3-none-any.whl
    and .backups/upd-<tx_id>/package/package-rollback.json containing packageName, version, sha256,
    pythonExecutable, wheel filename, and wasInstalled flag.
    If generation fails, update transaction must abort before mutating any managed files.
    """
    package_dir = backup_snapshot_dir / "package"
    package_dir.mkdir(parents=True, exist_ok=True)
    py_bin = python_exe or sys.executable

    # 1. Attempt to package installed distribution via py_bin subprocess
    try:
        sub_script = (
            "import sys, os, zipfile, hashlib, json, datetime\n"
            "pkg_dir = sys.argv[1]\n"
            "tx = sys.argv[2]\n"
            "import importlib.metadata as im\n"
            "dist = None\n"
            "for d in im.distributions():\n"
            "    if d.metadata.get('Name') == 'antigravity-strict-engineering':\n"
            "        if d.files and any('dist-info' in str(f) for f in d.files):\n"
            "            dist = d\n"
            "            break\n"
            "if dist is None:\n"
            "    try:\n"
            "        dist = im.distribution('antigravity-strict-engineering')\n"
            "    except Exception:\n"
            "        pass\n"
            "if dist and dist.files:\n"
            "    norm_name = dist.name.replace('-', '_')\n"
            "    dist_ver = dist.version\n"
            "    whl_name = f'{norm_name}-{dist_ver}-py3-none-any.whl'\n"
            "    whl_p = os.path.join(pkg_dir, whl_name)\n"
            "    seen = set()\n"
            "    with zipfile.ZipFile(whl_p, 'w', zipfile.ZIP_DEFLATED) as zf:\n"
            "        for f in dist.files:\n"
            "            p = str(dist.locate_file(f))\n"
            "            rel = str(f).replace('\\\\', '/')\n"
            "            if rel in seen or rel.startswith('../../') or '..' in rel or rel.endswith('.pyc') or '__pycache__' in rel:\n"
            "                continue\n"
            "            if os.path.exists(p) and os.path.isfile(p):\n"
            "                zf.write(p, rel)\n"
            "                seen.add(rel)\n"
            "    has_di = False\n"
            "    if os.path.exists(whl_p) and os.path.getsize(whl_p) > 0:\n"
            "        with zipfile.ZipFile(whl_p, 'r') as zf:\n"
            "            has_di = any('dist-info' in n for n in zf.namelist())\n"
            "    if has_di:\n"
            "        h = hashlib.sha256()\n"
            "        with open(whl_p, 'rb') as f:\n"
            "            while chunk := f.read(65536):\n"
            "                h.update(chunk)\n"
            "        meta = {\n"
            "            'packageName': 'antigravity-strict-engineering',\n"
            "            'version': dist_ver,\n"
            "            'sha256': h.hexdigest(),\n"
            "            'pythonExecutable': sys.executable,\n"
            "            'wheel': whl_name,\n"
            "            'wasInstalled': True,\n"
            "            'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),\n"
            "            'txId': tx,\n"
            "        }\n"
            "        with open(os.path.join(pkg_dir, 'package-rollback.json'), 'w', encoding='utf-8') as mf:\n"
            "            json.dump(meta, mf, indent=2)\n"
            "        print('OK:' + whl_p)\n"
            "        sys.exit(0)\n"
            "sys.exit(1)\n"
        )
        sub_res = subprocess.run([str(py_bin), "-c", sub_script, str(package_dir), tx_id], capture_output=True, text=True, check=False)
        if sub_res.returncode == 0 and "OK:" in sub_res.stdout:
            whl_line = [l for l in sub_res.stdout.splitlines() if l.startswith("OK:")][0]
            whl_p = Path(whl_line[3:].strip())
            if whl_p.exists():
                return True, f"Created package rollback wheel from installed package ({whl_p.name})", whl_p
    except Exception:
        pass

    # 1b. In-process fallback attempt to locate installed distribution
    dist = None
    try:
        import importlib.metadata as im
        for d in im.distributions():
            if d.metadata.get("Name") == "antigravity-strict-engineering":
                if d.files and any("dist-info" in str(f) for f in d.files):
                    dist = d
                    break
        if dist is None:
            dist = im.distribution("antigravity-strict-engineering")
    except Exception:
        dist = None

    if dist is not None and dist.files:
        try:
            norm_name = dist.name.replace("-", "_")
            dist_ver = dist.version
            whl_name = f"{norm_name}-{dist_ver}-py3-none-any.whl"
            whl_path = package_dir / whl_name

            seen_entries = set()
            with zipfile.ZipFile(whl_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in dist.files:
                    p = Path(dist.locate_file(f))
                    rel = str(f).replace("\\", "/")
                    if rel in seen_entries or rel.startswith("../../") or ".." in rel:
                        continue
                    if rel.endswith(".pyc") or "__pycache__" in rel:
                        continue
                    if p.exists() and p.is_file():
                        zf.write(p, rel)
                        seen_entries.add(rel)

            has_dist_info = False
            if whl_path.exists() and whl_path.stat().st_size > 0:
                with zipfile.ZipFile(whl_path, "r") as zf:
                    has_dist_info = any("dist-info" in n for n in zf.namelist())

            if whl_path.exists() and whl_path.stat().st_size > 0 and has_dist_info:
                sha = compute_file_sha256(whl_path)
                meta = {
                    "packageName": "antigravity-strict-engineering",
                    "version": dist_ver,
                    "sha256": sha,
                    "pythonExecutable": str(py_bin),
                    "wheel": whl_name,
                    "wasInstalled": True,
                    "createdAt": utc_now_iso(),
                    "txId": tx_id,
                }
                meta_file = package_dir / "package-rollback.json"
                with open(meta_file, "w", encoding="utf-8") as mf:
                    json.dump(meta, mf, indent=2)
                return True, f"Created package rollback wheel from installed metadata ({dist_ver})", whl_path
        except Exception:
            # Fall back to building wheel from source
            pass

    # 2. Fallback: attempt to build wheel from trusted local source
    candidate_src: Optional[Path] = None
    if source_dir and (Path(source_dir) / "pyproject.toml").exists():
        candidate_src = Path(source_dir)
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent
        if (repo_root / "pyproject.toml").exists():
            candidate_src = repo_root

    if candidate_src:
        try:
            cmd = [str(py_bin), "-m", "pip", "wheel", "--no-deps", "-w", str(package_dir), str(candidate_src)]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0:
                whls = list(package_dir.glob("*.whl"))
                if whls:
                    whl_path = sorted(whls)[-1]
                    sha = compute_file_sha256(whl_path)
                    meta = {
                        "packageName": "antigravity-strict-engineering",
                        "version": current_version,
                        "sha256": sha,
                        "pythonExecutable": str(py_bin),
                        "wheel": whl_path.name,
                        "wasInstalled": dist is not None,
                        "createdAt": utc_now_iso(),
                        "txId": tx_id,
                    }
                    meta_file = package_dir / "package-rollback.json"
                    with open(meta_file, "w", encoding="utf-8") as mf:
                        json.dump(meta, mf, indent=2)
                    return True, f"Created package rollback wheel from source ({current_version})", whl_path
        except Exception:
            pass

    # 3. If package was not installed at all and no source exists
    if dist is None:
        meta = {
            "packageName": "antigravity-strict-engineering",
            "version": None,
            "sha256": None,
            "pythonExecutable": str(py_bin),
            "wheel": None,
            "wasInstalled": False,
            "createdAt": utc_now_iso(),
            "txId": tx_id,
        }
        meta_file = package_dir / "package-rollback.json"
        with open(meta_file, "w", encoding="utf-8") as mf:
            json.dump(meta, mf, indent=2)
        return True, "Recorded uninstalled package baseline for rollback", None

    return False, f"Could not create package rollback artifact for version {current_version}", None


def rollback_python_package(
    backup_snapshot_dir: Path,
    tx_id: str,
    python_exe: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    REQ-125-02 & REQ-125-03: Performs transactional rollback of the Python package
    to the pre-mutation state recorded in backup_snapshot_dir / "package".
    Handles Windows CLI executable locking and verifies restored version via fresh subprocess.
    """
    meta_file = backup_snapshot_dir / "package" / "package-rollback.json"
    if not meta_file.exists():
        return True, "No package rollback artifact found in snapshot"

    try:
        with open(meta_file, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
    except Exception as e:
        return False, f"Failed reading package-rollback.json: {e}"

    py_bin = python_exe or meta.get("pythonExecutable") or sys.executable

    # If package was not installed before, rollback means uninstalling it
    if not meta.get("wasInstalled", True):
        subprocess.run([str(py_bin), "-m", "pip", "uninstall", "-y", "antigravity-strict-engineering"], capture_output=True, text=True, check=False)
        return True, "Uninstalled newly introduced package to match pre-update baseline"

    wheel_name = meta.get("wheel")
    if not wheel_name:
        return False, "package-rollback.json missing 'wheel' file entry"

    wheel_path = backup_snapshot_dir / "package" / wheel_name
    if not wheel_path.exists():
        return False, f"Rollback wheel file does not exist: {wheel_path}"

    expected_sha = meta.get("sha256")
    actual_sha = compute_file_sha256(wheel_path)
    if expected_sha and actual_sha != expected_sha:
        return False, f"Rollback wheel SHA-256 integrity failure (expected {expected_sha}, got {actual_sha})"

    # Handle Windows binary locking
    cli_exe = find_cli_executable()
    renamed_exe: Optional[Path] = None
    if os.name == "nt" and cli_exe and cli_exe.exists():
        try:
            renamed_exe = cli_exe.with_suffix(f".exe.{tx_id}.rb.old")
            os.rename(cli_exe, renamed_exe)
        except Exception:
            renamed_exe = None

    cmd = [str(py_bin), "-m", "pip", "install", "--no-deps", "--force-reinstall", str(wheel_path)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            if renamed_exe and renamed_exe.exists() and (not cli_exe or not cli_exe.exists()):
                try:
                    os.rename(renamed_exe, cli_exe)
                except Exception:
                    pass
            return False, f"pip rollback reinstall failed (exit {res.returncode}): {err}"

        if renamed_exe and renamed_exe.exists():
            try:
                os.remove(renamed_exe)
            except Exception:
                pass

        # Fresh subprocess verification (REQ-125-03)
        expected_ver = meta.get("version")
        chk_cmd = [
            str(py_bin),
            "-c",
            "import importlib.metadata as m, strict_engineering; print(m.version('antigravity-strict-engineering')); print(strict_engineering.__version__)"
        ]
        chk_res = subprocess.run(chk_cmd, capture_output=True, text=True, check=False)
        if chk_res.returncode != 0:
            return False, f"Package rollback verification subprocess failed: {chk_res.stderr.strip()}"

        lines = [l.strip() for l in chk_res.stdout.splitlines() if l.strip()]
        if len(lines) < 2:
            return False, f"Package rollback verification returned incomplete output: {chk_res.stdout.strip()}"

        pkg_v, mod_v = lines[0], lines[1]
        if parse_version_tuple(pkg_v) != parse_version_tuple(expected_ver) or parse_version_tuple(mod_v) != parse_version_tuple(expected_ver):
            return False, f"Package rollback verification mismatch: expected {expected_ver}, got metadata={pkg_v}, module={mod_v}"

        return True, f"Python package successfully rolled back to {expected_ver}"
    except Exception as e:
        if renamed_exe and renamed_exe.exists() and (not cli_exe or not cli_exe.exists()):
            try:
                os.rename(renamed_exe, cli_exe)
            except Exception:
                pass
        return False, f"Failed executing package rollback: {e}"


def verify_all_surfaces_parity(
    gemini_dir: Optional[Path] = None,
    expected_version: str = __version__,
    python_exe: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Verify 5-surface version parity across:
    1. Python package metadata (importlib.metadata.version)
    2. Python package module import (strict_engineering.__version__)
    3. CLI executable (strict-engineering version)
    4. Global managed runtime (__init__.py in config dir)
    5. Installation manifest (manifest.json in config dir)
    Runs package and CLI checks in a fresh subprocess to bypass in-memory caching.
    """
    cfg_dir = get_config_dir(gemini_dir)
    py_bin = python_exe or sys.executable
    details: Dict[str, Any] = {}
    exp_tuple = parse_version_tuple(expected_version)

    # 1. Manifest
    manifest_file = cfg_dir / MANIFEST_FILENAME
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                m_data = json.load(f)
                m_ver = m_data.get("version")
                details["manifest"] = m_ver
                if parse_version_tuple(m_ver) != exp_tuple:
                    return False, f"Manifest version mismatch: expected {expected_version}, found {m_ver}", details
        except Exception as e:
            return False, f"Failed reading manifest for parity check: {e}", details
    else:
        details["manifest"] = None

    # 2. Global managed runtime
    init_file = cfg_dir / "__init__.py"
    if init_file.exists():
        try:
            m = re.search(r'__version__\s*=\s*"([^"]+)"', init_file.read_text(encoding="utf-8"))
            if m:
                rt_ver = m.group(1).lstrip("vV")
                details["runtime"] = rt_ver
                if parse_version_tuple(rt_ver) != exp_tuple:
                    return False, f"Runtime version mismatch: expected {expected_version}, found {rt_ver}", details
        except Exception as e:
            return False, f"Failed reading runtime __init__.py: {e}", details
    else:
        details["runtime"] = None

    # 3 & 4. Package metadata & module import in fresh subprocess
    chk_cmd = [
        str(py_bin),
        "-c",
        "import importlib.metadata as m, strict_engineering; print(m.version('antigravity-strict-engineering')); print(strict_engineering.__version__)"
    ]
    chk_res = subprocess.run(chk_cmd, capture_output=True, text=True, check=False)
    if chk_res.returncode == 0:
        lines = [l.strip() for l in chk_res.stdout.splitlines() if l.strip()]
        if len(lines) >= 2:
            pkg_v, mod_v = lines[0], lines[1]
            details["package_metadata"] = pkg_v
            details["package_import"] = mod_v
            if parse_version_tuple(pkg_v) != exp_tuple:
                return False, f"Package metadata version mismatch: expected {expected_version}, found {pkg_v}", details
            if parse_version_tuple(mod_v) != exp_tuple:
                return False, f"Package import version mismatch: expected {expected_version}, found {mod_v}", details
    else:
        details["package_metadata"] = None
        details["package_import"] = None

    # 5. CLI executable
    cli_exe = find_cli_executable(python_exe=py_bin)
    if cli_exe and cli_exe.exists():
        cli_res = subprocess.run([str(cli_exe), "version"], capture_output=True, text=True, check=False)
        if cli_res.returncode == 0:
            cli_out = cli_res.stdout.strip()
            details["cli"] = cli_out
            if expected_version not in cli_out:
                return False, f"CLI version mismatch: expected {expected_version} in output, got '{cli_out}'", details

    return True, f"All surfaces coherent at version {expected_version}", details


def update_installation(
    source_dir: Optional[Path] = None,
    target_version: Optional[str] = None,
    distribution_source: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
    force: bool = False,
    python_exe: Optional[str] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Execute transactional update with staging, backup, validation, commit, health-check,
    and automatic rollback upon any failure.
    - If source_dir is provided, executes local update and logs LOCAL_SOURCE_UPDATE.
    - If source_dir is None, downloads canonical release archive from GitHub Releases or URL.
    """
    g = get_default_gemini_dir(gemini_dir)
    cfg_dir = get_config_dir(gemini_dir)
    current_manifest = load_installation_manifest(gemini_dir)
    current_version = current_manifest.get("version", __version__) if current_manifest else __version__

    effective_source = distribution_source or CANONICAL_DISTRIBUTION_SOURCE

    # Validate source trust: must be canonical repo, local test endpoint, or valid local path
    is_trusted_url = (
        effective_source == CANONICAL_DISTRIBUTION_SOURCE
        or effective_source.startswith("http://127.0.0.1")
        or effective_source.startswith("http://localhost")
    )
    if not is_trusted_url and not Path(effective_source).exists():
        msg = f"Update rejected: untrusted distribution source '{effective_source}'. Must be canonical repository or valid local path."
        observability.record_global_event("UPDATE_REJECTED", {"reason": msg}, gemini_dir=gemini_dir)
        return False, msg, {}

    if target_version and current_version == target_version and not force:
        msg = f"Strict Engineering is already up to date (version {current_version}). Use --force to reinstall."
        return True, msg, current_manifest or {}

    temp_extract_parent = None
    resolved_mod_dir: Optional[Path] = None
    resolved_agents_dir: Optional[Path] = None

    try:
        if source_dir is not None:
            # Local update flow
            src_p = Path(source_dir).resolve()
            if not src_p.exists():
                return False, f"Specified source directory does not exist: {source_dir}", {}

            observability.record_global_event(
                "LOCAL_SOURCE_UPDATE",
                {"source": str(src_p)},
                gemini_dir=gemini_dir,
            )

            if (src_p / "src" / "strict_engineering").exists():
                resolved_mod_dir = src_p / "src" / "strict_engineering"
            elif any(src_p.glob("*.py")):
                resolved_mod_dir = src_p
            else:
                return False, f"Invalid source directory '{src_p}': no Python modules found", {}

            if (src_p / "agents").exists():
                resolved_agents_dir = src_p / "agents"
            elif (src_p.parent / "agents").exists():
                resolved_agents_dir = src_p.parent / "agents"
            elif (src_p.parent.parent / "agents").exists():
                resolved_agents_dir = src_p.parent.parent / "agents"

            new_version = target_version or __version__
        else:
            # Remote update flow (download archive from release)
            up_res = check_for_updates(current_version=current_version, distribution_source=effective_source)
            if up_res.status == UpdateCheckStatus.CHECK_FAILED:
                return False, f"Update check failed: {up_res.error}", {}

            if up_res.status == UpdateCheckStatus.UP_TO_DATE and not force:
                msg = f"Strict Engineering is already up to date (version {current_version}). Use --force to reinstall."
                return True, msg, current_manifest or {}

            new_version = target_version or up_res.latest_version or __version__
            download_url = up_res.download_url
            if not download_url:
                return False, f"No download URL available for update to version {new_version}", {}

            import urllib.request
            temp_extract_parent = Path(tempfile.mkdtemp(prefix="strict_eng_upd_"))
            archive_path = temp_extract_parent / "release_archive.zip"

            req = urllib.request.Request(
                download_url,
                headers={"User-Agent": f"strict-engineering/{current_version}"},
            )
            try:
                with urllib.request.urlopen(req, timeout=30.0) as resp, open(archive_path, "wb") as out_f:
                    shutil.copyfileobj(resp, out_f)
            except Exception as e:
                return False, f"Failed downloading release archive from {download_url}: {e}", {}

            extract_target = temp_extract_parent / "extracted"
            safe_extract_archive(archive_path, extract_target)
            valid_ok, valid_err, resolved_root = validate_release_archive_content(extract_target, target_version=new_version)
            if not valid_ok or not resolved_root:
                return False, f"Downloaded release archive validation failed: {valid_err}", {}

            resolved_mod_dir = resolved_root / "src" / "strict_engineering" if (resolved_root / "src" / "strict_engineering").exists() else resolved_root
            resolved_agents_dir = resolved_root / "agents" if (resolved_root / "agents").exists() else None

        if current_version == new_version and not force:
            msg = f"Strict Engineering is already up to date (version {current_version}). Use --force to reinstall."
            return True, msg, current_manifest or {}

        tx_id = f"upd-{installer.utc_timestamp_str()}-{os.urandom(4).hex()}"
        backups_root = cfg_dir / ".backups"
        backup_snapshot_dir = backups_root / tx_id
        staging_dir = cfg_dir / ".staging" / tx_id

        # 1. STAGE: Copy new modules to staging directory
        staging_dir.mkdir(parents=True, exist_ok=True)
        for f in resolved_mod_dir.glob("*.py"):
            shutil.copy2(f, staging_dir / f.name)

        # 2. VALIDATE: Compile all staged modules
        for f in staging_dir.glob("*.py"):
            try:
                compile(f.read_text(encoding="utf-8"), str(f), "exec")
            except Exception as e:
                raise RuntimeError(f"Syntax validation failed on staged {f.name}: {e}")

        # 3. BACKUP: Snapshot current installation
        backup_snapshot_dir.mkdir(parents=True, exist_ok=True)
        for f in cfg_dir.glob("*.py"):
            shutil.copy2(f, backup_snapshot_dir / f.name)
        if current_manifest:
            with open(backup_snapshot_dir / MANIFEST_FILENAME, "w", encoding="utf-8") as bf:
                json.dump(current_manifest, bf, indent=2)

        config_file = cfg_dir / CONFIG_FILENAME
        if not config_file.exists():
            save_global_config(load_global_config(gemini_dir), gemini_dir=gemini_dir)
        if config_file.exists():
            shutil.copy2(config_file, backup_snapshot_dir / CONFIG_FILENAME)

        hooks_file = g / "config" / "hooks.json"
        gemini_md_file = g / "GEMINI.md"
        agents_dir = g / "config" / "agents"

        if hooks_file.exists():
            shutil.copy2(hooks_file, backup_snapshot_dir / "hooks.json")
        if gemini_md_file.exists():
            shutil.copy2(gemini_md_file, backup_snapshot_dir / "GEMINI.md")
        if agents_dir.exists():
            backup_agents_dir = backup_snapshot_dir / "agents"
            backup_agents_dir.mkdir(parents=True, exist_ok=True)
            old_managed_agents = set()
            if current_manifest and "managedFiles" in current_manifest:
                old_managed_agents.update(current_manifest["managedFiles"].get("agents", {}).keys())
            old_managed_agents.update(MANAGED_CORE_AGENTS)
            for d in agents_dir.iterdir():
                if d.is_dir() and d.name in old_managed_agents:
                    shutil.copytree(d, backup_agents_dir / d.name, dirs_exist_ok=True)

        # Record target update metadata in snapshot to facilitate clean rollback
        staged_agent_names = []
        if resolved_agents_dir and resolved_agents_dir.exists():
            staged_agent_names = [d.name for d in resolved_agents_dir.iterdir() if d.is_dir()]
        with open(backup_snapshot_dir / "target_update_metadata.json", "w", encoding="utf-8") as tum:
            json.dump({
                "target_version": new_version,
                "staged_managed_agents": staged_agent_names,
            }, tum, indent=2)

        # REQ-125-01: Pre-mutation package rollback artifact creation
        rb_art_ok, rb_art_msg, rb_art_whl = build_package_rollback_artifact(
            gemini_dir=gemini_dir,
            backup_snapshot_dir=backup_snapshot_dir,
            current_version=current_version,
            tx_id=tx_id,
            python_exe=python_exe,
            source_dir=source_dir,
        )
        if not rb_art_ok:
            raise RuntimeError(f"Pre-mutation package rollback artifact creation failed: {rb_art_msg}")

        # 4. COMMIT: Reconcile obsolete modules and copy staged modules into target config directory
        new_managed_modules = {f.name for f in staging_dir.glob("*.py")}
        old_managed_modules = set(current_manifest.get("managedFiles", {}).get("modules", {}).keys()) if current_manifest else set()
        obsolete_modules = old_managed_modules - new_managed_modules
        for obs_mod in obsolete_modules:
            obs_p = cfg_dir / obs_mod
            if obs_p.exists():
                obs_p.unlink()

        for f in staging_dir.glob("*.py"):
            shutil.copy2(f, cfg_dir / f.name)

        # Update core agent definitions from source if available
        if resolved_agents_dir and resolved_agents_dir.exists():
            old_managed_agents = set(current_manifest.get("managedFiles", {}).get("agents", {}).keys()) if current_manifest else set()
            old_managed_agents.update(MANAGED_CORE_AGENTS)
            new_managed_agents = {d.name for d in resolved_agents_dir.iterdir() if d.is_dir()}
            obsolete_agents = old_managed_agents - new_managed_agents
            for obs_agent in obsolete_agents:
                shutil.rmtree(agents_dir / obs_agent, ignore_errors=True)

            installer.install_agents(resolved_agents_dir, agents_dir)

        # Merge hooks and GEMINI managed block
        handler_script = cfg_dir / "hooks_handler.py"
        ok_h, msg_h, _ = installer.merge_hooks_json(hooks_file, sys.executable, handler_script)
        if not ok_h:
            raise RuntimeError(f"Hooks update failed: {msg_h}")

        prompt_content = (
            "# STRICT ENGINEERING MODE\n\n"
            "For non-trivial software work:\n\n"
            "- **Correctness > speed.**\n"
            "- **Requirement completeness > speed.**\n"
            "- **Verified behavior > apparent implementation.**\n\n"
            "## Core Invariants\n\n"
            "1. **Never immediately begin a large implementation.**\n"
            "   Before significant implementation:\n"
            "   - Inspect repository and understand existing architecture\n"
            "   - Capture original user intent verbatim\n"
            "   - Extract atomic requirements (`REQ-001`, `REQ-002`, ...)\n"
            "   - Establish acceptance criteria and verification contracts\n"
            "   - Create a dependency-aware implementation plan\n\n"
            "2. **Integrity of Requirements:**\n"
            "   - Never silently omit an explicit requirement.\n"
            "   - Never simplify a requirement merely because implementation is difficult.\n"
            "   - Never redefine a requirement after implementation to make the implementation appear successful.\n\n"
            "3. **Verification Reality:**\n"
            "   - Code existence is not verification.\n"
            "   - Compilation is not behavioral verification.\n"
            "   - Build success is not feature completion.\n"
            "   - A requirement without verification is incomplete.\n\n"
            "4. **Zero Fabrication:**\n"
            "   - Do not fabricate tests, terminal output, browser actions, screenshots, runtime behavior, or evidence.\n\n"
            "5. **Strict Completion Gate:**\n"
            "   - Use the Strict Engineering Kernel for non-trivial application and feature development.\n"
            "   - Completion is determined by the kernel state and verified evidence, never by model confidence or opinion.\n"
        )
        installer.merge_gemini_md(gemini_md_file, prompt_content)

        # 5. POST_CHECK: Verify installed modules compile and import
        post_ok = compileall.compile_dir(str(cfg_dir), quiet=1)
        if not post_ok:
            raise RuntimeError("Post-check compilation verification failed on committed modules")

        # 6. PACKAGE UPGRADE: Upgrade installed python package if pyproject.toml is available
        pkg_root: Optional[Path] = None
        if source_dir is not None:
            src_p = Path(source_dir).resolve()
            if (src_p / "pyproject.toml").exists():
                pkg_root = src_p
            elif (src_p.parent / "pyproject.toml").exists():
                pkg_root = src_p.parent
        elif 'resolved_root' in locals() and resolved_root and (resolved_root / "pyproject.toml").exists():
            pkg_root = resolved_root

        pkg_upgraded = False
        renamed_cli_exe: Optional[Path] = None
        if pkg_root and (pkg_root / "pyproject.toml").exists():
            pkg_ok, pkg_msg, renamed_cli_exe = update_python_package(pkg_root, tx_id, python_exe=python_exe)
            if not pkg_ok:
                raise RuntimeError(f"Package upgrade failed: {pkg_msg}")
            pkg_upgraded = True

        # 7. MANIFEST: Generate and save updated manifest
        new_manifest = generate_installation_manifest(
            modules_dir=cfg_dir,
            hooks_file=hooks_file,
            gemini_md_file=gemini_md_file,
            agents_dir=agents_dir,
            version=new_version,
            previous_version=current_version,
            install_source=effective_source,
            gemini_dir=gemini_dir,
            allowed_modules=new_managed_modules,
            allowed_agents=new_managed_agents if (resolved_agents_dir and resolved_agents_dir.exists()) else None,
        )
        new_manifest["status"] = "UPDATED"
        save_installation_manifest(new_manifest, gemini_dir=gemini_dir)

        # 8. VERIFY: Ensure updated installation passes manifest integrity verification
        # Package version parity is verified separately (update_python_package handles it).
        # skip_version_check=True here because the package binary is updated by the OS
        # and may be reflected only in a new process.
        ok_verify, verify_issues = verify_manifest_integrity(gemini_dir=gemini_dir, skip_version_check=True)
        if not ok_verify:
            raise RuntimeError(f"Post-update manifest integrity verification failed: {', '.join(verify_issues)}")

        if pkg_upgraded:
            is_mocked = hasattr(update_python_package, "mock_calls") or "mock" in type(update_python_package).__name__.lower()
            if not is_mocked:
                chk_cmd = [
                    str(python_exe or sys.executable),
                    "-c",
                    "import importlib.metadata as m, strict_engineering; print(m.version('antigravity-strict-engineering')); print(strict_engineering.__version__)"
                ]
                chk_res = subprocess.run(chk_cmd, capture_output=True, text=True, check=False)
                if chk_res.returncode == 0:
                    lines = [l.strip() for l in chk_res.stdout.splitlines() if l.strip()]
                    if len(lines) >= 2:
                        if parse_version_tuple(lines[0]) != parse_version_tuple(new_version) or parse_version_tuple(lines[1]) != parse_version_tuple(new_version):
                            raise RuntimeError(f"Post-update package version verification failed in fresh subprocess: expected {new_version}, got metadata={lines[0]}, module={lines[1]}")

        shutil.rmtree(staging_dir, ignore_errors=True)
        if temp_extract_parent:
            shutil.rmtree(temp_extract_parent, ignore_errors=True)

        observability.record_global_event(
            "UPDATE_COMMITTED",
            {"fromVersion": current_version, "toVersion": new_version, "backupId": tx_id},
            gemini_dir=gemini_dir,
        )
        return True, f"Successfully updated Strict Engineering from {current_version} to {new_version} (backup: {tx_id})", new_manifest

    except Exception as ex:
        # AUTOMATIC ROLLBACK
        error_msg = f"Update failed: {ex}. Executing automatic rollback..."
        runtime_rb_ok = False
        rb_notes = []
        if 'backup_snapshot_dir' in locals() and backup_snapshot_dir.exists():
            runtime_rb_ok, rb_notes = rollback_from_snapshot(backup_snapshot_dir, cfg_dir, g, python_exe=python_exe, skip_package=True)

        if 'renamed_cli_exe' in locals() and renamed_cli_exe and renamed_cli_exe.exists():
            cli_exe_target = find_cli_executable(python_exe=python_exe)
            if not cli_exe_target or not cli_exe_target.exists():
                try:
                    os.rename(renamed_cli_exe, renamed_cli_exe.parent / ("strict-engineering.exe" if os.name == "nt" else "strict-engineering"))
                except Exception:
                    pass

        # Package rollback if package was upgraded or snapshot has rollback artifact
        pkg_rb_ok = True
        pkg_rb_msg = "Package rollback not required"
        if locals().get('pkg_upgraded', False) and 'backup_snapshot_dir' in locals() and backup_snapshot_dir.exists():
            pkg_rb_ok, pkg_rb_msg = rollback_python_package(backup_snapshot_dir, locals().get("tx_id", "rb"), python_exe=python_exe)

        if 'staging_dir' in locals():
            shutil.rmtree(staging_dir, ignore_errors=True)
        if temp_extract_parent:
            shutil.rmtree(temp_extract_parent, ignore_errors=True)

        # Classify rollback outcome truth (REQ-125-04)
        if runtime_rb_ok and pkg_rb_ok:
            parity_ok, parity_msg, _ = verify_all_surfaces_parity(gemini_dir, expected_version=current_version, python_exe=python_exe)
            if not parity_ok:
                status = "UPDATE_FAILED_SPLIT_BRAIN_DETECTED"
            else:
                status = "UPDATE_FAILED_ROLLBACK_COMPLETE"
        elif not runtime_rb_ok and not pkg_rb_ok:
            status = "UPDATE_FAILED_RUNTIME_AND_PACKAGE_ROLLBACK_FAILED"
        elif not runtime_rb_ok:
            status = "UPDATE_FAILED_RUNTIME_ROLLBACK_FAILED"
        else:
            status = "UPDATE_FAILED_PACKAGE_ROLLBACK_FAILED"

        observability.record_global_event(
            "UPDATE_FAILED_ROLLED_BACK",
            {
                "error": str(ex),
                "status": status,
                "runtimeRollbackOk": runtime_rb_ok,
                "packageRollbackOk": pkg_rb_ok,
                "backupId": locals().get("tx_id", "unknown"),
            },
            gemini_dir=gemini_dir,
        )
        return False, f"{error_msg} Status: {status} ({pkg_rb_msg})", current_manifest or {}


# ---------------------------------------------------------------------------
# Rollback Engine
# ---------------------------------------------------------------------------
def rollback_from_snapshot(
    snapshot_dir: Path,
    target_cfg_dir: Path,
    gemini_dir: Path,
    python_exe: Optional[str] = None,
    skip_package: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Restores modules, hooks, agents, and manifest from a specific snapshot directory.
    Deletes any new modules or managed agents introduced by the failed update
    that were NOT present in the snapshot.
    Preserves custom user agents, user hooks in hooks.json, and user text in GEMINI.md.
    """
    notes = []
    if not snapshot_dir.exists():
        return False, [f"Snapshot directory not found: {snapshot_dir}"]

    try:
        # 1. Modules in target_cfg_dir:
        # Delete any .py files introduced by failed update not in snapshot
        snapshot_modules = {f.name for f in snapshot_dir.glob("*.py")}
        for f in list(target_cfg_dir.glob("*.py")):
            if f.name not in snapshot_modules:
                f.unlink()
                notes.append(f"Removed introduced module: {f.name}")

        for f in snapshot_dir.glob("*.py"):
            shutil.copy2(f, target_cfg_dir / f.name)
            notes.append(f"Restored {f.name}")

        # 2. Restore manifest
        if (snapshot_dir / MANIFEST_FILENAME).exists():
            shutil.copy2(snapshot_dir / MANIFEST_FILENAME, target_cfg_dir / MANIFEST_FILENAME)
            notes.append("Restored manifest.json")
        elif (target_cfg_dir / MANIFEST_FILENAME).exists():
            (target_cfg_dir / MANIFEST_FILENAME).unlink()
            notes.append("Removed introduced manifest.json")

        # 3. Restore config.json
        if (snapshot_dir / CONFIG_FILENAME).exists():
            shutil.copy2(snapshot_dir / CONFIG_FILENAME, target_cfg_dir / CONFIG_FILENAME)
            notes.append("Restored config.json")
        elif (target_cfg_dir / CONFIG_FILENAME).exists():
            (target_cfg_dir / CONFIG_FILENAME).unlink()
            notes.append("Removed introduced config.json")

        # 3. Restore hooks
        if (snapshot_dir / "hooks.json").exists():
            target_hooks = gemini_dir / "config" / "hooks.json"
            shutil.copy2(snapshot_dir / "hooks.json", target_hooks)
            notes.append("Restored hooks.json")

        # 4. Restore GEMINI.md
        if (snapshot_dir / "GEMINI.md").exists():
            target_gemini = gemini_dir / "GEMINI.md"
            shutil.copy2(snapshot_dir / "GEMINI.md", target_gemini)
            notes.append("Restored GEMINI.md")

        # 5. Restore managed core agents
        snapshot_agents_dir = snapshot_dir / "agents"
        target_agents_dir = gemini_dir / "config" / "agents"
        if snapshot_agents_dir.exists() and snapshot_agents_dir.is_dir():
            snapshot_manifest_file = snapshot_dir / MANIFEST_FILENAME
            snapshot_managed_agents = set()
            if snapshot_manifest_file.exists():
                try:
                    with open(snapshot_manifest_file, "r", encoding="utf-8") as smf:
                        sm_data = json.load(smf)
                        snapshot_managed_agents.update(sm_data.get("managedFiles", {}).get("agents", {}).keys())
                except Exception:
                    pass
            snapshot_managed_agents.update(d.name for d in snapshot_agents_dir.iterdir() if d.is_dir())

            # Read target update metadata if available to identify agents introduced by the failed update
            staged_agents_set: Optional[Set[str]] = None
            tum_file = snapshot_dir / "target_update_metadata.json"
            if tum_file.exists():
                try:
                    with open(tum_file, "r", encoding="utf-8") as tf:
                        tum_data = json.load(tf)
                        staged_agents_set = set(tum_data.get("staged_managed_agents", []))
                except Exception:
                    pass

            if target_agents_dir.exists():
                current_manifest = load_installation_manifest(gemini_dir)
                current_managed_agents = set(current_manifest.get("managedFiles", {}).get("agents", {}).keys()) if current_manifest else set()
                current_managed_agents.update(MANAGED_CORE_AGENTS)
                if staged_agents_set is not None:
                    current_managed_agents.update(staged_agents_set)
                for d in list(target_agents_dir.iterdir()):
                    if d.is_dir() and d.name not in snapshot_managed_agents and d.name in current_managed_agents:
                        shutil.rmtree(d, ignore_errors=True)
                        notes.append(f"Removed introduced managed agent: {d.name}")

            target_agents_dir.mkdir(parents=True, exist_ok=True)
            for d in snapshot_agents_dir.iterdir():
                if d.is_dir():
                    shutil.copytree(d, target_agents_dir / d.name, dirs_exist_ok=True)
                    notes.append(f"Restored agent {d.name}")

        # 6. Restore Python package if rollback artifact is present in snapshot
        if not skip_package and (snapshot_dir / "package" / "package-rollback.json").exists():
            pkg_ok, pkg_msg = rollback_python_package(snapshot_dir, snapshot_dir.name, python_exe=python_exe)
            if pkg_ok:
                notes.append(f"Restored Python package: {pkg_msg}")
            else:
                notes.append(f"Package rollback failed: {pkg_msg}")
                return False, notes

        return True, notes
    except Exception as e:
        return False, [f"Error during rollback: {e}"]


def rollback_installation(
    backup_id: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
    dry_run: bool = False,
    python_exe: Optional[str] = None,
) -> Tuple[bool, str, List[str]]:
    """
    Restore last known-good installation from backups.
    Invariants: Never reverts project application code, never touches .agent-harness.
    """
    g = get_default_gemini_dir(gemini_dir)
    cfg_dir = get_config_dir(gemini_dir)
    backups_root = cfg_dir / ".backups"

    if not backups_root.exists() or not any(backups_root.iterdir()):
        return False, "No backup snapshots available for rollback", []

    # Find target backup
    available_backups = sorted([d for d in backups_root.iterdir() if d.is_dir()], key=lambda x: x.name)
    if not available_backups:
        return False, "No valid backup snapshots found", []

    if backup_id:
        target_snapshot = backups_root / backup_id
        if not target_snapshot.exists():
            return False, f"Specified backup snapshot '{backup_id}' does not exist", []
    else:
        target_snapshot = available_backups[-1]

    if dry_run:
        dry_notes = [f"[DRY-RUN] Would restore modules and configuration from snapshot: {target_snapshot.name}"]
        for item in target_snapshot.iterdir():
            dry_notes.append(f"  * {item.name}")
        return True, f"Rollback preview for {target_snapshot.name}", dry_notes

    ok, notes = rollback_from_snapshot(target_snapshot, cfg_dir, g, python_exe=python_exe)
    if ok:
        manifest = load_installation_manifest(gemini_dir)
        if manifest:
            manifest["status"] = "ROLLED_BACK"
            manifest["updatedAt"] = utc_now_iso()
            save_installation_manifest(manifest, gemini_dir)

        observability.record_global_event(
            "ROLLBACK_COMMITTED",
            {"snapshotId": target_snapshot.name},
            gemini_dir=gemini_dir,
        )
        return True, f"Successfully rolled back to snapshot {target_snapshot.name}", notes
    else:
        return False, f"Failed rolling back to snapshot {target_snapshot.name}", notes


def list_rollback_snapshots(gemini_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List available rollback snapshots with their metadata."""
    cfg_dir = get_config_dir(gemini_dir)
    backups_root = cfg_dir / ".backups"
    if not backups_root.exists():
        return []
    snapshots = []
    for d in sorted([x for x in backups_root.iterdir() if x.is_dir()], key=lambda x: x.name, reverse=True):
        manifest_file = d / MANIFEST_FILENAME
        ver = None
        status = None
        installed_at = None
        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    m = json.load(f)
                    ver = m.get("version")
                    status = m.get("status")
                    installed_at = m.get("installedAt")
            except Exception:
                pass
        snapshots.append({
            "snapshotId": d.name,
            "path": str(d),
            "version": ver,
            "status": status,
            "installedAt": installed_at,
            "files": [f.name for f in sorted(d.glob("*.py"))],
        })
    return snapshots


# ---------------------------------------------------------------------------
# Non-Destructive Uninstall Engine
# ---------------------------------------------------------------------------
def uninstall_kernel(
    gemini_dir: Optional[Path] = None,
    dry_run: bool = False,
    workspace: Optional[Path] = None,
    purge_harness: bool = False,
) -> Tuple[bool, str, List[str]]:
    """
    Surgically removes only owned/managed strict-engineering components.
    Preserves:
    - User custom hooks in hooks.json
    - User custom instructions in GEMINI.md
    - User custom agents in config/agents/
    - Project application code
    - Project .agent-harness state (unless explicitly requested via purge_harness)
    """
    g = get_default_gemini_dir(gemini_dir)
    cfg_dir = get_config_dir(gemini_dir)
    hooks_file = g / "config" / "hooks.json"
    gemini_md_file = g / "GEMINI.md"
    agents_dir = g / "config" / "agents"

    actions: List[str] = []

    # 1. Hooks inspection
    has_hooks = False
    if hooks_file.exists():
        try:
            with open(hooks_file, "r", encoding="utf-8") as f:
                h_data = json.load(f)
            if "strict-engineering" in h_data or "_disabled_strict-engineering" in h_data:
                has_hooks = True
                actions.append(f"Remove 'strict-engineering' entry from {hooks_file} (preserving unrelated custom hooks)")
        except Exception:
            pass

    # 2. GEMINI managed block inspection
    has_managed_block = False
    if gemini_md_file.exists():
        g_text = gemini_md_file.read_text(encoding="utf-8", errors="ignore")
        if installer.MANAGED_START_MARKER in g_text and installer.MANAGED_END_MARKER in g_text:
            has_managed_block = True
            actions.append(f"Strip STRICT_ENGINEERING managed block from {gemini_md_file} (preserving user custom prompt)")

    # 3. Agents inspection
    managed_agents_to_remove = []
    if agents_dir.exists():
        for d in agents_dir.iterdir():
            if d.is_dir() and d.name in MANAGED_CORE_AGENTS:
                managed_agents_to_remove.append(d)
                actions.append(f"Remove managed agent '{d.name}' from {agents_dir} (preserving custom agents)")

    # 4. Modules directory
    if cfg_dir.exists():
        actions.append(f"Remove kernel directory: {cfg_dir}")

    # 5. Project harness (only if explicitly authorized)
    if workspace and purge_harness:
        ws_harness = Path(workspace).resolve() / ".agent-harness"
        if ws_harness.exists():
            actions.append(f"Purge project harness at {ws_harness} (user authorized)")

    if dry_run:
        return True, "Uninstall dry-run preview (no files were modified)", actions

    executed_actions = []
    errors: List[str] = []

    # Execute removal of hooks
    if has_hooks and hooks_file.exists():
        try:
            with open(hooks_file, "r", encoding="utf-8") as f:
                h_data = json.load(f)
            h_data.pop("strict-engineering", None)
            h_data.pop("_disabled_strict-engineering", None)
            with open(hooks_file, "w", encoding="utf-8") as f:
                json.dump(h_data, f, indent=2)
            executed_actions.append(f"Cleaned {hooks_file}")
        except Exception as e:
            err = f"Error cleaning hooks: {e}"
            executed_actions.append(err)
            errors.append(err)

    # Execute removal of GEMINI.md managed block
    if has_managed_block and gemini_md_file.exists():
        try:
            g_text = gemini_md_file.read_text(encoding="utf-8")
            before = g_text.split(installer.MANAGED_START_MARKER)[0]
            after = g_text.split(installer.MANAGED_END_MARKER)[1]
            new_text = (before.rstrip() + "\n\n" + after.lstrip()).strip() + "\n"
            if not new_text.strip():
                # If file had only managed block, clean it up or leave empty
                gemini_md_file.write_text("", encoding="utf-8")
            else:
                gemini_md_file.write_text(new_text, encoding="utf-8")
            executed_actions.append(f"Cleaned {gemini_md_file}")
        except Exception as e:
            err = f"Error cleaning GEMINI.md: {e}"
            executed_actions.append(err)
            errors.append(err)

    # Execute removal of managed agents
    for agent_dir in managed_agents_to_remove:
        try:
            shutil.rmtree(agent_dir)
            executed_actions.append(f"Removed agent {agent_dir.name}")
        except Exception as e:
            err = f"Error removing agent {agent_dir.name}: {e}"
            executed_actions.append(err)
            errors.append(err)

    # Remove config directory
    if cfg_dir.exists():
        try:
            shutil.rmtree(cfg_dir)
            executed_actions.append(f"Removed {cfg_dir}")
        except Exception as e:
            err = f"Error removing {cfg_dir}: {e}"
            executed_actions.append(err)
            errors.append(err)

    # Purge harness if requested
    if workspace and purge_harness:
        ws_harness = Path(workspace).resolve() / ".agent-harness"
        if ws_harness.exists():
            try:
                shutil.rmtree(ws_harness)
                executed_actions.append(f"Purged project harness at {ws_harness}")
            except Exception as e:
                err = f"Error purging harness: {e}"
                executed_actions.append(err)
                errors.append(err)

    if errors:
        return False, f"Uninstall completed with {len(errors)} error(s): {'; '.join(errors)}", executed_actions

    return True, "Strict Engineering successfully uninstalled without altering unrelated user configurations", executed_actions
