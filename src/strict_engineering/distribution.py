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
        __version__ = "1.2.3"
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


def compute_managed_agents_hashes(agents_dir: Path) -> Dict[str, Dict[str, str]]:
    """
    Computes deterministic SHA-256 hashes for all managed core agents (agent.md).
    Custom agents outside MANAGED_CORE_AGENTS are completely excluded from ownership.
    """
    p = Path(agents_dir).resolve()
    result: Dict[str, Dict[str, str]] = {}
    if not p.exists() or not p.is_dir():
        return result
    for d in sorted(p.iterdir()):
        if d.is_dir() and d.name in MANAGED_CORE_AGENTS:
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
    agents_map = compute_managed_agents_hashes(agents_dir)

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


def verify_manifest_integrity(gemini_dir: Optional[Path] = None) -> Tuple[bool, List[str]]:
    """
    Comprehensive, precise manifest integrity check:
    - Verifies all managed module file hashes match disk
    - Verifies all managed core agent definitions exist and hashes match disk
    - Verifies strict-engineering hook entry hash in hooks.json
    - Verifies managed block hash in GEMINI.md
    - Verifies global config.json exists and is valid
    - Verifies package version matches installed manifest version
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
    if isinstance(config_info, dict) and config_info.get("sha256"):
        expected_cfg_sha = config_info.get("sha256")
        if not cfg_file.exists():
            issues.append(f"Global configuration missing from {cfg_file}")
        else:
            actual_cfg_sha = compute_file_sha256(cfg_file)
            if actual_cfg_sha != expected_cfg_sha:
                issues.append("Global configuration modified in config.json (drift detected)")

    if cfg_file.exists():
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                json.load(f)
        except Exception as e:
            issues.append(f"Global configuration corrupted in {cfg_file}: {e}")

    # 7. Package version vs manifest version
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

    if target_version:
        init_file = modules_dir / "__init__.py"
        if init_file.exists():
            import re
            m = re.search(r'__version__\s*=\s*"([^"]+)"', init_file.read_text(encoding="utf-8"))
            if m:
                found_ver = m.group(1).lstrip("vV")
                if parse_version_tuple(found_ver) != parse_version_tuple(target_version):
                    return False, f"Archive version mismatch: expected {target_version}, found {found_ver}", None

    return True, None, resolved_root


def update_installation(
    source_dir: Optional[Path] = None,
    target_version: Optional[str] = None,
    distribution_source: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
    force: bool = False,
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
            for d in agents_dir.iterdir():
                if d.is_dir() and d.name in MANAGED_CORE_AGENTS:
                    shutil.copytree(d, backup_agents_dir / d.name, dirs_exist_ok=True)

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
            new_managed_agents = {d.name for d in resolved_agents_dir.iterdir() if d.is_dir() and d.name in MANAGED_CORE_AGENTS}
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

        # 6. MANIFEST: Generate and save updated manifest
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
        )
        new_manifest["status"] = "UPDATED"
        save_installation_manifest(new_manifest, gemini_dir=gemini_dir)

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
        rollback_ok = False
        if 'backup_snapshot_dir' in locals() and backup_snapshot_dir.exists():
            rollback_ok, rb_notes = rollback_from_snapshot(backup_snapshot_dir, cfg_dir, g)
        if 'staging_dir' in locals():
            shutil.rmtree(staging_dir, ignore_errors=True)
        if temp_extract_parent:
            shutil.rmtree(temp_extract_parent, ignore_errors=True)
        observability.record_global_event(
            "UPDATE_FAILED_ROLLED_BACK",
            {"error": str(ex), "rollbackOk": rollback_ok, "backupId": locals().get("tx_id", "unknown")},
            gemini_dir=gemini_dir,
        )
        return False, f"{error_msg} (Rollback result: {rollback_ok})", current_manifest or {}


# ---------------------------------------------------------------------------
# Rollback Engine
# ---------------------------------------------------------------------------
def rollback_from_snapshot(
    snapshot_dir: Path,
    target_cfg_dir: Path,
    gemini_dir: Path,
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
            snapshot_agent_names = {d.name for d in snapshot_agents_dir.iterdir() if d.is_dir()}
            if target_agents_dir.exists():
                for d in list(target_agents_dir.iterdir()):
                    if d.is_dir() and d.name in MANAGED_CORE_AGENTS and d.name not in snapshot_agent_names:
                        shutil.rmtree(d)
                        notes.append(f"Removed introduced managed agent: {d.name}")

            target_agents_dir.mkdir(parents=True, exist_ok=True)
            for d in snapshot_agents_dir.iterdir():
                if d.is_dir() and d.name in MANAGED_CORE_AGENTS:
                    shutil.copytree(d, target_agents_dir / d.name, dirs_exist_ok=True)
                    notes.append(f"Restored agent {d.name}")

        return True, notes
    except Exception as e:
        return False, [f"Error during rollback: {e}"]


def rollback_installation(
    backup_id: Optional[str] = None,
    gemini_dir: Optional[Path] = None,
    dry_run: bool = False,
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

    ok, notes = rollback_from_snapshot(target_snapshot, cfg_dir, g)
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
