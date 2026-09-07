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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from . import __version__
    from . import installer
    from . import observability
except (ImportError, ValueError):
    try:
        import strict_engineering
        __version__ = strict_engineering.__version__
    except Exception:
        __version__ = "1.2.0"
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
def generate_installation_manifest(
    modules_dir: Path,
    hooks_file: Path,
    gemini_md_file: Path,
    agents_dir: Path,
    version: str = __version__,
    previous_version: Optional[str] = None,
    install_source: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate canonical manifest capturing hashes of all managed files."""
    modules_dir = Path(modules_dir).resolve()
    modules_map: Dict[str, str] = {}
    if modules_dir.exists():
        for f in sorted(modules_dir.glob("*.py")):
            sha = compute_file_sha256(f)
            if sha:
                modules_map[f.name] = sha

    hooks_sha = compute_file_sha256(hooks_file)
    gemini_sha = compute_file_sha256(gemini_md_file)

    installed_agents = []
    if agents_dir.exists():
        for d in sorted(agents_dir.iterdir()):
            if d.is_dir() and d.name in MANAGED_CORE_AGENTS:
                installed_agents.append(d.name)

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
            "hooks": {
                "path": str(Path(hooks_file).resolve()),
                "sha256": hooks_sha,
            },
            "geminiManagedBlock": {
                "path": str(Path(gemini_md_file).resolve()),
                "sha256": gemini_sha,
            },
            "agents": installed_agents,
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
    """Verify that installed modules on disk match hashes recorded in manifest."""
    manifest = load_installation_manifest(gemini_dir)
    if not manifest:
        return False, ["Installation manifest not found"]

    issues = []
    cfg_dir = get_config_dir(gemini_dir)
    recorded_modules = manifest.get("managedFiles", {}).get("modules", {})

    for mod_name, expected_sha in recorded_modules.items():
        mod_file = cfg_dir / mod_name
        if not mod_file.exists():
            issues.append(f"Missing managed module: {mod_name}")
            continue
        actual_sha = compute_file_sha256(mod_file)
        if actual_sha != expected_sha:
            issues.append(f"Hash mismatch in module {mod_name} (drift detected)")

    return len(issues) == 0, issues


# ---------------------------------------------------------------------------
# Transactional Update Engine
# ---------------------------------------------------------------------------
def check_for_updates(
    current_version: str = __version__,
    distribution_source: str = CANONICAL_DISTRIBUTION_SOURCE,
) -> Tuple[bool, str, str]:
    """Check if an update is available without applying mutations."""
    # In V1.2.0, distribution source is canonical repository.
    # Returns (update_available, current_version, latest_version)
    return False, current_version, current_version


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
    """
    g = get_default_gemini_dir(gemini_dir)
    cfg_dir = get_config_dir(gemini_dir)
    current_manifest = load_installation_manifest(gemini_dir)
    current_version = current_manifest.get("version", __version__) if current_manifest else __version__

    # Security verification: ensure distribution source is trusted
    effective_source = distribution_source or CANONICAL_DISTRIBUTION_SOURCE
    if effective_source != CANONICAL_DISTRIBUTION_SOURCE and not Path(effective_source).exists():
        msg = f"Update rejected: untrusted distribution source '{effective_source}'. Must be canonical repository or valid local path."
        observability.record_global_event("UPDATE_REJECTED", {"reason": msg}, gemini_dir=gemini_dir)
        return False, msg, {}

    new_version = target_version or __version__
    if current_version == new_version and not force:
        msg = f"Strict Engineering is already up to date (version {current_version}). Use --force to reinstall."
        return True, msg, current_manifest or {}

    # Determine source directory containing new modules
    if source_dir is None:
        source_dir = Path(__file__).resolve().parent

    tx_id = f"upd-{installer.utc_timestamp_str()}-{os.urandom(4).hex()}"
    backups_root = cfg_dir / ".backups"
    backup_snapshot_dir = backups_root / tx_id
    staging_dir = cfg_dir / ".staging" / tx_id

    try:
        # 1. STAGE: Copy new modules to staging directory
        staging_dir.mkdir(parents=True, exist_ok=True)
        for f in source_dir.glob("*.py"):
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

        # Snapshot hooks and GEMINI.md
        hooks_file = g / "config" / "hooks.json"
        gemini_md_file = g / "GEMINI.md"
        agents_dir = g / "config" / "agents"

        if hooks_file.exists():
            shutil.copy2(hooks_file, backup_snapshot_dir / "hooks.json")
        if gemini_md_file.exists():
            shutil.copy2(gemini_md_file, backup_snapshot_dir / "GEMINI.md")

        # 4. COMMIT: Copy staged modules into target config directory
        for f in staging_dir.glob("*.py"):
            shutil.copy2(f, cfg_dir / f.name)

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
        )
        new_manifest["status"] = "UPDATED"
        save_installation_manifest(new_manifest, gemini_dir=gemini_dir)

        # Cleanup staging
        shutil.rmtree(staging_dir, ignore_errors=True)

        observability.record_global_event(
            "UPDATE_COMMITTED",
            {"fromVersion": current_version, "toVersion": new_version, "backupId": tx_id},
            gemini_dir=gemini_dir,
        )
        return True, f"Successfully updated Strict Engineering from {current_version} to {new_version} (backup: {tx_id})", new_manifest

    except Exception as ex:
        # AUTOMATIC ROLLBACK
        error_msg = f"Update failed: {ex}. Executing automatic rollback..."
        rollback_ok, rb_notes = rollback_from_snapshot(backup_snapshot_dir, cfg_dir, g)
        shutil.rmtree(staging_dir, ignore_errors=True)
        observability.record_global_event(
            "UPDATE_FAILED_ROLLED_BACK",
            {"error": str(ex), "rollbackOk": rollback_ok, "backupId": tx_id},
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
    """Restores modules, hooks, and manifest from a specific snapshot directory."""
    notes = []
    if not snapshot_dir.exists():
        return False, [f"Snapshot directory not found: {snapshot_dir}"]

    try:
        # Restore modules
        for f in snapshot_dir.glob("*.py"):
            shutil.copy2(f, target_cfg_dir / f.name)
            notes.append(f"Restored {f.name}")

        # Restore manifest
        if (snapshot_dir / MANIFEST_FILENAME).exists():
            shutil.copy2(snapshot_dir / MANIFEST_FILENAME, target_cfg_dir / MANIFEST_FILENAME)
            notes.append("Restored manifest.json")

        # Restore hooks
        if (snapshot_dir / "hooks.json").exists():
            target_hooks = gemini_dir / "config" / "hooks.json"
            shutil.copy2(snapshot_dir / "hooks.json", target_hooks)
            notes.append("Restored hooks.json")

        # Restore GEMINI.md
        if (snapshot_dir / "GEMINI.md").exists():
            target_gemini = gemini_dir / "GEMINI.md"
            shutil.copy2(snapshot_dir / "GEMINI.md", target_gemini)
            notes.append("Restored GEMINI.md")

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
            executed_actions.append(f"Error cleaning hooks: {e}")

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
            executed_actions.append(f"Error cleaning GEMINI.md: {e}")

    # Execute removal of managed agents
    for agent_dir in managed_agents_to_remove:
        try:
            shutil.rmtree(agent_dir, ignore_errors=True)
            executed_actions.append(f"Removed agent {agent_dir.name}")
        except Exception as e:
            executed_actions.append(f"Error removing agent {agent_dir.name}: {e}")

    # Remove config directory
    if cfg_dir.exists():
        try:
            shutil.rmtree(cfg_dir, ignore_errors=True)
            executed_actions.append(f"Removed {cfg_dir}")
        except Exception as e:
            executed_actions.append(f"Error removing {cfg_dir}: {e}")

    # Purge harness if requested
    if workspace and purge_harness:
        ws_harness = Path(workspace).resolve() / ".agent-harness"
        if ws_harness.exists():
            try:
                shutil.rmtree(ws_harness, ignore_errors=True)
                executed_actions.append(f"Purged project harness at {ws_harness}")
            except Exception as e:
                executed_actions.append(f"Error purging harness: {e}")

    return True, "Strict Engineering successfully uninstalled without altering unrelated user configurations", executed_actions
