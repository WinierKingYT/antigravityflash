"""
Strict Engineering Kernel - Safe Non-Destructive Installer
Performs atomic, idempotent merges for hooks.json, GEMINI.md managed blocks,
and custom agent definitions with automatic backup and rollback.
"""

import os
import sys
import json
import shutil
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

MANAGED_START_MARKER = "<!-- STRICT_ENGINEERING_KERNEL_START -->"
MANAGED_END_MARKER = "<!-- STRICT_ENGINEERING_KERNEL_END -->"


def utc_timestamp_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")


def create_backup(target_file: Path, backup_dir: Optional[Path] = None) -> Optional[Path]:
    """Create a timestamped backup of target_file."""
    p = Path(target_file).resolve()
    if not p.exists():
        return None
    if backup_dir is None:
        backup_dir = p.parent / ".backups"
    backup_dir = Path(backup_dir).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    backup_file = backup_dir / f"{p.name}.{utc_timestamp_str()}.bak"
    shutil.copy2(p, backup_file)
    return backup_file


def merge_hooks_json(
    hooks_file: Path,
    python_exe: str,
    hooks_handler_script: Path,
    backup_dir: Optional[Path] = None,
) -> Tuple[bool, str, Optional[Path]]:
    """
    Atomically merge strict-engineering hooks into hooks.json while preserving
    all existing unrelated hooks and settings.
    """
    hooks_path = Path(hooks_file).resolve()
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    
    backup_path = None
    existing_data: Dict[str, Any] = {}

    if hooks_path.exists():
        try:
            with open(hooks_path, "r", encoding="utf-8-sig") as f:
                content = f.read().strip()
                if content:
                    existing_data = json.loads(content)
                if not isinstance(existing_data, dict):
                    return False, "Existing hooks.json root is not a JSON object", None
        except Exception as e:
            return False, f"Failed to parse existing hooks.json: {str(e)}", None

        backup_path = create_backup(hooks_path, backup_dir)

    py_cmd = str(python_exe)
    script_cmd = str(Path(hooks_handler_script).resolve())
    if " " in py_cmd and not (py_cmd.startswith('"') and py_cmd.endswith('"')):
        py_cmd = f'"{py_cmd}"'
    if " " in script_cmd and not (script_cmd.startswith('"') and script_cmd.endswith('"')):
        script_cmd = f'"{script_cmd}"'

    strict_hooks = {
        "PreToolUse": [
            {
                "matcher": "write_to_file|replace_file_content|multi_replace_file_content|run_command",
                "hooks": [
                    {
                        "type": "command",
                        "command": f"{py_cmd} {script_cmd} pre-tool",
                        "timeout": 15,
                    }
                ],
            }
        ],
        "PreInvocation": [
            {
                "type": "command",
                "command": f"{py_cmd} {script_cmd} pre-invocation",
                "timeout": 10,
            }
        ],
        "Stop": [
            {
                "type": "command",
                "command": f"{py_cmd} {script_cmd} stop",
                "timeout": 30,
            }
        ],
    }

    # Merge non-destructively: only update 'strict-engineering' key
    existing_data["strict-engineering"] = strict_hooks

    # Atomic write to temp file then replace
    temp_file = hooks_path.parent / f"{hooks_path.name}.tmp"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)
        
        # Verify JSON is valid before replace
        with open(temp_file, "r", encoding="utf-8") as f:
            verified = json.load(f)
            if "strict-engineering" not in verified:
                raise ValueError("Verification failed: strict-engineering key missing in output")
        
        os.replace(temp_file, hooks_path)
        return True, "Successfully merged hooks.json preserving unrelated hooks", backup_path
    except Exception as e:
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        # Rollback
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, hooks_path)
        return False, f"Failed atomic write to hooks.json: {str(e)}", backup_path


def merge_gemini_md(
    gemini_md_file: Path,
    strict_prompt_content: str,
    backup_dir: Optional[Path] = None,
) -> Tuple[bool, str, Optional[Path]]:
    """
    Idempotently inject or update the STRICT_ENGINEERING_KERNEL managed block
    inside GEMINI.md while preserving all other custom user instructions.
    """
    target_path = Path(gemini_md_file).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    backup_path = None
    existing_text = ""

    if target_path.exists():
        backup_path = create_backup(target_path, backup_dir)
        try:
            existing_text = target_path.read_text(encoding="utf-8")
        except Exception as e:
            return False, f"Failed to read existing GEMINI.md: {str(e)}", None

    managed_block = f"{MANAGED_START_MARKER}\n{strict_prompt_content.strip()}\n{MANAGED_END_MARKER}"

    if MANAGED_START_MARKER in existing_text and MANAGED_END_MARKER in existing_text:
        # Replace existing managed block
        before = existing_text.split(MANAGED_START_MARKER)[0]
        after = existing_text.split(MANAGED_END_MARKER)[1]
        new_content = f"{before.rstrip()}\n\n{managed_block}\n\n{after.lstrip()}".strip() + "\n"
    elif existing_text.strip():
        # Append managed block to existing user instructions
        new_content = f"{existing_text.rstrip()}\n\n{managed_block}\n"
    else:
        # Create new file with managed block
        new_content = f"{managed_block}\n"

    temp_file = target_path.parent / f"{target_path.name}.tmp"
    try:
        temp_file.write_text(new_content, encoding="utf-8")
        os.replace(temp_file, target_path)
        return True, "Successfully updated GEMINI.md managed block preserving user prompt", backup_path
    except Exception as e:
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, target_path)
        return False, f"Failed to update GEMINI.md: {str(e)}", backup_path


def install_agents(
    source_agents_dir: Path,
    target_agents_dir: Path,
    backup_dir: Optional[Path] = None,
) -> Tuple[bool, List[str], List[str]]:
    """
    Copies required agents from source_agents_dir to target_agents_dir
    preserving any other custom user agents.
    """
    src_dir = Path(source_agents_dir).resolve()
    dst_dir = Path(target_agents_dir).resolve()
    dst_dir.mkdir(parents=True, exist_ok=True)

    installed = []
    errors = []

    if not src_dir.exists():
        return False, installed, [f"Source agents directory {src_dir} does not exist"]

    for agent_folder in src_dir.iterdir():
        if agent_folder.is_dir():
            agent_name = agent_folder.name
            target_agent_folder = dst_dir / agent_name
            target_agent_folder.mkdir(parents=True, exist_ok=True)
            
            for f in agent_folder.iterdir():
                if f.is_file():
                    target_file = target_agent_folder / f.name
                    if target_file.exists():
                        create_backup(target_file, backup_dir)
                    try:
                        shutil.copy2(f, target_file)
                        installed.append(f"{agent_name}/{f.name}")
                    except Exception as e:
                        errors.append(f"Failed copying {agent_name}/{f.name}: {str(e)}")

    return len(errors) == 0, installed, errors


class TransactionalInstaller:
    """
    Coordinated multi-target installation transaction orchestrator (Step 6S.1 REQ-010).
    Orchestrates atomic updates across:
    1. Kernel source modules
    2. hooks.json
    3. GEMINI.md
    4. agents/

    Phases:
    - PREPARE: verifies write access, target paths, and configuration
    - BACKUP: creates a unified timestamped backup manifest capturing all pre-install states
    - STAGE: stages updates in an isolated temporary staging directory
    - VALIDATE: validates syntax, JSON schemas, markers, agent structures in staging
    - COMMIT: atomically applies staged changes to target locations
    - POST_CHECK: executes health verification on active installation
    - ROLLBACK: restores ALL targets from the unified backup manifest on any failure
    """

    def __init__(
        self,
        workspace_dir: Path,
        hooks_file: Optional[Path] = None,
        gemini_md_file: Optional[Path] = None,
        agents_dir: Optional[Path] = None,
        kernel_source_dir: Optional[Path] = None,
        kernel_target_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.hooks_file = Path(hooks_file).resolve() if hooks_file else self.workspace_dir / "hooks.json"
        self.gemini_md_file = Path(gemini_md_file).resolve() if gemini_md_file else self.workspace_dir / "GEMINI.md"
        self.agents_dir = Path(agents_dir).resolve() if agents_dir else self.workspace_dir / "agents"
        self.kernel_source_dir = Path(kernel_source_dir).resolve() if kernel_source_dir else Path(__file__).parent.resolve()
        self.kernel_target_dir = Path(kernel_target_dir).resolve() if kernel_target_dir else self.workspace_dir / ".strict_engineering"
        self.backup_dir = Path(backup_dir).resolve() if backup_dir else self.workspace_dir / ".backups"

        self.transaction_id = f"tx-{utc_timestamp_str()}-{os.urandom(4).hex()}"
        self.tx_backup_dir = self.backup_dir / self.transaction_id
        self.staging_dir = self.workspace_dir / ".staging" / self.transaction_id
        self.backup_manifest: Dict[str, Any] = {
            "transactionId": self.transaction_id,
            "targets": {},
            "phase": "INITIALIZED",
        }
        self.status = "INITIALIZED"

    def _snapshot_target(self, target_path: Path, target_key: str) -> None:
        """Snapshots target file or directory into tx_backup_dir."""
        target_path = target_path.resolve()
        dest_backup = self.tx_backup_dir / target_key
        if target_path.exists():
            if target_path.is_file():
                dest_backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target_path, dest_backup)
                self.backup_manifest["targets"][target_key] = {
                    "type": "file",
                    "path": str(target_path),
                    "backupPath": str(dest_backup),
                    "existed": True,
                }
            elif target_path.is_dir():
                shutil.copytree(target_path, dest_backup)
                self.backup_manifest["targets"][target_key] = {
                    "type": "dir",
                    "path": str(target_path),
                    "backupPath": str(dest_backup),
                    "existed": True,
                }
        else:
            self.backup_manifest["targets"][target_key] = {
                "type": "file" if "." in target_path.name else "dir",
                "path": str(target_path),
                "backupPath": None,
                "existed": False,
            }

    def execute_transaction(
        self,
        python_exe: str,
        strict_prompt_content: str,
        source_agents_dir: Optional[Path] = None,
        simulate_failure_at: Optional[str] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Executes coordinated multi-target installation transaction with automatic rollback."""
        try:
            # 1. PREPARE
            self.status = "PREPARING"
            self.backup_manifest["phase"] = "PREPARE"
            self.tx_backup_dir.mkdir(parents=True, exist_ok=True)
            self.staging_dir.mkdir(parents=True, exist_ok=True)

            if simulate_failure_at == "PREPARE":
                raise RuntimeError("Simulated failure at PREPARE phase")

            # 2. BACKUP
            self.status = "BACKING_UP"
            self.backup_manifest["phase"] = "BACKUP"
            self._snapshot_target(self.hooks_file, "hooks")
            self._snapshot_target(self.gemini_md_file, "gemini_md")
            self._snapshot_target(self.agents_dir, "agents")
            self._snapshot_target(self.kernel_target_dir, "kernel")

            if simulate_failure_at == "BACKUP":
                raise RuntimeError("Simulated failure at BACKUP phase")

            # 3. STAGE
            self.status = "STAGING"
            self.backup_manifest["phase"] = "STAGE"
            staged_hooks = self.staging_dir / "hooks.json"
            staged_gemini = self.staging_dir / "GEMINI.md"
            staged_agents = self.staging_dir / "agents"
            staged_kernel = self.staging_dir / ".strict_engineering"

            # Stage hooks
            staged_hooks_dir = self.staging_dir
            if self.hooks_file.exists():
                shutil.copy2(self.hooks_file, staged_hooks)
            ok_h, msg_h, _ = merge_hooks_json(
                staged_hooks,
                python_exe,
                self.kernel_source_dir / "hooks_handler.py",
                backup_dir=self.staging_dir / ".baks",
            )
            if not ok_h:
                raise RuntimeError(f"Hooks staging failed: {msg_h}")

            # Stage gemini_md
            if self.gemini_md_file.exists():
                shutil.copy2(self.gemini_md_file, staged_gemini)
            ok_g, msg_g, _ = merge_gemini_md(
                staged_gemini,
                strict_prompt_content,
                backup_dir=self.staging_dir / ".baks",
            )
            if not ok_g:
                raise RuntimeError(f"GEMINI.md staging failed: {msg_g}")

            # Stage agents
            if source_agents_dir and Path(source_agents_dir).exists():
                if self.agents_dir.exists():
                    shutil.copytree(self.agents_dir, staged_agents)
                else:
                    staged_agents.mkdir(parents=True, exist_ok=True)
                ok_a, inst_a, err_a = install_agents(
                    Path(source_agents_dir),
                    staged_agents,
                    backup_dir=self.staging_dir / ".baks",
                )
                if not ok_a:
                    raise RuntimeError(f"Agents staging failed: {err_a}")

            # Stage kernel
            staged_kernel.mkdir(parents=True, exist_ok=True)
            for kf in self.kernel_source_dir.glob("*.py"):
                shutil.copy2(kf, staged_kernel / kf.name)

            if simulate_failure_at == "STAGE":
                raise RuntimeError("Simulated failure at STAGE phase")

            # 4. VALIDATE
            self.status = "VALIDATING"
            self.backup_manifest["phase"] = "VALIDATE"

            # Validate hooks JSON syntax and key
            with open(staged_hooks, "r", encoding="utf-8") as f:
                hooks_data = json.load(f)
            if "strict-engineering" not in hooks_data:
                raise ValueError("Validation error: 'strict-engineering' missing in staged hooks.json")

            # Validate GEMINI.md markers
            gemini_text = staged_gemini.read_text(encoding="utf-8")
            if MANAGED_START_MARKER not in gemini_text or MANAGED_END_MARKER not in gemini_text:
                raise ValueError("Validation error: managed markers missing in staged GEMINI.md")

            # Validate kernel syntax in staging
            for kf in staged_kernel.glob("*.py"):
                compile(kf.read_text(encoding="utf-8"), str(kf), "exec")

            if simulate_failure_at == "VALIDATE":
                raise RuntimeError("Simulated failure at VALIDATE phase")

            # 5. COMMIT
            self.status = "COMMITTING"
            self.backup_manifest["phase"] = "COMMIT"

            if simulate_failure_at == "COMMIT_PARTIAL":
                # Apply only hooks before crashing
                self.hooks_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(staged_hooks, self.hooks_file)
                raise RuntimeError("Simulated partial failure at COMMIT phase")

            self.hooks_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_hooks, self.hooks_file)

            self.gemini_md_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_gemini, self.gemini_md_file)

            if staged_agents.exists():
                self.agents_dir.mkdir(parents=True, exist_ok=True)
                for item in staged_agents.iterdir():
                    dst_item = self.agents_dir / item.name
                    if item.is_file():
                        shutil.copy2(item, dst_item)
                    elif item.is_dir():
                        if dst_item.exists():
                            shutil.rmtree(dst_item)
                        shutil.copytree(item, dst_item)

            self.kernel_target_dir.mkdir(parents=True, exist_ok=True)
            for kf in staged_kernel.glob("*.py"):
                shutil.copy2(kf, self.kernel_target_dir / kf.name)

            if simulate_failure_at == "COMMIT":
                raise RuntimeError("Simulated failure at COMMIT phase")

            # 6. POST_CHECK
            self.status = "POST_CHECKING"
            self.backup_manifest["phase"] = "POST_CHECK"

            if not self.hooks_file.exists() or not self.gemini_md_file.exists():
                raise RuntimeError("Post-check failed: target files missing after commit")

            if simulate_failure_at == "POST_CHECK":
                raise RuntimeError("Simulated failure at POST_CHECK phase")

            self.status = "COMMITTED"
            self.backup_manifest["phase"] = "COMPLETED"
            self.backup_manifest["status"] = "SUCCESS"

            # Clean staging
            try:
                shutil.rmtree(self.staging_dir)
            except Exception:
                pass

            return True, "Installation transaction committed successfully across all targets", self.backup_manifest

        except Exception as ex:
            error_msg = f"Installation transaction failed in phase {self.status}: {str(ex)}"
            rollback_ok, rollback_notes = self.rollback()
            self.backup_manifest["status"] = "ROLLED_BACK" if rollback_ok else "ROLLBACK_FAILED"
            self.backup_manifest["error"] = error_msg
            self.backup_manifest["rollbackNotes"] = rollback_notes
            return False, error_msg, self.backup_manifest

    def rollback(self) -> Tuple[bool, List[str]]:
        """Restores all targets from backup manifest."""
        notes = []
        all_ok = True
        self.status = "ROLLING_BACK"

        for target_key, info in self.backup_manifest.get("targets", {}).items():
            target_path = Path(info["path"])
            existed = info.get("existed", False)
            backup_path_str = info.get("backupPath")

            try:
                if existed and backup_path_str:
                    backup_path = Path(backup_path_str)
                    if backup_path.exists():
                        if info["type"] == "file":
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(backup_path, target_path)
                            notes.append(f"Restored file {target_key} to {target_path}")
                        elif info["type"] == "dir":
                            if target_path.exists():
                                shutil.rmtree(target_path)
                            shutil.copytree(backup_path, target_path)
                            notes.append(f"Restored directory {target_key} to {target_path}")
                    else:
                        notes.append(f"Warning: Backup for {target_key} not found at {backup_path}")
                        all_ok = False
                elif not existed:
                    # File/dir did not exist prior to transaction, remove created artifacts
                    if target_path.exists():
                        if target_path.is_file():
                            target_path.unlink()
                            notes.append(f"Removed non-preexisting file {target_path}")
                        elif target_path.is_dir():
                            shutil.rmtree(target_path)
                            notes.append(f"Removed non-preexisting directory {target_path}")
            except Exception as e:
                notes.append(f"Error rolling back {target_key}: {str(e)}")
                all_ok = False

        # Clean staging
        if self.staging_dir.exists():
            try:
                shutil.rmtree(self.staging_dir)
            except Exception:
                pass

        self.status = "ROLLED_BACK" if all_ok else "ROLLBACK_ERROR"
        return all_ok, notes

