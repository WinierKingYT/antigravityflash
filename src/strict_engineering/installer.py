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
            with open(hooks_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    existing_data = json.loads(content)
                if not isinstance(existing_data, dict):
                    return False, "Existing hooks.json root is not a JSON object", None
        except Exception as e:
            return False, f"Failed to parse existing hooks.json: {str(e)}", None

        backup_path = create_backup(hooks_path, backup_dir)

    escaped_python = str(python_exe).replace("\\", "\\\\")
    escaped_script = str(Path(hooks_handler_script).resolve()).replace("\\", "\\\\")

    strict_hooks = {
        "PreToolUse": [
            {
                "matcher": "write_to_file|replace_file_content|multi_replace_file_content|run_command",
                "hooks": [
                    {
                        "type": "command",
                        "command": f"{escaped_python} {escaped_script} pre-tool",
                        "timeout": 15,
                    }
                ],
            }
        ],
        "PreInvocation": [
            {
                "type": "command",
                "command": f"{escaped_python} {escaped_script} pre-invocation",
                "timeout": 10,
            }
        ],
        "Stop": [
            {
                "type": "command",
                "command": f"{escaped_python} {escaped_script} stop",
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
