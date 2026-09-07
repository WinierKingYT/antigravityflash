#!/usr/bin/env python3
"""
Strict Engineering Kernel Installer Entrypoint
"""

import sys
import shutil
from pathlib import Path

# Add src to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from strict_engineering import installer


def main():
    gemini_dir = Path.home() / ".gemini"
    python_exe = sys.executable

    print("==========================================================")
    print(" Installing Antigravity Strict Engineering Kernel V1.0.1")
    print("==========================================================")
    print(f"Target Gemini Directory: {gemini_dir}")
    print(f"Using Python Executable: {python_exe}")

    target_config_dir = gemini_dir / "config" / "strict-engineering"
    target_config_dir.mkdir(parents=True, exist_ok=True)

    # 1. Copy modules
    src_dir = root_dir / "src" / "strict_engineering"
    for f in src_dir.glob("*.py"):
        shutil.copy2(f, target_config_dir / f.name)
    print(f"[OK] Modules copied to {target_config_dir}")

    # 2. Merge hooks.json non-destructively
    hooks_file = gemini_dir / "config" / "hooks.json"
    handler_script = target_config_dir / "hooks_handler.py"
    ok, msg, bak = installer.merge_hooks_json(hooks_file, python_exe, handler_script)
    if ok:
        print(f"[OK] {msg}")
    else:
        print(f"[ERROR] {msg}")
        sys.exit(1)

    # 3. Merge GEMINI.md managed block
    gemini_md_file = gemini_dir / "GEMINI.md"
    src_gemini_md = root_dir / "GEMINI.md"
    if src_gemini_md.exists():
        prompt_content = src_gemini_md.read_text(encoding="utf-8")
        ok, msg, bak = installer.merge_gemini_md(gemini_md_file, prompt_content)
        if ok:
            print(f"[OK] {msg}")
        else:
            print(f"[ERROR] {msg}")
            sys.exit(1)

    # 4. Install agents non-destructively
    src_agents = root_dir / "agents"
    target_agents = gemini_dir / "config" / "agents"
    if src_agents.exists():
        ok, installed, errs = installer.install_agents(src_agents, target_agents)
        if ok:
            print(f"[OK] Installed {len(installed)} agent definitions into {target_agents}")
        else:
            print(f"[ERROR] Failed installing agents: {', '.join(errs)}")
            sys.exit(1)

    print("\n[SUCCESS] Antigravity Strict Engineering Kernel V1.0.1 successfully installed!")


if __name__ == "__main__":
    main()
