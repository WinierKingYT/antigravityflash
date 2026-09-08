"""
Strict Engineering Kernel V1.2.2 - Operational CLI, Distribution & Project UX
Provides the unified command-line entrypoint `strict-engineering` for:
- version
- install
- init
- status
- doctor
- pause
- resume
- enable
- disable
- update
- rollback
- uninstall
"""

import os
import sys
import json
import shutil
import hashlib
import platform
import argparse
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from . import __version__
except (ImportError, ValueError):
    try:
        import strict_engineering
        __version__ = strict_engineering.__version__
    except Exception:
        __version__ = "1.2.2"

try:
    from . import kernel
    from . import gate
    from . import installer
    from . import runtime_safety
    from . import context_registry
    from . import distribution
    from . import observability
    from . import concern
except (ImportError, ValueError):
    import kernel  # type: ignore
    import gate  # type: ignore
    import installer  # type: ignore
    import runtime_safety  # type: ignore
    import context_registry  # type: ignore
    import distribution  # type: ignore
    import observability  # type: ignore
    import concern  # type: ignore


# ---------------------------------------------------------------------------
# Exit Codes
# ---------------------------------------------------------------------------
EXIT_SUCCESS = 0
EXIT_OPERATIONAL_FAILURE = 1
EXIT_INVALID_USAGE = 2
EXIT_HARNESS_BLOCKED = 3


def get_default_gemini_dir() -> Path:
    return Path.home() / ".gemini"


# ---------------------------------------------------------------------------
# Command: version
# ---------------------------------------------------------------------------
def cmd_version(args: argparse.Namespace) -> int:
    """Display kernel version, Python version, and global installation status."""
    gemini_dir = get_default_gemini_dir()
    hooks_file = gemini_dir / "config" / "hooks.json"
    modules_dir = gemini_dir / "config" / "strict-engineering"
    gemini_md = gemini_dir / "GEMINI.md"
    agents_dir = gemini_dir / "config" / "agents"

    # Modules check
    if modules_dir.exists() and any(modules_dir.glob("*.py")):
        mod_count = len(list(modules_dir.glob("*.py")))
        modules_status = f"INSTALLED ({mod_count} modules at {modules_dir})"
    else:
        modules_status = f"NOT_INSTALLED (directory {modules_dir} missing or empty)"

    # Hooks check
    hook_state, hook_detail = installer.get_hooks_status(hooks_file)

    # GEMINI.md managed block check
    if gemini_md.exists():
        text = gemini_md.read_text(encoding="utf-8", errors="ignore")
        if (
            installer.MANAGED_START_MARKER in text
            and installer.MANAGED_END_MARKER in text
        ):
            gemini_status = "INSTALLED (managed block present)"
        else:
            gemini_status = "PARTIAL (file exists, managed block missing)"
    else:
        gemini_status = "NOT_INSTALLED (file missing)"

    # Agents check
    if agents_dir.exists() and any(agents_dir.iterdir()):
        agent_names = [d.name for d in agents_dir.iterdir() if d.is_dir()]
        agents_status = f"INSTALLED ({len(agent_names)} agents: {', '.join(sorted(agent_names)[:5])}{'...' if len(agent_names) > 5 else ''})"
    else:
        agents_status = "NOT_INSTALLED"

    # Manifest check
    manifest = distribution.load_installation_manifest(gemini_dir)
    if manifest:
        m_ver = manifest.get("version", "unknown")
        m_health = manifest.get("installationHealth", "HEALTHY")
        m_mods = len(manifest.get("managedFiles", {}).get("modules", {}))
        manifest_status = f"V{m_ver} ({m_health}, tracking {m_mods} modules)"
    else:
        manifest_status = "NOT_FOUND"

    print("==========================================================")
    print(f" Antigravity Strict Engineering Kernel V{__version__}")
    print("==========================================================")
    print(f"Kernel Version:             {__version__}")
    print(f"Python Version:             {platform.python_version()} ({sys.executable})")
    print(f"Global Modules:             {modules_status}")
    print(f"Global Hooks ({hook_state}): {hook_detail}")
    print(f"GEMINI Managed Block:       {gemini_status}")
    print(f"Agent Definitions:          {agents_status}")
    print(f"Installation Manifest:      {manifest_status}")
    print("==========================================================")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Command: install
# ---------------------------------------------------------------------------
def cmd_install(args: argparse.Namespace) -> int:
    """Wrap canonical installer with concise checks."""
    gemini_dir = get_default_gemini_dir()
    python_exe = sys.executable

    # Find repository root / source files
    src_dir = Path(__file__).resolve().parent
    repo_root = src_dir.parent.parent

    target_config_dir = gemini_dir / "config" / "strict-engineering"
    target_config_dir.mkdir(parents=True, exist_ok=True)

    print("==========================================================")
    print(f" Installing Antigravity Strict Engineering Kernel V{__version__}")
    print("==========================================================")
    print(f"Target Gemini Directory: {gemini_dir}")
    print(f"Using Python Executable: {python_exe}")

    # 1. Copy modules
    copied_count = 0
    for f in src_dir.glob("*.py"):
        shutil.copy2(f, target_config_dir / f.name)
        copied_count += 1
    print(f"[OK] Kernel modules: copied {copied_count} modules to {target_config_dir}")

    # 2. Merge hooks.json non-destructively
    hooks_file = gemini_dir / "config" / "hooks.json"
    handler_script = target_config_dir / "hooks_handler.py"
    ok, msg, _ = installer.merge_hooks_json(hooks_file, python_exe, handler_script)
    if not ok:
        print(f"[FAIL] Hooks configuration failed: {msg}")
        return EXIT_OPERATIONAL_FAILURE
    print(f"[OK] PreToolUse hook: registered in {hooks_file}")
    print(f"[OK] PreInvocation hook: registered in {hooks_file}")
    print(f"[OK] Stop hook: registered in {hooks_file}")

    # 3. Merge GEMINI.md managed block
    gemini_md_file = gemini_dir / "GEMINI.md"
    candidate_roots = [
        Path.cwd(),
        src_dir.parent.parent,
        src_dir.parent,
        src_dir,
    ]
    src_gemini_md = None
    for cr in candidate_roots:
        if (cr / "GEMINI.md").exists():
            src_gemini_md = cr / "GEMINI.md"
            break

    if src_gemini_md and src_gemini_md.exists():
        prompt_content = src_gemini_md.read_text(encoding="utf-8")
    else:
        # Default canonical managed rules fallback
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

    ok, msg, _ = installer.merge_gemini_md(gemini_md_file, prompt_content)
    if not ok:
        print(f"[FAIL] GEMINI.md managed block failed: {msg}")
        return EXIT_OPERATIONAL_FAILURE
    print(f"[OK] GEMINI managed block: injected into {gemini_md_file}")

    # 4. Install agents non-destructively
    src_agents = None
    for cr in candidate_roots:
        if (cr / "agents").exists() and (cr / "agents").is_dir():
            src_agents = cr / "agents"
            break

    target_agents = gemini_dir / "config" / "agents"
    if src_agents and src_agents.exists():
        ok, installed_list, errs = installer.install_agents(src_agents, target_agents)
        if not ok:
            print(f"[FAIL] Failed installing agents: {', '.join(errs)}")
            return EXIT_OPERATIONAL_FAILURE
        print(f"[OK] Agent definitions: installed {len(installed_list)} definitions into {target_agents}")
    elif target_agents.exists() and any(target_agents.iterdir()):
        existing_agents = len([d for d in target_agents.iterdir() if d.is_dir()])
        print(f"[OK] Agent definitions: preserved {existing_agents} existing definitions in {target_agents}")
    else:
        print(f"[WARN] Source agents folder not found; skipping agent install")

    # 5. Generate and save canonical installation manifest
    target_manifest = distribution.generate_installation_manifest(
        modules_dir=target_config_dir,
        hooks_file=hooks_file,
        gemini_md_file=gemini_md_file,
        agents_dir=target_agents,
        version=__version__,
        install_source=str(repo_root),
    )
    manifest_file = distribution.save_installation_manifest(target_manifest, gemini_dir=gemini_dir)
    print(f"[OK] Installation manifest: saved to {manifest_file} (tracking {len(target_manifest.get('managedFiles', {}).get('modules', {}))} modules)")

    # 6. Global configuration
    config = distribution.load_global_config(gemini_dir=gemini_dir)
    distribution.save_global_config(config, gemini_dir=gemini_dir)
    print(f"[OK] Global configuration: verified at {target_config_dir / 'config.json'}")

    # 7. Observability log
    observability.record_global_event(
        "INSTALL_COMPLETED",
        {"version": __version__, "modulesCount": copied_count},
        gemini_dir=gemini_dir,
    )

    print(f"\n[SUCCESS] Antigravity Strict Engineering Kernel V{__version__} successfully installed!")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Command: init
# ---------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    """Initialize project harness with strict intent integrity."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    print(f"Initializing Strict Engineering in: {workspace}")

    # Detect Git repository
    git_dir = workspace / ".git"
    is_git = git_dir.exists()
    if is_git:
        try:
            res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(workspace),
                capture_output=True,
                text=True,
                check=False,
            )
            dirty_lines = [l for l in res.stdout.strip().splitlines() if l.strip()]
            if dirty_lines:
                print(f"[WARN] Workspace has {len(dirty_lines)} uncommitted change(s) (dirty Git state)")
        except Exception:
            pass
    else:
        print("[WARN] Target directory is not a Git repository")

    # Check existing harness
    harness_dir = workspace / ".agent-harness"
    state_file = harness_dir / "state.json"
    if harness_dir.exists() and state_file.exists():
        print(
            f"[BLOCKED] Strict Engineering harness already exists in {workspace}.\n"
            f"Initialization aborted to protect existing project truth.\n"
            f"Use 'strict-engineering status' to inspect current project state.\n"
            f"If you intentionally want a new engineering project, manually archive or remove .agent-harness outside the kernel."
        )
        return EXIT_HARNESS_BLOCKED

    # Determine intent without fabricating synthetic text
    intent = args.intent
    if not intent:
        if getattr(args, "await_intent", False):
            intent = ""
        elif sys.stdin.isatty():
            try:
                entered = input("Enter original project intent: ").strip()
                if entered:
                    intent = entered
            except (KeyboardInterrupt, EOFError):
                print("\n[ABORTED] Initialization cancelled by user.")
                return EXIT_INVALID_USAGE

    if not intent:
        if getattr(args, "await_intent", False):
            # Safe awaiting-intent state
            harness_dir.mkdir(parents=True, exist_ok=True)
            initial_state = {
                "active": True,
                "schemaVersion": "5.1.0",
                "phase": "AWAITING_INTENT",
                "runtimeStatus": "RUNNING",
                "pauseReason": None,
                "specLocked": False,
                "acceptanceLocked": False,
                "originalRequestSha256": None,
                "workspaceFingerprint": None,
                "activeTask": None,
                "builderSubagentActive": False,
                "finalAuditPassed": False,
                "createdAt": kernel.utc_now_iso(),
                "updatedAt": kernel.utc_now_iso(),
            }
            kernel.save_state(workspace, initial_state)
            kernel.save_requirements(workspace, [])
            print(f"[OK] Harness initialized in safe 'AWAITING_INTENT' state at {workspace}")
            return EXIT_SUCCESS
        else:
            print(
                "[ERROR] No project intent provided.\n"
                "To preserve requirement integrity, the kernel refuses to invent synthetic user intent.\n"
                "Please run:\n"
                "    strict-engineering init --intent \"<describe your project goal>\"\n"
                "or pass --await-intent to initialize in an idle state."
            )
            return EXIT_INVALID_USAGE

    # Initialize with verified user intent
    state = kernel.initialize_harness(workspace, original_intent=intent.strip())
    print(f"[OK] Strict Engineering Harness initialized successfully!")
    print(f"     Workspace:   {workspace}")
    print(f"     Phase:       {state.get('phase')}")
    print(f"     Intent SHA:  {state.get('originalRequestSha256')}")
    print(f"     Status:      RUNNING")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Command: status
# ---------------------------------------------------------------------------
def cmd_status(args: argparse.Namespace) -> int:
    """Read-only operational status check."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    gemini_dir = get_default_gemini_dir()
    hooks_file = gemini_dir / "config" / "hooks.json"
    harness_dir = workspace / ".agent-harness"
    state_file = harness_dir / "state.json"

    # Global hooks status
    global_hook_state, global_hook_detail = installer.get_hooks_status(hooks_file)

    if not state_file.exists():
        if getattr(args, "json", False):
            print(json.dumps({
                "active": False,
                "workspace": str(workspace),
                "status": "INACTIVE",
                "globalHooks": global_hook_state,
            }, indent=2))
        else:
            print("==========================================================")
            print(f" Strict Engineering Status: INACTIVE")
            print(f" Project:      {workspace.name} ({workspace})")
            print(f" Harness:      No .agent-harness directory found")
            print(f" Global Hooks: {global_hook_state} ({global_hook_detail})")
            print(f" To start:     strict-engineering init --intent \"<goal>\"")
            print("==========================================================")
        return EXIT_SUCCESS

    # Load active harness data
    state = kernel.load_state(workspace)
    requirements = kernel.load_requirements(workspace)
    is_active = bool(state.get("active", False))
    phase = state.get("phase", "UNKNOWN")
    runtime_status = state.get("runtimeStatus", "UNKNOWN")
    pause_reason = state.get("pauseReason")
    spec_locked = bool(state.get("specLocked", False))
    acceptance_locked = bool(state.get("acceptanceLocked", False))

    # Requirements summary
    req_counts: Dict[str, int] = {}
    for r in requirements:
        st = r.get("status", "UNKNOWN")
        req_counts[st] = req_counts.get(st, 0) + 1

    # Blocking concerns check
    concerns_file = harness_dir / "concerns.json"
    blocking_concerns = []
    if concerns_file.exists():
        try:
            with open(concerns_file, "r", encoding="utf-8") as f:
                c_data = json.load(f)
                concerns = c_data if isinstance(c_data, list) else c_data.get("concerns", [])
                for c in concerns:
                    c_status = c.get("status")
                    c_risk = concern.get_concern_risk(c) if hasattr(concern, "get_concern_risk") else (c.get("riskLevel") or c.get("risk"))
                    blocking_states = getattr(concern, "CONCERN_BLOCKING_STATES", {"ACTIVE", "DISCOVERED"})
                    if c_status in blocking_states and c_risk in {"CRITICAL", "HIGH"}:
                        blocking_concerns.append(f"{c.get('id', 'CONCERN')}: {c.get('title', c.get('statement', ''))}")
        except Exception:
            pass

    # Circuit breaker check
    target_conv_raw = getattr(args, "conversation", None)
    target_conv = str(target_conv_raw).strip() if (isinstance(target_conv_raw, str) and target_conv_raw.strip()) else None
    cb_data = runtime_safety.load_circuit_breaker(workspace, conversation_id=target_conv)
    cb_summary = cb_data.get("projectSummary", {})
    if not cb_summary and hasattr(runtime_safety, "get_circuit_breaker_project_summary"):
        cb_summary = runtime_safety.get_circuit_breaker_project_summary(workspace)

    cb_tripped = bool(cb_data.get("tripped", cb_data.get("circuitBreakerTripped", False)))
    cb_consecutive = int(cb_data.get("automaticContinueCount", cb_data.get("consecutiveContinuesWithoutProgress", 0)))
    cb_reason = cb_data.get("tripReason")

    # Evidence count
    evidence_file = harness_dir / "evidence.jsonl"
    evidence_count = 0
    if evidence_file.exists():
        try:
            with open(evidence_file, "r", encoding="utf-8") as f:
                evidence_count = sum(1 for l in f if l.strip())
        except Exception:
            pass

    # Authoritative completion readiness analysis directly from engineering gate
    completion_ready, blocked_reasons = gate.inspect_completion_readiness(workspace)
    if global_hook_state == "DISABLED":
        blocked_reasons.append("Hooks are globally disabled in ~/.gemini/config/hooks.json")
        completion_ready = False

    if target_conv and cb_tripped:
        blocked_reasons.append(f"Circuit breaker is TRIPPED for conversation '{target_conv}': {cb_reason or 'Automatic continue limit exceeded'}")
        completion_ready = False

    non_pass = [r.get("id") for r in requirements if r.get("status") != "PASS"]
    if non_pass and not any("requirement(s) not in PASS status" in r for r in blocked_reasons):
        blocked_reasons.append(f"{len(non_pass)} requirement(s) not in PASS status: {', '.join(str(x) for x in non_pass[:5])}{'...' if len(non_pass) > 5 else ''}")

    # Observability & telemetry
    latency_summary = observability.get_latency_summary(gemini_dir)
    recent_events = observability.load_global_events(limit=5, gemini_dir=gemini_dir)
    last_event = recent_events[-1] if recent_events else None

    cb_dict = {
        "tripped": cb_tripped,
        "consecutiveContinues": cb_consecutive,
        "projectSummary": cb_summary,
    }
    if target_conv:
        cb_dict["conversationId"] = target_conv
        cb_dict["tripReason"] = cb_reason
    else:
        cb_dict["totalConversations"] = cb_summary.get("totalConversations", 0)
        cb_dict["trippedConversationsCount"] = cb_summary.get("trippedConversationsCount", 0)
        cb_dict["trippedConversations"] = cb_summary.get("trippedConversations", [])
        cb_dict["latestConversationId"] = cb_summary.get("latestConversationId")

    data = {
        "active": is_active,
        "workspace": str(workspace),
        "projectName": workspace.name,
        "kernelVersion": __version__,
        "phase": phase,
        "runtimeStatus": runtime_status,
        "pauseReason": pause_reason,
        "globalHooks": global_hook_state,
        "specLocked": spec_locked,
        "acceptanceLocked": acceptance_locked,
        "requirements": req_counts,
        "totalRequirements": len(requirements),
        "evidenceCount": evidence_count,
        "blockingConcerns": blocking_concerns,
        "circuitBreaker": cb_dict,
        "telemetry": {
            "latency": latency_summary,
            "lastEvent": last_event,
        },
        "completionReady": completion_ready,
        "blockedReasons": blocked_reasons,
    }

    if getattr(args, "json", False):
        print(json.dumps(data, indent=2))
        return EXIT_SUCCESS

    print("==========================================================")
    print(f" Strict Engineering Status: {'ACTIVE' if is_active else 'DISABLED'}")
    print("==========================================================")
    print(f"Project:              {workspace.name} ({workspace})")
    print(f"Kernel Version:       {__version__}")
    print(f"Lifecycle Phase:      {phase}")
    print(f"Runtime Status:       {runtime_status}{f' (Reason: {pause_reason})' if pause_reason else ''}")
    print(f"Global Hooks:         {global_hook_state}")
    print(f"Specification:        {'LOCKED' if spec_locked else 'UNLOCKED'}")
    print(f"Acceptance Contracts: {'LOCKED' if acceptance_locked else 'UNLOCKED'}")
    print(f"Evidence Records:     {evidence_count}")
    print(f"Requirements:         Total={len(requirements)} | " + " | ".join(f"{k}: {v}" for k, v in sorted(req_counts.items())))
    if blocking_concerns:
        print(f"Blocking Concerns:    {len(blocking_concerns)}")
        for bc in blocking_concerns[:3]:
            print(f"  - {bc}")
    if target_conv:
        st_label = "TRIPPED" if cb_tripped else "HEALTHY"
        print(f"Circuit Breaker ({target_conv}): {st_label} ({cb_consecutive} continues without progress)")
        if cb_reason:
            print(f"  Trip Reason:        {cb_reason}")
    else:
        tot_convs = cb_summary.get("totalConversations", 0)
        tripped_cnt = cb_summary.get("trippedConversationsCount", 0)
        latest_cid = cb_summary.get("latestConversationId")
        if tripped_cnt > 0:
            print(f"Circuit Breaker:      TRIPPED ({tripped_cnt}/{tot_convs} conversations tripped)")
            print(f"  Tripped Convs:      {', '.join(cb_summary.get('trippedConversations', []))}")
        else:
            print(f"Circuit Breaker:      HEALTHY ({tripped_cnt}/{tot_convs} conversations tripped)")
        if latest_cid:
            print(f"  Latest Conv:        {latest_cid}")
    if latency_summary["count"] > 0:
        print(f"Hook Latency:         p50={latency_summary['p50Ms']}ms, p95={latency_summary['p95Ms']}ms, max={latency_summary['maxMs']}ms ({latency_summary['count']} samples)")
    if last_event:
        print(f"Last Runtime Event:   {last_event.get('eventType')} ({last_event.get('timestamp')})")
    print("----------------------------------------------------------")
    if completion_ready:
        print(f"Completion Readiness: READY TO COMPLETE")
    else:
        print(f"Completion Readiness: BLOCKED")
        for r in blocked_reasons:
            print(f"  * {r}")
    print("==========================================================")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Command: doctor
# ---------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> int:
    """Run comprehensive health checks across 14 categories."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    gemini_dir = get_default_gemini_dir()
    harness_dir = workspace / ".agent-harness"

    checks: List[Dict[str, Any]] = []

    def add_check(category: str, status: str, detail: str, recommendation: Optional[str] = None):
        checks.append({
            "category": category,
            "status": status,
            "detail": detail,
            "recommendation": recommendation,
        })

    # 1. Python compatibility
    py_ver = sys.version_info
    if py_ver >= (3, 11):
        add_check("Python compatibility", "PASS", f"Python {platform.python_version()} (>= 3.11)")
    else:
        add_check("Python compatibility", "FAIL", f"Python {platform.python_version()} is unsupported (requires >= 3.11)", "Upgrade Python to 3.11 or higher.")

    # 2. Global kernel install
    mod_dir = gemini_dir / "config" / "strict-engineering"
    if mod_dir.exists() and any(mod_dir.glob("*.py")):
        add_check("Global kernel install", "PASS", f"Kernel modules present at {mod_dir}")
    else:
        add_check("Global kernel install", "FAIL", f"Kernel modules missing at {mod_dir}", "Run 'strict-engineering install'.")

    # 3. Hook configuration
    hooks_file = gemini_dir / "config" / "hooks.json"
    hook_state, hook_detail = installer.get_hooks_status(hooks_file)
    if hook_state == "ENABLED":
        add_check("Hook configuration", "PASS", hook_detail)
    elif hook_state == "DISABLED":
        add_check("Hook configuration", "WARN", hook_detail, "Run 'strict-engineering enable' to re-activate hooks.")
    else:
        add_check("Hook configuration", "FAIL", hook_detail, "Run 'strict-engineering install' to configure hooks.")

    # 4. Hook target files
    if hooks_file.exists():
        try:
            with open(hooks_file, "r", encoding="utf-8") as f:
                h_data = json.load(f)
            strict_entry = h_data.get("strict-engineering") or h_data.get("_disabled_strict-engineering")
            if strict_entry and isinstance(strict_entry, dict):
                missing_targets = []
                for event, event_hooks in strict_entry.items():
                    if isinstance(event_hooks, list):
                        for item in event_hooks:
                            cmd_str = ""
                            if isinstance(item, dict):
                                cmd_str = item.get("command", "")
                                for sub in item.get("hooks", []):
                                    cmd_str = sub.get("command", "") or cmd_str
                            if "hooks_handler.py" in cmd_str:
                                parts = cmd_str.split()
                                for p in parts:
                                    clean_p = p.strip('\'"')
                                    if clean_p.endswith("hooks_handler.py"):
                                        if not Path(clean_p).exists():
                                            missing_targets.append(clean_p)
                if missing_targets:
                    add_check("Hook target files", "FAIL", f"Missing hook handler scripts: {', '.join(missing_targets)}", "Run 'strict-engineering install' to restore.")
                else:
                    add_check("Hook target files", "PASS", "Hook handler target script exists on disk")
            else:
                add_check("Hook target files", "WARN", "No strict-engineering hooks registered to inspect")
        except Exception as e:
            add_check("Hook target files", "FAIL", f"Error inspecting hooks.json: {e}")
    else:
        add_check("Hook target files", "FAIL", "hooks.json does not exist", "Run 'strict-engineering install'.")

    # 5. GEMINI managed block
    gemini_md = gemini_dir / "GEMINI.md"
    if gemini_md.exists():
        g_text = gemini_md.read_text(encoding="utf-8", errors="ignore")
        if installer.MANAGED_START_MARKER in g_text and installer.MANAGED_END_MARKER in g_text:
            add_check("GEMINI managed block", "PASS", "Managed rules block found in ~/.gemini/GEMINI.md")
        else:
            add_check("GEMINI managed block", "FAIL", "Managed rules block missing in ~/.gemini/GEMINI.md", "Run 'strict-engineering install'.")
    else:
        add_check("GEMINI managed block", "FAIL", "~/.gemini/GEMINI.md does not exist", "Run 'strict-engineering install'.")

    # 6. Agents
    agents_dir = gemini_dir / "config" / "agents"
    if agents_dir.exists():
        expected_agents = {"builder", "spec-architect", "test-oracle", "final-verifier"}
        found_agents = {d.name for d in agents_dir.iterdir() if d.is_dir()}
        missing = expected_agents - found_agents
        if not missing:
            add_check("Agents", "PASS", f"Required agents installed ({len(found_agents)} agents present)")
        else:
            add_check("Agents", "WARN", f"Missing core agents: {', '.join(missing)}", "Run 'strict-engineering install'.")
    else:
        add_check("Agents", "FAIL", "Agents directory ~/.gemini/config/agents does not exist", "Run 'strict-engineering install'.")

    # 7. Version drift
    installed_init = mod_dir / "__init__.py"
    if installed_init.exists():
        try:
            content = installed_init.read_text(encoding="utf-8")
            import re
            m = re.search(r'__version__\s*=\s*"([^"]+)"', content)
            if m:
                inst_ver = m.group(1)
                if inst_ver == __version__:
                    add_check("Version drift", "PASS", f"Installed version matches package version ({__version__})")
                else:
                    add_check("Version drift", "WARN", f"Installed version {inst_ver} differs from package version {__version__}", "Run 'strict-engineering install' to update installed files.")
            else:
                add_check("Version drift", "WARN", "Could not parse __version__ from installed modules")
        except Exception as e:
            add_check("Version drift", "WARN", f"Failed to check installed version: {e}")
    else:
        add_check("Version drift", "NOT_APPLICABLE", "Global modules not installed")

    # 8. Project harness integrity
    if harness_dir.exists():
        state_file = harness_dir / "state.json"
        req_file = harness_dir / "requirements.json"
        orig_file = harness_dir / "original-request.md"
        sha_file = harness_dir / "original-request.sha256"
        missing_files = []
        for name, p in [("state.json", state_file), ("requirements.json", req_file), ("original-request.md", orig_file), ("original-request.sha256", sha_file)]:
            if not p.exists():
                missing_files.append(name)
        if missing_files:
            add_check("Project harness integrity", "FAIL", f"Missing core harness artifacts: {', '.join(missing_files)}", "Reinitialize or repair harness.")
        else:
            add_check("Project harness integrity", "PASS", "All core harness files present in .agent-harness")
    else:
        add_check("Project harness integrity", "NOT_APPLICABLE", "Current workspace has no .agent-harness directory")

    # 9. State/evidence integrity
    if harness_dir.exists():
        orig_ok = kernel.verify_original_intent_integrity(workspace)
        if orig_ok:
            add_check("State/evidence integrity", "PASS", "original-request.md matches SHA-256 digest")
        else:
            add_check("State/evidence integrity", "FAIL", "original-request.md SHA-256 digest verification failed (tampering detected)", "Restore authentic original request.")
    else:
        add_check("State/evidence integrity", "NOT_APPLICABLE", "No active harness in workspace")

    # 10. Context registry
    if harness_dir.exists():
        reg_ok, reg_errors = context_registry.verify_context_registry(workspace)
        if reg_ok:
            add_check("Context registry", "PASS", "Context registry integrity verified")
        else:
            add_check("Context registry", "WARN", f"Context registry has {len(reg_errors)} warning(s)")
    else:
        add_check("Context registry", "NOT_APPLICABLE", "No active harness in workspace")

    # 11. Runtime/circuit breaker anomalies
    if harness_dir.exists():
        cb_data = runtime_safety.load_circuit_breaker(workspace)
        tripped = bool(cb_data.get("tripped", cb_data.get("circuitBreakerTripped", False)))
        if tripped:
            add_check("Runtime/circuit breaker", "WARN", "Circuit breaker is currently TRIPPED", "Run 'strict-engineering resume' after resolving blockers.")
        else:
            consec = int(cb_data.get("automaticContinueCount", cb_data.get("consecutiveContinuesWithoutProgress", 0)))
            add_check("Runtime/circuit breaker", "PASS", f"Circuit breaker normal ({consec} consecutive continues)")
    else:
        add_check("Runtime/circuit breaker", "NOT_APPLICABLE", "No active harness in workspace")

    # 12. Git repository
    is_git = (workspace / ".git").exists()
    if is_git:
        add_check("Git repository", "PASS", f"Git repository detected at {workspace}")
    else:
        add_check("Git repository", "WARN", "Workspace is not a Git repository", "Initialize git with 'git init'.")

    # 13. Dirty workspace
    if is_git:
        try:
            res = subprocess.run(["git", "status", "--porcelain"], cwd=str(workspace), capture_output=True, text=True, check=False)
            dirty_lines = [l for l in res.stdout.strip().splitlines() if l.strip()]
            if dirty_lines:
                add_check("Dirty workspace", "WARN", f"{len(dirty_lines)} uncommitted file(s) in workspace", "Commit or stash changes before initiating major phases.")
            else:
                add_check("Dirty workspace", "PASS", "Workspace is clean")
        except Exception as e:
            add_check("Dirty workspace", "WARN", f"Could not run git status: {e}")
    else:
        add_check("Dirty workspace", "NOT_APPLICABLE", "Not a Git repository")

    # 14. Package/import health
    try:
        import strict_engineering.kernel
        import strict_engineering.gate
        import strict_engineering.installer
        import strict_engineering.runtime_safety
        import strict_engineering.context_registry
        import strict_engineering.concern
        import strict_engineering.distribution
        import strict_engineering.observability
        add_check("Package/import health", "PASS", "All kernel submodules imported cleanly")
    except Exception as e:
        add_check("Package/import health", "FAIL", f"Failed importing kernel modules: {e}", "Reinstall package using 'pip install .'.")

    # 15. Installation manifest & drift
    manifest = distribution.load_installation_manifest(gemini_dir)
    if not manifest:
        add_check("Installation manifest", "WARN", "manifest.json not found", "Run 'strict-engineering install' to generate manifest.")
    else:
        m_ok, m_issues = distribution.verify_manifest_integrity(gemini_dir)
        if m_ok:
            mod_count = len(manifest.get("managedFiles", {}).get("modules", {}))
            agent_count = len(manifest.get("managedFiles", {}).get("agents", {}))
            add_check("Installation manifest", "PASS", f"Manifest valid ({mod_count} modules, {agent_count} core agents, hooks and prompt verified)")
        else:
            add_check("Installation manifest", "FAIL", f"Manifest drift detected: {'; '.join(m_issues)}", "Run 'strict-engineering update' or 'strict-engineering install'.")

    # 16. Observability log
    obs_file = gemini_dir / "config" / "strict-engineering" / "observability.jsonl"
    if obs_file.exists():
        obs_size_kb = round(obs_file.stat().st_size / 1024, 1)
        add_check("Observability log", "PASS", f"Log active at {obs_file} ({obs_size_kb} KB)")
    else:
        add_check("Observability log", "PASS", "No observability events logged yet")

    # Verbose diagnostics
    if getattr(args, "verbose", False):
        # 17. Rollback snapshots
        snapshots = distribution.list_rollback_snapshots(gemini_dir)
        if snapshots:
            add_check("Rollback snapshots", "PASS", f"{len(snapshots)} snapshot(s) available (latest: {snapshots[0]['snapshotId']})")
        else:
            add_check("Rollback snapshots", "WARN", "No rollback snapshots available")

        # 18. Hook latency telemetry
        lat = observability.get_latency_summary(gemini_dir)
        if lat["count"] > 0:
            add_check("Hook latency stats", "PASS", f"p50={lat['p50Ms']}ms, p95={lat['p95Ms']}ms, max={lat['maxMs']}ms ({lat['count']} calls)")
        else:
            add_check("Hook latency stats", "PASS", "Zero recorded hook calls")

        # 19. Global configuration
        cfg = distribution.load_global_config(gemini_dir)
        add_check("Global configuration", "PASS", f"Source={cfg.get('distributionSource')}, MaxContinues={cfg.get('maxAutomaticContinues')}")

    # Summarize
    pass_cnt = sum(1 for c in checks if c["status"] == "PASS")
    warn_cnt = sum(1 for c in checks if c["status"] == "WARN")
    fail_cnt = sum(1 for c in checks if c["status"] == "FAIL")
    na_cnt = sum(1 for c in checks if c["status"] == "NOT_APPLICABLE")

    if getattr(args, "json", False):
        print(json.dumps({
            "workspace": str(workspace),
            "summary": {"pass": pass_cnt, "warn": warn_cnt, "fail": fail_cnt, "notApplicable": na_cnt},
            "checks": checks,
        }, indent=2))
        return EXIT_OPERATIONAL_FAILURE if fail_cnt > 0 else EXIT_SUCCESS

    print("==========================================================")
    print(" Strict Engineering Doctor Diagnostic Report")
    print("==========================================================")
    print(f"Target Workspace: {workspace}")
    print("----------------------------------------------------------")
    for c in checks:
        st = c["status"]
        cat = c["category"]
        det = c["detail"]
        rec = c.get("recommendation")
        tag = f"[{st}]"
        print(f"{tag:<16} {cat}: {det}")
        if rec and st in {"WARN", "FAIL"}:
            print(f"                 Action: {rec}")

    print("----------------------------------------------------------")
    print(f"Summary: {pass_cnt} PASS, {warn_cnt} WARN, {fail_cnt} FAIL, {na_cnt} NOT_APPLICABLE")
    print("==========================================================")

    return EXIT_OPERATIONAL_FAILURE if fail_cnt > 0 else EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Command: pause
# ---------------------------------------------------------------------------
def cmd_pause(args: argparse.Namespace) -> int:
    """Pause active execution."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    reason = args.reason or "Paused via CLI"
    ok, msg, state = runtime_safety.pause_harness(workspace, reason=reason)
    if ok:
        print(f"[OK] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: resume
# ---------------------------------------------------------------------------
def cmd_resume(args: argparse.Namespace) -> int:
    """Resume paused execution."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    ok, msg, state = kernel.resume_execution(workspace)
    if ok:
        print(f"[OK] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: enable
# ---------------------------------------------------------------------------
def cmd_enable(args: argparse.Namespace) -> int:
    """Enable strict-engineering hooks or project harness."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    gemini_dir = get_default_gemini_dir()
    hooks_file = gemini_dir / "config" / "hooks.json"
    handler_script = gemini_dir / "config" / "strict-engineering" / "hooks_handler.py"

    if getattr(args, "project", False):
        # Enable project harness in workspace state.json
        state_file = workspace / ".agent-harness" / "state.json"
        if not state_file.exists():
            print(f"[FAIL] No .agent-harness/state.json found in {workspace}")
            return EXIT_OPERATIONAL_FAILURE
        state = kernel.load_state(workspace)
        state["active"] = True
        state["runtimeStatus"] = "RUNNING"
        kernel.save_state(workspace, state)
        print(f"[OK] Strict Engineering harness enabled for project at {workspace}")
        return EXIT_SUCCESS

    # Default / Global: enable in hooks.json
    ok, msg, bak = installer.enable_hooks(hooks_file, sys.executable, handler_script)
    if ok:
        print(f"[OK] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: disable
# ---------------------------------------------------------------------------
def cmd_disable(args: argparse.Namespace) -> int:
    """Disable strict-engineering hooks or project harness."""
    workspace = Path(args.workspace or os.getcwd()).resolve()
    gemini_dir = get_default_gemini_dir()
    hooks_file = gemini_dir / "config" / "hooks.json"

    if getattr(args, "project", False):
        # Disable project harness in workspace state.json
        state_file = workspace / ".agent-harness" / "state.json"
        if not state_file.exists():
            print(f"[FAIL] No .agent-harness/state.json found in {workspace}")
            return EXIT_OPERATIONAL_FAILURE
        state = kernel.load_state(workspace)
        state["active"] = False
        state["runtimeStatus"] = "DISABLED"
        kernel.save_state(workspace, state)
        print(f"[OK] Strict Engineering harness disabled for project at {workspace}")
        return EXIT_SUCCESS

    # Default / Global: disable in hooks.json
    ok, msg, bak = installer.disable_hooks(hooks_file)
    if ok:
        print(f"[OK] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: update
# ---------------------------------------------------------------------------
def cmd_update(args: argparse.Namespace) -> int:
    """Check for or apply transactional updates with automatic rollback."""
    gemini_dir = get_default_gemini_dir()

    if getattr(args, "check", False):
        print("Checking for Strict Engineering updates...")
        res = distribution.check_for_updates()
        if getattr(res, "status", None) == distribution.UpdateCheckStatus.CHECK_FAILED:
            print(f"[FAIL] Update check failed: {res.error}")
            return EXIT_OPERATIONAL_FAILURE

        cur = getattr(res, "current_version", __version__)
        lat = getattr(res, "latest_version", cur) or cur
        avail = bool(getattr(res, "update_available", False))

        print(f"Current installed version: {cur}")
        print(f"Latest available version:  {lat}")
        if avail:
            print("[INFO] A newer version is available. Run 'strict-engineering update' to install.")
        else:
            print("[OK] Strict Engineering is up to date.")
        return EXIT_SUCCESS

    source_dir = Path(args.source).resolve() if getattr(args, "source", None) else None
    target_ver = getattr(args, "target_version", None) or None
    force = getattr(args, "force", False)

    print("==========================================================")
    print(" Updating Antigravity Strict Engineering Kernel")
    print("==========================================================")
    ok, msg, manifest = distribution.update_installation(
        source_dir=source_dir,
        target_version=target_ver,
        gemini_dir=gemini_dir,
        force=force,
    )
    if ok:
        print(f"[SUCCESS] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: rollback
# ---------------------------------------------------------------------------
def cmd_rollback(args: argparse.Namespace) -> int:
    """Restore last known-good installation from backups."""
    gemini_dir = get_default_gemini_dir()

    if getattr(args, "list", False):
        snapshots = distribution.list_rollback_snapshots(gemini_dir)
        print("==========================================================")
        print(" Strict Engineering Rollback Snapshots")
        print("==========================================================")
        if not snapshots:
            print("No rollback snapshots found.")
        else:
            for s in snapshots:
                print(f"- Snapshot ID:  {s['snapshotId']}")
                print(f"  Version:      {s.get('version', 'unknown')}")
                print(f"  Installed At: {s.get('installedAt', 'unknown')}")
                print(f"  Modules:      {len(s.get('files', []))} files")
                print()
        print("==========================================================")
        return EXIT_SUCCESS

    snapshot_id = getattr(args, "snapshot", None) or None
    dry_run = getattr(args, "dry_run", False)

    print("==========================================================")
    print(f" Strict Engineering Rollback {'(DRY RUN)' if dry_run else ''}")
    print("==========================================================")
    print("INVARIANT: Rollback only restores global kernel modules and hooks.")
    print("           Project application code and .agent-harness are NEVER touched.")
    print("----------------------------------------------------------")

    ok, msg, notes = distribution.rollback_installation(
        backup_id=snapshot_id,
        gemini_dir=gemini_dir,
        dry_run=dry_run,
    )

    for note in notes:
        print(f"  * {note}")

    if ok:
        print(f"[SUCCESS] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Command: uninstall
# ---------------------------------------------------------------------------
def cmd_uninstall(args: argparse.Namespace) -> int:
    """Surgically remove Strict Engineering without altering unrelated configurations."""
    gemini_dir = get_default_gemini_dir()
    workspace = Path(args.workspace or os.getcwd()).resolve()
    dry_run = getattr(args, "dry_run", False)
    purge_harness = getattr(args, "purge_harness", False)

    print("==========================================================")
    print(f" Strict Engineering Uninstall {'(DRY RUN)' if dry_run else ''}")
    print("==========================================================")
    print("PRESERVATION GUARANTEES:")
    print("  - Custom hooks in hooks.json are PRESERVED")
    print("  - Custom user instructions in GEMINI.md are PRESERVED")
    print("  - Custom user agents in config/agents/ are PRESERVED")
    print("  - Project application code is NEVER TOUCHED")
    if not purge_harness:
        print("  - Project .agent-harness is PRESERVED (use --purge-harness to remove)")
    else:
        print(f"  - Project .agent-harness will be PURGED at {workspace}")
    print("----------------------------------------------------------")

    ok, msg, actions = distribution.uninstall_kernel(
        gemini_dir=gemini_dir,
        dry_run=dry_run,
        workspace=workspace if purge_harness else None,
        purge_harness=purge_harness,
    )

    for act in actions:
        print(f"  * {act}")

    if ok:
        print(f"\n[SUCCESS] {msg}")
        return EXIT_SUCCESS
    else:
        print(f"\n[FAIL] {msg}")
        return EXIT_OPERATIONAL_FAILURE


# ---------------------------------------------------------------------------
# Parser Configuration & Main Entrypoint
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strict-engineering",
        description="Antigravity Strict Engineering Kernel - Operational CLI, Distribution & UX",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # version
    p_ver = subparsers.add_parser("version", help="Display kernel and installation version info")
    p_ver.set_defaults(func=cmd_version)

    # install
    p_inst = subparsers.add_parser("install", help="Install global hooks and configuration non-destructively")
    p_inst.set_defaults(func=cmd_install)

    # init
    p_init = subparsers.add_parser("init", help="Initialize Strict Engineering harness in a project")
    p_init.add_argument("--intent", type=str, default="", help="Original user intent describing project goal")
    p_init.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_init.add_argument("--await-intent", action="store_true", help="Initialize in safe awaiting-intent state without intent text")
    p_init.set_defaults(func=cmd_init)

    # status
    p_stat = subparsers.add_parser("status", help="Show project lifecycle, requirements, and completion status")
    p_stat.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_stat.add_argument("--conversation", type=str, default="", help="Query exact conversation circuit breaker state")
    p_stat.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_stat.add_argument("--verbose", action="store_true", help="Include full details")
    p_stat.set_defaults(func=cmd_status)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run diagnostic health checks across environment and projects")
    p_doc.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_doc.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_doc.add_argument("--verbose", action="store_true", help="Include full diagnostic details")
    p_doc.set_defaults(func=cmd_doctor)

    # pause
    p_pause = subparsers.add_parser("pause", help="Pause active execution cleanly")
    p_pause.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_pause.add_argument("--reason", type=str, default="Paused via CLI", help="Pause reason")
    p_pause.set_defaults(func=cmd_pause)

    # resume
    p_res = subparsers.add_parser("resume", help="Resume paused execution deterministically")
    p_res.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_res.set_defaults(func=cmd_resume)

    # enable
    p_en = subparsers.add_parser("enable", help="Re-enable Strict Engineering hooks or project harness")
    p_en.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_en.add_argument("--global", dest="is_global", action="store_true", default=True, help="Enable hooks in ~/.gemini/config/hooks.json")
    p_en.add_argument("--project", action="store_true", help="Enable harness in project state.json")
    p_en.set_defaults(func=cmd_enable)

    # disable
    p_dis = subparsers.add_parser("disable", help="Disable Strict Engineering hooks or project harness")
    p_dis.add_argument("--workspace", type=str, default="", help="Target workspace path (defaults to current dir)")
    p_dis.add_argument("--global", dest="is_global", action="store_true", default=True, help="Disable hooks in ~/.gemini/config/hooks.json")
    p_dis.add_argument("--project", action="store_true", help="Disable harness in project state.json")
    p_dis.set_defaults(func=cmd_disable)

    # update
    p_upd = subparsers.add_parser("update", help="Check for or apply transactional updates with automatic rollback")
    p_upd.add_argument("--check", action="store_true", help="Check for updates without applying")
    p_upd.add_argument("--source", type=str, default="", help="Local directory source to update from")
    p_upd.add_argument("--target-version", type=str, default="", help="Target version string")
    p_upd.add_argument("--force", action="store_true", help="Force update even if same version")
    p_upd.set_defaults(func=cmd_update)

    # rollback
    p_rb = subparsers.add_parser("rollback", help="Restore last known-good installation from backups")
    p_rb.add_argument("--snapshot", type=str, default="", help="Specific snapshot ID to restore")
    p_rb.add_argument("--list", action="store_true", help="List available rollback snapshots")
    p_rb.add_argument("--dry-run", action="store_true", help="Preview rollback without modifying files")
    p_rb.set_defaults(func=cmd_rollback)

    # uninstall
    p_un = subparsers.add_parser("uninstall", help="Non-destructively remove Strict Engineering")
    p_un.add_argument("--dry-run", action="store_true", help="Preview removal without modifying files")
    p_un.add_argument("--workspace", type=str, default="", help="Target workspace path")
    p_un.add_argument("--purge-harness", action="store_true", help="Also remove .agent-harness from current workspace")
    p_un.set_defaults(func=cmd_uninstall)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv in (["-h"], ["--help"]):
        parser.print_help()
        return EXIT_SUCCESS

    try:
        args = parser.parse_args(argv)
    except SystemExit as se:
        return EXIT_INVALID_USAGE if se.code != 0 else EXIT_SUCCESS

    if hasattr(args, "func"):
        try:
            return args.func(args)
        except Exception as ex:
            sys.stderr.write(f"[strict-engineering] Operational failure: {ex}\n")
            return EXIT_OPERATIONAL_FAILURE

    parser.print_help()
    return EXIT_INVALID_USAGE


if __name__ == "__main__":
    sys.exit(main())
