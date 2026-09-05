"""
Strict Engineering Kernel V4.1 - Baseline & Regression Module
Captures initial project health (git, tests, build, lint, typecheck) and detects regressions.
"""

import os
import json
import datetime
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set


def run_cmd_capture(cmd: List[str], cwd: Path) -> Tuple[int, str, str]:
    """Run a command safely and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=60,
            shell=os.name == "nt",
        )
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return -1, "", str(e)


def capture_git_baseline(workspace_dir: Path) -> Dict[str, Any]:
    """Capture git status and commit baseline if git is present."""
    git_dir = workspace_dir / ".git"
    if not git_dir.exists():
        return {"git_present": False}

    rc_head, head_out, _ = run_cmd_capture(["git", "rev-parse", "HEAD"], workspace_dir)
    rc_status, status_out, _ = run_cmd_capture(["git", "status", "--porcelain"], workspace_dir)
    rc_branch, branch_out, _ = run_cmd_capture(["git", "rev-parse", "--abbrev-ref", "HEAD"], workspace_dir)

    return {
        "git_present": True,
        "head": head_out.strip() if rc_head == 0 else "",
        "branch": branch_out.strip() if rc_branch == 0 else "",
        "uncommitted_changes": status_out.strip().splitlines() if rc_status == 0 and status_out.strip() else [],
    }


def capture_project_baseline(
    workspace_dir: Path,
    test_command: Optional[str] = None,
    build_command: Optional[str] = None,
    lint_command: Optional[str] = None,
    typecheck_command: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Capture initial baseline of the workspace including tests, build, lint, and typecheck.
    """
    workspace_path = Path(workspace_dir).resolve()
    baseline = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git": capture_git_baseline(workspace_path),
        "build": {"executed": False, "passed": True, "exit_code": 0, "output": ""},
        "lint": {"executed": False, "passed": True, "exit_code": 0, "output": ""},
        "typecheck": {
            "executed": False,
            "passed": True,
            "status": "NOT_CONFIGURED" if typecheck_command is None else "PENDING",
            "exit_code": 0,
            "output": "",
        },
        "tests": {
            "executed": False,
            "passed": True,
            "exit_code": 0,
            "total": 0,
            "passed_count": 0,
            "failed_count": 0,
            "failed_tests": [],
            "output": "",
        },
    }

    if build_command:
        rc, out, err = run_cmd_capture(build_command.split(), workspace_path)
        baseline["build"] = {
            "executed": True,
            "passed": rc == 0,
            "exit_code": rc,
            "command": build_command,
            "output": (out + "\n" + err).strip(),
        }

    if lint_command:
        rc, out, err = run_cmd_capture(lint_command.split(), workspace_path)
        baseline["lint"] = {
            "executed": True,
            "passed": rc == 0,
            "exit_code": rc,
            "command": lint_command,
            "output": (out + "\n" + err).strip(),
        }

    if typecheck_command:
        rc, out, err = run_cmd_capture(typecheck_command.split(), workspace_path)
        baseline["typecheck"] = {
            "executed": True,
            "passed": rc == 0,
            "status": "PASSED" if rc == 0 else "FAILED",
            "exit_code": rc,
            "command": typecheck_command,
            "output": (out + "\n" + err).strip(),
        }
    else:
        baseline["typecheck"] = {
            "executed": False,
            "passed": True,
            "status": "NOT_CONFIGURED",
            "exit_code": 0,
            "command": "",
            "output": "",
        }

    if test_command:
        rc, out, err = run_cmd_capture(test_command.split(), workspace_path)
        baseline["tests"] = {
            "executed": True,
            "passed": rc == 0,
            "exit_code": rc,
            "command": test_command,
            "output": (out + "\n" + err).strip(),
            "failed_count": 1 if rc != 0 else 0,
            "failed_tests": [],
        }

    return baseline


def evaluate_regression(
    baseline: Dict[str, Any],
    current_test_results: Dict[str, Any],
    current_build_results: Optional[Dict[str, Any]] = None,
    current_lint_results: Optional[Dict[str, Any]] = None,
    current_typecheck_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compare current test/build/lint/typecheck results against baseline.
    Identifies new regressions vs pre-existing known failures.
    """
    regressions = []
    base_tests = baseline.get("tests", {})
    base_failed_tests = set(base_tests.get("failed_tests", []))
    base_failed_count = base_tests.get("failed_count", 0)

    curr_failed_tests = set(current_test_results.get("failed_tests", []))
    curr_failed_count = current_test_results.get("failed_count", 0)

    new_test_failures = sorted(list(curr_failed_tests - base_failed_tests))
    fixed_test_failures = sorted(list(base_failed_tests - curr_failed_tests))
    pre_existing_failures = sorted(list(base_failed_tests & curr_failed_tests))

    # 1. Check for newly failing named test cases
    if new_test_failures:
        regressions.append(
            f"New failing tests detected: {', '.join(new_test_failures)}"
        )

    # 2. Check for numeric count increase in failures
    if curr_failed_count > base_failed_count and not new_test_failures:
        regressions.append(
            f"Test failure count increased from baseline ({base_failed_count}) to current ({curr_failed_count})"
        )

    # 3. Check for newly failing build
    base_build = baseline.get("build", {})
    if current_build_results:
        if base_build.get("passed", True) and not current_build_results.get("passed", True):
            regressions.append("Build regression: build passed in baseline but failed currently")

    # 4. Check for newly failing lint
    base_lint = baseline.get("lint", {})
    if current_lint_results:
        if base_lint.get("passed", True) and not current_lint_results.get("passed", True):
            regressions.append("Lint regression: lint passed in baseline but failed currently")

    # 5. Check for newly failing typecheck
    base_tc = baseline.get("typecheck", {})
    typecheck_status = "NOT_CONFIGURED"
    if current_typecheck_results:
        typecheck_status = current_typecheck_results.get("status", "PASSED" if current_typecheck_results.get("passed", True) else "FAILED")
        if base_tc.get("passed", True) and not current_typecheck_results.get("passed", True):
            regressions.append("Typecheck regression: typecheck passed in baseline but failed currently")
    else:
        typecheck_status = base_tc.get("status", "NOT_CONFIGURED")

    return {
        "has_regression": len(regressions) > 0,
        "regression_count": len(regressions),
        "regressions": regressions,
        "pre_existing_test_failures": pre_existing_failures,
        "new_test_failures": new_test_failures,
        "fixed_test_failures": fixed_test_failures,
        "current_test_failures": sorted(list(curr_failed_tests)),
        "typecheck_status": typecheck_status,
    }


# Backward compatibility aliases
capture_workspace_baseline = capture_project_baseline

