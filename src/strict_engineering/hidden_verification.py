"""
Strict Engineering Kernel Step 6S - Hidden Verification Engine
Provides:
- Generation and execution of verifier-owned hidden checks to defeat narrow test-fitting
- Contract scoping (strictly rejects checks attempting to invent new product requirements)
- Hidden test types: BOUNDARY_VALUE, NEGATIVE_PATH, RESTART_PERSISTENCE, INVALID_INPUT,
  AUTHORIZATION_DENIAL, EMPTY_STATE, IDEMPOTENCY, RECOVERY
- Authority protection (owned by Test Oracle / Verifier; immutable by Builder)
- Automated promotion of discovered failing cases to permanent regression tests
"""

import os
import sys
import json
import time
import uuid
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable

try:
    from . import kernel
    from . import fingerprint
except (ImportError, ValueError):
    import kernel
    import fingerprint


ALLOWED_HIDDEN_TYPES = {
    "BOUNDARY_VALUE",
    "BOUNDARY_OVERFLOW",
    "EMPTY_BOUNDARY",
    "NEGATIVE_PATH",
    "RESTART_PERSISTENCE",
    "INVALID_INPUT",
    "AUTHORIZATION_DENIAL",
    "EMPTY_STATE",
    "IDEMPOTENCY",
    "RECOVERY",
    "RACE_CONDITION",
}


def create_hidden_check(*args, **kwargs) -> Dict[str, Any]:
    """
    Creates a verifier-owned hidden check (Sections 18, 19, 20, 22).
    Section 18 & S6S-H3: Must derive ONLY from existing requirements.
    Must NOT invent new product behavior. If is_new_behavior is True or check invents
    unauthorized scope, it is REJECTED.
    """
    pos_args = list(args)
    if pos_args:
        first = pos_args[0]
        if isinstance(first, Path) or (isinstance(first, str) and (os.path.isdir(first) or "/" in first or "\\" in first)):
            pos_args.pop(0)

    req_id = kwargs.get("requirement_id") or kwargs.get("requirementId")
    if not req_id and pos_args:
        req_id = pos_args.pop(0)

    check_type = kwargs.get("check_type") or kwargs.get("checkType") or kwargs.get("type")
    if not check_type and pos_args:
        check_type = pos_args.pop(0)

    rationale = kwargs.get("rationale") or kwargs.get("description")
    if not rationale and pos_args:
        rationale = pos_args.pop(0)

    test_cmd = (
        kwargs.get("test_command")
        or kwargs.get("testCommand")
        or kwargs.get("executable")
        or kwargs.get("executable_code_or_command")
    )
    if not test_cmd and pos_args:
        test_cmd = pos_args.pop(0)

    oracle = kwargs.get("expected_oracle") or kwargs.get("expectedOracle", "PASS")
    if not kwargs.get("expected_oracle") and not kwargs.get("expectedOracle") and pos_args:
        oracle = pos_args.pop(0)

    contract_ref = kwargs.get("contract_reference") or kwargs.get("contractReference", "")
    if not kwargs.get("contract_reference") and not kwargs.get("contractReference") and pos_args:
        contract_ref = pos_args.pop(0)

    is_new = kwargs.get("is_new_behavior", False)

    str_type = str(check_type or "")
    str_rat = str(rationale or "")

    if str_type not in ALLOWED_HIDDEN_TYPES:
        return {
            "status": "REJECTED",
            "reason": f"Unknown hidden check type '{str_type}'",
            "checkType": str_type,
            "requirementId": req_id,
        }

    if (
        is_new
        or "expansion" in str_type.lower()
        or "not in specification" in str_rat.lower()
        or "outside" in str_rat.lower()
        or "new requirement" in str_rat.lower()
    ):
        return {
            "status": "REJECTED",
            "reason": "Hidden check attempts to invent new product requirement outside existing contract",
            "checkType": str_type,
            "requirementId": req_id,
        }

    check_id = kwargs.get("check_id") or kwargs.get("checkId") or f"HCK-{uuid.uuid4().hex[:8].upper()}"
    return {
        "status": "ACTIVE",
        "checkId": check_id,
        "requirementId": req_id,
        "checkType": str_type,
        "type": str_type,
        "testCommand": test_cmd or "",
        "executable": test_cmd or "",
        "description": str_rat,
        "rationale": str_rat,
        "expectedOracle": oracle,
        "contractReference": contract_ref,
        "owner": "test_oracle",
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def execute_hidden_check(
    workspace_dir: Path,
    hidden_check: Dict[str, Any],
    custom_executor: Optional[Callable[[Dict[str, Any]], Tuple[bool, str]]] = None,
) -> Dict[str, Any]:
    """
    Executes a single hidden check against the workspace implementation in a disposable runner.
    """
    ws = Path(workspace_dir).resolve()
    executable = hidden_check.get("executable") or hidden_check.get("testCommand", "")
    oracle = hidden_check.get("expectedOracle", "PASS")
    start_time = time.time()

    if custom_executor is not None:
        try:
            passed, output = custom_executor(hidden_check)
            duration_ms = int((time.time() - start_time) * 1000)
            res_val = "PASS" if passed else "FAIL"
            return {
                "checkId": hidden_check.get("checkId"),
                "requirementId": hidden_check.get("requirementId"),
                "type": hidden_check.get("type") or hidden_check.get("checkType"),
                "checkType": hidden_check.get("checkType") or hidden_check.get("type"),
                "status": res_val,
                "result": res_val,
                "output": output,
                "durationMs": duration_ms,
                "error": None if passed else output,
            }
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return {
                "checkId": hidden_check.get("checkId"),
                "requirementId": hidden_check.get("requirementId"),
                "type": hidden_check.get("type") or hidden_check.get("checkType"),
                "checkType": hidden_check.get("checkType") or hidden_check.get("type"),
                "status": "FAIL",
                "result": "FAIL",
                "output": f"Execution error: {str(e)}",
                "durationMs": duration_ms,
                "error": str(e),
            }

    # Execute code in disposable python runner
    try:
        if (
            executable.startswith(sys.executable)
            or executable.startswith("python")
            or executable.startswith("pytest")
        ):
            cmd = executable
        elif executable.endswith(".py") and (ws / executable).exists():
            cmd = f"{sys.executable} {executable}"
        else:
            cmd = f"{sys.executable} -c \"{executable}\""

        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(ws),
            capture_output=True,
            text=True,
            timeout=30,
        )
        duration_ms = int((time.time() - start_time) * 1000)
        passed = (proc.returncode == 0 and oracle == "PASS") or (proc.returncode != 0 and oracle == "FAIL")
        output = proc.stdout if passed else (proc.stderr or proc.stdout)
        res_val = "PASS" if passed else "FAIL"

        return {
            "checkId": hidden_check.get("checkId"),
            "requirementId": hidden_check.get("requirementId"),
            "type": hidden_check.get("type") or hidden_check.get("checkType"),
            "checkType": hidden_check.get("checkType") or hidden_check.get("type"),
            "status": res_val,
            "result": res_val,
            "exitCode": proc.returncode,
            "output": output[:1000],
            "durationMs": duration_ms,
            "error": None if passed else output[:500],
        }
    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "checkId": hidden_check.get("checkId"),
            "requirementId": hidden_check.get("requirementId"),
            "type": hidden_check.get("type") or hidden_check.get("checkType"),
            "checkType": hidden_check.get("checkType") or hidden_check.get("type"),
            "status": "FAIL",
            "result": "FAIL",
            "output": "Hidden check timed out after 30s",
            "durationMs": duration_ms,
            "error": "TIMEOUT",
        }
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        return {
            "checkId": hidden_check.get("checkId"),
            "requirementId": hidden_check.get("requirementId"),
            "type": hidden_check.get("type") or hidden_check.get("checkType"),
            "checkType": hidden_check.get("checkType") or hidden_check.get("type"),
            "status": "FAIL",
            "result": "FAIL",
            "output": str(e),
            "durationMs": duration_ms,
            "error": str(e),
        }


def run_hidden_verification_suite(
    workspace_dir: Path,
    checks: List[Dict[str, Any]],
    custom_executor: Optional[Callable[[Dict[str, Any]], Tuple[bool, str]]] = None,
) -> Dict[str, Any]:
    """
    Executes a collection of hidden verification checks.
    Evaluates pass rates and returns structured summary.
    """
    results = []
    failed_checks = []
    passed_checks = []

    for c in checks:
        res = execute_hidden_check(workspace_dir, c, custom_executor=custom_executor)
        results.append(res)
        if res["status"] == "PASS":
            passed_checks.append(c.get("requirementId"))
        else:
            failed_checks.append(res)

    overall = "PASS" if len(failed_checks) == 0 else "FAIL"
    record = {
        "schemaVersion": "6S.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "totalChecks": len(checks),
        "passedChecks": len(checks) - len(failed_checks),
        "failedChecks": len(failed_checks),
        "overallStatus": overall,
        "results": results,
        "failures": failed_checks,
    }
    save_hidden_verification_record(workspace_dir, record)
    return record


def promote_failing_check_to_regression_test(
    workspace_dir: Path,
    failed_check: Dict[str, Any],
    test_file_path: Optional[str] = None,
) -> str:
    """
    Converts a discovered hidden check defect into a permanent regression test (Section 22).
    """
    ws = Path(workspace_dir)
    reg_dir = ws / "tests" / "regression"
    reg_dir.mkdir(parents=True, exist_ok=True)

    cid = str(failed_check.get("checkId", "hck")).lower().replace("-", "_")
    rid = str(failed_check.get("requirementId", "req")).lower().replace("-", "_")
    rel_name = test_file_path or f"test_{cid}_{rid}.py"
    target = reg_dir / Path(rel_name).name

    test_code = failed_check.get("testCode")
    if test_code:
        test_content = f'''"""
Permanent regression test promoted from discovered hidden verification defect.
Requirement: {failed_check.get("requirementId")}
Type: {failed_check.get("type") or failed_check.get("checkType")}
"""
import unittest

{test_code}

if __name__ == "__main__":
    unittest.main()
'''
    else:
        cmd = failed_check.get("executable") or failed_check.get("testCommand", "pass")
        test_content = f'''"""
Permanent regression test promoted from discovered hidden verification defect.
Requirement: {failed_check.get("requirementId")}
Type: {failed_check.get("type") or failed_check.get("checkType")}
"""
import unittest

class RegressionTest(unittest.TestCase):
    def test_regression_behavior(self):
        # Promoted check: {failed_check.get("description", "")}
        {cmd}

if __name__ == "__main__":
    unittest.main()
'''
    target.write_text(test_content, encoding="utf-8")
    return str(target)


def save_hidden_verification_record(workspace_dir: Path, record: Dict[str, Any]) -> None:
    harness = Path(workspace_dir) / ".agent-harness"
    harness.mkdir(parents=True, exist_ok=True)
    (harness / "hidden-checks.json").write_text(json.dumps(record, indent=2), encoding="utf-8")


def load_hidden_verification_record(workspace_dir: Path) -> Optional[Dict[str, Any]]:
    fpath = Path(workspace_dir) / ".agent-harness" / "hidden-checks.json"
    if fpath.exists():
        try:
            return json.loads(fpath.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


save_hidden_checks_record = save_hidden_verification_record
load_hidden_checks_record = load_hidden_verification_record
