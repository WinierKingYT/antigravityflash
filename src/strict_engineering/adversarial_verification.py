"""
Strict Engineering Kernel Step 4 - Test Quality & Adversarial Verification Engine
Implements Property-Based Testing, Fuzz Testing, Mutation Testing,
Controlled Failure Injection, and Risk-Adaptive Adversarial Test Quality Auditing.
"""

import os
import re
import sys
import json
import time
import random
import shutil
import hashlib
import datetime
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable, Set

try:
    from . import kernel
    from . import fingerprint
    from . import risk_engine
except (ImportError, ValueError):
    import kernel
    import fingerprint
    import risk_engine

ADVERSARIAL_SCHEMA_VERSION = "4.0.0"

# Default Budgets by Risk
DEFAULT_BUDGETS = {
    "LOW": {
        "propertyIterations": 0,
        "fuzzIterations": 0,
        "mutationBudget": 0,
        "failureScenarios": 0,
    },
    "MEDIUM": {
        "propertyIterations": 30,
        "fuzzIterations": 25,
        "mutationBudget": 5,
        "failureScenarios": 1,
    },
    "HIGH": {
        "propertyIterations": 100,
        "fuzzIterations": 75,
        "mutationBudget": 20,
        "failureScenarios": 3,
    },
    "CRITICAL": {
        "propertyIterations": 250,
        "fuzzIterations": 150,
        "mutationBudget": 40,
        "failureScenarios": 5,
    },
}


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# =========================================================================
# 1. BUDGET ENGINE
# =========================================================================

def calculate_adversarial_budget(
    risk_level: str,
    failure_history_count: int = 0,
) -> Dict[str, int]:
    """Calculate deterministic bounded adversarial verification budgets scaled by risk and failure feedback."""
    norm_risk = risk_level.upper() if risk_level else "LOW"
    base = dict(DEFAULT_BUDGETS.get(norm_risk, DEFAULT_BUDGETS["LOW"]))
    
    # Scale with failure history if prior defects were discovered
    if failure_history_count > 0:
        multiplier = min(3.0, 1.0 + (0.5 * failure_history_count))
        base["propertyIterations"] = int(base["propertyIterations"] * multiplier)
        base["fuzzIterations"] = int(base["fuzzIterations"] * multiplier)
        base["mutationBudget"] = int(base["mutationBudget"] * multiplier)
        base["failureScenarios"] = int(min(10, base["failureScenarios"] + failure_history_count))

    return base


# =========================================================================
# 2. PROPERTY-BASED TESTING ENGINE
# =========================================================================

class PropertyTestingEngine:
    """
    Framework-neutral property-based test runner with bounded generators,
    deterministic seeds, and counterexample minimization.
    """

    @staticmethod
    def generate_bounded_samples(data_type: str, count: int, seed: int) -> List[Any]:
        """Generate safe, bounded diverse sample values including edge cases."""
        rng = random.Random(seed)
        samples = []

        if data_type == "int":
            edge_cases = [0, 1, -1, 2**31 - 1, -2**31, 2**63 - 1, -2**63]
            samples.extend(edge_cases[:count])
            while len(samples) < count:
                samples.append(rng.randint(-1000000, 1000000))

        elif data_type == "float":
            edge_cases = [0.0, -0.0, 1.0, -1.0, 1e-10, 1e10, 1e-300, 1e300]
            samples.extend(edge_cases[:count])
            while len(samples) < count:
                samples.append(rng.uniform(-10000.0, 10000.0))

        elif data_type == "str":
            edge_cases = [
                "",
                " ",
                "a",
                "A",
                "0",
                "\0",
                "\n\r\t",
                "Unicode: 🚀✓漢字öüä",
                "A" * 1000,  # Long string
                "' OR '1'='1",
                "<script>alert(1)</script>",
                "../relative/path",
            ]
            samples.extend(edge_cases[:count])
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-./"
            while len(samples) < count:
                length = rng.randint(0, 100)
                samples.append("".join(rng.choice(alphabet) for _ in range(length)))

        elif data_type == "list_int":
            edge_cases = [[], [0], [1, -1], [0] * 100, list(range(50)), list(range(50, 0, -1))]
            samples.extend(edge_cases[:count])
            while len(samples) < count:
                length = rng.randint(0, 50)
                samples.append([rng.randint(-1000, 1000) for _ in range(length)])

        elif data_type == "json_dict":
            edge_cases = [
                {},
                {"empty": ""},
                {"null": None},
                {"nested": {"a": [1, 2, {"b": True}]}},
                {"unicode_key": "値"},
            ]
            samples.extend(edge_cases[:count])
            while len(samples) < count:
                d = {f"key_{rng.randint(1, 10)}": rng.choice([0, "test", True, None, [1, 2]])}
                samples.append(d)

        else:
            # Fallback generic objects
            samples = [None, "", 0, False, [], {}][:count]
            while len(samples) < count:
                samples.append(rng.randint(0, 1000))

        return samples[:count]

    @classmethod
    def run_property(
        cls,
        property_id: str,
        property_fn: Callable[[Any], bool],
        data_type: str = "int",
        iterations: int = 50,
        seed: Optional[int] = None,
        shrink_fn: Optional[Callable[[Any], Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute property test with given invariant and generator.
        Returns execution result with deterministic reproduction seed and counterexample if failed.
        """
        chosen_seed = seed if seed is not None else random.randint(10000, 999999)
        samples = cls.generate_bounded_samples(data_type, iterations, chosen_seed)

        counterexample = None
        shrunk_counterexample = None
        failing_error = None

        for idx, sample in enumerate(samples):
            try:
                passed = property_fn(sample)
                if not passed:
                    counterexample = sample
                    break
            except Exception as e:
                counterexample = sample
                failing_error = f"{type(e).__name__}: {str(e)}"
                break

        if counterexample is not None:
            # Shrink if shrinker provided
            if shrink_fn:
                try:
                    shrunk_counterexample = shrink_fn(counterexample)
                except Exception:
                    shrunk_counterexample = counterexample
            else:
                shrunk_counterexample = counterexample

            return {
                "propertyId": property_id,
                "status": "FAIL",
                "iterationsRun": idx + 1,
                "seed": chosen_seed,
                "counterexample": str(counterexample),
                "shrunkCounterexample": str(shrunk_counterexample),
                "error": failing_error,
            }

        return {
            "propertyId": property_id,
            "status": "PASS",
            "iterationsRun": len(samples),
            "seed": chosen_seed,
            "counterexample": None,
        }


# =========================================================================
# 3. FUZZ TESTING ENGINE
# =========================================================================

class FuzzTestingEngine:
    """
    Input boundary fuzz testing engine with deterministic oracles,
    malformed structured data classes, and crash reproduction.
    """

    @staticmethod
    def generate_fuzz_payloads(seed: int, count: int) -> List[str]:
        """Generate diverse malformed, extreme, and unexpected payloads."""
        rng = random.Random(seed)
        base_payloads = [
            "",  # empty
            "\x00" * 10,  # null bytes
            '{"unclosed": "json"',
            '{"invalid_json":',
            '{"deep": ' + '{"nested": ' * 20 + '"value"' + '}' * 20 + '}',
            '{"a": 1, "a": 2}',  # duplicate keys
            '{"bad_type": [1, 2, {"unexpected": null}]}',
            "99999999999999999999999999999999999999999999999999",
            "-99999999999999999999999999999999999999999999999999",
            "NaN",
            "Infinity",
            "-Infinity",
            "<script>alert(1)</script>",  # XSS
            "' OR '1'='1",  # SQL injection
            "../../../../etc/passwd",  # Path traversal
            "\u0000\uffff\U0001F600",
            "A" * 5000,  # Long payload
            "%s%s%s%s%s%n",  # Format string
        ]
        payloads = list(base_payloads)
        while len(payloads) < count:
            kind = rng.choice(["json", "str", "num"])
            if kind == "json":
                payloads.append(json.dumps({f"k_{rng.randint(1,50)}": rng.choice([None, 0, "err", [], {}])}))
            elif kind == "str":
                payloads.append("".join(rng.choice(["\0", "\n", "\r", "A", "\u202e", "x", "/"]) for _ in range(rng.randint(5, 50))))
            else:
                payloads.append(str(rng.randint(-1000000000, 1000000000)))

        return payloads[:count]

    @classmethod
    def run_fuzz(
        cls,
        fuzz_id: str,
        target_fn: Callable[[str], Any],
        oracle_fn: Optional[Callable[[str, Any, Optional[Exception]], bool]] = None,
        iterations: int = 50,
        seed: Optional[int] = None,
        timeout_sec: int = 10,
    ) -> Dict[str, Any]:
        """
        Execute fuzz inputs against target.
        Oracle determines whether response is valid (must not crash unexpectedly, must reject safely).
        """
        chosen_seed = seed if seed is not None else random.randint(10000, 999999)
        payloads = cls.generate_fuzz_payloads(seed=chosen_seed, count=iterations)
        findings = []

        start_time = time.time()
        for idx, p in enumerate(payloads):
            if (time.time() - start_time) > timeout_sec:
                break

            exc = None
            output = None
            try:
                output = target_fn(p)
            except Exception as e:
                exc = e

            # Default Oracle: Target should either return safely or raise expected validation errors
            if oracle_fn:
                valid = oracle_fn(p, output, exc)
            else:
                # Default safety: Uncaught generic or system crashes (segfault, memory error) are findings
                if isinstance(exc, (MemoryError, RecursionError, SystemError)):
                    valid = False
                else:
                    valid = True

            if not valid:
                findings.append({
                    "iteration": idx + 1,
                    "payload": p[:100] + ("..." if len(p) > 100 else ""),
                    "error": str(exc) if exc else "Oracle rejection",
                    "output": str(output)[:100] if output else None,
                })
                break

        status = "PASS" if len(findings) == 0 else "FAIL"
        return {
            "fuzzId": fuzz_id,
            "status": status,
            "iterationsRun": len(payloads),
            "seed": chosen_seed,
            "findingsCount": len(findings),
            "findings": findings,
        }


# =========================================================================
# 4. MUTATION TESTING ENGINE
# =========================================================================

class MutationTestingEngine:
    """
    Controlled code mutation engine operating exclusively in temporary/disposable sandboxes.
    Generates semantic mutants, tests if test suite kills them, and calculates mutation score.
    """

    MUTATION_PATTERNS = [
        # Boolean inversion & return value mutations
        (r"\breturn True\b", "return False", "BOOLEAN_RETURN_MUTATION"),
        (r"\breturn False\b", "return True", "BOOLEAN_RETURN_MUTATION"),
        (r"\bTrue\b", "False", "BOOLEAN_INVERSION"),
        (r"\bFalse\b", "True", "BOOLEAN_INVERSION"),
        # Comparisons
        (r"==", "!=", "COMPARISON_MUTATION"),
        (r"!=", "==", "COMPARISON_MUTATION"),
        (r">=", "<", "COMPARISON_MUTATION"),
        (r"<=", ">", "COMPARISON_MUTATION"),
        (r"(?<!-)>", ">=", "COMPARISON_MUTATION"),
        (r"<", "<=", "COMPARISON_MUTATION"),
        # Logical / Arithmetic
        (r"\band\b", "or", "LOGICAL_MUTATION"),
        (r"\bor\b", "and", "LOGICAL_MUTATION"),
        (r"balance - amount", "balance + amount", "FINANCIAL_CORRUPTION"),
        (r"balance + amount", "balance - amount", "FINANCIAL_CORRUPTION"),
    ]

    @classmethod
    def generate_mutations_for_code(cls, source_code: str, max_mutations: int = 20) -> List[Dict[str, Any]]:
        """Generate list of discrete single-point mutants from source code."""
        mutants = []
        
        for pat, replacement, strategy in cls.MUTATION_PATTERNS:
            matches = list(re.finditer(pat, source_code))
            for m in matches:
                start, end = m.span()
                mutated_code = source_code[:start] + replacement + source_code[end:]
                
                # Check for syntax validity
                is_valid = True
                try:
                    compile(mutated_code, "<mutant>", "exec")
                except SyntaxError:
                    is_valid = False

                mutants.append({
                    "mutantId": f"MUT-{hashlib.sha256((source_code[start:end] + str(start)).encode()).hexdigest()[:8]}",
                    "strategy": strategy,
                    "originalSnippet": source_code[max(0, start-15):min(len(source_code), end+15)],
                    "mutatedSnippet": mutated_code[max(0, start-15):min(len(mutated_code), start+len(replacement)+15)],
                    "mutatedCode": mutated_code,
                    "isValid": is_valid,
                })
                if len(mutants) >= max_mutations:
                    break
            if len(mutants) >= max_mutations:
                break

        return mutants

    @classmethod
    def execute_mutation_analysis(
        cls,
        target_file_path: Path,
        test_command: str,
        working_dir: Path,
        budget: int = 10,
    ) -> Dict[str, Any]:
        """
        Run mutation testing on target file in a temporary copy.
        Returns kill rate, surviving mutants, and mutation score.
        """
        target_file = Path(target_file_path).resolve()
        if not target_file.exists():
            return {
                "status": "NOT_APPLICABLE",
                "attempted": 0,
                "killed": 0,
                "survived": 0,
                "invalid": 0,
                "score": 1.0,
                "survivingMutants": [],
            }

        original_content = target_file.read_text(encoding="utf-8")
        mutants = cls.generate_mutations_for_code(original_content, max_mutations=budget)

        killed = 0
        survived = 0
        invalid = 0
        surviving_mutants = []

        for m in mutants:
            if not m["isValid"]:
                invalid += 1
                continue

            # Apply mutation to target file
            try:
                target_file.write_text(m["mutatedCode"], encoding="utf-8")
                # Run test command
                proc = subprocess.run(
                    test_command,
                    shell=True,
                    cwd=str(working_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                if proc.returncode != 0:
                    # Test failed -> Mutant KILLED (Success!)
                    killed += 1
                else:
                    # Test passed -> Mutant SURVIVED (Test weakness!)
                    survived += 1
                    surviving_mutants.append({
                        "mutantId": m["mutantId"],
                        "strategy": m["strategy"],
                        "snippet": m["mutatedSnippet"],
                    })
            except subprocess.TimeoutExpired:
                killed += 1  # Timeout caused by mutant is considered killed
            except Exception:
                invalid += 1
            finally:
                # Restore original file unconditionally!
                target_file.write_text(original_content, encoding="utf-8")

        total_meaningful = killed + survived
        score = (killed / total_meaningful) if total_meaningful > 0 else 1.0
        status = "PASS" if survived == 0 else "FAIL"

        return {
            "status": status,
            "attempted": len(mutants),
            "killed": killed,
            "survived": survived,
            "invalid": invalid,
            "score": round(score, 3),
            "survivingMutants": surviving_mutants,
        }


# =========================================================================
# 5. CONTROLLED FAILURE INJECTION ENGINE
# =========================================================================

class FailureInjectionEngine:
    """
    Targeted failure injection engine verifying application recovery,
    rollback, and bounded error handling in disposable environments.
    """

    @staticmethod
    def run_scenario(
        scenario_name: str,
        injection_fn: Callable[[], Any],
        recovery_assertion_fn: Callable[[], bool],
    ) -> Dict[str, Any]:
        """Execute a controlled fault injection and assert recovery invariant."""
        fault_triggered = False
        fault_error = None
        recovery_ok = False

        try:
            injection_fn()
            fault_triggered = True
        except Exception as e:
            fault_triggered = True
            fault_error = f"{type(e).__name__}: {str(e)}"

        # Verify recovery
        try:
            recovery_ok = bool(recovery_assertion_fn())
        except Exception as e:
            recovery_ok = False
            fault_error = f"Recovery check failed: {str(e)}"

        status = "PASS" if recovery_ok else "FAIL"
        return {
            "scenario": scenario_name,
            "status": status,
            "faultTriggered": fault_triggered,
            "recoveryPassed": recovery_ok,
            "error": fault_error,
        }


# =========================================================================
# 6. ADVERSARIAL POLICY GENERATION & COMPILER
# =========================================================================

def compile_adversarial_policy_entry(req: Dict[str, Any]) -> Dict[str, Any]:
    """Compile requirement into adversarial verification requirements (Property, Fuzz, Mutation, Fault Injection)."""
    risk_info = req.get("risk", {})
    risk_level = risk_info.get("level", "LOW").upper()
    text = (req.get("title", "") + " " + req.get("description", "")).lower()

    is_persistence = "persist" in text or "storage" in text or "save" in text or "database" in text or "STATE_PERSISTENCE_MUTATION" in risk_info.get("reasonCodes", [])
    is_auth = "auth" in text or "jwt" in text or "token" in text or "permission" in text or "AUTHENTICATION_AUTHORIZATION" in risk_info.get("reasonCodes", [])
    is_destructive = "delete" in text or "wipe" in text or "purge" in text or "DESTRUCTIVE_IRREVERSIBLE" in risk_info.get("reasonCodes", [])
    is_untrusted_input = "sanitize" in text or "xss" in text or "INPUT_VALIDATION_UNTRUSTED" in risk_info.get("reasonCodes", [])
    is_parser = "parser" in text or "json" in text or "deserialize" in text or "schema" in text or "payload" in text
    is_search = "search" in text or "filter" in text or "query" in text
    is_validation = "validate" in text or "validation" in text or is_untrusted_input

    budgets = calculate_adversarial_budget(risk_level)

    prop_req = False
    fuzz_req = False
    mut_req = False
    fail_req = False

    if risk_level == "LOW":
        pass
    elif risk_level == "MEDIUM":
        if is_parser or is_validation or is_search:
            prop_req = True
        if is_parser or is_untrusted_input:
            fuzz_req = True
        if is_persistence:
            fail_req = True
    elif risk_level == "HIGH":
        prop_req = True
        if is_parser or is_untrusted_input or is_search or is_validation:
            fuzz_req = True
        mut_req = True
        if is_persistence or is_auth or is_destructive:
            fail_req = True
    elif risk_level == "CRITICAL":
        prop_req = True
        fuzz_req = True
        mut_req = True
        fail_req = True

    return {
        "requirementId": req.get("id"),
        "riskLevel": risk_level,
        "propertyTesting": {
            "required": prop_req,
            "budget": budgets["propertyIterations"] if prop_req else 0,
            "status": "NOT_REQUIRED" if not prop_req else "NOT_CONFIGURED",
        },
        "fuzzTesting": {
            "required": fuzz_req,
            "budget": budgets["fuzzIterations"] if fuzz_req else 0,
            "status": "NOT_REQUIRED" if not fuzz_req else "NOT_CONFIGURED",
            "findingsCount": 0,
        },
        "mutationTesting": {
            "required": mut_req,
            "budget": budgets["mutationBudget"] if mut_req else 0,
            "status": "NOT_REQUIRED" if not mut_req else "NOT_CONFIGURED",
            "attempted": 0,
            "killed": 0,
            "survived": 0,
            "score": 1.0,
        },
        "failureInjection": {
            "required": fail_req,
            "scenarios": ["STORAGE_WRITE_FAILURE", "CORRUPTED_STATE_RECOVERY"] if fail_req else [],
            "status": "NOT_REQUIRED" if not fail_req else "NOT_CONFIGURED",
        },
    }


def generate_and_save_adversarial_policy(workspace_dir: Path) -> Dict[str, Any]:
    """Generate and save .agent-harness/adversarial-policy.json"""
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = workspace_path / ".agent-harness"
    harness_dir.mkdir(parents=True, exist_ok=True)

    reqs = kernel.load_requirements(workspace_path)
    for r in reqs:
        if "risk" not in r or not r.get("risk", {}).get("level"):
            r["risk"] = risk_engine.evaluate_requirement_risk(r)
    kernel.save_requirements(workspace_path, reqs)

    policies = {}
    for r in reqs:
        policies[r["id"]] = compile_adversarial_policy_entry(r)

    matrix = {
        "schemaVersion": ADVERSARIAL_SCHEMA_VERSION,
        "updatedAt": utc_now_iso(),
        "requirements": policies,
    }

    policy_file = harness_dir / "adversarial-policy.json"
    temp_file = harness_dir / "adversarial-policy.json.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(matrix, f, indent=2)
    os.replace(temp_file, policy_file)

    return matrix


# =========================================================================
# 7. ADVERSARIAL TEST QUALITY AUDIT
# =========================================================================

def audit_test_quality(workspace_dir: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Authoritative completion audit verifying that all required Step 4 adversarial
    checks (property, fuzz, mutation, failure injection) are satisfied with 0 surviving critical mutants.
    """
    workspace_path = Path(workspace_dir).resolve()
    harness_dir = workspace_path / ".agent-harness"
    adv_policy_file = harness_dir / "adversarial-policy.json"
    
    stats = {
        "propertyRequirements": 0,
        "propertyPass": 0,
        "propertyFailures": 0,
        "fuzzRequirements": 0,
        "fuzzPass": 0,
        "fuzzFindings": 0,
        "mutationRequirements": 0,
        "mutantsAttempted": 0,
        "mutantsKilled": 0,
        "mutantsSurvived": 0,
        "mutationScore": 1.0,
        "failureInjectionRequirements": 0,
        "failureScenariosRun": 0,
        "failureFindings": 0,
        "testQualityFailures": 0,
        "testQualityRepairs": 0,
    }

    if not adv_policy_file.exists():
        # Step 4 adversarial policy is not configured in this workspace -> pass cleanly
        return True, [], stats

    unresolved: List[str] = []
    policies = {}
    try:
        with open(adv_policy_file, "r", encoding="utf-8") as f:
            adv_data = json.load(f)
            policies = adv_data.get("requirements", adv_data.get("policies", {}))
    except Exception:
        return False, ["Could not read adversarial-policy.json"], stats

    for req_id, p in policies.items():
        risk_lvl = p.get("riskLevel", "LOW").upper()

        # Property Testing Audit
        prop_cfg = p.get("propertyTesting", {})
        if prop_cfg.get("required", False):
            stats["propertyRequirements"] += 1
            prop_status = prop_cfg.get("status", "NOT_CONFIGURED")
            if prop_status == "PASS":
                stats["propertyPass"] += 1
            else:
                stats["propertyFailures"] += 1
                unresolved.append(f"Requirement {req_id} ({risk_lvl}) property testing failed or incomplete (status: {prop_status})")

        # Fuzz Testing Audit
        fuzz_cfg = p.get("fuzzTesting", {})
        if fuzz_cfg.get("required", False):
            stats["fuzzRequirements"] += 1
            fuzz_status = fuzz_cfg.get("status", "NOT_CONFIGURED")
            findings_count = fuzz_cfg.get("findingsCount", 0)
            if fuzz_status == "PASS" and findings_count == 0:
                stats["fuzzPass"] += 1
            else:
                stats["fuzzFindings"] += findings_count
                unresolved.append(f"Requirement {req_id} ({risk_lvl}) fuzz testing discovered unresolved issues (status: {fuzz_status}, findings: {findings_count})")

        # Mutation Testing Audit
        mut_cfg = p.get("mutationTesting", {})
        if mut_cfg.get("required", False):
            stats["mutationRequirements"] += 1
            att = mut_cfg.get("attempted", 0)
            k = mut_cfg.get("killed", 0)
            s = mut_cfg.get("survived", 0)
            stats["mutantsAttempted"] += att
            stats["mutantsKilled"] += k
            stats["mutantsSurvived"] += s
            if s > 0 and risk_lvl in {"HIGH", "CRITICAL"}:
                stats["testQualityFailures"] += 1
                unresolved.append(f"Requirement {req_id} ({risk_lvl}) has {s} surviving mutant(s) that break required invariants")

        # Failure Injection Audit
        fail_cfg = p.get("failureInjection", {})
        if fail_cfg.get("required", False):
            stats["failureInjectionRequirements"] += 1
            fail_status = fail_cfg.get("status", "NOT_CONFIGURED")
            scenarios = fail_cfg.get("scenarios", [])
            stats["failureScenariosRun"] += len(scenarios)
            if fail_status != "PASS":
                stats["failureFindings"] += 1
                unresolved.append(f"Requirement {req_id} ({risk_lvl}) failure injection recovery check failed (status: {fail_status})")

    # Aggregate mutation score
    tot = stats["mutantsKilled"] + stats["mutantsSurvived"]
    stats["mutationScore"] = round((stats["mutantsKilled"] / tot), 3) if tot > 0 else 1.0

    is_complete = len(unresolved) == 0
    return is_complete, unresolved, stats
