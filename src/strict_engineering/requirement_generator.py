"""
Strict Engineering Kernel Step 7 - Requirement Generator & Transition Gate
Compiles atomic, verifiable requirements (REQ-xxx) from canonical decisions.
Enforces the DISCOVERY -> SPECIFICATION transition gate.
Isolates suggestions (SUG-xxx) in a separate sandbox.
"""

import os
import re
import json
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import kernel
    from . import risk_engine
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
    from . import decision_graph
    from . import stopping_engine
    from . import consistency_reviewer
    from . import decision_coverage
    from . import decision_events
    from . import acceptance_protocol
except (ImportError, ValueError):
    try:
        import kernel
        import risk_engine
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
        import decision_graph
        import stopping_engine
        import consistency_reviewer
        import decision_coverage
        import decision_events
        import acceptance_protocol
    except ImportError:
        kernel = None
        risk_engine = None
        frame_mod = None
        concern_mod = None
        decision_mod = None
        decision_graph = None
        stopping_engine = None
        consistency_reviewer = None
        decision_coverage = None
        decision_events = None
        acceptance_protocol = None


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_suggestions_path(workspace_dir: Union[str, Path]) -> Path:
    """Return absolute path to suggestions.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "suggestions.json"


def load_suggestions(workspace_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """Load suggestions from suggestions.json."""
    s_path = get_suggestions_path(workspace_dir)
    if not s_path.exists():
        return []
    try:
        with open(s_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_suggestions(workspace_dir: Union[str, Path], suggestions: List[Dict[str, Any]]) -> None:
    """Atomically save suggestions to suggestions.json."""
    s_path = get_suggestions_path(workspace_dir)
    s_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = s_path.with_suffix(".json.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(suggestions, f, indent=2, sort_keys=True)
    os.replace(temp_path, s_path)


def record_suggestion_sandbox(
    workspace_dir: Union[str, Path],
    title: str,
    description: str,
    source_concern_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Record an unconfirmed idea or model recommendation into the SUGGESTION sandbox (SUG-xxx).
    SUG-xxx items are strictly excluded from requirements.json (INV-7-01, INV-7-03).
    """
    existing = load_suggestions(workspace_dir)
    next_num = len(existing) + 1
    sug_id = f"SUG-{str(next_num).zfill(3)}"

    sug = {
        "id": sug_id,
        "title": title.strip(),
        "description": description.strip(),
        "sourceConcernId": source_concern_id,
        "status": "SANDBOXED",
        "createdAt": utc_now_iso(),
        "metadata": metadata or {},
    }
    existing.append(sug)
    save_suggestions(workspace_dir, existing)
    return sug


def compute_requirement_contract_fingerprint(req: Dict[str, Any]) -> str:
    """
    Requirement Contract Fingerprint V2 (RC2 canonical specification).
    Compute a deterministic SHA-256 hash binding all authority-relevant semantic fields:
    title, description, category, acceptanceCriteria (sorted/normalized),
    sourceIntentIds, sourceDecisionIds, sourceConcernIds, riskLevel, verificationContract.
    Timestamps (createdAt, updatedAt, lockedAt) are strictly excluded.
    """
    title = str(req.get("title", "")).strip()
    desc = str(req.get("description", "")).strip()
    cat = str(req.get("category", "")).strip().upper()
    crit_list = req.get("acceptanceCriteria", [])
    if isinstance(crit_list, list):
        norm_crits = sorted(str(c).strip() for c in crit_list if str(c).strip())
    else:
        norm_crits = [str(crit_list).strip()]
    vcontract = str(req.get("verificationContract", "")).strip()

    sources = req.get("sources", [])
    if not isinstance(sources, list):
        sources = [str(sources)]

    source_intents = req.get("sourceIntentIds")
    if source_intents is None:
        source_intents = sorted(set(
            [str(s).strip() for s in sources if str(s).startswith("INTENT-")] +
            ([str(req["intentId"]).strip()] if req.get("intentId") else [])
        ))
    else:
        source_intents = sorted(str(i).strip() for i in source_intents if str(i).strip())

    source_decisions = req.get("sourceDecisionIds")
    if source_decisions is None:
        source_decisions = sorted(set(
            [str(s).strip() for s in sources if str(s).startswith("DEC-")] +
            ([str(req["decisionId"]).strip()] if req.get("decisionId") else [])
        ))
    else:
        source_decisions = sorted(str(d).strip() for d in source_decisions if str(d).strip())

    source_concerns = req.get("sourceConcernIds")
    if source_concerns is None:
        source_concerns = sorted(set(
            [str(s).strip() for s in sources if str(s).startswith("CONCERN-")] +
            ([str(req["concernId"]).strip()] if req.get("concernId") else [])
        ))
    else:
        source_concerns = sorted(str(c).strip() for c in source_concerns if str(c).strip())

    risk = str(req.get("riskLevel", "MEDIUM")).strip().upper()

    canonical_obj = {
        "title": title,
        "description": desc,
        "category": cat,
        "acceptanceCriteria": norm_crits,
        "sourceIntentIds": source_intents,
        "sourceDecisionIds": source_decisions,
        "sourceConcernIds": source_concerns,
        "riskLevel": risk,
        "verificationContract": vcontract,
    }
    encoded = json.dumps(canonical_obj, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_requirement_quality(req: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate requirement quality against strict standards:
    - Non-empty title (len >= 5), not purely placeholder/tautology ('Implement DEC-xxx')
    - Non-empty description (len >= 10), not purely generic placeholder
    - When acceptanceStatus is PENDING, empty acceptanceCriteria is valid awaiting Test Oracle
    - When acceptance criteria are present: non-empty, zero tautological criteria, zero generic placeholders
    - Returns (is_valid, errors)
    """
    errors: List[str] = []
    if not isinstance(req, dict):
        return False, ["Requirement must be a dictionary."]

    title = str(req.get("title", "")).strip()
    if len(title) < 5:
        errors.append("Requirement title is too short (must be >= 5 chars).")
    if re.match(r"^(?:requirement\s+for\s+dec-\d+|implement\s+dec-\d+)$", title, re.IGNORECASE):
        errors.append(f"Requirement title '{title}' is a placeholder/tautology.")

    desc = str(req.get("description", "")).strip()
    if len(desc) < 10:
        errors.append("Requirement description is too short (must be >= 10 chars).")

    criteria = req.get("acceptanceCriteria")
    # If acceptanceStatus is PENDING, empty criteria is valid awaiting Test Oracle
    if req.get("acceptanceStatus") == "PENDING" and (criteria is None or criteria == []):
        return len(errors) == 0, errors

    placeholder_pattern = re.compile(
        r"\b(expected\s+behavior|behaves\s+according\s+to|implementation\s+satisfies|works\s+correctly|appropriate\s+error|as\s+expected)\b",
        re.IGNORECASE,
    )

    if not criteria or not isinstance(criteria, list):
        errors.append("Requirement must have at least one acceptance criterion.")
    else:
        for idx, crit in enumerate(criteria):
            crit_str = str(crit).strip()
            if not crit_str:
                errors.append(f"Acceptance criterion at index {idx} is empty.")
                continue
            if placeholder_pattern.search(crit_str):
                errors.append(f"Acceptance criterion at index {idx} contains generic placeholder: '{crit_str}'.")
            if re.match(r"^selected\s+option\s+.*is\s+verified", crit_str, re.IGNORECASE):
                errors.append(f"Acceptance criterion at index {idx} is tautological: '{crit_str}'.")

    return len(errors) == 0, errors


def generate_behavioral_acceptance_criteria(
    title: str,
    chosen_option: str,
    category: str = "CORE_BEHAVIOR",
    context: str = "",
) -> List[str]:
    """
    Generate verifiable, observable Given-When-Then behavioral acceptance criteria.
    Avoids placeholders and tautologies like 'expected behavior' or 'behaves according to'.
    """
    clean_title = title.strip()
    clean_opt = chosen_option.strip() if chosen_option else clean_title

    criteria = [
        f"Given a valid operational runtime environment, When executing operations under '{clean_title}', Then the system applies the configured '{clean_opt}' specification and produces deterministic outputs.",
        f"Given abnormal or malformed boundary input for '{clean_title}', When invoked, Then the system safely rejects the operation and emits structured diagnostic error details.",
    ]
    return criteria


def compile_requirements_from_intents(
    workspace_dir: Union[str, Path],
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Directly compile atomic requirements from canonical frame intents (INTENT -> REQ).
    Enforces non-destructive merge with pre-existing requirements in .agent-harness/requirements.json.
    """
    ws = Path(workspace_dir).resolve()
    if frame_mod is None:
        return False, "Frame module unavailable", []

    f_data = frame_mod.load_frame(ws)
    intents = f_data.get("intents", [])
    if not intents:
        goals = f_data.get("goals", [])
        constraints = f_data.get("constraints", [])
        c_idx = 1
        for g in goals:
            g_text = g.get("text", str(g)) if isinstance(g, dict) else str(g)
            if g_text:
                intents.append({
                    "id": f"INTENT-{str(c_idx).zfill(3)}",
                    "text": g_text,
                    "category": "GOAL",
                    "provenance": "EXPLICIT_USER_STATEMENT",
                })
                c_idx += 1
        for c in constraints:
            c_text = c.get("text", str(c)) if isinstance(c, dict) else str(c)
            if c_text:
                intents.append({
                    "id": f"INTENT-{str(c_idx).zfill(3)}",
                    "text": c_text,
                    "category": "CONSTRAINT",
                    "provenance": "EXPLICIT_USER_STATEMENT",
                })
                c_idx += 1

    if not intents:
        return True, "No canonical intents found to compile", []

    existing_reqs = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        existing_reqs = kernel.load_requirements(ws)
    else:
        r_path = ws / ".agent-harness" / "requirements.json"
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    existing_reqs = json.load(f)
            except Exception:
                existing_reqs = []

    existing_by_intent = {r.get("intentId"): r for r in existing_reqs if isinstance(r, dict) and r.get("intentId")}
    existing_by_id = {r.get("id"): r for r in existing_reqs if isinstance(r, dict) and r.get("id")}

    def next_req_id() -> str:
        idx = 1
        while f"REQ-{str(idx).zfill(3)}" in existing_by_id:
            idx += 1
        new_id = f"REQ-{str(idx).zfill(3)}"
        existing_by_id[new_id] = {}
        return new_id

    compiled_intent_reqs: List[Dict[str, Any]] = []

    for it in intents:
        if not isinstance(it, dict):
            continue
        icat = str(it.get("category", "")).upper()
        # Invariant 17: Broad goals are not requirements.
        # Only compile explicit requirements and constraints.
        if icat not in ("EXPLICIT_REQUIREMENT", "EXPLICIT_CONSTRAINT", "CONSTRAINT"):
            continue
        iid = str(it.get("id", "INTENT-001"))
        itext = str(it.get("text", "")).strip()
        if not itext:
            continue

        is_constraint = icat in ("EXPLICIT_CONSTRAINT", "CONSTRAINT")
        req_title = f"{'Constraint' if is_constraint else 'Requirement'}: {itext[:60]}"
        req_desc = f"The system shall implement the explicit user {'constraint' if is_constraint else 'requirement'}: {itext}."
        cat = "IMPLEMENTATION_CONSTRAINT" if is_constraint else "CORE_BEHAVIOR"

        # Dynamic risk evaluation (Fact H & RC-REQ-04)
        r_level = "MEDIUM"
        if risk_engine is not None and hasattr(risk_engine, "evaluate_requirement_risk"):
            try:
                r_eval = risk_engine.evaluate_requirement_risk({"title": req_title, "description": req_desc})
                r_level = r_eval.get("riskLevel", r_eval.get("level", "MEDIUM"))
            except Exception:
                r_level = "MEDIUM"
        elif concern_mod is not None and hasattr(concern_mod, "evaluate_concern_risk"):
            r_level, _ = concern_mod.evaluate_concern_risk(req_title, req_desc, cat)

        ex_r = existing_by_intent.get(iid, {})
        ex_crits = ex_r.get("acceptanceCriteria", [])
        ex_acc_status = ex_r.get("acceptanceStatus", "PENDING" if not ex_crits else "LOCKED")
        ex_acc_locked = ex_r.get("acceptanceLocked", bool(ex_crits))

        req_obj = {
            "id": ex_r.get("id", "TEMP"),
            "title": req_title,
            "description": req_desc,
            "category": cat,
            "status": ex_r.get("status", "DISCOVERED"),
            "required": True,
            "riskLevel": r_level,
            "decisionId": None,
            "concernId": None,
            "intentId": iid,
            "sources": [iid],
            "sourceIntentIds": [iid],
            "sourceDecisionIds": [],
            "sourceConcernIds": [],
            "authority": it.get("provenance", "USER_DIRECT"),
            "acceptanceCriteria": ex_crits,
            "acceptanceStatus": ex_acc_status,
            "acceptanceLocked": ex_acc_locked,
            "verificationContract": f"Verify behavioral compliance of requirement according to user statement {iid}",
            "createdAt": ex_r.get("createdAt", utc_now_iso()),
            "updatedAt": utc_now_iso(),
        }

        if iid in existing_by_intent:
            req_id = ex_r.get("id", next_req_id())
            old_status = ex_r.get("status", "DISCOVERED")
            old_fp = ex_r.get("contractFingerprint")
            req_obj["id"] = req_id
            req_obj["verificationContract"] = f"Verify behavioral compliance of {req_id} according to user statement {iid}"
            req_fp = compute_requirement_contract_fingerprint(req_obj)
            req_obj["contractFingerprint"] = req_fp

            if old_status in ("PASS", "VERIFIED", "IN_PROGRESS"):
                if old_fp and old_fp != req_fp:
                    req_obj["status"] = "STALE"
                    req_obj["previousStatus"] = old_status
                    req_obj["stalenessReason"] = "Requirement contract changed; re-verification required"
                else:
                    req_obj["status"] = old_status
            else:
                req_obj["status"] = old_status
        else:
            req_id = next_req_id()
            req_obj["id"] = req_id
            req_obj["verificationContract"] = f"Verify behavioral compliance of {req_id} according to user statement {iid}"
            req_fp = compute_requirement_contract_fingerprint(req_obj)
            req_obj["contractFingerprint"] = req_fp

        val_ok, _ = validate_requirement_quality(req_obj)
        if val_ok:
            compiled_intent_reqs.append(req_obj)

    # Merge non-destructively
    merged_map = {r["id"]: r for r in existing_reqs if isinstance(r, dict) and r.get("id")}
    for r in compiled_intent_reqs:
        merged_map[r["id"]] = r
    merged_list = list(merged_map.values())

    if kernel is not None and hasattr(kernel, "save_requirements"):
        kernel.save_requirements(ws, merged_list)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        temp_file = r_file.with_suffix(".json.tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(merged_list, f, indent=2, sort_keys=True)
        os.replace(temp_file, r_file)

    if acceptance_protocol is not None and hasattr(acceptance_protocol, "create_acceptance_requests_for_all"):
        try:
            acceptance_protocol.create_acceptance_requests_for_all(ws)
        except Exception:
            pass

    return True, f"Successfully compiled {len(compiled_intent_reqs)} direct requirements from intents", compiled_intent_reqs


def compile_requirements_from_decisions(
    workspace_dir: Union[str, Path],
    include_intents: bool = False,
    **kwargs,
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Compile atomic requirements from confirmed decisions in .agent-harness/decisions.json.
    Enforces stopping, consistency, and graph validation gates.
    Supports 0:1, 1:1, and 1:N cardinality and non-destructive merge with pre-existing requirements.
    Dead bypass flags like 'force' are strictly rejected.
    """
    if "force" in kwargs:
        raise TypeError("compile_requirements_from_decisions does not accept 'force' parameter (dead bypass flags are rejected).")

    ws = Path(workspace_dir).resolve()

    # 1. Gate Check: Stopping conditions
    if stopping_engine is not None:
        status_path = stopping_engine.get_decision_status_path(ws)
        if status_path.exists():
            status_data = stopping_engine.load_decision_status(ws)
        else:
            status_data = stopping_engine.sync_decision_status(ws)
        if not status_data.get("canProceedToSpec", False):
            return False, f"Discovery stopping gate blocked: {status_data.get('reason', 'Conditions not met')}", []

    # 2. Gate Check: Consistency review
    if consistency_reviewer is not None:
        is_consistent, issues = consistency_reviewer.audit_workspace_consistency(ws)
        if not is_consistent:
            blocking_msgs = [i["message"] for i in issues if i.get("severity") == "BLOCKING"]
            return False, f"Consistency review gate blocked: {'; '.join(blocking_msgs)}", []

    # 3. Gate Check: Graph validation
    if decision_graph is not None:
        graph_data = decision_graph.load_decision_graph(ws)
        valid, g_errors = decision_graph.validate_decision_graph(graph_data)
        if not valid:
            return False, f"Decision graph validation gate blocked: {'; '.join(g_errors)}", []

    # If requested, compile direct intent requirements first
    if include_intents:
        compile_requirements_from_intents(ws)

    # Load decisions & concerns
    decisions_list = []
    if decision_mod is not None:
        decisions_list = decision_mod.load_decisions(ws)
    else:
        d_path = ws / ".agent-harness" / "decisions.json"
        if d_path.exists():
            with open(d_path, "r", encoding="utf-8") as f:
                decisions_list = json.load(f)

    concerns_list = []
    if concern_mod is not None:
        concerns_list = concern_mod.load_concerns(ws)
    else:
        c_path = ws / ".agent-harness" / "concerns.json"
        if c_path.exists():
            with open(c_path, "r", encoding="utf-8") as f:
                concerns_list = json.load(f)

    c_map = {c.get("id"): c for c in concerns_list if c.get("id")}

    # Active (non-superseded) decisions
    active_decisions = [
        d for d in decisions_list
        if not d.get("supersededBy") and str(d.get("status", "ACTIVE")).upper() != "SUPERSEDED"
    ]

    # Zero-decision project support (RC-REQ-07, Fact L)
    if not active_decisions:
        curr_reqs = []
        if kernel is not None and hasattr(kernel, "load_requirements"):
            curr_reqs = kernel.load_requirements(ws)
        else:
            r_p = ws / ".agent-harness" / "requirements.json"
            if r_p.exists():
                try:
                    with open(r_p, "r", encoding="utf-8") as f:
                        curr_reqs = json.load(f)
                except Exception:
                    curr_reqs = []
        if curr_reqs:
            return True, f"Zero active decisions; preserved {len(curr_reqs)} direct requirements", []
        return False, "No active decisions available to compile requirements from", []

    # Load existing requirements to preserve IDs and enable non-destructive merge
    existing_reqs = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        existing_reqs = kernel.load_requirements(ws)
    else:
        r_path = ws / ".agent-harness" / "requirements.json"
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    existing_reqs = json.load(f)
            except Exception:
                existing_reqs = []

    dec_to_existing_req: Dict[str, Dict[str, Any]] = {}
    existing_by_id: Dict[str, Dict[str, Any]] = {}
    for r in existing_reqs:
        if isinstance(r, dict):
            d_id = r.get("decisionId")
            if d_id:
                dec_to_existing_req[d_id] = r
            if r.get("id"):
                existing_by_id[r["id"]] = r

    def next_req_id() -> str:
        idx = 1
        while f"REQ-{str(idx).zfill(3)}" in existing_by_id:
            idx += 1
        new_id = f"REQ-{str(idx).zfill(3)}"
        existing_by_id[new_id] = {}
        return new_id

    compiled_reqs: List[Dict[str, Any]] = []

    for d in active_decisions:
        did = d.get("id", "UNKNOWN")
        cid = d.get("concernId")
        associated_concern = c_map.get(cid, {})

        # Cardinality Check: 0:1 cardinality for operational/process decisions
        generates = d.get("generatesRequirements", True)
        num_reqs = d.get("numberOfRequirements", 1)
        dtype = str(d.get("decisionType", "")).upper()
        if (generates is False) or (num_reqs == 0) or (dtype in ("OPERATIONAL", "PROCESS")):
            continue

        # Check for 1:N cardinality (childRequirements / subRequirements)
        sub_specs = d.get("subRequirements") or d.get("childRequirements")
        if sub_specs and isinstance(sub_specs, list) and len(sub_specs) > 0:
            for s_idx, sub in enumerate(sub_specs):
                sub_title = sub.get("title", f"{d.get('title')} - Part {s_idx + 1}")
                sub_opt = sub.get("chosenOption", d.get("chosenOption", ""))
                sub_req_id = next_req_id()
                sub_intent_ref = associated_concern.get("source", {}).get("reference")
                sub_req_obj = {
                    "id": sub_req_id,
                    "title": sub_title,
                    "description": f"The system shall implement {sub_title}: {sub_opt}.",
                    "category": associated_concern.get("category", "CORE_BEHAVIOR"),
                    "status": "DISCOVERED",
                    "required": True,
                    "riskLevel": associated_concern.get("riskLevel", "MEDIUM"),
                    "decisionId": did,
                    "concernId": cid,
                    "intentId": sub_intent_ref or "ORIGINAL_INTENT",
                    "sources": [did] + ([cid] if cid else []),
                    "sourceIntentIds": [sub_intent_ref] if sub_intent_ref else [],
                    "sourceDecisionIds": [did],
                    "sourceConcernIds": [cid] if cid else [],
                    "authority": d.get("authority", "USER_DIRECT"),
                    "acceptanceCriteria": [],
                    "acceptanceStatus": "PENDING",
                    "acceptanceLocked": False,
                    "verificationContract": f"Verify behavioral compliance of {sub_req_id} according to decision {did}",
                    "createdAt": utc_now_iso(),
                    "updatedAt": utc_now_iso(),
                }
                sub_req_obj["contractFingerprint"] = compute_requirement_contract_fingerprint(sub_req_obj)
                val_ok, _ = validate_requirement_quality(sub_req_obj)
                if val_ok:
                    d.setdefault("affectedRequirements", [])
                    if sub_req_id not in d["affectedRequirements"]:
                        d["affectedRequirements"].append(sub_req_id)
                    compiled_reqs.append(sub_req_obj)
            continue

        # Standard 1:1 cardinality
        existing_target = dec_to_existing_req.get(did, {})
        if did in dec_to_existing_req:
            req_id = existing_target.get("id", next_req_id())
            prev_status = existing_target.get("status", "DISCOVERED")
        else:
            req_id = next_req_id()
            prev_status = "DISCOVERED"

        title = d.get("title", f"Requirement for {did}")
        chosen_opt = d.get("chosenOption", "")
        rationale = d.get("rationale", "")

        description = f"The system shall implement {title}: {chosen_opt}."
        if rationale:
            description += f" (Rationale: {rationale})"

        # Determine risk level
        concern_risk = associated_concern.get("riskLevel")
        if not concern_risk and risk_engine is not None and hasattr(risk_engine, "evaluate_requirement_risk"):
            try:
                r_eval = risk_engine.evaluate_requirement_risk({"title": title, "description": description})
                concern_risk = r_eval.get("level", "MEDIUM") if isinstance(r_eval, dict) else "MEDIUM"
            except Exception:
                concern_risk = "MEDIUM"
        if not concern_risk:
            concern_risk = "MEDIUM"

        intent_ref = associated_concern.get("source", {}).get("reference", "ORIGINAL_INTENT")
        category = associated_concern.get("category", "CORE_BEHAVIOR")

        ex_crits = existing_target.get("acceptanceCriteria", [])
        ex_acc_status = existing_target.get("acceptanceStatus", "PENDING" if not ex_crits else "LOCKED")
        ex_acc_locked = existing_target.get("acceptanceLocked", bool(ex_crits))

        req_obj = {
            "id": req_id,
            "title": title,
            "description": description,
            "category": category,
            "status": prev_status,
            "required": True,
            "riskLevel": concern_risk,
            "decisionId": did,
            "concernId": cid,
            "intentId": intent_ref,
            "sources": [did] + ([cid] if cid else []),
            "sourceIntentIds": [intent_ref] if intent_ref else [],
            "sourceDecisionIds": [did],
            "sourceConcernIds": [cid] if cid else [],
            "authority": d.get("authority", "USER_DIRECT"),
            "acceptanceCriteria": ex_crits,
            "acceptanceStatus": ex_acc_status,
            "acceptanceLocked": ex_acc_locked,
            "verificationContract": f"Verify behavioral compliance of {req_id} according to decision {did}",
            "createdAt": existing_target.get("createdAt", utc_now_iso()),
            "updatedAt": utc_now_iso(),
        }

        req_obj["contractFingerprint"] = compute_requirement_contract_fingerprint(req_obj)

        val_ok, val_errs = validate_requirement_quality(req_obj)
        if val_ok:
            d.setdefault("affectedRequirements", [])
            if req_id not in d["affectedRequirements"]:
                d["affectedRequirements"].append(req_id)
            compiled_reqs.append(req_obj)

    # Save decisions with updated affectedRequirements
    if decision_mod is not None:
        decision_mod.save_decisions(ws, decisions_list)
    else:
        with open(ws / ".agent-harness" / "decisions.json", "w", encoding="utf-8") as f:
            json.dump(decisions_list, f, indent=2)

    # Non-destructive merge with pre-existing requirements
    merged_map = {r["id"]: r for r in existing_reqs if isinstance(r, dict) and r.get("id")}
    superseded_decision_ids = {
        d.get("id") for d in decisions_list
        if d.get("supersededBy") or str(d.get("status", "")).upper() == "SUPERSEDED"
    }
    for r in merged_map.values():
        if r.get("decisionId") in superseded_decision_ids and r.get("status") != "STALE":
            r["status"] = "STALE"
            r["stalenessReason"] = f"Derives from superseded decision {r.get('decisionId')}"
            r["updatedAt"] = utc_now_iso()

    for r in compiled_reqs:
        rid = r["id"]
        if rid in merged_map:
            ex_r = merged_map[rid]
            old_status = ex_r.get("status", "DISCOVERED")
            old_fp = ex_r.get("contractFingerprint")
            new_fp = r.get("contractFingerprint")
            if old_status in ("PASS", "VERIFIED", "IN_PROGRESS"):
                if old_fp and old_fp != new_fp:
                    r["status"] = "STALE"
                    r["previousStatus"] = old_status
                    r["stalenessReason"] = "Requirement contract changed; re-verification required"
                else:
                    r["status"] = old_status
            else:
                r["status"] = old_status
        merged_map[rid] = r

    final_merged_reqs = list(merged_map.values())

    # Save merged requirements
    if kernel is not None and hasattr(kernel, "save_requirements"):
        kernel.save_requirements(ws, final_merged_reqs)
    else:
        r_file = ws / ".agent-harness" / "requirements.json"
        temp_file = r_file.with_suffix(".json.tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(final_merged_reqs, f, indent=2, sort_keys=True)
        os.replace(temp_file, r_file)

    # Sync decision graph and coverage matrix (FAIL CLOSED on errors)
    if decision_graph is not None:
        try:
            decision_graph.sync_decision_graph(ws)
        except Exception as e:
            return False, f"Critical sync failed (decision_graph): {e}", []

    if decision_coverage is not None:
        try:
            decision_coverage.sync_decision_coverage(ws)
        except Exception as e:
            return False, f"Critical sync failed (decision_coverage): {e}", []

    # Record event in ledger (FAIL CLOSED on errors)
    if decision_events is not None:
        try:
            decision_events.record_decision_event(
                workspace_dir=ws,
                event_type="REQUIREMENTS_GENERATED",
                payload={
                    "requirementCount": len(compiled_reqs),
                    "totalRequirementCount": len(final_merged_reqs),
                    "requirementIds": [r["id"] for r in compiled_reqs],
                },
                actor="requirement-generator",
            )
        except Exception as e:
            return False, f"Critical sync failed (decision_events): {e}", []

    # Auto-emit acceptance requests for pending requirements
    if acceptance_protocol is not None and hasattr(acceptance_protocol, "create_acceptance_requests_for_all"):
        try:
            acceptance_protocol.create_acceptance_requests_for_all(ws)
        except Exception:
            pass

    return True, f"Successfully compiled {len(compiled_reqs)} requirements from active decisions", compiled_reqs


def compile_all_requirements(
    workspace_dir: Union[str, Path],
) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Compile both direct frame intent requirements and decision requirements into requirements.json.
    """
    return compile_requirements_from_decisions(workspace_dir, include_intents=True)
