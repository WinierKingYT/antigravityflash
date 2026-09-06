"""
Strict Engineering Kernel Step 7 - Project Frame Model & Storage
Implements the Structured Project Frame (.agent-harness/frame.json), schemaVersion: "7.0",
with atomic persistence, strict schema validation, and heuristic requirement discovery extractor.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import kernel
except (ImportError, ValueError):
    try:
        import kernel
    except ImportError:
        kernel = None

SCHEMA_VERSION = "7.0"

VALID_PROVENANCE_TYPES = {
    "EXPLICIT_USER_STATEMENT",
    "AUTHORIZED_DECISION",
    "SAFE_INFERENCE",
    "MODEL_HYPOTHESIS",
    "USER_EXPLICIT",
    "EXTRACTED_FROM_DOC",
    "INTERVIEW_CONFIRMED",
    "CODEBASE_OBSERVED",
    "POLICY_DERIVED",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_frame_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to frame.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "frame.json"


def _normalize_provenance_item(
    item: Union[Dict[str, str], str],
    default_provenance: str = "EXPLICIT_USER_STATEMENT",
) -> Dict[str, str]:
    """Normalize item to {text: str, provenance: str} dict."""
    if isinstance(item, dict):
        text = str(item.get("text", "")).strip()
        prov = str(item.get("provenance", default_provenance)).strip()
        if prov not in VALID_PROVENANCE_TYPES:
            prov = default_provenance
        return {"text": text, "provenance": prov}
    elif isinstance(item, str):
        return {"text": item.strip(), "provenance": default_provenance}
    else:
        return {"text": str(item).strip(), "provenance": default_provenance}


# Public alias for provenance normalization
normalize_text_provenance = _normalize_provenance_item



def create_initial_frame(
    project_goal: str,
    primary_user: str = "",
    problem_statement: str = "",
    explicit_constraints: Optional[List[Union[Dict[str, str], str]]] = None,
    explicit_non_goals: Optional[List[Union[Dict[str, str], str]]] = None,
    known_facts: Optional[List[Union[Dict[str, str], str]]] = None,
    unknowns: Optional[List[Union[Dict[str, str], str]]] = None,
    assumptions: Optional[List[Union[Dict[str, str], str]]] = None,
    source_references: Optional[List[str]] = None,
    success_definition: Optional[List[Union[Dict[str, str], str]]] = None,
) -> Dict[str, Any]:
    """
    Construct a canonical Structured Project Frame dict conforming to schemaVersion "7.0".
    """
    cleaned_goal = (project_goal or "").strip()
    cleaned_user = (primary_user or "developer").strip()
    cleaned_problem = (problem_statement or cleaned_goal).strip()

    def norm_list(items: Optional[List[Any]], default_prov: str = "EXPLICIT_USER_STATEMENT") -> List[Dict[str, str]]:
        if not items:
            return []
        normalized = []
        for it in items:
            entry = _normalize_provenance_item(it, default_prov)
            if entry["text"]:
                normalized.append(entry)
        return normalized

    success_def = norm_list(success_definition, "EXPLICIT_USER_STATEMENT")
    if not success_def and cleaned_goal:
        success_def = [{"text": f"Successfully complete: {cleaned_goal}", "provenance": "SAFE_INFERENCE"}]

    norm_constraints = norm_list(explicit_constraints, "EXPLICIT_USER_STATEMENT")
    norm_nongoals = norm_list(explicit_non_goals, "EXPLICIT_USER_STATEMENT")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "projectGoal": cleaned_goal,
        "primaryUser": cleaned_user,
        "problemStatement": cleaned_problem,
        "successDefinition": success_def,
        "explicitConstraints": norm_constraints,
        "constraints": norm_constraints,
        "explicitNonGoals": norm_nongoals,
        "nonGoals": norm_nongoals,
        "goals": [cleaned_goal] if cleaned_goal else [],
        "knownFacts": norm_list(known_facts, "EXPLICIT_USER_STATEMENT"),
        "unknowns": norm_list(unknowns, "MODEL_HYPOTHESIS"),
        "assumptions": norm_list(assumptions, "SAFE_INFERENCE"),
        "sourceReferences": [str(s).strip() for s in (source_references or []) if str(s).strip()],
        "updatedAt": utc_now_iso(),
    }



def load_frame(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Load .agent-harness/frame.json from workspace. Returns empty dict if not found.
    """
    frame_path = get_frame_path(workspace_dir)
    if not frame_path.exists():
        return {}
    try:
        with open(frame_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_frame(workspace_dir: Union[str, Path], frame_data: Dict[str, Any]) -> None:
    """
    Atomically persist frame_data to .agent-harness/frame.json using a .tmp file.
    """
    frame_path = get_frame_path(workspace_dir)
    frame_path.parent.mkdir(parents=True, exist_ok=True)
    frame_data["updatedAt"] = utc_now_iso()

    temp_path = frame_path.with_name(f"{frame_path.name}.tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(frame_data, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, frame_path)


def validate_frame(frame_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Strictly validate that frame_data conforms to schemaVersion 7.0 requirements.
    Returns (isValid, errors).
    """
    errors: List[str] = []
    if not isinstance(frame_data, dict):
        return False, ["Frame data must be a JSON object (dict)."]

    # 1. schemaVersion
    if frame_data.get("schemaVersion") != SCHEMA_VERSION:
        errors.append(f"schemaVersion must be '{SCHEMA_VERSION}', got '{frame_data.get('schemaVersion')}'.")

    # 2. String fields
    for str_field in ["projectGoal", "primaryUser", "problemStatement"]:
        val = frame_data.get(str_field)
        if val is None or not isinstance(val, str):
            errors.append(f"Field '{str_field}' must be a string.")
        elif str_field == "projectGoal" and not val.strip():
            errors.append("Field 'projectGoal' must not be empty.")

    # 3. Provenance list fields
    prov_list_fields = [
        "successDefinition",
        "explicitConstraints",
        "explicitNonGoals",
        "knownFacts",
        "unknowns",
        "assumptions",
    ]
    for field in prov_list_fields:
        items = frame_data.get(field)
        if not isinstance(items, list):
            errors.append(f"Field '{field}' must be a list of provenance entries.")
            continue
        for idx, entry in enumerate(items):
            if not isinstance(entry, dict):
                errors.append(f"Field '{field}[{idx}]' must be a dict with 'text' and 'provenance'.")
                continue
            text = entry.get("text")
            prov = entry.get("provenance")
            if not isinstance(text, str) or not text.strip():
                errors.append(f"Field '{field}[{idx}].text' must be a non-empty string.")
            if prov not in VALID_PROVENANCE_TYPES:
                errors.append(
                    f"Field '{field}[{idx}].provenance' ('{prov}') must be one of {sorted(VALID_PROVENANCE_TYPES)}."
                )

    # 4. sourceReferences
    refs = frame_data.get("sourceReferences")
    if not isinstance(refs, list):
        errors.append("Field 'sourceReferences' must be a list of strings.")
    else:
        for idx, r in enumerate(refs):
            if not isinstance(r, str):
                errors.append(f"Field 'sourceReferences[{idx}]' must be a string.")

    # 5. updatedAt
    updated_at = frame_data.get("updatedAt")
    if not isinstance(updated_at, str) or not updated_at.strip():
        errors.append("Field 'updatedAt' must be an ISO timestamp string.")

    return len(errors) == 0, errors


def extract_frame_from_raw_request(original_intent: str) -> Dict[str, Any]:
    """
    Heuristic requirement discovery extractor that parses raw unstructured user intent
    into an initial structured project frame (schemaVersion: '7.0').
    Identifies goals, primary users, constraints, non-goals, known facts, and unknowns.
    """
    raw_text = (original_intent or "").strip()
    if not raw_text:
        return create_initial_frame(
            project_goal="Unspecified goal",
            primary_user="developer",
            problem_statement="Unspecified request",
        )

    lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]

    # Section patterns
    section_map: Dict[str, List[str]] = {
        "goal": [],
        "user": [],
        "problem": [],
        "success": [],
        "non_goals": [],
        "constraints": [],
        "facts": [],
        "unknowns": [],
        "assumptions": [],
    }

    current_section: Optional[str] = None

    non_goal_headers = re.compile(r"^(?:#+|\*+)?\s*(?:explicit\s+)?(?:non[- ]goals?|out of scope|excluded)(?:\s*:)?", re.IGNORECASE)
    constraint_headers = re.compile(r"^(?:#+|\*+)?\s*(?:explicit\s+)?(?:constraints?|limitations?|rules|restrictions)(?:\s*:)?", re.IGNORECASE)
    fact_headers = re.compile(r"^(?:#+|\*+)?\s*(?:known\s+)?(?:facts?|context|environment|current state)(?:\s*:)?", re.IGNORECASE)
    success_headers = re.compile(r"^(?:#+|\*+)?\s*(?:success\s+criteria|acceptance\s+criteria|success\s+definition|deliverables?)(?:\s*:)?", re.IGNORECASE)
    goal_headers = re.compile(r"^(?:#+|\*+)?\s*(?:project\s+)?(?:goals?|objective|purpose|task)(?:\s*:)?", re.IGNORECASE)
    problem_headers = re.compile(r"^(?:#+|\*+)?\s*(?:problem(?:\s+statement)?|background|motivation)(?:\s*:)?", re.IGNORECASE)
    unknown_headers = re.compile(r"^(?:#+|\*+)?\s*(?:unknowns?|open questions?|tbd|to be determined)(?:\s*:)?", re.IGNORECASE)
    assumption_headers = re.compile(r"^(?:#+|\*+)?\s*(?:assumptions?)(?:\s*:)?", re.IGNORECASE)
    user_headers = re.compile(r"^(?:#+|\*+)?\s*(?:primary\s+)?(?:user|audience|actor|persona)(?:\s*:)?", re.IGNORECASE)

    # Heuristic inline markers
    non_goal_keyword_regex = re.compile(
        r"\b(?:non[- ]goals?|out of scope|do not|don't|must not|should not|will not|won't|never|avoid|no need to|exclude|excluding|not support)\b",
        re.IGNORECASE,
    )
    constraint_keyword_regex = re.compile(
        r"\b(?:constraint|constraints|must|shall|strictly|limit|limited to|maximum|minimum|at least|at most|no external|requires?|only use|only support|cannot)\b",
        re.IGNORECASE,
    )
    fact_keyword_regex = re.compile(
        r"\b(?:we have|currently|existing|already|workspace|environment|running on|python\s+3\.\d+|windows|linux|macOS|version)\b",
        re.IGNORECASE,
    )
    unknown_keyword_regex = re.compile(
        r"\b(?:unknown|unsure|tbd|to be decided|open question|verify whether|unclear)\b",
        re.IGNORECASE,
    )
    assumption_keyword_regex = re.compile(
        r"\b(?:assume|assuming|assumption|presume|presuming)\b",
        re.IGNORECASE,
    )

    for line in lines:
        # Check if line matches a section header
        if non_goal_headers.match(line):
            current_section = "non_goals"
            cleaned_line = non_goal_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["non_goals"].append(cleaned_line)
            continue
        elif constraint_headers.match(line):
            current_section = "constraints"
            cleaned_line = constraint_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["constraints"].append(cleaned_line)
            continue
        elif fact_headers.match(line):
            current_section = "facts"
            cleaned_line = fact_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["facts"].append(cleaned_line)
            continue
        elif success_headers.match(line):
            current_section = "success"
            cleaned_line = success_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["success"].append(cleaned_line)
            continue
        elif goal_headers.match(line):
            current_section = "goal"
            cleaned_line = goal_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["goal"].append(cleaned_line)
            continue
        elif problem_headers.match(line):
            current_section = "problem"
            cleaned_line = problem_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["problem"].append(cleaned_line)
            continue
        elif unknown_headers.match(line):
            current_section = "unknowns"
            cleaned_line = unknown_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["unknowns"].append(cleaned_line)
            continue
        elif assumption_headers.match(line):
            current_section = "assumptions"
            cleaned_line = assumption_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["assumptions"].append(cleaned_line)
            continue
        elif user_headers.match(line):
            current_section = "user"
            cleaned_line = user_headers.sub("", line).strip(" :-*#")
            if cleaned_line:
                section_map["user"].append(cleaned_line)
            continue

        # If inside a designated section
        cleaned = re.sub(r"^[-*•\d.]+\s*", "", line).strip()
        if not cleaned:
            continue

        if current_section and current_section in section_map:
            section_map[current_section].append(cleaned)
            continue

        # Otherwise perform sentence/clause level classification
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", cleaned) if s.strip()]
        if not sentences:
            sentences = [cleaned]

        for sent in sentences:
            if non_goal_keyword_regex.search(sent):
                section_map["non_goals"].append(sent)
            elif constraint_keyword_regex.search(sent):
                section_map["constraints"].append(sent)
            elif unknown_keyword_regex.search(sent):
                section_map["unknowns"].append(sent)
            elif assumption_keyword_regex.search(sent):
                section_map["assumptions"].append(sent)
            elif fact_keyword_regex.search(sent):
                section_map["facts"].append(sent)
            else:
                if not section_map["goal"]:
                    section_map["goal"].append(sent)
                else:
                    section_map["problem"].append(sent)

    # Derive fields
    if section_map["goal"]:
        project_goal = " ".join(section_map["goal"]).strip()
    else:
        project_goal = lines[0].strip() if lines else "Unspecified project goal"

    # Clean project goal if it starts with markdown headers
    project_goal = re.sub(r"^#+\s*", "", project_goal).strip()

    # Extract primary user
    primary_user = "developer"
    if section_map["user"]:
        primary_user = section_map["user"][0].strip()
    else:
        user_matches = re.findall(r"\b(developer|end[- ]user|administrator|admin|operator|engineer|auditor|customer|client|guest|user)\b", raw_text, re.IGNORECASE)
        if user_matches:
            primary_user = user_matches[0].lower()

    # Problem statement
    if section_map["problem"]:
        problem_statement = " ".join(section_map["problem"]).strip()
    else:
        problem_statement = project_goal

    # Build provenance dicts
    explicit_non_goals = [
        {"text": text, "provenance": "EXPLICIT_USER_STATEMENT"}
        for text in section_map["non_goals"]
    ]
    explicit_constraints = [
        {"text": text, "provenance": "EXPLICIT_USER_STATEMENT"}
        for text in section_map["constraints"]
    ]
    known_facts = [
        {"text": text, "provenance": "EXPLICIT_USER_STATEMENT"}
        for text in section_map["facts"]
    ]
    success_def = [
        {"text": text, "provenance": "EXPLICIT_USER_STATEMENT"}
        for text in section_map["success"]
    ]
    unknowns = [
        {"text": text, "provenance": "MODEL_HYPOTHESIS"}
        for text in section_map["unknowns"]
    ]
    assumptions = [
        {"text": text, "provenance": "SAFE_INFERENCE"}
        for text in section_map["assumptions"]
    ]

    source_references = [f"original_intent_sha256:{len(raw_text)}chars"]

    return create_initial_frame(
        project_goal=project_goal,
        primary_user=primary_user,
        problem_statement=problem_statement,
        explicit_constraints=explicit_constraints,
        explicit_non_goals=explicit_non_goals,
        known_facts=known_facts,
        unknowns=unknowns,
        assumptions=assumptions,
        source_references=source_references,
        success_definition=success_def,
    )


# Canonical alias for Step 7 discovery orchestration
extract_frame_from_intent = extract_frame_from_raw_request

