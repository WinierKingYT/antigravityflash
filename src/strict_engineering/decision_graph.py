"""
Strict Engineering Kernel Step 7 - Decision Graph Topology Engine
Implements the Directed Acyclic Graph connecting Concerns -> Decisions -> Affected Concerns -> Requirements.
Canonical persistence file: .agent-harness/decision-graph.json.
"""

import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union, Set
from collections import deque

try:
    from . import kernel
    from . import concern
    from . import decision
except (ImportError, ValueError):
    try:
        import kernel
        import concern
        import decision
    except ImportError:
        kernel = None
        concern = None
        decision = None


GRAPH_VERSION = "7.0"
ALLOWED_NODE_TYPES = {"CONCERN", "DECISION", "REQUIREMENT"}
ALLOWED_RELATIONSHIPS = {"RESOLVES", "AFFECTS", "DEPENDS_ON", "SUPERSEDES", "DERIVES"}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_decision_graph_path(workspace_dir: Union[str, Path]) -> Path:
    """Return the absolute Path to decision-graph.json in .agent-harness."""
    return Path(workspace_dir).resolve() / ".agent-harness" / "decision-graph.json"


def load_decision_graph(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Load decision graph from .agent-harness/decision-graph.json.
    Returns a default empty graph dictionary if file does not exist or cannot be parsed.
    """
    graph_path = get_decision_graph_path(workspace_dir)
    if not graph_path.exists():
        return {
            "nodes": {},
            "edges": [],
            "metadata": {
                "generatedAt": utc_now_iso(),
                "nodeCount": 0,
                "edgeCount": 0,
                "version": GRAPH_VERSION,
            },
        }
    try:
        with open(graph_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "nodes" in data and "edges" in data:
                return data
            return {
                "nodes": {},
                "edges": [],
                "metadata": {
                    "generatedAt": utc_now_iso(),
                    "nodeCount": 0,
                    "edgeCount": 0,
                    "version": GRAPH_VERSION,
                },
            }
    except Exception:
        return {
            "nodes": {},
            "edges": [],
            "metadata": {
                "generatedAt": utc_now_iso(),
                "nodeCount": 0,
                "edgeCount": 0,
                "version": GRAPH_VERSION,
            },
        }


def save_decision_graph(workspace_dir: Union[str, Path], graph_data: Dict[str, Any]) -> None:
    """
    Atomically persist decision graph to .agent-harness/decision-graph.json via a .tmp file.
    """
    graph_path = get_decision_graph_path(workspace_dir)
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = graph_path.with_name(f"{graph_path.name}.tmp")

    # Update metadata counts
    nodes = graph_data.get("nodes", {})
    edges = graph_data.get("edges", [])
    if "metadata" not in graph_data or not isinstance(graph_data["metadata"], dict):
        graph_data["metadata"] = {}
    graph_data["metadata"]["nodeCount"] = len(nodes)
    graph_data["metadata"]["edgeCount"] = len(edges)
    graph_data["metadata"]["generatedAt"] = utc_now_iso()
    graph_data["metadata"]["version"] = GRAPH_VERSION

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, graph_path)


def build_decision_graph(
    concerns: Union[List[Dict[str, Any]], Dict[str, Any]],
    decisions: Union[List[Dict[str, Any]], Dict[str, Any]],
    requirements: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build directed acyclic graph connecting:
    Concerns -> Decisions -> Affected Concerns -> Requirements.
    """
    # Normalize concerns list
    c_list: List[Dict[str, Any]] = []
    if isinstance(concerns, list):
        c_list = concerns
    elif isinstance(concerns, dict):
        if "concerns" in concerns and isinstance(concerns["concerns"], list):
            c_list = concerns["concerns"]
        else:
            c_list = list(concerns.values())

    # Normalize decisions list
    d_list: List[Dict[str, Any]] = []
    if isinstance(decisions, list):
        d_list = decisions
    elif isinstance(decisions, dict):
        if "decisions" in decisions and isinstance(decisions["decisions"], list):
            d_list = decisions["decisions"]
        else:
            d_list = list(decisions.values())

    # Normalize requirements list
    r_list: List[Dict[str, Any]] = []
    if requirements:
        if isinstance(requirements, list):
            r_list = requirements
        elif isinstance(requirements, dict):
            if "requirements" in requirements and isinstance(requirements["requirements"], list):
                r_list = requirements["requirements"]
            else:
                r_list = list(requirements.values())

    nodes: Dict[str, Any] = {}
    edges: List[Dict[str, str]] = []
    edge_keys: Set[Tuple[str, str, str]] = set()

    def add_edge(source: str, target: str, relationship: str) -> None:
        key = (source, target, relationship)
        if key not in edge_keys:
            edge_keys.add(key)
            edges.append({
                "source": source,
                "target": target,
                "relationship": relationship,
            })

    # 1. Populate Concern nodes
    for c in c_list:
        cid = c.get("id")
        if not cid:
            continue
        nodes[cid] = {
            "id": cid,
            "type": "CONCERN",
            "data": c,
            "status": c.get("status", "DISCOVERED"),
        }

    # 2. Populate Decision nodes
    for d in d_list:
        did = d.get("id")
        if not did:
            continue
        is_superseded = bool(d.get("supersededBy"))
        d_status = "SUPERSEDED" if is_superseded else "ACTIVE"
        nodes[did] = {
            "id": did,
            "type": "DECISION",
            "data": d,
            "status": d_status,
        }

    # 3. Populate Requirement nodes
    for r in r_list:
        rid = r.get("id") or r.get("req_id")
        if not rid:
            continue
        nodes[rid] = {
            "id": rid,
            "type": "REQUIREMENT",
            "data": r,
            "status": r.get("status", "DISCOVERED"),
        }

    # 4. Create Edges
    # 4a. Concern dependencies (dependsOn & blocks)
    for c in c_list:
        cid = c.get("id")
        if not cid or cid not in nodes:
            continue
        # If c dependsOn prerequisite p, p precedes c (p -> c)
        for dep in c.get("dependsOn", []):
            if dep in nodes:
                add_edge(dep, cid, "DEPENDS_ON")
        # If c blocks b, c precedes b (c -> b)
        for blk in c.get("blocks", []):
            if blk in nodes:
                add_edge(cid, blk, "DEPENDS_ON")

    # 4b. Decisions: Concerns -> Decisions (RESOLVES)
    for d in d_list:
        did = d.get("id")
        if not did or did not in nodes:
            continue
        cid = d.get("concernId")
        if cid and cid in nodes:
            add_edge(cid, did, "RESOLVES")

        # Decisions -> Affected Concerns (AFFECTS)
        for aff_c in d.get("affectedConcerns", []):
            if aff_c in nodes and aff_c != cid:
                add_edge(did, aff_c, "AFFECTS")

        # Decisions -> Affected Requirements (DERIVES)
        for aff_r in d.get("affectedRequirements", []):
            if aff_r in nodes:
                add_edge(did, aff_r, "DERIVES")

        # Supersedes edge
        super_by = d.get("supersededBy")
        if super_by and super_by in nodes:
            add_edge(did, super_by, "SUPERSEDES")

    # 4c. Requirements deriving from decisions or concerns
    for r in r_list:
        rid = r.get("id") or r.get("req_id")
        if not rid or rid not in nodes:
            continue
        # Trace decision
        d_ref = r.get("decisionId") or r.get("sourceDecision")
        if d_ref and d_ref in nodes:
            add_edge(d_ref, rid, "DERIVES")
        # Trace concern
        c_ref = r.get("concernId") or r.get("sourceConcern")
        if c_ref and c_ref in nodes:
            add_edge(c_ref, rid, "DERIVES")

    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "generatedAt": utc_now_iso(),
            "nodeCount": len(nodes),
            "edgeCount": len(edges),
            "version": GRAPH_VERSION,
        },
    }


def compute_downstream_reach(graph_data: Dict[str, Any], node_id: str) -> int:
    """
    Compute the transitive closure count of all downstream nodes reachable from node_id.
    Traverses forward directed edges (source -> target).
    """
    if not isinstance(graph_data, dict) or "edges" not in graph_data:
        return 0

    edges = graph_data.get("edges", [])
    nodes = graph_data.get("nodes", {})
    if node_id not in nodes and not any(e.get("source") == node_id for e in edges):
        return 0

    adj: Dict[str, List[str]] = {}
    for e in edges:
        s = e.get("source")
        t = e.get("target")
        if s and t:
            adj.setdefault(s, []).append(t)

    visited: Set[str] = set()
    queue = deque([node_id])

    while queue:
        curr = queue.popleft()
        for neighbor in adj.get(curr, []):
            if neighbor not in visited and neighbor != node_id:
                visited.add(neighbor)
                queue.append(neighbor)

    return len(visited)


def validate_decision_graph(graph_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate decision graph integrity:
    - Detects invalid cycles (DFS cycle detection)
    - Detects dangling references (edges referencing nonexistent node IDs)
    - Detects missing source provenance in decisions
    - Detects multiple active conflicting decisions for the same concern
    - Detects superseded decisions still marked active
    - Detects orphaned required requirements without decision/intent trace
    - Fails closed on graph corruption
    """
    errors: List[str] = []

    # 1. Structural integrity check (fail closed on corruption)
    if not isinstance(graph_data, dict):
        return False, ["Corrupt decision graph: Root object must be a dictionary."]

    nodes = graph_data.get("nodes")
    edges = graph_data.get("edges")
    metadata = graph_data.get("metadata")

    if not isinstance(nodes, dict):
        return False, ["Corrupt decision graph: 'nodes' must be a dictionary."]
    if not isinstance(edges, list):
        return False, ["Corrupt decision graph: 'edges' must be a list."]
    if not isinstance(metadata, dict):
        return False, ["Corrupt decision graph: 'metadata' must be a dictionary."]

    # 2. Dangling references & Edge schema check
    adj: Dict[str, List[str]] = {}
    for idx, e in enumerate(edges):
        if not isinstance(e, dict):
            errors.append(f"Edge at index {idx} is not a dictionary.")
            continue
        src = e.get("source")
        tgt = e.get("target")
        rel = e.get("relationship")

        if not src or not tgt:
            errors.append(f"Edge at index {idx} is missing source or target: {e}")
            continue

        if rel and rel not in ALLOWED_RELATIONSHIPS:
            errors.append(f"Edge ({src} -> {tgt}) has unknown relationship '{rel}'. Allowed: {ALLOWED_RELATIONSHIPS}")

        if src not in nodes:
            errors.append(f"Dangling reference: edge source '{src}' does not exist in graph nodes.")
        if tgt not in nodes:
            errors.append(f"Dangling reference: edge target '{tgt}' does not exist in graph nodes.")

        if src in nodes and tgt in nodes:
            adj.setdefault(src, []).append(tgt)

    # 3. Cycle detection (DFS coloring: 0=WHITE, 1=GRAY, 2=BLACK)
    visited_state: Dict[str, int] = {}
    cycle_detected = False

    def dfs_cycle(u: str, path: List[str]) -> bool:
        visited_state[u] = 1  # GRAY (visiting)
        for v in adj.get(u, []):
            if visited_state.get(v, 0) == 1:
                # Cycle found!
                cycle_idx = path.index(v) if v in path else 0
                cycle_path = path[cycle_idx:] + [v]
                errors.append(f"Cycle detected in decision graph: {' -> '.join(cycle_path)}")
                return True
            elif visited_state.get(v, 0) == 0:
                if dfs_cycle(v, path + [v]):
                    return True
        visited_state[u] = 2  # BLACK (visited)
        return False

    for node_id in list(nodes.keys()):
        if visited_state.get(node_id, 0) == 0:
            if dfs_cycle(node_id, [node_id]):
                cycle_detected = True

    # 4. Decision Node Checks: Provenance, Multiple Active Decisions, Superseded Active
    active_decisions_by_concern: Dict[str, List[str]] = {}

    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            errors.append(f"Node '{node_id}' is not a dictionary.")
            continue

        ntype = node.get("type")
        nstatus = node.get("status")
        ndata = node.get("data", {})
        if not isinstance(ndata, dict):
            ndata = {}

        if ntype == "DECISION":
            # Missing source provenance
            src_ref = ndata.get("sourceReference") or ndata.get("source_reference") or ndata.get("provenance")
            if not src_ref or not str(src_ref).strip():
                errors.append(f"Decision '{node_id}' is missing source provenance (sourceReference is empty).")

            # Superseded decisions marked active
            super_by = ndata.get("supersededBy")
            if super_by and str(nstatus).upper() == "ACTIVE":
                errors.append(f"Superseded decision '{node_id}' has supersededBy='{super_by}' but status is marked '{nstatus}' instead of 'SUPERSEDED'.")

            # Track active decisions per concern
            if str(nstatus).upper() == "ACTIVE" and not super_by:
                cid = ndata.get("concernId")
                # Also check incoming RESOLVES edge if concernId missing in data
                if not cid:
                    for e in edges:
                        if e.get("target") == node_id and e.get("relationship") == "RESOLVES":
                            cid = e.get("source")
                            break
                if cid:
                    active_decisions_by_concern.setdefault(cid, []).append(node_id)

    # Detect multiple active conflicting decisions for the same concern
    for cid, dec_ids in active_decisions_by_concern.items():
        if len(dec_ids) > 1:
            errors.append(f"Multiple active conflicting decisions for concern '{cid}': {dec_ids}")

    # 5. Orphaned required requirements without decision/intent trace
    for node_id, node in nodes.items():
        if not isinstance(node, dict):
            continue
        ntype = node.get("type")
        nstatus = node.get("status", "DISCOVERED")
        ndata = node.get("data", {})
        if not isinstance(ndata, dict):
            ndata = {}

        if ntype == "REQUIREMENT":
            # Check if requirement is dismissed or deferred
            if str(nstatus).upper() in {"DISMISSED", "DEFERRED", "CANCELLED"}:
                continue

            # Check for incoming edges from DECISION or CONCERN
            has_incoming_trace = False
            for e in edges:
                if e.get("target") == node_id:
                    src_node = nodes.get(e.get("source"))
                    if src_node and src_node.get("type") in {"DECISION", "CONCERN"}:
                        has_incoming_trace = True
                        break

            # Also check if data contains explicit source provenance trace
            has_data_trace = bool(
                ndata.get("decisionId")
                or ndata.get("sourceDecision")
                or ndata.get("concernId")
                or ndata.get("sourceConcern")
                or ndata.get("intentId")
                or ndata.get("sourceIntentIds")
                or ndata.get("sources")
                or ndata.get("provenance")
                or ndata.get("authority")
            )

            if not has_incoming_trace and not has_data_trace:
                errors.append(f"Orphaned requirement '{node_id}' has no decision or intent trace in decision graph.")

    return len(errors) == 0, errors


def sync_decision_graph(workspace_dir: Union[str, Path]) -> Dict[str, Any]:
    """
    Synchronize decision graph:
    Loads concerns, decisions, requirements from workspace, rebuilds and validates graph,
    and atomically saves to .agent-harness/decision-graph.json.
    Fails closed (raises ValueError) on validation failure or corruption.
    """
    ws = Path(workspace_dir).resolve()

    # Load concerns
    concerns_list = []
    if concern is not None and hasattr(concern, "load_concerns"):
        concerns_list = concern.load_concerns(ws)
    else:
        c_path = ws / ".agent-harness" / "concerns.json"
        if c_path.exists():
            try:
                with open(c_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    concerns_list = data if isinstance(data, list) else data.get("concerns", [])
            except Exception:
                concerns_list = []

    # Load decisions
    decisions_list = []
    if decision is not None and hasattr(decision, "load_decisions"):
        decisions_list = decision.load_decisions(ws)
    else:
        d_path = ws / ".agent-harness" / "decisions.json"
        if d_path.exists():
            try:
                with open(d_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    decisions_list = data if isinstance(data, list) else data.get("decisions", [])
            except Exception:
                decisions_list = []

    # Load requirements
    requirements_list = []
    if kernel is not None and hasattr(kernel, "load_requirements"):
        requirements_list = kernel.load_requirements(ws)
    else:
        r_path = ws / ".agent-harness" / "requirements.json"
        if r_path.exists():
            try:
                with open(r_path, "r", encoding="utf-8") as f:
                    requirements_list = json.load(f)
            except Exception:
                requirements_list = []

    # Build graph
    graph_data = build_decision_graph(concerns_list, decisions_list, requirements_list)

    # Validate graph
    is_valid, errors = validate_decision_graph(graph_data)
    if not is_valid:
        raise ValueError(f"Decision graph validation failed: {'; '.join(errors)}")

    # Atomic save
    save_decision_graph(ws, graph_data)
    return graph_data
