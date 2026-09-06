"""
Strict Engineering Kernel Step 7 - High-Level Decision Engine Facade
Coordinates the complete Step 7 workflow:
  FRAME -> CONCERN -> DECISION GRAPH -> QUESTION UTILITY -> INTERACTION POLICY
  -> PRINCIPLED STOPPING -> CONSISTENCY REVIEW -> COVERAGE -> REQUIREMENT GENERATION
"""

import os
import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

try:
    from . import frame as frame_mod
    from . import concern as concern_mod
    from . import decision as decision_mod
    from . import decision_events
    from . import decision_graph
    from . import question_utility
    from . import interaction_policy
    from . import stopping_engine
    from . import consistency_reviewer
    from . import decision_coverage
    from . import requirement_generator
    from . import kernel
except (ImportError, ValueError):
    try:
        import frame as frame_mod
        import concern as concern_mod
        import decision as decision_mod
        import decision_events
        import decision_graph
        import question_utility
        import interaction_policy
        import stopping_engine
        import consistency_reviewer
        import decision_coverage
        import requirement_generator
        import kernel
    except ImportError:
        frame_mod = None
        concern_mod = None
        decision_mod = None
        decision_events = None
        decision_graph = None
        question_utility = None
        interaction_policy = None
        stopping_engine = None
        consistency_reviewer = None
        decision_coverage = None
        requirement_generator = None
        kernel = None


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class DecisionEngine:
    """
    Session orchestrator for discovery and decision engineering.
    """

    def __init__(self, workspace_dir: Union[str, Path]):
        self.ws = Path(workspace_dir).resolve()
        self.harness_dir = self.ws / ".agent-harness"
        self.harness_dir.mkdir(parents=True, exist_ok=True)

    def initialize_discovery(self, raw_intent: str, project_name: str = "") -> Dict[str, Any]:
        """
        Initialize the discovery process from raw user intent.
        Constructs Frame, extracts initial concerns, builds graph, and records events.
        """
        # 1. Create Frame from raw intent
        frame_data = frame_mod.extract_frame_from_intent(raw_intent)
        if project_name:
            frame_data["projectName"] = project_name
        frame_mod.save_frame(self.ws, frame_data)

        decision_events.record_decision_event(
            workspace_dir=self.ws,
            event_type="FRAME_CREATED",
            payload={
                "projectName": frame_data.get("projectName"),
                "goals": frame_data.get("goals"),
                "constraints": frame_data.get("constraints"),
                "nonGoals": frame_data.get("nonGoals"),
            },
            actor="spec-architect",
        )

        # 2. Extract Concerns
        candidate_concerns = concern_mod.extract_candidate_concerns_from_frame(frame_data)
        concern_mod.save_concerns(self.ws, candidate_concerns)

        for c in candidate_concerns:
            decision_events.record_decision_event(
                workspace_dir=self.ws,
                event_type="CONCERN_DISCOVERED",
                payload={
                    "concernId": c["id"],
                    "category": c.get("category"),
                    "title": c.get("title"),
                    "riskLevel": c.get("riskLevel"),
                },
                actor="spec-architect",
            )

        # 3. Sync initial artifacts
        graph_data = decision_graph.sync_decision_graph(self.ws)
        status_data = stopping_engine.sync_decision_status(self.ws)
        cov_data = decision_coverage.sync_decision_coverage(self.ws)

        return {
            "frame": frame_data,
            "concerns": candidate_concerns,
            "status": status_data,
            "coverage": cov_data,
            "graph": graph_data,
        }

    def get_next_interaction(self) -> Dict[str, Any]:
        """
        Evaluate current state and return the next highest-utility interaction.
        Returns:
          - {"action": "PROCEED_TO_SPEC", ...} if stopping conditions are satisfied.
          - {"action": "ASK"|"SUGGEST"|"CHALLENGE", ...} if a user question is needed.
        Handles SAFE-INFER automatically.
        """
        # Sync and check stopping status
        status_data = stopping_engine.sync_decision_status(self.ws)
        if status_data.get("canProceedToSpec", False):
            return {
                "action": "PROCEED_TO_SPEC",
                "status": status_data,
                "message": f"Discovery complete. Ready to proceed to specification: {status_data.get('reason')}",
            }

        # Load concerns, graph, and asked questions
        concerns_list = concern_mod.load_concerns(self.ws)
        graph_data = decision_graph.load_decision_graph(self.ws)
        asked_questions = question_utility.load_asked_questions(self.ws)

        # Filter unresolved concerns
        unresolved = [
            c for c in concerns_list
            if str(c.get("status", "DISCOVERED")).upper() in stopping_engine.UNRESOLVED_CONCERN_STATES
        ]

        if not unresolved:
            return {
                "action": "PROCEED_TO_SPEC",
                "status": status_data,
                "message": "All concerns resolved. Ready to proceed to specification.",
            }

        # Rank by utility
        ranked = question_utility.rank_concerns_by_utility(
            concerns=unresolved,
            graph_data=graph_data,
            asked_questions=asked_questions,
        )

        for top_concern, utility_score in ranked:
            # Determine interaction mode
            mode_details = interaction_policy.determine_interaction_mode(
                concern=top_concern,
                utility=utility_score,
            )
            mode = mode_details.get("mode", "ASK")

            if mode == "SAFE-INFER":
                # Automatically apply safe inference without prompting user
                cid = top_concern["id"]
                rec_opt = mode_details.get("recommendedOption")
                chosen_opt_title = rec_opt.get("title", "Standard Default") if rec_opt else "Standard Reversible Default"
                
                # Create decision
                dec_data = decision_mod.create_decision(
                    concern_id=cid,
                    title=f"Inferred {top_concern.get('title')}",
                    chosen_option=chosen_opt_title,
                    authority="MODEL_DEFAULT",
                    tradeoffs=["Automated safe inference", "Reversible without data loss"],
                    rationale=mode_details.get("reason", "Inferred by interaction policy as safe and reversible"),
                )

                # Persist decision
                decisions = decision_mod.load_decisions(self.ws)
                decisions.append(dec_data)
                decision_mod.save_decisions(self.ws, decisions)

                # Update concern status
                for c in concerns_list:
                    if c.get("id") == cid:
                        c["status"] = "RESOLVED"
                        c["chosenDecisionId"] = dec_data["id"]
                concern_mod.save_concerns(self.ws, concerns_list)

                # Record event
                decision_events.record_decision_event(
                    workspace_dir=self.ws,
                    event_type="MODEL_DECISION_INFERRED",
                    payload={
                        "decisionId": dec_data["id"],
                        "concernId": cid,
                        "chosenOption": chosen_opt_title,
                        "authority": "MODEL_DEFAULT",
                    },
                    actor="decision-engine",
                )

                # Sync artifacts and check if we can stop or continue
                decision_graph.sync_decision_graph(self.ws)
                new_status = stopping_engine.sync_decision_status(self.ws)
                decision_coverage.sync_decision_coverage(self.ws)

                if new_status.get("canProceedToSpec", False):
                    return {
                        "action": "PROCEED_TO_SPEC",
                        "status": new_status,
                        "message": f"Discovery complete. Ready for specification: {new_status.get('reason')}",
                    }
                # Continue loop to next concern
                continue

            # Non-inferable: Record asked question
            q_text = top_concern.get("question") or top_concern.get("title") or ""
            topic = top_concern.get("category") or ""
            question_utility.record_asked_question(
                workspace_dir=self.ws,
                question_text=q_text,
                topic=topic,
                concern_id=top_concern["id"],
            )

            options = mode_details.get("options") or interaction_policy.generate_candidate_options(top_concern)

            return {
                "action": mode,  # ASK, SUGGEST, CHALLENGE
                "concernId": top_concern["id"],
                "category": top_concern.get("category"),
                "title": top_concern.get("title"),
                "question": q_text,
                "utilityScore": round(utility_score, 4),
                "options": options,
                "modeDetails": mode_details,
            }

        # Fallback if all were safe-inferred or filtered
        status_data = stopping_engine.sync_decision_status(self.ws)
        return {
            "action": "PROCEED_TO_SPEC",
            "status": status_data,
            "message": "All concerns processed.",
        }

    def record_user_decision(
        self,
        concern_id: str,
        user_response: str,
        actor: str = "user",
    ) -> Dict[str, Any]:
        """
        Process user response for a concern, parse choice, create decision,
        and update all downstream artifacts.
        """
        concerns_list = concern_mod.load_concerns(self.ws)
        target_concern = next((c for c in concerns_list if c.get("id") == concern_id), None)
        if not target_concern:
            raise ValueError(f"Concern '{concern_id}' not found in workspace")

        candidate_opts = target_concern.get("candidateOptions")
        if not candidate_opts:
            candidate_opts = interaction_policy.generate_candidate_options(target_concern)

        # Parse user response
        parse_res = decision_mod.parse_user_response(user_response, candidate_opts)
        
        parse_type = str(parse_res.get("type") or parse_res.get("intent") or "").upper()
        parse_status = str(parse_res.get("status") or "").upper()

        # 1. Uncertainty Check
        if parse_status == "UNCERTAIN" or parse_type in ("UNCERTAIN", "UNCERTAINTY"):
            # Never create a decision, never resolve concern
            decision_events.record_decision_event(
                workspace_dir=self.ws,
                event_type="USER_UNCERTAINTY_RECORDED",
                payload={
                    "concernId": concern_id,
                    "rawInput": user_response,
                    "action": "UNCERTAINTY_PRESERVED",
                },
                actor=actor,
            )
            graph_data = decision_graph.sync_decision_graph(self.ws)
            status_data = stopping_engine.sync_decision_status(self.ws)
            cov_data = decision_coverage.sync_decision_coverage(self.ws)

            return {
                "action": "UNCERTAINTY_PRESERVED",
                "concernId": concern_id,
                "message": f"User expressed uncertainty on '{target_concern.get('title')}'. Concern remains unresolved without hallucinating a decision.",
                "parseResult": parse_res,
                "status": status_data,
                "coverage": cov_data,
                "graph": graph_data,
            }

        # 2. Rejection Check
        if parse_status == "REJECTED" or parse_type == "REJECTION":
            custom_alt = parse_res.get("customAlternative")
            has_custom = bool(custom_alt and isinstance(custom_alt, str) and len(custom_alt.strip()) >= 2)

            if not has_custom:
                # Bare rejection without alternative: do NOT create decision, do NOT resolve concern
                decision_events.record_decision_event(
                    workspace_dir=self.ws,
                    event_type="USER_REJECTION_RECORDED",
                    payload={
                        "concernId": concern_id,
                        "rawInput": user_response,
                        "hasCustomAlternative": False,
                    },
                    actor=actor,
                )
                graph_data = decision_graph.sync_decision_graph(self.ws)
                status_data = stopping_engine.sync_decision_status(self.ws)
                cov_data = decision_coverage.sync_decision_coverage(self.ws)

                return {
                    "action": "REJECTION_RECORDED",
                    "concernId": concern_id,
                    "message": f"User rejected all candidate options for '{target_concern.get('title')}' without an alternative. Concern remains unresolved.",
                    "parseResult": parse_res,
                    "status": status_data,
                    "coverage": cov_data,
                    "graph": graph_data,
                }
            else:
                # User rejected candidate options but provided a custom alternative
                chosen_text = str(custom_alt).strip()
                authority = "USER"
                decision_type = "USER_EXPLICIT"
                tradeoffs = ["User specified custom alternative outside predefined candidate options"]
                rationale = f"User rejected candidate options and specified custom alternative: {chosen_text}"

        # 3. Delegation Check
        elif parse_status == "DELEGATED" or parse_type == "DELEGATION":
            risk = str(target_concern.get("riskLevel", "LOW")).upper()
            cat = str(target_concern.get("category", "")).upper()
            is_high_risk = (risk in ("CRITICAL", "HIGH")) or (cat in ("AUTHORIZATION", "SECURITY", "FINANCIAL", "IRREVERSIBILITY", "RECOVERY"))

            if is_high_risk:
                # Cannot silently resolve high-risk concern via delegation
                decision_events.record_decision_event(
                    workspace_dir=self.ws,
                    event_type="DELEGATION_RESTRICTED_HIGH_RISK",
                    payload={
                        "concernId": concern_id,
                        "riskLevel": risk,
                        "category": cat,
                        "rawInput": user_response,
                    },
                    actor=actor,
                )
                graph_data = decision_graph.sync_decision_graph(self.ws)
                status_data = stopping_engine.sync_decision_status(self.ws)
                cov_data = decision_coverage.sync_decision_coverage(self.ws)

                return {
                    "action": "DELEGATION_RESTRICTED",
                    "concernId": concern_id,
                    "riskLevel": risk,
                    "message": f"Cannot delegate {risk}-risk architectural concern '{target_concern.get('title')}' without explicit user confirmation.",
                    "parseResult": parse_res,
                    "status": status_data,
                    "coverage": cov_data,
                    "graph": graph_data,
                }
            else:
                authority = "USER_DELEGATED"
                decision_type = "USER_EXPLICIT"
                rec_opt = next((o for o in candidate_opts if o.get("isRecommended")), candidate_opts[0] if candidate_opts else {})
                chosen_text = rec_opt.get("title", "Recommended Default")
                tradeoffs = [f"Agent recommended option under user delegation: {chosen_text}"]
                rationale = f"User explicitly delegated decision authority: {user_response}"

        # 4. Standard Selection / Free Text
        else:
            authority = "USER"
            decision_type = "USER_EXPLICIT"
            chosen_text = str(parse_res.get("value") or parse_res.get("matchedOptionTitle") or user_response).strip()
            tradeoffs = [f"User selected: {parse_res.get('matchedOptionTitle', chosen_text)}"]
            rationale = f"User response: {user_response}"

        # Create decision
        dec_data = decision_mod.create_decision(
            concern_id=concern_id,
            title=f"Decision for {target_concern.get('title')}",
            chosen_option=str(chosen_text),
            authority=authority,
            decision_type=decision_type,
            tradeoffs=tradeoffs,
            rationale=rationale,
            risk_level=str(target_concern.get("riskLevel", "LOW")),
        )

        decisions_list = decision_mod.load_decisions(self.ws)
        decisions_list.append(dec_data)
        decision_mod.save_decisions(self.ws, decisions_list)

        # Update concern status to RESOLVED
        for c in concerns_list:
            if c.get("id") == concern_id:
                c["status"] = "RESOLVED"
                c["chosenDecisionId"] = dec_data["id"]
        concern_mod.save_concerns(self.ws, concerns_list)

        # Record event in append-only cryptographic ledger
        decision_events.record_decision_event(
            workspace_dir=self.ws,
            event_type="USER_DECISION_RECORDED",
            payload={
                "decisionId": dec_data["id"],
                "concernId": concern_id,
                "chosenOption": chosen_text,
                "authority": authority,
                "decisionType": decision_type,
                "parseType": parse_type,
                "confidence": parse_res.get("confidence"),
            },
            actor=actor,
        )

        # Sync all downstream artifacts
        graph_data = decision_graph.sync_decision_graph(self.ws)
        status_data = stopping_engine.sync_decision_status(self.ws)
        cov_data = decision_coverage.sync_decision_coverage(self.ws)

        return {
            "decision": dec_data,
            "parseResult": parse_res,
            "status": status_data,
            "coverage": cov_data,
            "graph": graph_data,
        }

    def supersede_decision(
        self,
        old_decision_id: str,
        new_chosen_option: str,
        rationale: str = "",
        actor: str = "user",
    ) -> Dict[str, Any]:
        """
        Supersede an existing decision and propagate changes downstream.
        Marks derived requirements as STALE.
        """
        decisions_list = decision_mod.load_decisions(self.ws)
        old_dec = next((d for d in decisions_list if d.get("id") == old_decision_id), None)
        if not old_dec:
            raise ValueError(f"Decision '{old_decision_id}' not found")

        cid = old_dec.get("concernId", "UNKNOWN")

        # Create new superseding decision
        new_dec = decision_mod.create_decision(
            concern_id=cid,
            title=f"Updated Decision for {old_dec.get('title')}",
            chosen_option=new_chosen_option,
            authority="USER_DIRECT",
            tradeoffs=["Supersedes previous architectural decision"],
            rationale=rationale or f"Supersedes {old_decision_id}",
        )

        # Mark old decision superseded
        old_dec["supersededBy"] = new_dec["id"]
        old_dec["status"] = "SUPERSEDED"

        decisions_list.append(new_dec)
        decision_mod.save_decisions(self.ws, decisions_list)

        # Record event
        decision_events.record_decision_event(
            workspace_dir=self.ws,
            event_type="DECISION_SUPERSEDED",
            payload={
                "oldDecisionId": old_decision_id,
                "newDecisionId": new_dec["id"],
                "concernId": cid,
                "newChosenOption": new_chosen_option,
            },
            actor=actor,
        )

        # Downstream Requirement Invalidation (Change Propagation)
        invalidated_reqs = self.propagate_decision_change(old_decision_id, new_dec["id"])

        # Sync graph, status, coverage
        decision_graph.sync_decision_graph(self.ws)
        status_data = stopping_engine.sync_decision_status(self.ws)
        decision_coverage.sync_decision_coverage(self.ws)

        return {
            "supersededDecisionId": old_decision_id,
            "newDecision": new_dec,
            "invalidatedRequirements": invalidated_reqs,
            "status": status_data,
        }

    def propagate_decision_change(
        self,
        superseded_decision_id: str,
        new_decision_id: Optional[str] = None,
    ) -> List[str]:
        """
        Find requirements deriving from superseded decision and invalidate them to STALE.
        """
        r_file = self.ws / ".agent-harness" / "requirements.json"
        if not r_file.exists():
            return []

        try:
            with open(r_file, "r", encoding="utf-8") as f:
                reqs = json.load(f)
        except Exception:
            return []

        invalidated = []
        for r in reqs:
            d_ref = r.get("decisionId") or r.get("sourceDecision")
            sources = r.get("sources", [])
            if d_ref == superseded_decision_id or superseded_decision_id in sources:
                r["status"] = "STALE"
                r["stalenessReason"] = f"Derives from superseded decision {superseded_decision_id}"
                r["updatedAt"] = utc_now_iso()
                if new_decision_id and new_decision_id not in sources:
                    sources.append(new_decision_id)
                invalidated.append(r.get("id"))

        if invalidated:
            if kernel is not None and hasattr(kernel, "save_requirements"):
                kernel.save_requirements(self.ws, reqs)
            else:
                temp_file = r_file.with_suffix(".json.tmp")
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(reqs, f, indent=2, sort_keys=True)
                os.replace(temp_file, r_file)

        return invalidated

    def transition_to_specification(self) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Execute the DISCOVERY -> SPECIFICATION gate and compile requirements.
        """
        return requirement_generator.compile_requirements_from_decisions(self.ws)

    def review_consistency(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Perform read-only consistency audit across frame, concerns, decisions, and graph.
        """
        f = frame_mod.load_frame(self.ws) if frame_mod else {}
        c = concern_mod.load_concerns(self.ws) if concern_mod else []
        d = decision_mod.load_decisions(self.ws) if decision_mod else []
        g = decision_graph.load_decision_graph(self.ws) if decision_graph else {}
        return consistency_reviewer.review_decision_consistency(f, c, d, g)

    def calculate_decision_coverage(self) -> Dict[str, Any]:
        """
        Build and sync the 4-tier decision coverage matrix.
        """
        return decision_coverage.sync_decision_coverage(self.ws)
