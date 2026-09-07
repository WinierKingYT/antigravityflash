"""
Strict Engineering Kernel V5.1 - Antigravity Hooks CLI Entrypoint
Handles stdin JSON payloads from PreToolUse, PreInvocation, and Stop events,
executes policy gates, records Antigravity runtime context metadata, and writes valid JSON to stdout.
Enforces fail-closed security for tool gates and completion protection.
"""

import sys
import json
import os
import traceback
from pathlib import Path

# Add current module directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import kernel
import gate
import context_registry


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"decision": "allow"}))
        return

    action = sys.argv[1].lower()

    # Read stdin JSON payload
    raw_input = ""
    payload = {}
    try:
        raw_input = sys.stdin.read()
        if raw_input.strip():
            payload = json.loads(raw_input)
    except Exception as e:
        sys.stderr.write(f"[Strict-Engineering-Hook] Warning: Failed to parse stdin JSON: {e}\n")
        payload = {}

    try:
        workspace = gate.resolve_workspace(payload)

        # Ingest authoritative runtime context metadata strictly through protected internal hook boundary
        conv_id = (
            payload.get("conversationId")
            or payload.get("conversation_id")
            or payload.get("conversationID")
        )
        if workspace and conv_id and kernel.is_harness_active(workspace):
            task_id = payload.get("taskId") or "TASK-STEP6S1"
            try:
                context_registry._ingest_antigravity_hook_context(
                    workspace_dir=workspace,
                    hook_payload=payload,
                    event_type=action,
                    task_id=task_id,
                )
            except Exception as reg_err:
                sys.stderr.write(f"[Strict-Engineering-Hook] Context ingestion notice: {reg_err}\n")

        if action in {"pre-tool", "pretooluse", "pre_tool", "pre_tool_use"}:
            result = gate.evaluate_pre_tool_use(payload)
            print(json.dumps(result))

        elif action in {"pre-invocation", "preinvocation", "pre_invocation"}:
            if workspace and kernel.is_harness_active(workspace):
                state = kernel.load_state(workspace)
                phase = state.get("phase", "ACTIVE")
                msg = (
                    f"Strict Engineering Kernel V5.1 active [Phase: {phase}]. "
                    f"Work against locked requirement ledger and acceptance contracts. "
                    f"All evidence must be cryptographically chained. Unverified work is incomplete."
                )
                print(json.dumps({"injectSteps": [{"ephemeralMessage": msg}]}))
            else:
                print(json.dumps({}))

        elif action in {"stop"}:
            result = gate.evaluate_stop(payload)
            print(json.dumps(result))

        else:
            print(json.dumps({"decision": "allow"}))

    except Exception as ex:
        sys.stderr.write(f"[Strict-Engineering-Hook] Critical Error in {action}: {ex}\n")
        traceback.print_exc(file=sys.stderr)
        
        # Contextual fail-closed policy (Section 41)
        if action in {"pre-tool", "pretooluse", "pre_tool", "pre_tool_use"}:
            # Fail-closed for tool mutations to prevent protected file tampering
            print(json.dumps({
                "decision": "deny",
                "reason": f"PreToolUse gate encountered internal error: {str(ex)}. Failing closed to protect harness integrity."
            }))
        elif action in {"stop"}:
            # Block false complete without creating endless retry loop (Section 10)
            if workspace and kernel.is_harness_active(workspace):
                try:
                    st = kernel.load_state(workspace)
                    st["runtimeStatus"] = "PAUSED_HOOK_ERROR"
                    st["pauseReason"] = f"Hook internal error: {str(ex)}"
                    kernel.save_state(workspace, st)
                    try:
                        import runtime_safety
                        runtime_safety.record_runtime_event(
                            workspace_dir=workspace,
                            event_type="HOOK_INTERNAL_ERROR",
                            termination_class="HOOK_INTERNAL_ERROR",
                            raw_reason=str(ex),
                            phase=st.get("phase"),
                            runtime_status="PAUSED_HOOK_ERROR",
                            decision="allow",
                        )
                    except Exception:
                        pass
                except Exception:
                    pass
            print(json.dumps({
                "decision": "allow",
                "reason": f"Completion gate encountered internal error: {str(ex)}. Pausing execution safely without false completion."
            }))
        else:
            print(json.dumps({}))


if __name__ == "__main__":
    main()
