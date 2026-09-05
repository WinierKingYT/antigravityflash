"""
Strict Engineering Kernel V5.1 - Antigravity Hooks CLI Entrypoint
Handles stdin JSON payloads from PreToolUse, PreInvocation, and Stop events,
executes policy gates, and writes valid JSON to stdout.
Enforces fail-closed security for tool gates and completion protection.
"""

import sys
import json
import traceback
from pathlib import Path

# Add current module directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

import kernel
import gate


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
        if action in {"pre-tool", "pretooluse", "pre_tool", "pre_tool_use"}:
            result = gate.evaluate_pre_tool_use(payload)
            print(json.dumps(result))

        elif action in {"pre-invocation", "preinvocation", "pre_invocation"}:
            workspace = gate.resolve_workspace(payload)
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
            # Block completion when gate crashes to prevent unverified exit
            print(json.dumps({
                "decision": "continue",
                "reason": f"Completion gate evaluation encountered internal error: {str(ex)}. Completion blocked."
            }))
        else:
            print(json.dumps({}))


if __name__ == "__main__":
    main()
