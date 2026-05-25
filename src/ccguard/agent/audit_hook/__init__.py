"""ccguard.agent.audit_hook — PostToolUse audit subsystem (TUA-01..03).

Privacy-by-design: raw `tool_input` is consumed only by `compute_fingerprint`
and never persisted, logged, or transmitted in any other form.
"""
