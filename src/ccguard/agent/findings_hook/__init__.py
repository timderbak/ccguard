"""ccguard.agent.findings_hook — async prompt-injection finding emit (PI-01, PI-03).

Clone-not-extend of :mod:`ccguard.agent.audit_hook` per Phase 5 D-1: a separate
SQLite WAL buffer + detached flusher subprocess keeps the PreToolUse hot-path
under 10 ms while findings are POSTed asynchronously to the server.
"""
