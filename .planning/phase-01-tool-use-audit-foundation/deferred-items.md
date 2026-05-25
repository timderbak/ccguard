# Deferred items — Phase 1

## tests/e2e/* failing pre-existing

`tests/e2e/test_end_to_end.py` and `tests/e2e/test_web_e2e.py` fail at
collection time with `httpx.ConnectError` and `FileNotFoundError` — they
require a running server / external scan corpus. Failures pre-date PLAN
01-06 (verified by running the suite on master before this plan).

**Status:** out of scope for Phase 1 closure. The full unit + integration
suite is green (356 passed). Address in a dedicated test-infra plan
(consider marking these `@pytest.mark.e2e` and excluding from default CI).
