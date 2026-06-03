# Tests

| Suite | Location | Needs AWS? | What it covers |
| ----- | -------- | ---------- | -------------- |
| Unit (Python) | `scripts/python/tests/` | No | Pure logic of the 5 operational scripts |
| Compliance (structure/policy) | `tests/compliance/` | No | Repo invariants: module layout, no hardcoded secrets, MFA enforced |
| Integration | `tests/integration/` | Yes | Live smoke tests against a deployed environment (opt-in) |

Run the no-AWS suites:

```bash
pytest scripts/python/tests tests/compliance -v
```

Integration tests are skipped automatically unless `PAM_INTEGRATION=1` and AWS
credentials are present.
