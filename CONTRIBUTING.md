# Contributing to AegisLab

## Setup

See the README's [Setup](./README.md#2-setup) section — `scripts/start_app.sh`
(or `.bat`) gets you a working dev environment in one command.

## Running tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest -v
```

All 43 tests should pass before opening a PR. If you're adding a new scan
module, see `backend/tests/mass_assignment_tests.py` or `ssrf_tests.py` for
the current pattern, and add a corresponding entry to:
- `backend/tests/__init__.py` (`MODULE_REGISTRY`)
- `backend/models.py` (`ScanConfig.modules_enabled` default list)
- `frontend/renderer.js` (the `MODULES` array — **this one's easy to
  forget and makes a working module completely unreachable from the UI**,
  see CHANGELOG's Sprint 4 entry for exactly this bug)
- `frontend/remediation.js` (a snippet rule, if a common fix pattern exists)
- `README.md`'s module table

## Adding a scan module — detection philosophy

Only flag on a **positive, verifiable signal** — a reflected value, a
confirmed status code difference, actual response content — not just "this
endpoint has a suspicious-sounding name." False positives erode trust in
the whole tool faster than missed findings do. See `mass_assignment_tests.py`'s
docstring for a worked example of this reasoning.

## Pull requests

- Keep PRs focused — one module, one bug fix, one doc update.
- Add tests for new detection logic. A module that isn't proven against
  `examples/mock_vulnerable_api.py` (or a unit test with a mocked
  response) isn't done.
- Run the full test suite locally before pushing; CI runs it too but
  faster feedback is faster feedback.

## Reporting security issues in AegisLab itself

See [SECURITY.md](./SECURITY.md) — please don't open a public issue for
vulnerabilities in AegisLab's own code.
