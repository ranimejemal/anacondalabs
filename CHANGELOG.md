# Changelog

## [Unreleased] — pending: Stripe live-account testing, code signing, beta feedback

## Sprint 7 — GitHub "Connect account" + repo import
- `backend/github_integration.py`: OAuth Authorization Code flow (with
  CSRF state validation), repo listing, and repo-as-zip download via
  GitHub's API. `GITHUB_CLIENT_SECRET` never leaves the backend process.
- New endpoints: `GET /api/github/oauth/authorize-url`,
  `POST /api/github/oauth/exchange`, `GET /api/github/repos`,
  `POST /api/github/import` — the last one feeds a picked repo through
  the exact same static-scan pipeline as an uploaded `.zip`
  (`_run_static_scan_and_store`, factored out of `/api/static-scan/upload`
  for this reuse).
- Electron main process now registers a custom `aegislab://` protocol and
  single-instance lock to receive GitHub's OAuth redirect regardless of
  platform (`open-url` on macOS, `second-instance` argv forwarding on
  Windows/Linux), and persists the resulting access token encrypted at
  rest via `safeStorage`.
- New "Connect GitHub" UI in the static-scan sidebar: sign in, pick a
  repo from a dropdown, import & scan — same findings/gauge/export UI as
  any other static scan.
- 16 new backend tests (OAuth state issuance/consumption/reuse-rejection,
  token exchange error paths, repo listing pagination/401, zip download
  size cap, and the four new endpoints); 68 pytest tests total.

## Sprint 6 — "Fix all" bulk AI remediation
- New `POST /api/ai/fix-all` endpoint: walks every finding in a scan
  (not just the Top 5 Priority Fixes) and either patches the affected
  file (premium, static scans) or falls back to a text suggestion
  (free tier, live scans, or project-wide findings with no single file),
  batching all patches into one downloadable zip. Still metered by the
  existing per-user daily rate limits — once hit, remaining findings are
  reported as skipped rather than erroring the whole batch.
- Refactored the single-file zip-rewrite logic out of `/api/ai/auto-fix`
  into a shared `_rewrite_zip_entry()` helper, used by both endpoints.
- New "✦ Fix all in AI Suggestions" button in the Top Priority Fixes
  panel, gated the same way as the existing per-finding button
  (sign-in required, auto-patch vs. suggestion-only by plan/scan type),
  with a results list and a single download for the patched archive.
- 8 new backend tests (patch batching across distinct files, free-tier
  and live-scan suggestion-only paths, partial rate-limit skipping,
  empty-findings case); 52 pytest tests total, all passing.

## v1.3.0 (this session's starting point)
- Core scanning engine: 6 OWASP-mapped dynamic test modules (auth,
  authorization, injection, rate limiting, data exposure, transport
  security) plus a separate static source-code scanner.
- AI-powered fix suggestions (Anthropic) with free-tier text suggestions
  and premium auto-apply, gated behind Supabase auth.

## Sprint 1 — Stabilize the core
- Fixed: `main.js` treated any backend stderr output as "started
  successfully," so a crashed backend (e.g. missing dependency) looked
  identical to a healthy one. Now polls `/api/health` and only proceeds on
  a real response, with per-attempt logging to `backend.log`.
- Fixed: the packaged Electron app never actually shipped the `backend/`
  directory at all (package.json's packaging root didn't include it).
  Added `extraResources` + packaging-aware path resolution.
- `scripts/start_app.sh` / `.bat` rewritten: no longer requires conda
  pre-installed — auto-creates a local `.venv`, installs dependencies, and
  installs Electron's `node_modules` on first run.

## Sprint 2 — Harden the AI + Supabase layer
- Applied the `profiles` table schema to the live Supabase project (it had
  been documented in a docstring but never actually applied).
- Added per-user daily rate limits on both AI endpoints.
- Added specific, distinct error handling for timeouts, network failures,
  invalid API keys, and upstream rate limits (both Anthropic and Supabase
  sides) instead of generic 500s.
- Security review: confirmed the service_role key never leaves the
  backend, premium status is always re-verified live against Supabase
  (never cached/trusted from the client), and premium checks fail closed.
- 25 pytest tests covering all of the above.

## Sprint 3 — Stripe billing
- Checkout session creation, customer portal, and webhook handling — all
  via raw `httpx` calls (no SDK), matching the existing Anthropic/Supabase
  pattern in the codebase.
- Checkout happens in the system browser (`shell.openExternal`), never
  embedded in the Electron window, to keep PCI scope minimal.
- Webhook is the only path that ever sets `is_premium`; grace-period
  policy means only `customer.subscription.deleted` revokes access, not a
  payment failure or a pending cancellation.
- Real HMAC webhook signature verification, implemented by hand.
- 13 additional pytest tests (38 total).

## Sprint 4 — Mass Assignment + SSRF modules
- `mass_assignment_tests.py`: probes write endpoints with undocumented
  privileged fields (role, isAdmin, price, etc.), only flags on confirmed
  reflection in the response.
- `ssrf_tests.py`: cloud-metadata probe (self-contained, no external
  infra needed) plus an optional out-of-band callback check.
- Both proven against a live instance of `examples/mock_vulnerable_api.py`,
  not just unit-tested in isolation.
- Fixed: the two new modules were unreachable from the desktop UI — the
  module checklist array in `renderer.js` hadn't been updated, so nothing
  sent from the app could ever enable them regardless of backend support.
- 43 pytest tests total.

## Sprint 5 — Polish, docs, and trust signals
- Fixed two leftover amber-theme colors that didn't match the rest of the
  brass/red UI.
- Fixed: the manual-add-endpoint dialog had no way to enter a request body
  or query parameters, silently disabling every body/param-based check for
  any endpoint added that way.
- README brought current (setup instructions, module table, OWASP
  coverage summary, Stripe section).
- Privacy Policy and Terms of Use drafted (explicitly flagged as drafts
  needing real legal review, not final documents).
- 4-step first-run onboarding walkthrough.
- Crash/error logging added on all three layers: backend (rotating file
  handler + global exception handler), Electron main process
  (`uncaughtException`/`render-process-gone`), and renderer
  (`window.onerror`/`unhandledrejection`), all writing to a shared log.

## Sprint 6 — Launch prep
- `electron-updater` wired to GitHub Releases, verified survives
  packaging.
- Landing page built extending the app's own "inspection blueprint"
  visual identity.
- "Report an issue" link added to the app, pointing at GitHub Issues.
- Code signing process documented as a runbook (`docs/CODE_SIGNING.md`) —
  actual signing needs real certificates, not something automatable here.
- Regenerated `examples/sample_scan_report.json`/`.pdf` via a real scan
  run, reflecting all 8 modules (previous sample predated Sprint 4).
- Fixed two real Supabase security/performance lint findings on the live
  project: an unpinned `search_path` on a `SECURITY DEFINER` function
  (privilege-escalation vector) and a publicly-callable trigger function
  that should only run via the trigger, not as a direct RPC endpoint.
