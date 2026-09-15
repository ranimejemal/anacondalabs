"""
AegisLab — pytest suite for the AI endpoints (/api/ai/suggest, /api/ai/auto-fix)
and the auth/premium/rate-limit layer they depend on.

Covers Sprint 2 Day 7-8's required cases (free user gets text suggestion,
free user blocked from auto-fix with 402, premium user gets auto-fix,
invalid token rejected, missing scan_id handled) plus the rate limiting
and error-handling work from Day 3-6, since those are exactly the kind of
regression this suite exists to catch.

Run with:  pytest backend/ -v
"""
import time
import zipfile

import ai_remediation
import main
from models import ScanResult, Vulnerability, Severity

from conftest import FREE_USER, PREMIUM_USER


FINDING_PAYLOAD = {
    "issue": "Missing rate limiting on login endpoint",
    "severity": "high",
    "endpoint": "POST /auth/login",
    "method": "POST",
    "recommendation": "Add a rate limiter middleware.",
}


# ---------------------------------------------------------------------------
# /api/ai/suggest — available to free AND premium users
# ---------------------------------------------------------------------------

def test_free_user_gets_text_suggestion(client, mock_supabase, mock_claude):
    resp = client.post(
        "/api/ai/suggest",
        json=FINDING_PAYLOAD,
        headers={"Authorization": "Bearer valid-free-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "ai_suggestion" in body
    assert body["finding"] == FINDING_PAYLOAD["issue"]


def test_premium_user_also_gets_text_suggestion(client, mock_supabase, mock_claude):
    resp = client.post(
        "/api/ai/suggest",
        json=FINDING_PAYLOAD,
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 200
    assert "ai_suggestion" in resp.json()


def test_suggest_with_no_token_is_401(client, mock_supabase, mock_claude):
    resp = client.post("/api/ai/suggest", json=FINDING_PAYLOAD)
    assert resp.status_code == 401


def test_suggest_with_invalid_token_is_401(client, mock_supabase, mock_claude):
    resp = client.post(
        "/api/ai/suggest",
        json=FINDING_PAYLOAD,
        headers={"Authorization": "Bearer this-token-does-not-exist"},
    )
    assert resp.status_code == 401
    assert "sign in" in resp.json()["detail"].lower()


def test_suggest_malformed_auth_header_is_401(client, mock_supabase, mock_claude):
    # Missing the "Bearer " prefix entirely
    resp = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "valid-free-token"}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /api/ai/auto-fix — premium only
# ---------------------------------------------------------------------------

def test_free_user_blocked_from_autofix_402(client, mock_supabase, mock_claude):
    resp = client.post(
        "/api/ai/auto-fix",
        json={"scan_id": "does-not-matter", "finding": FINDING_PAYLOAD},
        headers={"Authorization": "Bearer valid-free-token"},
    )
    assert resp.status_code == 402
    assert "premium" in resp.json()["detail"].lower()


def test_autofix_with_no_token_is_401(client, mock_supabase, mock_claude):
    resp = client.post("/api/ai/auto-fix", json={"scan_id": "x", "finding": FINDING_PAYLOAD})
    assert resp.status_code == 401


def test_premium_user_missing_scan_id_is_404(client, mock_supabase, mock_claude):
    """A scan_id that was never uploaded (or expired) should be a clear 404,
    not a crash — this is the 'missing scan_id handled' case from the DoD."""
    resp = client.post(
        "/api/ai/auto-fix",
        json={"scan_id": "never-existed-scan-id", "finding": FINDING_PAYLOAD},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 404
    assert "no longer available" in resp.json()["detail"].lower()


def test_premium_user_gets_autofix(client, mock_supabase, mock_claude, tmp_path, monkeypatch):
    # Simulate a previously-uploaded source zip the way /api/static-scan/upload does.
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)  # don't pollute the real reports_output/
    scan_id = "test-scan-autofix-1"
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("src/auth.js", "// original vulnerable code\n")
    main._static_scan_zips[scan_id] = zip_path

    finding = {**FINDING_PAYLOAD, "endpoint": "POST /auth/login (src/auth.js:12)"}
    resp = client.post(
        "/api/ai/auto-fix",
        json={"scan_id": scan_id, "finding": finding},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["patched_file"] == "src/auth.js"
    assert body["filename"].endswith(".zip")


def test_autofix_finding_with_no_file_is_400(client, mock_supabase, mock_claude, tmp_path):
    """Project-wide findings (no file/line in the endpoint string) can't be
    auto-patched and should say so clearly, not attempt a bad patch."""
    scan_id = "test-scan-autofix-2"
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("README.md", "hello\n")
    main._static_scan_zips[scan_id] = zip_path

    finding = {**FINDING_PAYLOAD, "endpoint": "project-wide missing CORS policy"}
    resp = client.post(
        "/api/ai/auto-fix",
        json={"scan_id": scan_id, "finding": finding},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Rate limiting (Sprint 2 Day 3)
# ---------------------------------------------------------------------------

def test_rate_limit_blocks_after_daily_cap(client, mock_supabase, mock_claude, monkeypatch):
    monkeypatch.setattr(ai_remediation, "SUGGEST_DAILY_LIMIT", 2)
    headers = {"Authorization": "Bearer valid-free-token"}

    r1 = client.post("/api/ai/suggest", json=FINDING_PAYLOAD, headers=headers)
    r2 = client.post("/api/ai/suggest", json=FINDING_PAYLOAD, headers=headers)
    r3 = client.post("/api/ai/suggest", json=FINDING_PAYLOAD, headers=headers)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert "daily ai limit" in r3.json()["detail"].lower()


def test_rate_limit_is_tracked_per_user(client, mock_supabase, mock_claude, monkeypatch):
    monkeypatch.setattr(ai_remediation, "SUGGEST_DAILY_LIMIT", 1)

    free_resp = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer valid-free-token"}
    )
    premium_resp = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer valid-premium-token"}
    )
    # Different users, both should get their own first-call quota, not share one.
    assert free_resp.status_code == 200
    assert premium_resp.status_code == 200


def test_rate_limit_does_not_consume_quota_on_auth_failure(client, mock_supabase, mock_claude, monkeypatch):
    """An invalid token must be rejected before the rate limiter is touched,
    so a stranger spamming bad tokens can't burn a real user's quota."""
    monkeypatch.setattr(ai_remediation, "SUGGEST_DAILY_LIMIT", 1)
    bad = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer garbage-token"}
    )
    assert bad.status_code == 401

    good = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer valid-free-token"}
    )
    assert good.status_code == 200  # quota was untouched by the failed attempt


# ---------------------------------------------------------------------------
# Graceful "not configured" behavior
# ---------------------------------------------------------------------------

def test_ai_suggest_503_when_anthropic_not_configured(client, mock_supabase, monkeypatch):
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "")
    resp = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer valid-free-token"}
    )
    assert resp.status_code == 503
    assert "anthropic_api_key" in resp.json()["detail"].lower()


def test_ai_suggest_503_when_supabase_not_configured(client, mock_claude, monkeypatch):
    import supabase_auth
    monkeypatch.setattr(supabase_auth, "_SUPABASE_CONFIGURED", False)
    resp = client.post(
        "/api/ai/suggest", json=FINDING_PAYLOAD, headers={"Authorization": "Bearer valid-free-token"}
    )
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# PREMIUM_FREE_FOR_ALL launch flag (temporary: premium free for everyone
# while pricing isn't finalized — see supabase_auth.py's get_current_user)
# ---------------------------------------------------------------------------

def test_premium_free_for_all_flag_off_by_default(client, mock_supabase, mock_claude):
    """Sanity check: without the flag set, a free-token user is NOT premium
    (this is really just re-confirming existing behavior, but explicitly
    as a regression guard for the flag's default)."""
    resp = client.get("/api/me", headers={"Authorization": "Bearer valid-free-token"})
    assert resp.status_code == 200
    assert resp.json()["is_premium"] is False


def test_premium_free_for_all_flag_grants_premium_to_free_account(client, mock_supabase, mock_claude, monkeypatch):
    import supabase_auth
    monkeypatch.setattr(supabase_auth, "PREMIUM_FREE_FOR_ALL", True)

    me_resp = client.get("/api/me", headers={"Authorization": "Bearer valid-free-token"})
    assert me_resp.status_code == 200
    assert me_resp.json()["is_premium"] is True

    # And the actual gate (not just the badge) opens up too:
    autofix_resp = client.post(
        "/api/ai/auto-fix",
        json={"scan_id": "does-not-exist", "finding": FINDING_PAYLOAD},
        headers={"Authorization": "Bearer valid-free-token"},
    )
    # 404 (scan not found) proves it got PAST the 402 premium gate — the
    # request only fails on a later, unrelated check.
    assert autofix_resp.status_code == 404


def test_premium_free_for_all_flag_does_not_bypass_authentication(client, mock_supabase, mock_claude, monkeypatch):
    """The flag skips the PAYWALL, not the login requirement — an invalid
    token must still be rejected even with the flag on."""
    import supabase_auth
    monkeypatch.setattr(supabase_auth, "PREMIUM_FREE_FOR_ALL", True)

    resp = client.get("/api/me", headers={"Authorization": "Bearer garbage-token"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /api/ai/fix-all — bulk version of suggest/auto-fix over every finding
# ---------------------------------------------------------------------------

def _vuln(endpoint, issue="Some issue", severity=Severity.MEDIUM):
    return Vulnerability(
        endpoint=endpoint, method="POST", test_module="mass_assignment_tests",
        owasp_category="API3:2023 Broken Object Property Level Authorization",
        issue=issue, severity=severity,
        description="desc", impact="impact", recommendation="recommendation",
    )


def test_fix_all_unknown_scan_id_404(client, mock_supabase, mock_claude):
    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": "never-existed"},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 404


def test_fix_all_static_premium_patches_distinct_files_and_suggests_the_rest(
    client, mock_supabase, mock_claude, tmp_path, monkeypatch
):
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)
    scan_id = "fixall-static-1"
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("src/auth.js", "// original\n")
        zf.writestr("src/users.js", "// original\n")
    main._static_scan_zips[scan_id] = zip_path

    findings = [
        _vuln("POST /auth/login (src/auth.js:12)", issue="Missing rate limit"),
        _vuln("POST /users (src/users.js:5)", issue="Mass assignment"),
        _vuln("project-wide missing CORS policy", issue="No CORS policy"),
    ]
    main._static_scans[scan_id] = ScanResult(
        scan_id=scan_id, base_url="(static scan)", started_at=time.time(),
        status="completed", vulnerabilities=findings,
    )

    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": scan_id},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 200
    body = resp.json()

    kinds = {f["issue"]: f["kind"] for f in body["fixed"]}
    assert kinds["Missing rate limit"] == "patch"
    assert kinds["Mass assignment"] == "patch"
    assert kinds["No CORS policy"] == "suggestion"  # no single file to patch
    assert body["output_zip"]["filename"].endswith(".zip")
    assert body["skipped_rate_limited"] == 0


def test_fix_all_free_user_gets_suggestions_only_even_on_static_scan(
    client, mock_supabase, mock_claude, tmp_path, monkeypatch
):
    """Auto-patching is a premium feature — a free user hitting fix-all on a
    static scan should get text suggestions for everything, never a patched
    zip, same tier boundary as the single-finding endpoints."""
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)
    scan_id = "fixall-static-free"
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("src/auth.js", "// original\n")
    main._static_scan_zips[scan_id] = zip_path
    main._static_scans[scan_id] = ScanResult(
        scan_id=scan_id, base_url="(static scan)", started_at=time.time(),
        status="completed", vulnerabilities=[_vuln("POST /auth/login (src/auth.js:12)")],
    )

    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": scan_id},
        headers={"Authorization": "Bearer valid-free-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fixed"][0]["kind"] == "suggestion"
    assert body["output_zip"] is None


def test_fix_all_live_scan_uses_suggestions_only(client, mock_supabase, mock_claude):
    """A live/DAST scan has no uploaded source zip at all, so even a
    premium user only gets text suggestions, never a patch attempt."""
    scan_id = "fixall-live-1"
    main._scans[scan_id] = {
        "queue": None, "status": "completed",
        "result": ScanResult(
            scan_id=scan_id, base_url="http://example.com", started_at=time.time(),
            status="completed", vulnerabilities=[_vuln("GET /users/{id}")],
        ),
    }

    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": scan_id},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fixed"][0]["kind"] == "suggestion"
    assert body["output_zip"] is None


def test_fix_all_reports_skipped_findings_once_rate_limit_hit(client, mock_supabase, mock_claude, monkeypatch):
    monkeypatch.setattr(ai_remediation, "SUGGEST_DAILY_LIMIT", 1)
    scan_id = "fixall-rate-limited"
    main._scans[scan_id] = {
        "queue": None, "status": "completed",
        "result": ScanResult(
            scan_id=scan_id, base_url="http://example.com", started_at=time.time(),
            status="completed",
            vulnerabilities=[_vuln("GET /a", issue="A"), _vuln("GET /b", issue="B"), _vuln("GET /c", issue="C")],
        ),
    }

    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": scan_id},
        headers={"Authorization": "Bearer valid-free-token"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["fixed"]) == 1
    assert body["skipped_rate_limited"] == 2


def test_fix_all_no_findings_returns_empty_result(client, mock_supabase, mock_claude):
    scan_id = "fixall-empty"
    main._scans[scan_id] = {
        "queue": None, "status": "completed",
        "result": ScanResult(
            scan_id=scan_id, base_url="http://example.com", started_at=time.time(),
            status="completed", vulnerabilities=[],
        ),
    }
    resp = client.post(
        "/api/ai/fix-all", json={"scan_id": scan_id},
        headers={"Authorization": "Bearer valid-premium-token"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"fixed": [], "skipped_rate_limited": 0, "output_zip": None}
