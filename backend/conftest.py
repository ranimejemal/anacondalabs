"""
Pytest configuration for the AegisLab backend test suite.

Sets fake-but-present config values BEFORE main.py (and the modules it
imports) are loaded, since supabase_auth.py and ai_remediation.py read their
required environment variables at import time. This makes the app report as
"configured" so we're actually testing the auth/premium/rate-limit/error
logic, not just the "not configured" early-exit paths.

No real network calls are made anywhere in this suite — Supabase and
Anthropic HTTP calls are monkeypatched at the function level in each test
that needs them. That's a deliberate choice: these are unit/integration
tests of AegisLab's own logic, not a check that Supabase/Anthropic are up.
"""
import os

os.environ.setdefault("SUPABASE_URL", "https://test-project.supabase.co")
os.environ.setdefault("SUPABASE_ANON_KEY", "test-anon-key")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-key")
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_fake")
os.environ.setdefault("STRIPE_PRICE_ID", "price_fake123")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_fake_secret")

import pytest
from fastapi.testclient import TestClient

import ai_remediation
import supabase_auth
import stripe_billing
import main


FREE_USER = {"id": "11111111-1111-1111-1111-111111111111", "email": "free@example.com"}
PREMIUM_USER = {"id": "22222222-2222-2222-2222-222222222222", "email": "premium@example.com"}

TOKEN_TO_USER = {
    "valid-free-token": FREE_USER,
    "valid-premium-token": PREMIUM_USER,
}
PREMIUM_USER_IDS = {PREMIUM_USER["id"]}


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Each test starts with a clean rate-limit counter so tests can't
    bleed into each other through the shared in-memory usage dict."""
    ai_remediation._usage.clear()
    yield
    ai_remediation._usage.clear()


@pytest.fixture
def mock_supabase(monkeypatch):
    """Stubs out the two real network calls in supabase_auth.py with
    behavior that mirrors what real Supabase would do: unknown/malformed
    tokens are rejected, known tokens resolve to a fixed user + premium
    flag. This exercises AegisLab's own auth/premium-gating code paths for
    real, without touching the network."""

    async def fake_fetch_supabase_user(access_token: str) -> dict:
        user = TOKEN_TO_USER.get(access_token)
        if not user:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="Invalid or expired session — please sign in again.")
        return user

    async def fake_fetch_is_premium(user_id: str) -> bool:
        return user_id in PREMIUM_USER_IDS

    monkeypatch.setattr(supabase_auth, "_fetch_supabase_user", fake_fetch_supabase_user)
    monkeypatch.setattr(supabase_auth, "_fetch_is_premium", fake_fetch_is_premium)


@pytest.fixture
def mock_claude(monkeypatch):
    """Stubs out the real Anthropic call with a canned response, for tests
    that only care about auth/rate-limit/routing behavior, not AI output."""

    async def fake_call_claude(system: str, user_msg: str, max_tokens: int = 1200) -> str:
        return "```js\n// mocked AI fix\n```"

    monkeypatch.setattr(ai_remediation, "_call_claude", fake_call_claude)
