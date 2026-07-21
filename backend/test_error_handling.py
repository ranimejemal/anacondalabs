"""
AegisLab — pytest suite for the error-handling pass on ai_remediation.py and
supabase_auth.py (Sprint 2 Day 4-6): timeouts, unreachable services, invalid
API keys, and upstream rate limits should each produce a clear HTTPException
with a sensible status code — never an unhandled exception / raw stack trace.

Uses small fake httpx client stand-ins instead of a real dependency like
respx, since these are the only two places we need to simulate httpx-level
failures and it keeps requirements-dev.txt minimal.
"""
import httpx
import pytest
from fastapi import HTTPException

import ai_remediation
import supabase_auth


class _FakeResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text or str(json_data)

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    """Drop-in stand-in for httpx.AsyncClient used as an async context manager."""

    def __init__(self, behavior):
        self._behavior = behavior  # callable(*args, **kwargs) -> _FakeResponse, or raises

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, *args, **kwargs):
        return self._behavior(*args, **kwargs)

    async def post(self, *args, **kwargs):
        return self._behavior(*args, **kwargs)


def _install_fake_client(monkeypatch, module, behavior):
    monkeypatch.setattr(module.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(behavior))


# ---------------------------------------------------------------------------
# ai_remediation._call_claude
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_claude_timeout_is_504(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    _install_fake_client(monkeypatch, ai_remediation, raise_timeout)
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 504


@pytest.mark.asyncio
async def test_call_claude_network_error_is_502(monkeypatch):
    def raise_connect_error(*args, **kwargs):
        raise httpx.ConnectError("no route to host")

    _install_fake_client(monkeypatch, ai_remediation, raise_connect_error)
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_call_claude_invalid_api_key_is_503(monkeypatch):
    _install_fake_client(monkeypatch, ai_remediation, lambda *a, **kw: _FakeResponse(401))
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 503
    assert "invalid" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_call_claude_upstream_rate_limited_is_429(monkeypatch):
    _install_fake_client(monkeypatch, ai_remediation, lambda *a, **kw: _FakeResponse(429))
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_call_claude_upstream_down_is_502(monkeypatch):
    _install_fake_client(monkeypatch, ai_remediation, lambda *a, **kw: _FakeResponse(503))
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_call_claude_success_returns_text(monkeypatch):
    good_response = _FakeResponse(200, json_data={"content": [{"type": "text", "text": "the fix"}]})
    _install_fake_client(monkeypatch, ai_remediation, lambda *a, **kw: good_response)
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "sk-ant-fake")

    result = await ai_remediation._call_claude("system", "hello")
    assert result == "the fix"


@pytest.mark.asyncio
async def test_call_claude_not_configured_is_503(monkeypatch):
    monkeypatch.setattr(ai_remediation, "ANTHROPIC_API_KEY", "")
    with pytest.raises(HTTPException) as exc:
        await ai_remediation._call_claude("system", "hello")
    assert exc.value.status_code == 503


# ---------------------------------------------------------------------------
# supabase_auth._fetch_is_premium — must fail CLOSED, never grant premium
# as a side effect of a network problem
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_is_premium_fails_closed_on_network_error(monkeypatch):
    def raise_connect_error(*args, **kwargs):
        raise httpx.ConnectError("no route to host")

    _install_fake_client(monkeypatch, supabase_auth, raise_connect_error)
    result = await supabase_auth._fetch_is_premium("some-user-id")
    assert result is False


@pytest.mark.asyncio
async def test_fetch_is_premium_fails_closed_on_bad_status(monkeypatch):
    _install_fake_client(monkeypatch, supabase_auth, lambda *a, **kw: _FakeResponse(500))
    result = await supabase_auth._fetch_is_premium("some-user-id")
    assert result is False


@pytest.mark.asyncio
async def test_fetch_supabase_user_timeout_is_504(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    _install_fake_client(monkeypatch, supabase_auth, raise_timeout)
    with pytest.raises(HTTPException) as exc:
        await supabase_auth._fetch_supabase_user("some-token")
    assert exc.value.status_code == 504
