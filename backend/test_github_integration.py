"""
AegisLab — pytest suite for github_integration.py and the /api/github/*
endpoints (OAuth "Connect account" flow, repo listing, repo import into
the existing static-scan pipeline).

Uses the same small fake-httpx-client stand-in pattern as
test_error_handling.py, since these are the only places needing to
simulate GitHub API/OAuth responses.
"""
import zipfile
from io import BytesIO

import pytest

import github_integration
import main


class _FakeResponse:
    def __init__(self, status_code, json_data=None, content=b"", text=""):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.content = content
        self.text = text or str(json_data)

    def json(self):
        return self._json_data


class _FakeAsyncClient:
    def __init__(self, behavior):
        self._behavior = behavior  # callable(method, url, **kwargs) -> _FakeResponse

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        return self._behavior("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return self._behavior("POST", url, **kwargs)


def _install_fake_client(monkeypatch, behavior):
    monkeypatch.setattr(github_integration.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(behavior))


@pytest.fixture(autouse=True)
def _configure_github(monkeypatch):
    monkeypatch.setattr(github_integration, "GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(github_integration, "GITHUB_CLIENT_SECRET", "test-client-secret")
    github_integration._pending_states.clear()
    yield
    github_integration._pending_states.clear()


# ---------------------------------------------------------------------------
# build_authorize_url / state handling
# ---------------------------------------------------------------------------

def test_build_authorize_url_includes_client_id_and_state():
    url = github_integration.build_authorize_url()
    assert "client_id=test-client-id" in url
    assert "state=" in url
    assert len(github_integration._pending_states) == 1


def test_not_configured_returns_503(monkeypatch):
    monkeypatch.setattr(github_integration, "GITHUB_CLIENT_ID", "")
    with pytest.raises(Exception) as exc_info:
        github_integration.build_authorize_url()
    assert "503" in str(exc_info.value) or getattr(exc_info.value, "status_code", None) == 503


# ---------------------------------------------------------------------------
# exchange_code_for_token
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exchange_rejects_unknown_state(monkeypatch):
    with pytest.raises(Exception) as exc_info:
        await github_integration.exchange_code_for_token("some-code", "never-issued-state")
    assert getattr(exc_info.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_exchange_success(monkeypatch):
    url = github_integration.build_authorize_url()
    state = url.split("state=")[1].split("&")[0]

    def behavior(method, url, **kwargs):
        if "access_token" in url:
            return _FakeResponse(200, json_data={"access_token": "gho_faketoken"})
        if url.endswith("/user"):
            return _FakeResponse(200, json_data={"login": "octocat", "avatar_url": "https://example.com/a.png"})
        raise AssertionError(f"unexpected call to {url}")

    _install_fake_client(monkeypatch, behavior)
    result = await github_integration.exchange_code_for_token("some-code", state)
    assert result == {"access_token": "gho_faketoken", "login": "octocat", "avatar_url": "https://example.com/a.png"}
    # state is single-use
    assert state not in github_integration._pending_states


@pytest.mark.asyncio
async def test_exchange_state_cannot_be_reused(monkeypatch):
    url = github_integration.build_authorize_url()
    state = url.split("state=")[1].split("&")[0]

    def behavior(method, url, **kwargs):
        if "access_token" in url:
            return _FakeResponse(200, json_data={"access_token": "gho_faketoken"})
        return _FakeResponse(200, json_data={"login": "octocat"})

    _install_fake_client(monkeypatch, behavior)
    await github_integration.exchange_code_for_token("some-code", state)

    with pytest.raises(Exception) as exc_info:
        await github_integration.exchange_code_for_token("some-code", state)
    assert getattr(exc_info.value, "status_code", None) == 400


@pytest.mark.asyncio
async def test_exchange_github_error_response(monkeypatch):
    url = github_integration.build_authorize_url()
    state = url.split("state=")[1].split("&")[0]

    def behavior(method, url, **kwargs):
        return _FakeResponse(200, json_data={"error": "bad_verification_code", "error_description": "expired code"})

    _install_fake_client(monkeypatch, behavior)
    with pytest.raises(Exception) as exc_info:
        await github_integration.exchange_code_for_token("bad-code", state)
    assert getattr(exc_info.value, "status_code", None) == 400


# ---------------------------------------------------------------------------
# list_user_repos
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_user_repos_single_page(monkeypatch):
    def behavior(method, url, **kwargs):
        return _FakeResponse(200, json_data=[
            {"full_name": "octocat/hello-world", "private": False, "default_branch": "main"},
        ])

    _install_fake_client(monkeypatch, behavior)
    repos = await github_integration.list_user_repos("gho_faketoken")
    assert len(repos) == 1
    assert repos[0]["full_name"] == "octocat/hello-world"


@pytest.mark.asyncio
async def test_list_user_repos_expired_token_is_401(monkeypatch):
    def behavior(method, url, **kwargs):
        return _FakeResponse(401, json_data={"message": "Bad credentials"})

    _install_fake_client(monkeypatch, behavior)
    with pytest.raises(Exception) as exc_info:
        await github_integration.list_user_repos("expired-token")
    assert getattr(exc_info.value, "status_code", None) == 401


# ---------------------------------------------------------------------------
# download_repo_zip
# ---------------------------------------------------------------------------

def _make_zip_bytes(files: dict) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_download_repo_zip_success(monkeypatch):
    zip_bytes = _make_zip_bytes({"repo-main/app.js": "console.log(1)"})

    def behavior(method, url, **kwargs):
        return _FakeResponse(200, content=zip_bytes)

    _install_fake_client(monkeypatch, behavior)
    result = await github_integration.download_repo_zip("gho_faketoken", "octocat", "hello-world")
    assert result == zip_bytes


@pytest.mark.asyncio
async def test_download_repo_zip_not_found(monkeypatch):
    def behavior(method, url, **kwargs):
        return _FakeResponse(404, text="Not Found")

    _install_fake_client(monkeypatch, behavior)
    with pytest.raises(Exception) as exc_info:
        await github_integration.download_repo_zip("gho_faketoken", "octocat", "does-not-exist")
    assert getattr(exc_info.value, "status_code", None) == 404


@pytest.mark.asyncio
async def test_download_repo_zip_too_large_is_413(monkeypatch):
    monkeypatch.setattr(github_integration, "MAX_REPO_ZIP_BYTES", 10)

    def behavior(method, url, **kwargs):
        return _FakeResponse(200, content=b"x" * 100)

    _install_fake_client(monkeypatch, behavior)
    with pytest.raises(Exception) as exc_info:
        await github_integration.download_repo_zip("gho_faketoken", "octocat", "huge-repo")
    assert getattr(exc_info.value, "status_code", None) == 413


# ---------------------------------------------------------------------------
# /api/github/* endpoints (through main.app)
# ---------------------------------------------------------------------------

def test_authorize_url_endpoint_not_configured_returns_503(client, monkeypatch):
    monkeypatch.setattr(github_integration, "GITHUB_CLIENT_ID", "")
    resp = client.get("/api/github/oauth/authorize-url")
    assert resp.status_code == 503


def test_authorize_url_endpoint_returns_url(client):
    resp = client.get("/api/github/oauth/authorize-url")
    assert resp.status_code == 200
    assert resp.json()["url"].startswith(github_integration.AUTHORIZE_URL)


def test_exchange_endpoint_rejects_bad_state(client):
    resp = client.post("/api/github/oauth/exchange", json={"code": "x", "state": "unknown"})
    assert resp.status_code == 400


def test_repos_endpoint_requires_token_header(client):
    resp = client.get("/api/github/repos")
    assert resp.status_code == 422  # missing required X-GitHub-Token header


def test_import_endpoint_runs_static_scan(client, monkeypatch, tmp_path):
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(main, "UPLOADS_DIR", tmp_path)
    zip_bytes = _make_zip_bytes({"README.md": "hello\n"})

    async def fake_download(access_token, owner, repo, ref=None):
        return zip_bytes

    monkeypatch.setattr(github_integration, "download_repo_zip", fake_download)

    resp = client.post(
        "/api/github/import",
        json={"access_token": "gho_faketoken", "owner": "octocat", "repo": "hello-world"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "scan_id" in body
    assert body["result"]["base_url"] == "(GitHub import: octocat/hello-world)"
