"""
AegisLab — pytest suite for Sprint 3 billing (Stripe Checkout, customer
portal, and webhook handling).

Stripe's HTTP API itself is mocked (same pattern as test_error_handling.py)
since this is testing AegisLab's own logic — signature verification,
webhook event routing, and the premium-flip side effects — not whether
Stripe's API is reachable. Webhook signatures are constructed for real
using the same HMAC scheme Stripe uses, against the test STRIPE_WEBHOOK_SECRET
set in conftest.py, so the signature verification path is exercised
genuinely rather than bypassed.
"""
import hashlib
import hmac
import json
import time

import stripe_billing
from conftest import FREE_USER, PREMIUM_USER
from test_error_handling import _FakeResponse, _install_fake_client


def _sign(payload: bytes, secret: str, timestamp: int | None = None) -> str:
    ts = timestamp if timestamp is not None else int(time.time())
    signed_payload = f"{ts}.{payload.decode()}"
    sig = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ---------------------------------------------------------------------------
# /api/billing/checkout
# ---------------------------------------------------------------------------

def test_checkout_returns_stripe_url(client, mock_supabase, monkeypatch):
    fake_resp = _FakeResponse(200, json_data={"url": "https://checkout.stripe.com/c/session_123"})
    _install_fake_client(monkeypatch, stripe_billing, lambda *a, **kw: fake_resp)

    resp = client.post("/api/billing/checkout", headers={"Authorization": "Bearer valid-free-token"})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://checkout.stripe.com/c/session_123"


def test_checkout_requires_auth(client, mock_supabase, monkeypatch):
    resp = client.post("/api/billing/checkout")
    assert resp.status_code == 401


def test_checkout_blocked_if_already_premium(client, mock_supabase, monkeypatch):
    resp = client.post("/api/billing/checkout", headers={"Authorization": "Bearer valid-premium-token"})
    assert resp.status_code == 400
    assert "already premium" in resp.json()["detail"].lower()


def test_checkout_surfaces_stripe_error(client, mock_supabase, monkeypatch):
    fake_resp = _FakeResponse(400, json_data={"error": {"message": "No such price: price_fake123"}})
    _install_fake_client(monkeypatch, stripe_billing, lambda *a, **kw: fake_resp)

    resp = client.post("/api/billing/checkout", headers={"Authorization": "Bearer valid-free-token"})
    assert resp.status_code == 502
    assert "no such price" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# /api/billing/portal
# ---------------------------------------------------------------------------

def test_portal_requires_existing_customer(client, mock_supabase, monkeypatch):
    async def fake_get_customer_id(user_id):
        return None
    monkeypatch.setattr("main.get_stripe_customer_id", fake_get_customer_id)

    resp = client.post("/api/billing/portal", headers={"Authorization": "Bearer valid-premium-token"})
    assert resp.status_code == 400


def test_portal_returns_url_for_existing_customer(client, mock_supabase, monkeypatch):
    async def fake_get_customer_id(user_id):
        return "cus_fake123"
    monkeypatch.setattr("main.get_stripe_customer_id", fake_get_customer_id)

    fake_resp = _FakeResponse(200, json_data={"url": "https://billing.stripe.com/p/session_456"})
    _install_fake_client(monkeypatch, stripe_billing, lambda *a, **kw: fake_resp)

    resp = client.post("/api/billing/portal", headers={"Authorization": "Bearer valid-premium-token"})
    assert resp.status_code == 200
    assert "billing.stripe.com" in resp.json()["url"]


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------

def test_webhook_rejects_missing_signature(client):
    resp = client.post("/api/billing/webhook", content=b'{"type": "x"}')
    assert resp.status_code == 400


def test_webhook_rejects_bad_signature(client):
    payload = b'{"type": "checkout.session.completed"}'
    bad_sig = _sign(payload, "wrong-secret")
    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": bad_sig})
    assert resp.status_code == 400


def test_webhook_rejects_stale_timestamp(client):
    payload = b'{"type": "checkout.session.completed"}'
    old_sig = _sign(payload, "whsec_test_fake_secret", timestamp=int(time.time()) - 10_000)
    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": old_sig})
    assert resp.status_code == 400
    assert "replay" in resp.json()["detail"].lower() or "tolerance" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Webhook event handling — the actual premium-flip side effects
# ---------------------------------------------------------------------------

def test_webhook_checkout_completed_grants_premium(client, monkeypatch):
    calls = {}

    async def fake_set_premium_status(user_id, is_premium, stripe_customer_id=None, stripe_subscription_id=None):
        calls["args"] = (user_id, is_premium, stripe_customer_id, stripe_subscription_id)

    monkeypatch.setattr("main.set_premium_status", fake_set_premium_status)

    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "client_reference_id": FREE_USER["id"],
            "customer": "cus_new123",
            "subscription": "sub_new123",
        }},
    }
    payload = json.dumps(event).encode()
    sig = _sign(payload, "whsec_test_fake_secret")

    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": sig})
    assert resp.status_code == 200
    assert calls["args"] == (FREE_USER["id"], True, "cus_new123", "sub_new123")


def test_webhook_subscription_deleted_revokes_premium(client, monkeypatch):
    calls = {}

    async def fake_find_user(customer_id):
        return PREMIUM_USER["id"]

    async def fake_set_premium_status(user_id, is_premium, stripe_customer_id=None, stripe_subscription_id=None):
        calls["args"] = (user_id, is_premium)

    monkeypatch.setattr("main.find_user_id_by_stripe_customer", fake_find_user)
    monkeypatch.setattr("main.set_premium_status", fake_set_premium_status)

    event = {"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_premium123"}}}
    payload = json.dumps(event).encode()
    sig = _sign(payload, "whsec_test_fake_secret")

    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": sig})
    assert resp.status_code == 200
    assert calls["args"] == (PREMIUM_USER["id"], False)


def test_webhook_payment_failed_does_not_revoke_premium(client, monkeypatch):
    """Day 8 grace-period policy: a failed payment alone must NOT flip
    is_premium — only an actual subscription.deleted event does."""
    called = {"flag": False}

    async def fake_set_premium_status(*a, **kw):
        called["flag"] = True

    monkeypatch.setattr("main.set_premium_status", fake_set_premium_status)

    event = {"type": "invoice.payment_failed", "data": {"object": {"customer": "cus_premium123"}}}
    payload = json.dumps(event).encode()
    sig = _sign(payload, "whsec_test_fake_secret")

    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": sig})
    assert resp.status_code == 200
    assert called["flag"] is False


def test_webhook_cancel_at_period_end_does_not_revoke_immediately(client, monkeypatch):
    """subscription.updated with cancel_at_period_end=true should NOT
    immediately revoke — access continues until subscription.deleted."""
    called = {"flag": False}

    async def fake_set_premium_status(*a, **kw):
        called["flag"] = True

    monkeypatch.setattr("main.set_premium_status", fake_set_premium_status)

    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {"customer": "cus_premium123", "cancel_at_period_end": True, "status": "active"}},
    }
    payload = json.dumps(event).encode()
    sig = _sign(payload, "whsec_test_fake_secret")

    resp = client.post("/api/billing/webhook", content=payload, headers={"stripe-signature": sig})
    assert resp.status_code == 200
    assert called["flag"] is False
