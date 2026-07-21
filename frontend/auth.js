/**
 * AegisLab - auth.js
 * ===================
 * Thin wrapper around Supabase Auth for the sidebar account panel. Exposes
 * window.aegisAuth for renderer.js / remediation rendering to read the
 * current session and premium status without each having to know about
 * Supabase directly.
 *
 * Session persistence: supabase-js itself stores the session in
 * localStorage (this is a real desktop Electron file, not a sandboxed
 * Artifact, so that's fine here) and restores it automatically on reload.
 */

let _sbClient = null;
let _currentUser = null; // { id, email, is_premium } | null

function _getClient() {
  if (_sbClient) return _sbClient;
  const cfg = window.AEGISLAB_CONFIG || {};
  if (!cfg.SUPABASE_URL || !cfg.SUPABASE_ANON_KEY) return null;
  _sbClient = window.supabase.createClient(cfg.SUPABASE_URL, cfg.SUPABASE_ANON_KEY);
  return _sbClient;
}

async function _refreshPremiumStatus(backendUrl) {
  const client = _getClient();
  if (!client) return null;
  const { data } = await client.auth.getSession();
  const session = data && data.session;
  if (!session) {
    _currentUser = null;
    return null;
  }
  try {
    const resp = await fetch(`${backendUrl}/api/me`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (!resp.ok) throw new Error("me lookup failed");
    const me = await resp.json();
    _currentUser = { id: me.id, email: me.email, is_premium: !!me.is_premium, accessToken: session.access_token };
  } catch (e) {
    // Backend AI features may not be configured yet — still treat the user
    // as signed in (free tier) so the UI doesn't look broken.
    _currentUser = { id: session.user.id, email: session.user.email, is_premium: false, accessToken: session.access_token };
  }
  return _currentUser;
}

function _setAuthError(msg) {
  const el = document.getElementById("authError");
  if (el) el.textContent = msg || "";
}

function _renderAccountUI() {
  const signedOut = document.getElementById("accountSignedOut");
  const signedIn = document.getElementById("accountSignedIn");
  if (!signedOut || !signedIn) return;

  if (_currentUser) {
    signedOut.style.display = "none";
    signedIn.style.display = "block";
    document.getElementById("accountEmail").textContent = _currentUser.email || "";
    document.getElementById("premiumBadge").style.display = _currentUser.is_premium ? "inline-block" : "none";
    document.getElementById("upgradeBtn").style.display = _currentUser.is_premium ? "none" : "block";
    document.getElementById("manageBillingBtn").style.display = _currentUser.is_premium ? "block" : "none";
  } else {
    signedOut.style.display = "block";
    signedIn.style.display = "none";
  }
  document.dispatchEvent(new CustomEvent("aegis-auth-changed", { detail: _currentUser }));
}

let _pollTimer = null;

function _pollForPremiumUpgrade(backendUrl, attemptsLeft = 24) {
  // After sending the user to Stripe Checkout in their system browser, the
  // app has no way to know when they're done — so poll /api/me for a couple
  // of minutes (24 x 5s) after the checkout tab is opened. Cheap and simple;
  // the user can also just re-open the app panel later and it'll be current
  // regardless, since /api/me always reflects live Supabase state.
  if (_pollTimer) clearInterval(_pollTimer);
  if (!attemptsLeft) return;
  _pollTimer = setInterval(async () => {
    attemptsLeft -= 1;
    const before = _currentUser && _currentUser.is_premium;
    await _refreshPremiumStatus(backendUrl);
    _renderAccountUI();
    const after = _currentUser && _currentUser.is_premium;
    if ((!before && after) || attemptsLeft <= 0) {
      clearInterval(_pollTimer);
      _pollTimer = null;
      if (!before && after) _setBillingStatus("Upgraded to Premium — thanks!");
    }
  }, 5000);
}

function _setBillingStatus(msg) {
  const el = document.getElementById("billingStatus");
  if (el) el.textContent = msg || "";
}

async function initAuth(backendUrl) {
  const client = _getClient();
  const errEl = document.getElementById("authError");

  if (!client) {
    if (errEl) errEl.textContent = "AI sign-in isn't configured yet (see frontend/config.js).";
    document.getElementById("signInBtn")?.setAttribute("disabled", "true");
    document.getElementById("signUpBtn")?.setAttribute("disabled", "true");
    return;
  }

  await _refreshPremiumStatus(backendUrl);
  _renderAccountUI();

  document.getElementById("signInBtn").addEventListener("click", async () => {
    _setAuthError("");
    const email = document.getElementById("authEmail").value.trim();
    const password = document.getElementById("authPassword").value;
    const { error } = await client.auth.signInWithPassword({ email, password });
    if (error) return _setAuthError(error.message);
    await _refreshPremiumStatus(backendUrl);
    _renderAccountUI();
  });

  document.getElementById("signUpBtn").addEventListener("click", async () => {
    _setAuthError("");
    const email = document.getElementById("authEmail").value.trim();
    const password = document.getElementById("authPassword").value;
    const { error } = await client.auth.signUp({ email, password });
    if (error) return _setAuthError(error.message);
    _setAuthError("Check your email to confirm your account, then sign in.");
  });

  document.getElementById("signOutBtn").addEventListener("click", async () => {
    await client.auth.signOut();
    _currentUser = null;
    _renderAccountUI();
  });

  document.getElementById("upgradeBtn").addEventListener("click", async () => {
    _setBillingStatus("Opening checkout in your browser…");
    try {
      const resp = await fetch(`${backendUrl}/api/billing/checkout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${_currentUser.accessToken}` },
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Checkout failed");
      await window.aegis.openExternal(data.url);
      _setBillingStatus("Complete checkout in your browser, then come back here.");
      _pollForPremiumUpgrade(backendUrl);
    } catch (e) {
      _setBillingStatus(`Couldn't start checkout: ${e.message}`);
    }
  });

  document.getElementById("manageBillingBtn").addEventListener("click", async () => {
    _setBillingStatus("Opening billing portal…");
    try {
      const resp = await fetch(`${backendUrl}/api/billing/portal`, {
        method: "POST",
        headers: { Authorization: `Bearer ${_currentUser.accessToken}` },
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Couldn't open billing portal");
      await window.aegis.openExternal(data.url);
      _setBillingStatus("");
      _pollForPremiumUpgrade(backendUrl); // catches cancellations too
    } catch (e) {
      _setBillingStatus(`Couldn't open billing portal: ${e.message}`);
    }
  });
}

window.aegisAuth = {
  init: initAuth,
  getUser: () => _currentUser,
  isSignedIn: () => !!_currentUser,
  isPremium: () => !!(_currentUser && _currentUser.is_premium),
  getAccessToken: () => (_currentUser ? _currentUser.accessToken : null),
};
