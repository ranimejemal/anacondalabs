# What AegisLab does, and how to test it yourself

## What it is, in plain terms

AegisLab is a desktop app that checks an API (or a codebase) for common
security mistakes — automatically, in minutes, without you needing to be
a security expert to run it or read the results.

Think of it like a spell-checker, but for API security bugs instead of
typos. You point it at a target, it runs a battery of checks, and it hands
you back a scored report: what's wrong, how bad it is, why it matters, and
often the exact code fix.

It runs entirely on your own machine — nothing about your API or your code
is sent anywhere unless you explicitly turn on the optional AI features.

## What it actually checks

AegisLab tests for 8 categories of the **OWASP API Security Top 10** — the
industry-standard list of the most common ways APIs get broken into:

| # | What it catches | Plain-language example |
|---|---|---|
| Broken Authentication | Weak login/session handling | Your login endpoint doesn't rate-limit password guesses |
| Broken Object Level Authorization (BOLA) | Cross-account data access | User A can view User B's order by just changing an ID in the URL |
| Broken Function Level Authorization | Missing admin checks | A regular user can hit `/admin/dashboard` because nobody checks their role |
| Mass Assignment | Unexpected fields accepted | Sending `"role": "admin"` in a signup request actually makes you an admin |
| Server-Side Request Forgery (SSRF) | Server fetches attacker URLs | An "avatar URL" field lets you make the server fetch its own cloud credentials |
| Unrestricted Resource Consumption | No rate limiting | Nothing stops someone from hammering your login endpoint 10,000 times a second |
| Injection | SQL/NoSQL injection signatures | A search box that leaks database errors when you send it malformed input |
| Security Misconfiguration | Bad headers, CORS, unencrypted transport | Your API allows requests from any website with credentials attached |

It also does a **static scan**: upload a .zip of your source code (no
running API needed) and it checks for hardcoded secrets (API keys,
passwords committed to the repo) and missing security middleware.

Every finding gets a severity (Critical/High/Medium/Low), a plain-English
explanation of the impact, and a recommended fix — often as an exact code
snippet you can paste in.

## What it's *not*

- Not a full penetration test — it's automated checks, not a human trying
  creative attacks.
- Not comprehensive — it covers 7 of 10 OWASP categories on purpose (the
  other 3 need business context a generic scanner can't infer — see the
  README for exactly which and why).
- Not something to run against systems you don't own or aren't authorized
  to test — the app requires you to confirm that before any live scan.

---

## How to test it yourself

### Step 1 — Install the prerequisites (one-time)

You need two things installed on your machine:
- **Python 3.11+** — [python.org/downloads](https://www.python.org/downloads/)
- **Node.js 18+** — [nodejs.org](https://nodejs.org/)

That's it. Everything else installs itself.

### Step 2 — Unzip the project and run one command

```bash
# macOS/Linux:
cd AegisLab
./scripts/start_app.sh

# Windows:
cd AegisLab
scripts\start_app.bat
```

First run takes a minute or two — it's creating a local Python environment
and installing dependencies automatically. After that, it just launches.

The app window should open. You'll see a short 4-step welcome walkthrough
— click through it or hit Skip.

### Step 3 — Scan something safe, on purpose

The project includes a **deliberately vulnerable practice API** you can
scan without worrying about testing something you don't own. Open a
second terminal and run:

```bash
cd AegisLab
python examples/mock_vulnerable_api.py
```

This starts a fake API on `http://127.0.0.1:9000` with real, intentional
security bugs baked in — safe to attack because it's just a local test
target.

### Step 4 — Run your first scan

Back in the AegisLab app:

1. Under **Target Base URL**, enter: `http://127.0.0.1:9000`
2. Click **Click to import spec (JSON/YAML)** and select
   `examples/sample_openapi.json` from the project folder — this loads 8
   pre-defined endpoints on the practice API, including ones deliberately
   vulnerable to mass assignment and SSRF.
3. Check the **consent checkbox** ("I confirm I own or am authorized to
   test this target") — required before any live scan runs.
4. Click **Start Scan**.

Within a few seconds you should see:
- A **Security Score** gauge (this practice API scores close to 0/100,
  Grade F — it's *supposed* to fail badly, that's the point)
- A **Findings by Severity** breakdown
- A **Findings Log** you can filter and click into for details
- A **Top Priority Fixes** panel with the worst issues and, for several,
  a ready-to-paste code fix

### Step 5 — Try a static scan (no running API needed)

Instead of a live target, you can zip up a source code folder and drag it
onto the **Static Source-Code Scan** dropzone. It checks for hardcoded
secrets and missing security middleware (Express/NestJS) without making a
single network request.

### Step 6 — Export a report

Once a scan finishes, **Export JSON** or **Export PDF** in the top bar
saves a full report to disk — useful for sharing with a team or keeping a
record.

### Step 7 (optional) — Try it against your own API

Once you've seen it work against the practice target, point `Target Base
URL` at a real API **you own or are explicitly authorized to test**, and
either import its OpenAPI spec or add its endpoints manually via **+ Add
endpoint manually**.

### Step 8 (optional) — AI-powered fixes

This needs extra setup (an Anthropic API key, a free Supabase account) —
see the README's "Optional: AI, sign-in, and billing setup" section.
Without it, everything above still works fully; you'll just see a "sign in
to unlock AI suggestions" message instead of AI-generated fixes.

---

## If something doesn't work

- **App won't launch**: run `scripts/start_app.sh` (or `.bat`) directly
  from a terminal rather than double-clicking — it'll print the exact
  error instead of failing silently.
- **"Could not reach the security engine"**: the Python backend didn't
  start. Check `logs/backend_app.log` in the project folder.
- **Scan hangs on "running"**: confirm `examples/mock_vulnerable_api.py`
  is actually running in that second terminal — the scan needs a live
  target to hit.
