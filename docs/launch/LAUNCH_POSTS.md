# Launch post drafts

Fill in [bracketed placeholders] before posting — download links, repo URL,
pricing. Post Show HN and the Reddit post within the same day if possible;
cross-posting too far apart dilutes both.

---

## Hacker News (Show HN)

**Title:** Show HN: AegisLab – a desktop app that runs OWASP API security checks locally

**Body:**

I built AegisLab because every API security scanner I found was either a
SaaS that wants your API's traffic routed through their servers, or a
heavyweight pentest tool with a learning curve steep enough that I'd never
reach for it on a random Tuesday to sanity-check a side project's API.

AegisLab is a desktop app (Electron + Python/FastAPI backend, runs
entirely on your own machine). Point it at an API — import an OpenAPI
spec or add endpoints manually — or upload a source code .zip for a
static scan, and it runs 8 checks mapped to the OWASP API Security Top 10:
broken auth, broken object-level authorization (BOLA), mass assignment,
SSRF, missing rate limiting, injection signatures, data exposure, and
security misconfiguration. You get a 0-100 score, a plain-language
explanation of each finding, and — for a few common issue types — an
exact code snippet to fix it.

Nothing about your API or your code leaves your machine unless you
explicitly opt into AI-powered fix suggestions (which sends just the
specific finding + affected file to Claude, not your whole codebase).

It's free to scan, no account needed. An account only unlocks AI fix
suggestions; a paid tier unlocks one-click auto-apply on uploaded source.

Coverage is honestly scoped — 7 of 10 OWASP categories, not 10, because
the other three (business flow abuse, inventory management, third-party
API trust) don't reduce to an automated HTTP probe the way the rest do,
and I'd rather say that than fake coverage.

Repo: [link]
Download: [link]

Happy to answer questions about the architecture, the detection
approach for any specific module, or why I made specific scope decisions
(e.g. why SSRF detection doesn't require you to stand up your own
out-of-band callback infrastructure).

---

## Reddit — r/netsec

**Title:** AegisLab – open-source-ish desktop tool for OWASP API Top 10 scanning (local-first)

**Body:**

Sharing a tool I built: AegisLab, a desktop app that runs automated OWASP
API Security Top 10 checks against an API you're authorized to test.

Why another scanner: most options I found were either SaaS (your API
traffic goes through a third party) or full pentest suites with a setup
cost too high for "let me just check this one API before I ship it."
AegisLab runs entirely locally — Electron frontend, Python/FastAPI
backend on 127.0.0.1, nothing phones home.

**What it checks** (mapped to OWASP API Security Top 10):
- Broken authentication (missing auth, weak token validation)
- Broken object-level authorization / BOLA
- Broken function-level authorization
- Mass assignment (probes for undocumented privileged fields accepted +
  reflected back)
- SSRF (cloud metadata probe, self-contained — no external infra needed;
  optional out-of-band callback check if you supply your own canary URL)
- Missing rate limiting
- Injection signatures (SQL/NoSQL)
- Data exposure + security misconfiguration (CORS, headers, transport)

**What it doesn't claim to check**, on purpose: business-flow abuse,
API inventory management, third-party API trust (API6/9/10) — these need
context a generic scanner can't infer, and I'd rather scope honestly than
pad a coverage number.

Consent is enforced in the app itself — a required checkbox before any
live scan runs, specifically because running scans against systems you're
not authorized to test has real legal exposure (CFAA and equivalents).

Static source scanning (upload a .zip, no running API needed) checks for
hardcoded secrets and missing security middleware.

Would appreciate feedback from this sub specifically on the detection
logic — happy to walk through any module's approach in the comments, and
genuinely interested in false-positive/false-negative reports against
real-world APIs.

Repo: [link]

---

## Twitter/X thread

**1/**
Shipped AegisLab: a desktop app that runs OWASP API Security Top 10 checks
against your API — entirely locally, no account needed to scan.

[screenshot of scan results]

**2/**
Point it at a live API (import an OpenAPI spec or add endpoints manually)
or upload source code for a static scan. 8 checks: broken auth, BOLA,
mass assignment, SSRF, rate limiting, injection, data exposure, misconfig.

**3/**
Every finding maps to its OWASP category, in plain language, with a fix
recommendation — and for common issue types, an exact code snippet to
paste in.

**4/**
Coverage is honest: 7/10 OWASP categories, not 10. The other three don't
reduce to an automated probe. Didn't want to pad the number.

**5/**
Free to scan, forever, no account. AI-powered fix suggestions (opt-in)
unlock with a free account; auto-apply is a paid feature.

**6/**
Built with Electron + Python/FastAPI. [Repo link] if you want to see how
any of the detection modules work — SSRF's cloud-metadata probe in
particular doesn't need you to stand up external callback infrastructure.

**7/**
Download: [link]. Would love bug reports, false-positive reports, or just
"ran it against my API and here's what happened."
