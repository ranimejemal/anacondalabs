# Security Policy

AegisLab is a security testing tool, which makes vulnerabilities in AegisLab
itself worth taking especially seriously — please report them responsibly
rather than opening a public issue.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email [security contact email — fill in before publishing] with:
- A description of the vulnerability and its potential impact
- Steps to reproduce it
- Any relevant logs, screenshots, or proof-of-concept code

We'll acknowledge your report within 3 business days and aim to provide a
timeline for a fix. If you'd like credit for the finding, let us know how
you'd like to be acknowledged once it's fixed.

## Scope

This covers vulnerabilities in AegisLab itself — the Electron app, the
Python backend, the Supabase/Stripe/Anthropic integration code. It does not
cover:
- Vulnerabilities in target APIs *found by* AegisLab (that's the product
  working as intended — report those to the target's own owner, not us)
- Vulnerabilities in third-party dependencies (report those upstream;
  though we'd still appreciate a heads-up so we can update)

## Supported versions

Only the latest released version is supported with security fixes.

## What "authorized to test" means for this repo

AegisLab's own README and Terms of Use require users to only scan systems
they own or are explicitly authorized to test. If you're security testing
AegisLab's own reference/example targets (`examples/mock_vulnerable_api.py`)
locally, that's fine — it exists for exactly that purpose.
