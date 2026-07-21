# AegisLab Privacy Policy

**Draft — last updated: [fill in date before publishing]**

> ⚠️ **This is a first draft written to accurately describe what the
> software actually does, based on the current codebase. It is NOT legal
> advice, and has not been reviewed by a lawyer.** Have an actual attorney
> (ideally one familiar with your jurisdiction and, if you take EU/UK
> users, GDPR) review this before you publish or rely on it. Fill in the
> bracketed placeholders ([Company/Developer Name], [contact email],
> [jurisdiction]) before shipping.

## The short version

AegisLab is designed to be **local-first**. The security scans themselves
— the API you're testing, the findings, the reports — never leave your
own machine unless you explicitly export or share them. We only collect
the minimum needed to run three *optional* features: account sign-in, AI
fix suggestions, and billing.

## What AegisLab does NOT do

- It does not phone home with usage analytics, telemetry, or tracking of
  any kind. There is no third-party analytics SDK in this app.
- It does not upload your scan targets, scan results, or source code
  anywhere by default. Everything runs against a local backend process on
  your own machine ([http://127.0.0.1:8765](http://127.0.0.1:8765)).
- It does not see or store your payment card details — that's handled
  entirely by Stripe's own hosted Checkout and billing portal (see
  "Billing" below).

## What data is collected, and by which feature

### Scanning (core feature — no account needed)
Scan configuration, findings, and generated reports are held **in memory**
in the local backend process while the app is running, and written to disk
only when you explicitly export a report or when uploading a source `.zip`
for static scanning (temporarily, to run the checks — see "Local storage"
below). None of this is transmitted to us or any third party.

### Account sign-in (optional)
If you create an account, authentication is handled by **Supabase**
(a third-party auth provider). We store:
- Your email address (via Supabase Auth)
- A `profiles` record: your user ID, whether your account is premium, and
  (if you subscribe) your Stripe customer/subscription ID

We do not store your password — Supabase handles that. See
[Supabase's own privacy policy](https://supabase.com/privacy) for how they
process this data.

### AI-powered fix suggestions (optional, opt-in per click)
When you click "Get AI fix suggestion" or "Auto-apply AI fix," the
specific finding you clicked on — its description, severity, and affected
endpoint — is sent to **Anthropic's API** to generate a suggested fix. For
"Auto-apply," the specific affected source file (identified from your
uploaded zip) is also sent, so Claude can rewrite it. **Only the file(s)
relevant to that one finding are sent — not your whole codebase, and not
your live API's actual data or credentials.** See
[Anthropic's privacy policy](https://www.anthropic.com/legal/privacy) for
how they process this.

### Billing (optional)
Subscription payments are handled entirely by **Stripe** via their hosted
Checkout and customer portal, opened in your system browser — card details
never pass through AegisLab's own code. We only receive and store a Stripe
customer ID and subscription ID (used to check your premium status), via
Stripe's webhook. See [Stripe's privacy policy](https://stripe.com/privacy)
for how they process payment data.

### Local diagnostic logs
The backend writes a local log file (`backend.log`, in the app's local
data directory) to help diagnose startup problems. This file stays on your
machine and is never transmitted anywhere; you can delete it at any time.

## Data retention

- Scan results held in memory are cleared when you close the app.
- Uploaded source `.zip` files (for static scanning) are kept temporarily
  on local disk for the duration of your session so AI auto-fix can locate
  the relevant file, and are not transmitted anywhere except the specific
  files sent to Anthropic as described above.
- Account/profile data persists in Supabase until you request deletion
  (contact [contact email]) or delete your account.

## Your choices

- Use AegisLab's scanning features entirely without an account.
- Sign in without ever using the AI features — the AI buttons simply won't
  be used, and nothing is sent to Anthropic.
- Request deletion of your account and associated data at any time via
  [contact email].

## Children's privacy

AegisLab is a developer/security-testing tool not directed at children,
and we do not knowingly collect data from anyone under 13 (or the relevant
age of consent in your jurisdiction).

## Changes to this policy

If this policy changes materially, we'll update the "last updated" date
above. [Add your notification mechanism here, e.g. an in-app notice or
changelog entry, once you have one.]

## Contact

Questions about this policy or your data: [contact email].
