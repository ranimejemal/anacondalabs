"""
AegisLab - static_scanner/secret_scan.py
===========================================
Language-agnostic detection of hardcoded secrets and credentials committed
to source. This is the highest-value check in the static scanner: dynamic
(running-API) tests can never see this class of issue, because the secret
just sits in a file and is never sent over the wire during a scan.

Every pattern here is a well-known, documented secret format (AWS key IDs,
Stripe live keys, Google API keys, PEM private key headers, JWT structure)
— the same signatures used by widely-deployed secret scanners like
git-secrets, truffleHog, and GitHub's own push-protection. Detecting that a
string MATCHES a known secret format is not the same as using that secret;
nothing here attempts to validate, use, or exfiltrate any detected key.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from models import Vulnerability, Severity

PLACEHOLDER_MARKERS = (
    "xxxx", "changeme", "your-", "your_", "example", "<your", "{{",
    "insert_", "replace_", "process.env", "import.meta.env", "${", "dummy",
)

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": Severity.CRITICAL,
        "issue": "Hardcoded AWS Access Key ID found in source",
        "impact": "An AWS access key committed to source grants whoever finds it programmatic access to your AWS account, scoped to whatever permissions that key has.",
        "recommendation": "Revoke this key immediately in the AWS IAM console, then move credentials to environment variables or a secrets manager (AWS Secrets Manager, Vault, etc.) and remove it from git history.",
    },
    {
        "name": "Stripe Live Secret Key",
        "regex": re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"),
        "severity": Severity.CRITICAL,
        "issue": "Hardcoded Stripe LIVE secret key found in source",
        "impact": "This key can create real charges, refunds, and payouts on your live Stripe account if it falls into the wrong hands.",
        "recommendation": "Roll this key in the Stripe dashboard immediately, then load it from an environment variable / secrets manager, never from source.",
    },
    {
        "name": "Google API Key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "severity": Severity.HIGH,
        "issue": "Hardcoded Google API key found in source",
        "impact": "An exposed Google API key can be used to consume your quota (billing impact) or, if unrestricted, access whichever Google APIs it's scoped to.",
        "recommendation": "Restrict the key by HTTP referrer/IP in Google Cloud Console, and move it to an environment variable.",
    },
    {
        "name": "PEM Private Key Block",
        "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
        "severity": Severity.CRITICAL,
        "issue": "Private key material committed to source",
        "impact": "A committed private key can be used to impersonate your server, decrypt traffic, or access systems that trust the matching public key.",
        "recommendation": "Rotate the key pair immediately, remove it from git history, and load private keys from a secrets manager or mounted secret file at runtime — never from the repo.",
    },
]

# Generic hardcoded-credential detection, handled separately from PATTERNS above
# because it needs to match keywords *inside* compound identifiers (JWT_SECRET,
# API_SECRET_KEY, DB_PASSWORD, etc.) rather than requiring an exact \b-bounded
# token — a plain `\bsecret\b` regex misses "JWT_SECRET" entirely, since
# underscores are word characters and there's no boundary before "SECRET".
GENERIC_ASSIGNMENT_RE = re.compile(
    r"""\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]\s*['"]([^'"\n]{8,})['"]"""
)
CREDENTIAL_NAME_MARKERS = (
    "secret", "password", "passwd", "apikey", "api_key", "accesstoken",
    "access_token", "clientsecret", "client_secret", "privatekey", "private_key",
    "authtoken", "auth_token", "signingkey", "signing_key", "encryptionkey", "encryption_key",
)
SAFE_VALUE_CONSTANTS = {
    "bearer", "basic", "jwt", "none", "rs256", "hs256", "es256", "es512", "ps256", "true", "false",
}

ENV_FILE_NAMES = {".env", ".env.local", ".env.production", ".env.development"}


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS) or len(value) < 8


def _decode_jwt_role(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = lambda s: s + "=" * (-len(s) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return payload.get("role")
    except Exception:
        return None


def scan_file_for_secrets(path: Path, repo_root: Path) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    rel_path = str(path.relative_to(repo_root))

    # 1. Committed .env file — flag regardless of content, this is almost
    #    always a mistake (the file format itself implies real secrets).
    if path.name in ENV_FILE_NAMES:
        findings.append(Vulnerability(
            endpoint=rel_path, method="STATIC",
            test_module="static_secret_scan",
            owasp_category="A05:2021 Security Misconfiguration",
            issue="Environment file committed to the repository",
            severity=Severity.HIGH,
            description=f"A '{path.name}' file was found inside the uploaded archive. Files of this type conventionally hold real secrets (API keys, DB credentials, signing secrets).",
            impact="If this archive corresponds to what's pushed to version control, every collaborator (and anyone with repo access, past or present) can read these secrets.",
            recommendation="Add this filename to .gitignore, remove it from git history if already committed (e.g. git filter-repo), and rotate every credential that was inside it.",
            evidence={"file": rel_path},
        ))

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    if not text:
        return findings

    lines = text.splitlines()

    lines_matched_by_named_pattern = set()

    for pattern in PATTERNS:
        for match in pattern["regex"].finditer(text):
            matched_value = match.group(pattern.get("value_group", 0))
            if pattern.get("value_group") and _is_placeholder(matched_value):
                continue

            line_no = text[:match.start()].count("\n") + 1
            line_preview = lines[line_no - 1].strip()[:140] if line_no - 1 < len(lines) else ""
            lines_matched_by_named_pattern.add(line_no)

            findings.append(Vulnerability(
                endpoint=rel_path, method="STATIC",
                test_module="static_secret_scan",
                owasp_category="A02:2021 Cryptographic Failures" if "PRIVATE KEY" in pattern["name"] else "A05:2021 Security Misconfiguration",
                issue=pattern["issue"],
                severity=pattern["severity"],
                description=f"Pattern '{pattern['name']}' matched at {rel_path}:{line_no}.",
                impact=pattern["impact"],
                recommendation=pattern["recommendation"],
                evidence={"file": rel_path, "line": line_no, "line_preview": line_preview},
            ))

    # Generic hardcoded-credential pass: walks every `IDENTIFIER = "value"` /
    # `IDENTIFIER: "value"` assignment and checks whether the *identifier*
    # contains a credential-like marker anywhere in it (substring match),
    # which correctly catches compound names like JWT_SECRET, DB_PASSWORD,
    # API_SECRET_KEY — not just an identifier that IS exactly "secret".
    # Lines already caught by a more specific named pattern above (e.g. the
    # dedicated Google API key check) are skipped here to avoid double-
    # reporting the same secret under two different findings.
    seen_lines_for_generic = set()
    for match in GENERIC_ASSIGNMENT_RE.finditer(text):
        identifier, value = match.group(1), match.group(2)
        identifier_lower = identifier.lower().replace("_", "").replace("-", "")
        if not any(marker.replace("_", "") in identifier_lower for marker in CREDENTIAL_NAME_MARKERS):
            continue
        if _is_placeholder(value) or value.lower() in SAFE_VALUE_CONSTANTS:
            continue

        line_no = text[:match.start()].count("\n") + 1
        if line_no in seen_lines_for_generic or line_no in lines_matched_by_named_pattern:
            continue
        seen_lines_for_generic.add(line_no)
        line_preview = lines[line_no - 1].strip()[:140] if line_no - 1 < len(lines) else ""

        findings.append(Vulnerability(
            endpoint=rel_path, method="STATIC",
            test_module="static_secret_scan",
            owasp_category="A05:2021 Security Misconfiguration",
            issue=f"Possible hardcoded credential in variable '{identifier}'",
            severity=Severity.HIGH,
            description=f"The variable '{identifier}' is assigned a literal string at {rel_path}:{line_no}, and its name suggests it holds a credential.",
            impact="Credentials embedded directly in source are exposed to anyone with read access to the repository (including its full git history), and can't be rotated without a code change.",
            recommendation=f"Move this value into an environment variable (e.g. process.env.{identifier} / os.environ['{identifier}']) and inject it via your deployment platform's secret management.",
            evidence={"file": rel_path, "line": line_no, "line_preview": line_preview},
        ))

    # 2. Supabase service_role JWT — distinct, high-impact check.
    # A service_role key bypasses Row Level Security entirely; finding one
    # committed to source (especially anywhere near frontend code) is critical.
    for jwt_match in re.finditer(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text):
        token = jwt_match.group(0)
        role = _decode_jwt_role(token)
        if role == "service_role":
            line_no = text[:jwt_match.start()].count("\n") + 1
            findings.append(Vulnerability(
                endpoint=rel_path, method="STATIC",
                test_module="static_secret_scan",
                owasp_category="API1:2023 Broken Object Level Authorization",
                issue="Supabase service_role key committed to source",
                severity=Severity.CRITICAL,
                description=f"A JWT with role=service_role was found at {rel_path}:{line_no}. This key bypasses Row Level Security entirely.",
                impact="Anyone with this key has full, unrestricted read/write access to every table in the Supabase project, regardless of any RLS policies configured.",
                recommendation="Rotate this key immediately in the Supabase dashboard (Settings → API). Never use the service_role key outside of trusted server-side code, and never commit it — use the anon key + RLS policies for anything client-reachable.",
                evidence={"file": rel_path, "line": line_no},
            ))

    return findings
