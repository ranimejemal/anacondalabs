# Code Signing — Sprint 6, Day 1-2

This is the one Sprint 6 item that's genuinely **human-only**: it needs
real money, a real identity/business verification, and (for macOS) an
Apple Developer account — none of which an AI assistant can do on your
behalf. This doc is the exact runbook so it's a checklist, not a mystery.

## Why this matters (don't skip it)

Without code signing:
- **Windows**: SmartScreen shows a full-page "Windows protected your PC"
  warning with an unsigned .exe. Most users will not click through it.
- **macOS**: Gatekeeper blocks the app outright ("AegisLab can't be opened
  because it is from an unidentified developer"), with no easy right-click
  bypass for most users since Sequoia — this isn't just a scary warning,
  unsigned macOS builds are effectively unusable for non-technical users.
- **Linux (AppImage)**: no equivalent OS-level gatekeeping, lowest priority
  of the three.

## Windows: EV or standard code signing certificate

1. Buy a code signing certificate from a CA — DigiCert, Sectigo, or
   SSL.com are common choices. Standard certs (~$70-400/yr) still trigger
   SmartScreen until enough install reputation builds up; **EV certs**
   (~$300-600/yr) get SmartScreen trust immediately but require a hardware
   token (USB) and stricter identity verification (may need a registered
   business, not just an individual).
2. Once issued, sign via `electron-builder`'s built-in signing — set these
   env vars before running `npm run release` (or `npm run dist`):
   ```bash
   export CSC_LINK=/path/to/certificate.pfx
   export CSC_KEY_PASSWORD=your-cert-password
   ```
   electron-builder picks these up automatically for the `win` target —
   no config file changes needed.

## macOS: Apple Developer Program + notarization

1. Enroll in the [Apple Developer Program](https://developer.apple.com/programs/) — $99/year, requires identity
   verification (and a D-U-N-S number if enrolling as an organization).
2. Create a "Developer ID Application" certificate in Xcode or the Apple
   Developer portal, and download it into your local Keychain.
3. Add notarization config to `frontend/package.json`'s `"mac"` block:
   ```json
   "mac": {
     "target": "dmg",
     "category": "public.app-category.developer-tools",
     "hardenedRuntime": true,
     "gatekeeperAssess": false,
     "notarize": true
   }
   ```
4. Set these env vars before building (an app-specific password, not your
   main Apple ID password — generate one at appleid.apple.com):
   ```bash
   export APPLE_ID="you@example.com"
   export APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
   export APPLE_TEAM_ID="YOUR_TEAM_ID"
   ```
   electron-builder handles signing + submitting for notarization +
   stapling the ticket automatically when these are set and you're
   building on macOS (notarization requires building on an actual Mac,
   not cross-compiled from Linux/Windows).

## Linux (AppImage)

No code signing infrastructure equivalent exists for AppImage in practice.
Optionally GPG-sign the AppImage and publish the signature alongside it
for users who want to verify it, but this isn't blocking for launch.

## Verifying before you publish

- Windows: right-click the built `.exe` → Properties → Digital Signatures
  tab should show your certificate.
- macOS: `codesign -dv --verbose=4 AegisLab.app` and
  `spctl -a -vvv -t install AegisLab.app` should both report accepted/valid.

## Cost summary

| Platform | Cost | Recurring |
|---|---|---|
| Windows (standard) | ~$70-400 | Yearly |
| Windows (EV, immediate SmartScreen trust) | ~$300-600 | Yearly |
| macOS (Apple Developer Program) | $99 | Yearly |
| Linux | $0 | — |
