# Frippflix Updates

Public release channel for Frippflix Fire TV APK updates.

This repository is intended to contain **published APK releases and the update manifest only**. Keep application source code and signing credentials elsewhere.

## Publishing a release

1. Build a release APK on the maintainer's Mac using the same signing key as the installed app.
2. Increment `versionCode` for every release. Never reuse a version code.
3. Create a GitHub Release tagged `vX.Y.Z`.
4. Attach the APK with the exact asset name `Frippflix.apk`.
5. Update `latest.json` on the default branch with the new version, release URL, APK asset URL, SHA-256, and release notes.
6. The app compares `versionCode`, downloads only newer releases, verifies SHA-256, and then invokes Android's package installer for user confirmation.

Do not publish an APK until its signature has been checked against the installed production signature. A signature mismatch prevents in-place upgrades.

## Update manifest

See [`latest.json`](latest.json). The app should fetch it over HTTPS, cache the last successful check, and fail gracefully if GitHub is unavailable.

## Security

- HTTPS only.
- Verify SHA-256 before handing an APK to the package installer.
- Only accept manifest URLs on `github.com` / `release-assets.githubusercontent.com` (or the final approved GitHub asset host) and the expected repository.
- Never place signing keys, passwords, Plex tokens, or source code in this repository.
- User confirmation is expected for sideloaded APK installation on Fire TV.
