# Frippflix Updates

Public release channel and update manifest for Frippflix Fire TV (`com.dean.plexfiretv`). The repository contains release metadata only; keep application source and signing credentials elsewhere.

## Requirements

Run the publisher on macOS with Python 3, Git, GitHub CLI (`gh`) authenticated as an account with repository write access, and Android SDK Build Tools on `PATH` (`apkanalyzer` or `aapt`, plus `apksigner`). `shasum` is also required. The tool never reads signing keys or prints GitHub credentials.

## Establish the trusted production signer pin (one time)

Do not trust a fingerprint merely because it came from a candidate release APK. Obtain a known legitimate installed Frippflix APK from a trusted Fire TV installation (for example, use `adb shell pm path com.dean.plexfiretv` to locate it and `adb pull` the returned APK path), or use a previously distributed APK whose provenance you independently trust. Inspect it:

```sh
./publish_release.py check-cert /path/to/known-good/Frippflix.apk
```

Independently confirm the printed SHA-256 certificate fingerprint belongs to the production app, then explicitly store that value outside this repository:

```sh
./publish_release.py set-fingerprint 'PASTE_THE_INDEPENDENTLY_VERIFIED_64_HEX_SHA256_FINGERPRINT'
./publish_release.py check-fingerprint
```

The configuration is stored at `~/.config/frippflix-updates/config.json` with owner-only file permissions. This is a public certificate fingerprint, not a signing key. Do not set the pin from the release candidate itself. To inspect a candidate and compare it with the configured pin, use `check-cert APK --compare`.

## Release notes

Create a Markdown file using [`RELEASE_TEMPLATE.md`](RELEASE_TEMPLATE.md), replace its placeholders, and save it outside the repository or in a temporary local location. Keep the notes user-facing. Version name and version code are read from the APK itself. Version names may have three or four numeric components (for example `0.8.4` or `0.8.4.2`); the GitHub tag is derived exactly as `v<versionName>`.

## Dry-run (default)

```sh
./publish_release.py publish --apk /absolute/path/to/Frippflix.apk --notes-file /absolute/path/to/release-notes.md
```

Dry-run validates the local APK, signer pin, version and release notes, performs read-only GitHub checks, fetches the upstream branch, and requires the repository default branch to be clean and fully synchronized with its upstream. It prints the proposed tag and manifest. It does not create releases or tags, upload files, commit, or push.

## Publish

After reviewing the complete dry-run output, explicitly enable publishing:

```sh
./publish_release.py publish --apk /absolute/path/to/Frippflix.apk --notes-file /absolute/path/to/release-notes.md --publish
```

The tool refuses an existing release/tag, an invalid or mismatched signer, a non-increasing version code, a dirty/diverged Git branch, and any release asset conflict. It creates a draft release, uploads `Frippflix.apk`, verifies the asset SHA-256, publishes the release, then updates, commits, and pushes `latest.json`. It verifies the release and remote manifest. Review all printed proposed changes before running with `--publish`.

## Resume an interrupted release

For an existing draft release, supply the same local APK and notes. Dry-run first:

```sh
./publish_release.py resume --tag v0.8.4.2 --apk /absolute/path/to/Frippflix.apk --notes-file /absolute/path/to/release-notes.md
```

Then add `--publish` to continue. A draft with no APK receives the verified local APK; a draft with a matching APK is verified and published. If already published, the command stops and directs you to manifest repair. Any tag, APK hash, metadata, or certificate mismatch aborts without replacing assets. For remote verification, the tool uses GitHub's asset `digest` SHA-256 when available; otherwise it downloads the asset to a temporary directory and hashes it.

## Repair a failed manifest update

For a release already published when the manifest commit/push failed, dry-run:

```sh
./publish_release.py repair-manifest --tag v0.8.4.2
```

The tool downloads and inspects the released APK (or accepts `--apk /path/to/Frippflix.apk`), checks its signer pin and metadata, and verifies the remote asset digest. Add `--publish` to update, commit, push, and verify `latest.json`. It will not upload or replace a release asset. If a push failed after creating a local manifest change or a manifest-only commit, preserve it: repair permits those `latest.json`-only recovery states and pushes the verified candidate. It rejects unrelated changes, unrelated commits, and a branch behind/diverged from upstream. Do not create another release.

## Recovery and safety

- Dry-run is the default for all release workflows. `--publish` is required for GitHub or Git mutations.
- Existing release tags and assets are never silently replaced. If a draft contains a wrong asset, stop and inspect it manually; the tool intentionally will not delete or overwrite it.
- If draft creation/upload/publication fails, inspect the release state in GitHub. Use `resume --tag TAG` only for a draft with the intended tag, and `repair-manifest --tag TAG` only for a published release.
- If a Git operation fails after the release is published, leave the release intact and repair the manifest. Check `git status` and `git log` before retrying.
- Signing keys, passwords, tokens, and credentials must never be placed in this repository. Authentication is provided by existing `gh` and Git credential configuration.

## Update manifest

[`latest.json`](latest.json) contains the current release metadata. The app should fetch it over HTTPS, cache its last successful check, verify the APK SHA-256, and request user confirmation before sideload installation. Never publish an APK whose signer differs from the installed production signer.
