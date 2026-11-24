#!/usr/bin/env python3
"""Safely publish Frippflix APK releases. Dry-run is the default."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from pathlib import Path

REPO = "deanxro/frippflix-updates"
APP_ID = "com.dean.plexfiretv"
APK_NAME = "Frippflix.apk"
ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "latest.json"
CONFIG = Path.home() / ".config/frippflix-updates/config.json"
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")


class PublishError(Exception):
    pass


def run(args: list[str], *, check: bool = True, capture: bool = True, cwd: Path = ROOT) -> str:
    try:
        p = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.PIPE if capture else None)
    except FileNotFoundError as e:
        raise PublishError(f"Required command not found: {args[0]}") from e
    if check and p.returncode:
        detail = (p.stderr or p.stdout or "").strip()
        raise PublishError(f"Command failed ({p.returncode}): {' '.join(args[:3])}\n{detail}")
    return p.stdout.strip() if p.stdout is not None else ""


def require_tool(name: str) -> str:
    p = shutil.which(name)
    if not p:
        raise PublishError(f"Required tool '{name}' is not in PATH. Install/configure it and retry.")
    return p


def get_manifest() -> dict:
    try:
        data = json.loads(MANIFEST.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise PublishError(f"Cannot read valid {MANIFEST.name}: {e}") from e
    if data.get("appId") != APP_ID or data.get("apkFileName") != APK_NAME:
        raise PublishError("latest.json appId or apkFileName does not match this publishing tool")
    return data


def normalize_fp(value: str) -> str:
    fp = value.strip().replace(":", "").upper()
    if not re.fullmatch(r"[0-9A-F]{64}", fp):
        raise PublishError("Fingerprint must be a SHA-256 certificate fingerprint (64 hex characters).")
    return fp


def trusted_fp() -> str:
    raw = os.environ.get("FRIPPFLIX_TRUSTED_CERT_SHA256")
    if raw:
        return normalize_fp(raw)
    try:
        cfg = json.loads(CONFIG.read_text())
        return normalize_fp(cfg["trustedCertificateSha256"])
    except FileNotFoundError as e:
        raise PublishError(f"No trusted signer pin configured. Establish it from a known legitimate installation, then run: {Path(sys.argv[0]).name} set-fingerprint SHA256_FROM_TRUSTED_SOURCE") from e
    except (OSError, json.JSONDecodeError, KeyError) as e:
        raise PublishError(f"Trusted signer configuration is missing or invalid: {CONFIG}") from e


def apk_metadata(apk: Path) -> dict:
    if not apk.is_file():
        raise PublishError(f"APK does not exist: {apk}")
    analyzer = shutil.which("apkanalyzer")
    aapt = shutil.which("aapt")
    if analyzer:
        package = run([analyzer, "manifest", "application-id", str(apk)])
        version_name = run([analyzer, "manifest", "version-name", str(apk)])
        version_code = run([analyzer, "manifest", "version-code", str(apk)])
    elif aapt:
        output = run([aapt, "dump", "badging", str(apk)])
        m = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", output, re.M)
        if not m:
            raise PublishError("Could not parse package/version metadata from aapt output")
        package, version_code, version_name = m.groups()
    else:
        raise PublishError("Install Android SDK Build Tools and put apkanalyzer or aapt on PATH.")
    if package != APP_ID:
        raise PublishError(f"Wrong APK package ID: expected {APP_ID}, found {package}")
    if not VERSION_RE.fullmatch(version_name):
        raise PublishError(f"APK versionName must contain 3 or 4 numeric components; found {version_name!r}")
    try:
        code = int(version_code)
    except ValueError as e:
        raise PublishError(f"APK versionCode is not an integer: {version_code!r}") from e
    if code <= 0:
        raise PublishError("APK versionCode must be greater than zero")
    signer = shutil.which("apksigner")
    if not signer:
        raise PublishError("Install Android SDK Build Tools and put apksigner on PATH.")
    signature = run([signer, "verify", "--print-certs", str(apk)])
    m = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", signature)
    if not m:
        raise PublishError("APK signature verification did not report a signer SHA-256 certificate fingerprint")
    return {"appId": package, "versionName": version_name, "versionCode": code,
            "fingerprint": normalize_fp(m.group(1)), "sha256": sha256(apk)}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_pin(meta: dict) -> None:
    expected = trusted_fp()
    if meta["fingerprint"] != expected:
        raise PublishError("APK signing certificate does not match the locally trusted production fingerprint; refusing to continue.")


def gh_json(args: list[str]) -> dict:
    try:
        return json.loads(run([require_tool("gh"), *args]))
    except json.JSONDecodeError as e:
        raise PublishError(f"GitHub returned invalid JSON for {' '.join(args[:3])}") from e


def release(tag: str) -> dict | None:
    # The by-tag endpoint omits drafts on some GitHub responses. The releases
    # collection includes authenticated drafts and supports pagination.
    try:
        pages = json.loads(run([require_tool("gh"), "api", "--paginate", "--slurp",
                                f"repos/{REPO}/releases", "--field", "per_page=100"]))
    except json.JSONDecodeError as e:
        raise PublishError("GitHub returned invalid release-list JSON") from e
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise PublishError("GitHub release listing had an unexpected shape; refusing to assume the tag is absent")
    releases = []
    for page in pages:
        releases.extend(page)
    if any(not isinstance(item, dict) or "tag_name" not in item for item in releases):
        raise PublishError("GitHub release listing contained incomplete entries; refusing to continue")
    matches = [item for item in releases if item.get("tag_name") == tag]
    if len(matches) > 1:
        raise PublishError(f"GitHub returned duplicate releases for tag {tag}; refusing recovery")
    return matches[0] if matches else None


def release_by_id(release_id: int) -> dict | None:
    p = subprocess.run([require_tool("gh"), "api", f"repos/{REPO}/releases/{release_id}"],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode:
        if "Not Found" in p.stderr or "HTTP 404" in p.stderr:
            return None
        raise PublishError(f"Cannot inspect GitHub release ID {release_id}: {p.stderr.strip()}")
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError as e:
        raise PublishError("GitHub returned invalid release JSON by ID") from e


def wait_for_release(tag: str, release_id: int | None = None, attempts: int = 6,
                     interval: float = 1.0) -> dict:
    """Bounded consistency wait for a release collection entry and its ID endpoint."""
    for attempt in range(attempts):
        listed = release(tag)
        if listed and (release_id is None or listed.get("id") == release_id):
            detail = release_by_id(int(listed["id"]))
            if detail and detail.get("tag_name") == tag:
                return detail
        if attempt + 1 < attempts:
            time.sleep(interval)
    suffix = f" (release ID {release_id})" if release_id is not None else ""
    raise PublishError(f"Release {tag}{suffix} did not become consistently visible after {attempts} checks; keep the draft and retry --resume")


def remote_tag_exists(tag: str) -> bool:
    p = subprocess.run([require_tool("gh"), "api", f"repos/{REPO}/git/ref/tags/{tag}"],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode == 0:
        return True
    if "Not Found" in p.stderr or "HTTP 404" in p.stderr:
        return False
    raise PublishError(f"Cannot check whether tag {tag} already exists: {p.stderr.strip()}")


def local_tag_exists(tag: str) -> bool:
    p = subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"], cwd=ROOT)
    if p.returncode not in (0, 1):
        raise PublishError("Could not inspect local Git tags")
    return p.returncode == 0


def verify_release_asset(rel: dict, apk: Path | None, meta: dict | None = None) -> tuple[dict, str]:
    assets = [a for a in rel.get("assets", []) if a.get("name") == APK_NAME]
    if len(assets) > 1:
        raise PublishError("Release contains duplicate Frippflix.apk assets; refusing recovery")
    if not assets:
        raise PublishError("Release has no Frippflix.apk asset")
    asset = assets[0]
    if asset.get("state") != "uploaded":
        raise PublishError("Release asset is not in GitHub's uploaded state yet")
    if apk is not None and int(asset.get("size", -1)) != apk.stat().st_size:
        raise PublishError("Existing release APK size does not match the supplied local APK")
    digest = asset.get("digest") or ""
    if digest.lower().startswith("sha256:"):
        remote_hash = digest.split(":", 1)[1].lower()
    else:
        with tempfile.TemporaryDirectory(prefix="frippflix-verify-") as td:
            downloaded = Path(td) / APK_NAME
            download_asset(asset, downloaded)
            remote_hash = sha256(downloaded)
    if apk is not None and remote_hash != sha256(apk):
        raise PublishError("Existing release APK does not match the supplied local APK; refusing to overwrite or resume")
    if meta is not None and apk is not None:
        remote_meta = apk_metadata(apk)
        if remote_meta != meta:
            raise PublishError("Local APK metadata changed during verification")
    return asset, remote_hash


def upload_url(rel: dict) -> str:
    raw = (rel.get("upload_url") or "").split("{", 1)[0]
    parts = urlsplit(raw)
    if parts.scheme != "https" or parts.hostname != "uploads.github.com":
        raise PublishError("Draft release has no valid GitHub upload URL; keep the draft and inspect it manually")
    query = dict(parse_qsl(parts.query))
    query["name"] = APK_NAME
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def upload_apk(rel: dict, apk: Path) -> dict:
    # `gh api` obtains authentication through gh's credential store. The token
    # is never requested, copied into our process, logged, or written to disk.
    response = run([require_tool("gh"), "api", "--method", "POST", upload_url(rel),
                    "--input", str(apk), "--header", "Accept: application/vnd.github+json",
                    "--header", "Content-Type: application/octet-stream"])
    try:
        return json.loads(response)
    except json.JSONDecodeError as e:
        raise PublishError("GitHub asset upload returned invalid JSON; preserve the draft and inspect its assets") from e


def download_asset(asset: dict, destination: Path) -> None:
    if not asset.get("id"):
        raise PublishError("Release asset has no ID for authenticated checksum verification")
    run([require_tool("gh"), "api", f"repos/{REPO}/releases/assets/{asset['id']}",
         "--header", "Accept: application/octet-stream", "--output", str(destination)])


def check_git_sync() -> tuple[str, str]:
    if run(["git", "status", "--porcelain"]):
        raise PublishError("Git working tree must be clean before publishing")
    branch = run(["git", "branch", "--show-current"])
    default_branch = gh_json(["api", f"repos/{REPO}"]).get("default_branch")
    if branch != default_branch:
        raise PublishError(f"Publishing must run from the repository default branch ({default_branch}), not {branch}")
    upstream = run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"])
    if not upstream:
        raise PublishError("Current branch has no upstream configured")
    run(["git", "fetch", "--prune", "origin"])
    counts = run(["git", "rev-list", "--left-right", "--count", f"{branch}...{upstream}"]).split()
    if len(counts) != 2 or counts != ["0", "0"]:
        raise PublishError(f"Local branch is not fully synchronized with {upstream}; reconcile it before publishing")
    return branch, upstream


def check_repair_git(candidate: dict) -> tuple[str, str]:
    """Allow only latest.json recovery changes and manifest-only commits ahead of upstream."""
    branch = run(["git", "branch", "--show-current"])
    default_branch = gh_json(["api", f"repos/{REPO}"]).get("default_branch")
    if branch != default_branch:
        raise PublishError(f"Manifest repair must run from the repository default branch ({default_branch}), not {branch}")
    upstream = run(["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"])
    if not upstream:
        raise PublishError("Current branch has no upstream configured")
    run(["git", "fetch", "--prune", "origin"])
    counts = run(["git", "rev-list", "--left-right", "--count", f"{branch}...{upstream}"]).split()
    if len(counts) != 2 or counts[1] != "0":
        raise PublishError(f"Branch is behind/diverged from {upstream}; synchronize it before manifest repair")
    status = run(["git", "status", "--porcelain"])
    for line in status.splitlines():
        if line[3:] != "latest.json":
            raise PublishError("Manifest repair requires a clean worktree apart from latest.json")
    try:
        on_disk = json.loads(MANIFEST.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise PublishError(f"Local latest.json is not valid JSON: {e}") from e
    if status and on_disk != candidate:
        raise PublishError("Local latest.json has changes beyond the verified repair candidate")
    if int(counts[0]) > 0:
        changed = run(["git", "diff", "--name-only", f"{upstream}...{branch}"]).splitlines()
        if set(changed) - {"latest.json"}:
            raise PublishError("Local commits ahead of upstream include files other than latest.json")
        committed = run(["git", "show", f"{branch}:latest.json"])
        try:
            if json.loads(committed) != candidate:
                raise PublishError("Ahead commit does not contain the verified manifest candidate")
        except json.JSONDecodeError as e:
            raise PublishError("Ahead commit contains invalid latest.json") from e
    return branch, upstream


def notes_text(file: Path, tag: str, meta: dict) -> str:
    if not file.is_file():
        raise PublishError(f"Release notes file not found: {file}")
    notes = file.read_text().strip()
    if (not notes or "Describe user-facing changes" in notes
            or "as configured by the app" in notes.lower()
            or "vX.Y.Z" in notes):
        raise PublishError("Release notes are empty or still contain the template placeholder")
    if not re.search(r"^##\s+What's new\s*$", notes, re.I | re.M):
        raise PublishError("Release notes must include a ## What's new section")
    if not notes.startswith(f"# Frippflix {tag}"):
        notes = f"# Frippflix {tag}\n\n" + notes
    return notes + ("\n\n## Build metadata\n" f"- Package: `{APP_ID}`\n- Version name: `{meta['versionName']}`\n"
                    f"- Version code: `{meta['versionCode']}`\n- APK SHA-256: `{meta['sha256']}`\n"
                    f"- Signing certificate SHA-256: `{meta['fingerprint']}`\n")


def make_manifest(old: dict, tag: str, meta: dict, release_url: str, apk_url: str) -> dict:
    data = dict(old)
    data.update(versionName=meta["versionName"], versionCode=meta["versionCode"], releaseTag=tag,
                releaseUrl=release_url, apkUrl=apk_url, apkFileName=APK_NAME, sha256=meta["sha256"])
    data["releaseNotes"] = [line.strip(" -*") for line in (old.get("releaseNotes") or []) if line.strip()]
    return data


def validate_meta(old: dict, meta: dict, tag: str) -> None:
    if meta["versionCode"] <= int(old.get("versionCode", 0)):
        raise PublishError("APK versionCode must be greater than the current latest.json versionCode")
    if tag != f"v{meta['versionName']}":
        raise PublishError(f"Tag must match APK versionName exactly: v{meta['versionName']}")


def validate_repair_meta(old: dict, meta: dict, tag: str) -> None:
    if tag != f"v{meta['versionName']}":
        raise PublishError(f"Tag must match APK versionName exactly: v{meta['versionName']}")
    already_current = (old.get("releaseTag") == tag and old.get("sha256") == meta["sha256"]
                       and int(old.get("versionCode", 0)) == meta["versionCode"])
    if not already_current and meta["versionCode"] <= int(old.get("versionCode", 0)):
        raise PublishError("APK versionCode must exceed current latest.json unless repairing this exact release")


def manifest_urls(tag: str) -> tuple[str, str]:
    base = f"https://github.com/{REPO}/releases/tag/{tag}"
    return base, f"https://github.com/{REPO}/releases/download/{tag}/{APK_NAME}"


def commit_manifest(candidate: dict) -> None:
    MANIFEST.write_text(json.dumps(candidate, indent=2) + "\n")
    run(["git", "add", "latest.json"])
    run(["git", "commit", "-m", f"Update latest.json for {candidate['releaseTag']}"])
    run(["git", "push"])


def confirm_publish() -> None:
    print("This will perform the GitHub/Git mutations listed above.")
    answer = input("Type PUBLISH to continue: ").strip()
    if answer != "PUBLISH":
        raise PublishError("Publishing cancelled; no mutation performed")


def cmd_pin(args: argparse.Namespace) -> None:
    if args.action == "check":
        print(f"Trusted certificate SHA-256: {trusted_fp()}")
        return
    fp = normalize_fp(args.fingerprint)
    print("Only continue if this fingerprint was independently verified from a legitimate existing installation or trusted distributed APK.")
    if input("Type TRUST to store this production signer pin: ").strip() != "TRUST":
        raise PublishError("Fingerprint setup cancelled")
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({"trustedCertificateSha256": fp}, indent=2) + "\n")
    CONFIG.chmod(0o600)
    print(f"Stored trusted fingerprint outside repository: {CONFIG}")


def cmd_check_cert(args: argparse.Namespace) -> None:
    meta = apk_metadata(Path(args.apk).expanduser().resolve())
    print(f"Package: {meta['appId']}\nVersion: {meta['versionName']} ({meta['versionCode']})\nSigner certificate SHA-256: {meta['fingerprint']}")
    if args.compare:
        verify_pin(meta)
        print("Signer matches trusted production pin.")


def candidate_and_print(old: dict, tag: str, meta: dict, notes: str, rel: dict | None = None) -> dict:
    release_url, apk_url = manifest_urls(tag)
    candidate = make_manifest(old, tag, meta, release_url, apk_url)
    # Keep release notes in the manifest aligned with user-facing What's new lines.
    in_whats_new = False
    release_bullets = []
    for line in notes.splitlines():
        if re.match(r"^##\s+What's new\s*$", line, re.I):
            in_whats_new = True
            continue
        if in_whats_new and line.startswith("## "):
            break
        if in_whats_new and line.strip().startswith(("- ", "* ")):
            item = line.strip().lstrip("-* ").strip()
            if item:
                release_bullets.append(item)
    candidate["releaseNotes"] = release_bullets
    if not candidate["releaseNotes"]:
        candidate["releaseNotes"] = [f"Frippflix {meta['versionName']} release"]
    print("Proposed release:")
    print(json.dumps({"repository": REPO, "tag": tag, "versionName": meta["versionName"],
                      "versionCode": meta["versionCode"], "package": meta["appId"],
                      "certificateSha256": meta["fingerprint"], "apkSha256": meta["sha256"],
                      "releaseUrl": release_url, "apkUrl": apk_url,
                      "existingReleaseState": ("draft" if rel and rel.get("draft") else "published" if rel else "absent"),
                      "manifest": candidate}, indent=2))
    return candidate


def execute(args: argparse.Namespace) -> None:
    if not args.publish:
        print("DRY RUN: no GitHub or Git mutations will be performed.")
    apk = Path(args.apk).expanduser().resolve() if args.apk else None
    old = get_manifest()
    if args.mode in ("publish", "resume"):
        if apk is None:
            raise PublishError("--apk is required for publish and resume")
        require_tool("shasum")
        meta = apk_metadata(apk)
        verify_pin(meta)
        tag = args.tag if args.mode == "resume" else f"v{meta['versionName']}"
        validate_meta(old, meta, tag)
    else:
        tag = args.tag
        rel = release(tag)
        if not rel:
            raise PublishError(f"No GitHub Release exists for {tag}")
        if rel.get("draft"):
            raise PublishError("--repair-manifest requires a published release; use --resume TAG for a draft")
        with tempfile.TemporaryDirectory(prefix="frippflix-repair-") as td:
            if apk is None:
                run([require_tool("gh"), "release", "download", tag, "--repo", REPO, "--pattern", APK_NAME, "--dir", td])
                apk = Path(td) / APK_NAME
            meta = apk_metadata(apk)
            verify_pin(meta)
            validate_repair_meta(old, meta, tag)
            _, digest = verify_release_asset(rel, apk, meta)
            if digest != meta["sha256"]:
                raise PublishError("Published release APK digest does not match inspected APK")
            if args.notes_file:
                notes = notes_text(Path(args.notes_file).expanduser().resolve(), tag, meta)
            else:
                notes = rel.get("body") or f"# Frippflix {tag}\n\n## What's new\n- Recovered manifest for verified release."
            candidate = candidate_and_print(old, tag, meta, notes, rel)
            check_repair_git(candidate)
            if args.publish:
                confirm_publish()
                current_disk = json.loads(MANIFEST.read_text())
                if current_disk != candidate:
                    MANIFEST.write_text(json.dumps(candidate, indent=2) + "\n")
                run(["git", "add", "latest.json"])
                staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode
                if staged not in (0, 1):
                    raise PublishError("Could not inspect staged manifest changes")
                if staged == 1:
                    run(["git", "commit", "-m", f"Update latest.json for {candidate['releaseTag']}"])
                run(["git", "push"])
                verify_remote_manifest(candidate)
        return

    notes = notes_text(Path(args.notes_file).expanduser().resolve(), tag, meta)
    rel = release(tag)
    if args.mode == "publish" and rel:
        raise PublishError(f"Release/tag {tag} already exists. Use --resume only for a verified draft, or --repair-manifest for a published release.")
    if args.mode == "publish" and remote_tag_exists(tag):
        raise PublishError(f"GitHub tag {tag} already exists without a matching release; inspect it manually")
    if args.mode == "publish" and local_tag_exists(tag):
        raise PublishError(f"Local Git tag {tag} already exists; inspect it manually")
    if args.mode == "resume":
        if not rel:
            raise PublishError(f"No existing release {tag} to resume")
        if rel.get("tag_name") != tag:
            raise PublishError("GitHub release tag does not match requested tag")
        if not rel.get("draft"):
            raise PublishError(f"Release {tag} is already published; use --repair-manifest {tag}")
        assets = [a for a in rel.get("assets", []) if a.get("name") == APK_NAME]
        if len(assets) > 1:
            raise PublishError("Draft has duplicate Frippflix.apk assets; refusing recovery")
        if assets:
            _, digest = verify_release_asset(rel, apk, meta)
            if digest != meta["sha256"]:
                raise PublishError("Draft APK checksum mismatch; refusing to overwrite")
    elif rel:
        raise PublishError(f"Release/tag {tag} already exists")
    candidate = candidate_and_print(old, tag, meta, notes, rel)
    branch, _ = check_git_sync()
    if not args.publish:
        if args.mode == "resume":
            print("Dry-run would upload only if the draft has no APK; otherwise it would publish the verified draft.")
        return
    confirm_publish()
    require_tool("gh")
    if args.mode == "publish":
        # Only mutate after all local, remote, signer, version and Git checks pass.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as f:
            f.write(notes)
            notes_path = f.name
        try:
            run([require_tool("gh"), "release", "create", tag, "--repo", REPO, "--draft", "--title", f"Frippflix {meta['versionName']}", "--notes-file", notes_path, "--target", branch])
        finally:
            Path(notes_path).unlink(missing_ok=True)
        rel = wait_for_release(tag)
        if not rel.get("draft"):
            raise PublishError("Draft release creation could not be verified; inspect GitHub before retrying")
    if args.mode == "resume":
        rel = wait_for_release(tag, int(rel["id"]))
    if not rel.get("draft"):
        raise PublishError(f"Release {tag} is no longer a draft; use --repair-manifest if it is published")
    assets = [a for a in rel.get("assets", []) if a.get("name") == APK_NAME]
    if not assets:
        upload_apk(rel, apk)
    rel = wait_for_release(tag, int(rel["id"]))
    if not rel.get("draft"):
        raise PublishError(f"Release {tag} became published during recovery; use --repair-manifest")
    _, remote_hash = verify_release_asset(rel, apk, meta)
    if remote_hash != meta["sha256"]:
        raise PublishError("Uploaded APK checksum verification failed")
    if args.mode == "resume" or args.mode == "publish":
        if rel.get("draft"):
            run([require_tool("gh"), "api", "--method", "PATCH", f"repos/{REPO}/releases/{rel['id']}", "-F", "draft=false"])
        rel = release(tag)
        if not rel or rel.get("draft"):
            raise PublishError("Release publication could not be verified. Resume after checking its state.")
    commit_manifest(candidate)
    verify_remote_manifest(candidate)


def verify_remote_manifest(expected: dict) -> None:
    raw = run([require_tool("gh"), "api", f"repos/{REPO}/contents/latest.json", "--jq", ".content"])
    import base64
    try:
        actual = json.loads(base64.b64decode(raw).decode())
    except Exception as e:
        raise PublishError("Could not read back remote latest.json") from e
    for key in ("appId", "versionName", "versionCode", "releaseTag", "releaseUrl", "apkUrl", "sha256"):
        if actual.get(key) != expected.get(key):
            raise PublishError(f"Remote manifest verification failed for {key}; inspect latest.json and repair if needed")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    pin = sub.add_parser("set-fingerprint", help="Store a fingerprint independently verified from a trusted source")
    pin.add_argument("fingerprint")
    pin.set_defaults(func=cmd_pin, action="set")
    check = sub.add_parser("check-fingerprint", help="Display the configured certificate pin")
    check.set_defaults(func=cmd_pin, action="check")
    cert = sub.add_parser("check-cert", help="Inspect APK metadata and signer; optionally compare with pin")
    cert.add_argument("apk")
    cert.add_argument("--compare", action="store_true")
    cert.set_defaults(func=cmd_check_cert)
    for mode in ("publish", "resume", "repair-manifest"):
        q = sub.add_parser(mode, help=f"{mode} release" if mode == "publish" else f"{mode.replace('-', ' ')}")
        q.add_argument("--apk", help="Local signed APK; repair can download the release asset if omitted")
        q.add_argument("--notes-file", help="Release notes markdown (required for publish/resume)")
        q.add_argument("--tag", required=(mode != "publish"), help="Existing tag for recovery")
        q.add_argument("--publish", action="store_true", help="Perform GitHub/Git mutations; otherwise dry-run")
        q.set_defaults(func=execute, mode=mode)
    return p


def main() -> int:
    p = parser()
    args = p.parse_args()
    if args.command in ("publish", "resume") and not args.notes_file:
        p.error(f"{args.command} requires --notes-file")
    try:
        args.func(args)
        return 0
    except PublishError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("Recovery: inspect local git status and the GitHub Release state. Use --resume TAG for a verified draft, or --repair-manifest TAG for a published release whose manifest update failed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
