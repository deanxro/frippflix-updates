import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "publish_release.py"
spec = importlib.util.spec_from_file_location("publish_release", SCRIPT)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublisherUnitTests(unittest.TestCase):
    def test_release_lookup_finds_draft_when_tag_endpoint_returns_404(self):
        # Exact incident: the authenticated collection contains the draft,
        # while GET /releases/tags/{tag} is a 404 on this GitHub state.
        draft = {"id": 9123, "tag_name": "v0.8.4.2", "draft": True, "assets": []}
        calls = []

        def fake_run(args):
            calls.append(args)
            endpoint = " ".join(args)
            if "/releases/tags/" in endpoint:
                raise AssertionError("lookup must not rely on the by-tag endpoint")
            self.assertIn("--paginate", args)
            self.assertIn("--slurp", args)
            return json.dumps([[{"id": 1, "tag_name": "v0.7.0", "draft": False}, draft]])

        with mock.patch.object(publisher, "require_tool", return_value="/fake/gh"), \
                mock.patch.object(publisher, "run", side_effect=fake_run):
            found = publisher.release("v0.8.4.2")
        self.assertEqual(found, draft)
        self.assertEqual(len(calls), 1)

    def test_fingerprint_normalization_and_validation(self):
        value = "ab" * 32
        self.assertEqual(publisher.normalize_fp(":".join(value[i:i + 2] for i in range(0, 64, 2))), value.upper())
        with self.assertRaises(publisher.PublishError):
            publisher.normalize_fp("not-a-fingerprint")

    def test_four_component_tag_is_derived_exactly(self):
        meta = {"versionName": "0.8.4.2", "versionCode": 42}
        publisher.validate_meta({"versionCode": 41}, meta, "v0.8.4.2")
        with self.assertRaises(publisher.PublishError):
            publisher.validate_meta({"versionCode": 41}, meta, "v0.8.4")

    def test_candidate_manifest_fields(self):
        old = {"schemaVersion": 1, "appId": publisher.APP_ID, "apkFileName": publisher.APK_NAME,
               "versionCode": 1, "releaseNotes": []}
        meta = {"appId": publisher.APP_ID, "versionName": "0.8.4.2", "versionCode": 42,
                "fingerprint": "A" * 64, "sha256": "b" * 64}
        doc = publisher.make_manifest(old, "v0.8.4.2", meta,
                                      "https://github.com/deanxro/frippflix-updates/releases/tag/v0.8.4.2",
                                      "https://github.com/deanxro/frippflix-updates/releases/download/v0.8.4.2/Frippflix.apk")
        self.assertEqual(doc["versionName"], "0.8.4.2")
        self.assertEqual(doc["versionCode"], 42)
        self.assertEqual(doc["sha256"], "b" * 64)

    def test_remote_asset_digest_field_matches_local_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "Frippflix.apk"
            apk.write_bytes(b"synthetic APK asset fixture")
            digest = publisher.sha256(apk)
            rel = {"tag_name": "v0.8.4.2", "assets": [{"name": "Frippflix.apk", "state": "uploaded", "size": apk.stat().st_size,
                                                                  "digest": f"sha256:{digest}"}]}
            asset, remote = publisher.verify_release_asset(rel, apk)
            self.assertEqual(asset["name"], "Frippflix.apk")
            self.assertEqual(remote, digest)

    def test_draft_upload_url_is_release_id_bound_and_named_exactly(self):
        rel = {"id": 9123, "upload_url": "https://uploads.github.com/repos/deanxro/frippflix-updates/releases/9123/assets{?name,label}"}
        self.assertEqual(publisher.upload_url(rel),
                         "https://uploads.github.com/repos/deanxro/frippflix-updates/releases/9123/assets?name=Frippflix.apk")

    def test_safe_dry_run_with_synthetic_apk_and_command_shims(self):
        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            log = temp / "mutations.log"
            def shim(name, body):
                path = bin_dir / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)

            shim("apkanalyzer", 'case "$2" in application-id) echo com.dean.plexfiretv;; version-name) echo 0.8.4.2;; version-code) echo 42;; esac')
            shim("apksigner", 'echo "Signer #1 certificate SHA-256 digest: ' + ("ab" * 32) + '"')
            shim("shasum", 'exec /usr/bin/shasum "$@"')
            shim("git", '''case "$1" in
status) exit 0;;
branch) echo main;;
rev-parse) echo origin/main;;
fetch) exit 0;;
rev-list) echo "0 0";;
show-ref) exit 1;;
*) echo "$*" >> "$MUTATION_LOG";;
esac''')
            shim("gh", '''case "$1 $2" in
"api repos/deanxro/frippflix-updates") echo '{"default_branch":"main"}';;
"api --paginate") echo '[[]]';;
"api repos/deanxro/frippflix-updates/git/ref/tags/v0.8.4.2") echo "Not Found" >&2; exit 1;;
*) echo "$*" >> "$MUTATION_LOG"; exit 99;;
esac''')
            apk = temp / "synthetic.apk"
            apk.write_bytes(b"safe test fixture, not a real APK")
            notes = temp / "notes.md"
            notes.write_text("# Frippflix v0.8.4.2\n\n## What's new\n- Synthetic fixture release notes.\n")
            env = os.environ.copy()
            env.update({"PATH": f"{bin_dir}:{env['PATH']}", "FRIPPFLIX_TRUSTED_CERT_SHA256": "ab" * 32,
                        "MUTATION_LOG": str(log)})
            p = subprocess.run([str(SCRIPT), "publish", "--apk", str(apk), "--notes-file", str(notes)],
                               env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
            self.assertIn('"tag": "v0.8.4.2"', p.stdout)
            self.assertIn("DRY RUN", p.stdout)
            self.assertFalse(log.exists(), "dry-run invoked a mutation-capable shim")


if __name__ == "__main__":
    unittest.main()
