#!/usr/bin/env python3
"""Check prospective Git files; optionally export only the checked source bytes.

This is a conservative source-file guard, not a complete secret detector or a
license-compliance decision. It never reads ignored phone exports or credentials.
"""

import argparse
import hashlib
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
LOCAL_ONLY = {
    "AGENTS.md", "requirements-recovery.txt", "scripts/recover_iphone.py",
    "docs/recovery-report.md", "docs/deeper-recovery.md", "docs/rebuild-spec.md",
    "docs/rebuild-validation.md", "docs/additional-artifact-findings.md",
    "docs/recovery-tool.md", "docs/cellular-routing-research.md",
}
# Public, synthetic TLS fixtures. No blanket exception for private-key files.
FIXTURES = {
    "Native/vendor/idevice/tests/fixtures/lockdown_tls/device.cert.der": "ceb5c22f76ca0733e5c330047fc07b475b27cbada175fd122a5af5432c9ddde4",
    "Native/vendor/idevice/tests/fixtures/lockdown_tls/device.key.der": "eb7300a2b9a6480de322c55e0dad5a5032f69b7a56b2ae530d62123ac70ee25b",
    "Native/vendor/idevice/tests/fixtures/lockdown_tls/other.cert.der": "c2ff243ae5ba935a18df3f4732dedf190516189234d62ef3469d92dda3644e0a",
    "Native/vendor/idevice/tests/fixtures/lockdown_tls/other.key.der": "d4c4f784bff91c39777b29e59f3ea1af42d58fa88b2bd06b08ab16cb9f32b1c0",
}
BLOCKED_PARTS = {
    ".git", ".toolchains", ".venv", ".build", ".swiftpm", "build",
    "DerivedData", "target", "xcuserdata", "__pycache__",
}
BLOCKED_SUFFIXES = {
    ".ipa", ".mobileprovision", ".provisionprofile", ".p8", ".p12", ".pfx",
    ".key", ".pem", ".der", ".cer", ".crt", ".dmg", ".apk", ".so",
    ".dylib", ".a", ".zip", ".tar", ".gz", ".log", ".xcuserstate",
}
PATTERNS = {
    "private-key PEM": rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s+[A-Za-z0-9+/]{16}",
    "GitHub token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "Apple device identifier": rb"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b",
    "local signing team": rb"\bDEVELOPMENT_TEAM\s*=\s*[\"']?[A-Z0-9]{10}[\"']?\s*[;\r\n]",
    "personal absolute path": rb"/(?:Users|home)/[A-Za-z0-9_.-]+/",
}


def git(*args, input_bytes=None):
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], input=input_bytes,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


def source_files():
    paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    return sorted(set(p.decode("utf-8") for p in paths.split(b"\0") if p))


def index_blobs():
    """Return stage-zero Git blobs so staged bytes receive the same checks."""
    indexed = {}
    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, name_bytes = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.split(b" ")
        if stage != b"0" or name_bytes in indexed:
            raise RuntimeError("Unmerged or duplicate Git index entry")
        indexed[name_bytes] = (mode, object_id)
    return {name.decode("utf-8"): value for name, value in indexed.items()}


def inspect_bytes(name, data, source, errors):
    if name in FIXTURES:
        if hashlib.sha256(data).hexdigest() != FIXTURES[name]:
            errors.append((name, f"{source}: synthetic fixture changed; review provenance before updating its hash"))
    else:
        for label, pattern in PATTERNS.items():
            if re.search(pattern, data):
                errors.append((name, f"{source}: {label}"))


def has_symlink_component(relative):
    path = ROOT
    for part in relative.parts:
        path /= part
        if path.is_symlink():
            return True
    return False


def inspect_sources(paths):
    errors, checked = [], {}
    indexed = index_blobs()
    symlinked = {
        name for name in paths
        if not PurePosixPath(name).is_absolute()
        and ".." not in PurePosixPath(name).parts
        and has_symlink_component(PurePosixPath(name))
    }
    # Include tracked files even when someone forced them past .gitignore.
    ignored_result = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--no-index", "-z", "--stdin"],
        input=b"\0".join(p.encode() for p in paths if p not in symlinked) + b"\0",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if ignored_result.returncode not in (0, 1):
        raise RuntimeError("Git ignore rules could not be checked")
    ignored = set(ignored_result.stdout.decode().split("\0"))
    for name in paths:
        relative = PurePosixPath(name)
        path = ROOT / name
        if relative.is_absolute() or ".." in relative.parts:
            errors.append((name, "unsafe path"))
            continue
        if name in symlinked:
            errors.append((name, "symlinks are not allowed in the source export"))
            continue
        if name in ignored:
            errors.append((name, "tracked file is excluded by publication ignore rules"))
            continue
        if (set(relative.parts) & BLOCKED_PARTS
                or any(p.endswith((".app", ".xcarchive", ".xcframework", ".dSYM")) for p in relative.parts)
                or name.startswith("recovery/")
                or name in LOCAL_ONLY
                or relative.name.startswith(".env")
                or name.endswith(".local.xcconfig")
                or (relative.suffix.lower() in BLOCKED_SUFFIXES and name not in FIXTURES)):
            errors.append((name, "private data, local output, or binary artifact path"))
            continue
        if name in indexed:
            mode, object_id = indexed[name]
            if mode not in (b"100644", b"100755"):
                errors.append((name, "Git index entry is not a regular source file"))
                continue
            size = int(git("cat-file", "-s", object_id.decode("ascii")))
            if size > 5 * 1024 * 1024:
                errors.append((name, "Git index entry exceeds 5 MiB"))
                continue
            inspect_bytes(name, git("cat-file", "blob", object_id.decode("ascii")), "Git index", errors)
        if not path.exists():
            # A tracked deletion is omitted from the working-tree source snapshot.
            continue
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            errors.append((name, "not a regular source file or exceeds 5 MiB"))
            continue
        data = path.read_bytes()
        inspect_bytes(name, data, "working tree", errors)
        checked[name] = (data, path.stat().st_mode)
    return errors, checked


def write_archive(destination, checked):
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves previous recovery/source archives.
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (data, mode) in checked.items():
            info = zipfile.ZipInfo("GPS-Rebuilt-source/" + name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if mode & 0o111 else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(f"Source archive: {destination.name}\nSHA-256: {digest}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="create a source ZIP after the checks pass (must not exist)")
    args = parser.parse_args()
    errors, checked = inspect_sources(source_files())
    if errors:
        for name, reason in errors:
            # A filename can itself contain a credential or personal identifier.
            path_digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
            print(f"BLOCKED: path sha256:{path_digest}: {reason}", file=sys.stderr)
        return 1
    print(f"Publication checks passed: {len(checked)} source files; ignored private files were not read.")
    if args.archive:
        write_archive(args.archive, checked)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, UnicodeError):
        print("Publication check failed; verify Git, file access, and that the archive path is new.", file=sys.stderr)
        sys.exit(1)
