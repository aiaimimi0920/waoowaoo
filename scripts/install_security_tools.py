"""Download only approved Linux release binaries and verify exact SHA-256."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request

MAX_ARCHIVE = 30 * 1024 * 1024

def install(manifest, destination):
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux" or platform.machine() != "x86_64":
        raise ValueError("hosted_linux_required")
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name, spec in manifest.items():
        if name not in {"gitleaks", "zizmor"}:
            raise ValueError("unexpected_tool")
        expected_prefix = "https://github.com/" + {
            "gitleaks": "gitleaks/gitleaks", "zizmor": "zizmorcore/zizmor"}[name] + "/releases/download/v" + spec["version"] + "/"
        if not spec["url"].startswith(expected_prefix):
            raise ValueError("unexpected_download_url")
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "repository-security-ci"})
        with urllib.request.urlopen(request, timeout=60) as response:
            archive = response.read(MAX_ARCHIVE + 1)
        if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != spec["sha256"]:
            raise ValueError("archive_hash_mismatch")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == name]
            if len(members) != 1 or not 0 < members[0].size <= MAX_ARCHIVE:
                raise ValueError("invalid_release_archive")
            with tar.extractfile(members[0]) as stream:
                binary = stream.read(MAX_ARCHIVE + 1)
        path = destination / name
        if path.is_symlink():
            raise ValueError("unsafe_binary_path")
        path.write_bytes(binary)
        path.chmod(0o700)
        command = [str(path), "version"] if name == "gitleaks" else [str(path), "--version"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
        if result.returncode or spec["version"] not in result.stdout.decode("utf-8"):
            raise ValueError("tool_version_mismatch")
        print(json.dumps({"tool": name, "version": spec["version"], "archive_sha256": spec["sha256"], "verified": True}))

def main():
    try:
        root = Path.cwd().resolve()
        if any(path.is_symlink() for path in [root / '.tmp', root / '.tmp/security-tools']):
            raise ValueError('unsafe_binary_directory')
        manifest = json.loads(Path(__file__).with_name("security_tools.json").read_text(encoding="utf-8"))
        install(manifest, root / ".tmp/security-tools")
        return 0
    except Exception:
        print(json.dumps({"tools_ready": False, "error": "security_tool_install_failed"}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
