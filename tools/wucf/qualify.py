"""Emit a reproducible offline test receipt for the exact checked-out files.

No production data, provider calls or deployment. This runner cannot prove
native WCS, live provider permissions, SaaS isolation or Dashboard builds.
Run only against a trusted checkout; tests are executable repository code.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
TEST_TIMEOUT = 180


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                          text=True, check=True, timeout=15).stdout.strip()


def inventory():
    result = {}
    for path in sorted(ROOT.iterdir()):
        if path.suffix not in {".py", ".md", ".json"}:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("unexpected qualification file")
        raw = path.read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("qualification file budget")
        result[path.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


def main():
    before = inventory()
    head = git("rev-parse", "HEAD")
    if git("status", "--porcelain", "--untracked-files=all", "--", "."):
        raise ValueError("WUCF checkout is dirty")
    # Do not pass credentials, proxies, Python path or user site customizations.
    env = {"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "LC_ALL": "C.UTF-8"}
    start = time.monotonic()
    output = ""
    exit_code = 1
    reason = "test_failure"
    try:
        proc = subprocess.run([sys.executable, "-I", "-B", "-m", "unittest",
                               "discover", "-s", str(ROOT), "-p", "test_*.py", "-v"],
                              cwd=ROOT, env=env, capture_output=True, text=True,
                              timeout=TEST_TIMEOUT)
        output = proc.stdout + proc.stderr
        exit_code = proc.returncode
        reason = "completed" if exit_code == 0 else "test_failure"
    except subprocess.TimeoutExpired as exc:
        output = "".join(x.decode("utf-8", "replace") if isinstance(x, bytes) else (x or "")
                         for x in (exc.stdout, exc.stderr))
        reason = "test_timeout"
    sys.stderr.write(output)
    after = inventory()
    clean = not git("status", "--porcelain", "--untracked-files=all", "--", ".")
    unchanged = before == after and head == git("rev-parse", "HEAD") and clean
    match = re.search(r"^Ran ([0-9]+) tests? in ", output, re.MULTILINE)
    count = int(match.group(1)) if match else 0
    # Prevent a successful zero-test discovery from being called qualification.
    skipped = bool(re.search(r"^OK \(.*(?:skipped|expected failures)=\d+", output, re.MULTILINE))
    passed = exit_code == 0 and unchanged and count > 0 and not skipped
    receipt = {"schema_version": 1, "qualification": "offline_reference_only",
               "git_head": head, "python": sys.version.split()[0],
               "test_count": count, "test_exit_code": exit_code, "skips_or_expected_failures": skipped,
               "result": "PASS" if passed else "FAIL", "reason": reason,
               "checkout_unchanged": unchanged,
               "duration_seconds": round(time.monotonic() - start, 3),
               "test_output_sha256": hashlib.sha256(output.encode()).hexdigest(),
               "files": before, "native_delivery_qualified": False,
               "live_provider_qualified": False, "production_activation_supported": False}
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
