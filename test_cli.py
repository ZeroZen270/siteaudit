"""Smoke tests for the siteaudit CLI (needs internet for live audits)."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_cli(*args):
    r = subprocess.run([sys.executable, "-m", "siteaudit.cli", *args],
                       capture_output=True, text=True, cwd=str(HERE))
    return r


def main():
    r = run_cli("example.com")
    assert r.returncode == 0, r.stderr
    assert "example.com" in r.stdout and "Issues found" in r.stdout, r.stdout
    print("human output OK")

    r = run_cli("example.com", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["domain"] == "example.com"
    assert data["notes"]["status"] == 200
    assert "no_meta_description" in data["issues"]
    print("json output OK:", data["issues"])

    r = run_cli("not a domain")
    assert r.returncode == 2 and "error" in r.stderr.lower(), (r.returncode, r.stderr)
    print("invalid input OK")

    r = run_cli("this-domain-definitely-does-not-exist-xyz123.com",
                "--timeout", "6")
    assert r.returncode == 0, r.stderr
    assert "unreachable" in r.stdout, r.stdout
    print("unreachable domain OK")
    print("ALL CLI TESTS PASSED")


if __name__ == "__main__":
    main()
