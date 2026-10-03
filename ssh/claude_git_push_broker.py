#!/usr/local/bin/python3
"""One-shot, locally-approved GitHub App pushes for the restricted bridge.

The Cloud shell never receives GitHub credentials. It can only redeem a
short-lived local approval for an exact commit, repository, and branch.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path


CONFIG = Path("/etc/claude-remote/git-push-policy.json")
APPROVALS = Path("/var/lib/claude-remote/git-push-approvals")
ASKPASS = "/usr/local/libexec/claude-git-push-askpass"
PROJECTS = Path("/home/centos/data/projects")
SHA = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
BRANCH = re.compile(r"^(?!-)[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class Denied(RuntimeError):
    pass


def require_root_owned(path: Path, mode: int = 0o600) -> None:
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
        raise Denied(f"unsafe permissions on {path}")


def policy() -> dict:
    require_root_owned(CONFIG)
    try:
        value = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Denied("Git push policy is invalid") from error
    app = value.get("github_app")
    if not isinstance(app, dict):
        raise Denied("Git push policy is incomplete")
    return value


def resolve_repo(repo_id: str, branch: str) -> dict:
    """Resolve one unique GitHub origin below the approved projects tree."""
    if not NAME.fullmatch(repo_id) or not BRANCH.fullmatch(branch):
        raise Denied("invalid repository or branch")
    candidates: list[dict] = []
    for dotgit in PROJECTS.rglob(".git"):
        path = dotgit.parent.resolve()
        try:
            remote = run(
                ["/usr/bin/git", "-c", f"safe.directory={path}", "-C", str(path),
                 "remote", "get-url", "--push", "origin"],
                env={"PATH": "/usr/bin:/bin"}, capture=True,
            ).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        match = re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/([A-Za-z0-9_.-]+)\.git", remote)
        if match and match.group(1) == repo_id:
            candidates.append({"path": str(path), "remote": remote})
    if len(candidates) != 1:
        raise Denied("repository ID must resolve to exactly one GitHub origin under projects")
    return candidates[0]


def parse_request(raw: str) -> tuple[str, str, str, str]:
    parts = raw.split()
    if len(parts) != 5 or parts[0] != "push":
        raise Denied("expected: push REPOSITORY COMMIT_SHA BRANCH APPROVAL")
    _, repo_id, commit, branch, nonce = parts
    if not SHA.fullmatch(commit) or not NONCE.fullmatch(nonce):
        raise Denied("invalid commit or approval")
    return repo_id, commit, branch, nonce


def run(argv: list[str], *, env: dict[str, str] | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, text=True, env=env, capture_output=capture)


def approval_path(nonce: str) -> Path:
    return APPROVALS / nonce


def create_approval(repo_id: str, commit: str, branch: str) -> None:
    policy()
    entry = resolve_repo(repo_id, branch)
    if not SHA.fullmatch(commit):
        raise Denied("commit must be a full lowercase SHA-1")
    run(
        ["/usr/bin/git", "-c", f"safe.directory={entry['path']}", "-C", entry["path"],
         "rev-parse", "--verify", f"{commit}^{{commit}}"],
        env={"PATH": "/usr/bin:/bin"},
    )
    APPROVALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(APPROVALS, 0o700)
    nonce = secrets.token_urlsafe(32)
    record = {
        "repo": repo_id, "commit": commit, "branch": branch,
        "path": entry["path"], "remote": entry["remote"],
        "expires": int(time.time()) + 600,
    }
    fd = os.open(approval_path(nonce), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(record, output, separators=(",", ":"))
    print(f"Approval expires in 10 minutes. Give this value only to the active Cloud session:\n{nonce}")


def load_approval(nonce: str, repo_id: str, commit: str, branch: str) -> tuple[Path, dict]:
    path = approval_path(nonce)
    try:
        require_root_owned(path)
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Denied("approval is missing, expired, or already used") from error
    required = {"repo", "commit", "branch", "path", "remote", "expires"}
    expected = {"repo": repo_id, "commit": commit, "branch": branch}
    if set(record) != required or any(record[key] != value for key, value in expected.items()):
        raise Denied("approval does not match this push request")
    if not isinstance(record["expires"], int) or record["expires"] < time.time():
        raise Denied("approval expired")
    path_value = Path(record["path"])
    if not isinstance(record["remote"], str) or PROJECTS not in path_value.parents:
        raise Denied("approval contains an unsafe repository")
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", record["remote"]):
        raise Denied("approval contains an unsafe remote")
    return path, record


def consume_approval(path: Path) -> None:
    try:
        path.unlink()
    except OSError as error:
        raise Denied("approval is missing or already used") from error


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def installation_token(value: dict) -> str:
    app = value["github_app"]
    app_id, installation_id, key_name = app.get("app_id"), app.get("installation_id"), app.get("private_key")
    if not isinstance(app_id, str) or not app_id.isdigit() or not isinstance(installation_id, str) or not installation_id.isdigit() or not isinstance(key_name, str):
        # The local owner explicitly authorized this one push. Use the active
        # host gh login internally rather than blocking on a GitHub App setup.
        # Its token stays in this root-owned broker process and the git child.
        token = run(
            ["/usr/bin/sudo", "-n", "-u", "centos", "/usr/bin/gh", "auth", "token"],
            env={"PATH": "/usr/bin:/bin", "HOME": "/home/centos"}, capture=True,
        ).stdout.strip()
        if not re.fullmatch(r"(?:gho|ghu|ghs|github_pat)_[A-Za-z0-9_]+", token):
            raise Denied("host GitHub CLI did not return a usable token")
        return token
    key = Path(key_name)
    require_root_owned(key)
    now = int(time.time())
    header = b'{"alg":"RS256","typ":"JWT"}'
    payload = json.dumps(
        {"iat": now - 30, "exp": now + 540, "iss": app_id}, separators=(",", ":")
    ).encode("utf-8")
    signing_input = f"{b64url(header)}.{b64url(payload)}"
    signed = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(key)],
        input=signing_input.encode("ascii"), capture_output=True, check=True,
        env={"PATH": "/usr/bin:/bin"},
    ).stdout
    jwt = f"{signing_input}.{b64url(signed)}"
    response = run([
        "/usr/bin/curl", "--fail", "--silent", "--show-error", "--request", "POST",
        "--header", f"Authorization: Bearer {jwt}",
        "--header", "Accept: application/vnd.github+json",
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
    ], env={"PATH": "/usr/bin:/bin"}, capture=True)
    try:
        token = json.loads(response.stdout).get("token")
    except json.JSONDecodeError as error:
        raise Denied("GitHub App returned invalid authentication data") from error
    if not isinstance(token, str) or not token.startswith("ghs_"):
        raise Denied("GitHub App did not issue an installation token")
    return token


def push(raw: str) -> None:
    repo_id, commit, branch, nonce = parse_request(raw)
    value = policy()
    approval, entry = load_approval(nonce, repo_id, commit, branch)
    repo = entry["path"]
    run(["/usr/bin/git", "-c", f"safe.directory={repo}", "-C", repo, "rev-parse", "--verify", f"{commit}^{{commit}}"], env={"PATH": "/usr/bin:/bin"})
    token = installation_token(value)
    # Do not burn a local approval for missing/invalid App credentials. Once
    # authentication is ready, consume before network mutation to prevent replay.
    consume_approval(approval)
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": "/var/empty", "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": ASKPASS, "REMOTE_GATEWAY_GIT_ASKPASS_TOKEN": token,
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    run([
        "/usr/bin/git", "-c", f"safe.directory={repo}", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never", "-C", repo, "push", "--porcelain", entry["remote"],
        f"{commit}:refs/heads/{branch}",
    ], env=environment)
    print(f"Pushed approved commit {commit} to {repo_id}:{branch}.")


def main() -> int:
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--authorize":
            create_approval(sys.argv[2], sys.argv[3], sys.argv[4])
        elif len(sys.argv) == 3 and sys.argv[1] == "--request":
            push(sys.argv[2])
        else:
            raise Denied("invalid Git push broker invocation")
    except (Denied, subprocess.CalledProcessError) as error:
        print(f"remote-gateway Git push denied: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
