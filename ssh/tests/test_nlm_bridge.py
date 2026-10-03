import base64
import importlib.util
from pathlib import Path

import pytest


SSH_DIR = Path(__file__).resolve().parents[1]


def load_broker():
    spec = importlib.util.spec_from_file_location("claude_nlm_broker", SSH_DIR / "claude_nlm_broker.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


broker = load_broker()


def request(*args, cwd="/workspace/projects"):
    return {"version": 1, "args": list(args), "cwd": cwd}


@pytest.mark.parametrize("args", [("login",), ("notebook", "delete", "abc"), ("--debug", "list"), ("config", "show")])
def test_sensitive_operations_fail_closed(args):
    with pytest.raises(broker.RequestError):
        broker.validate_request(request(*args))


def test_only_project_paths_cross_the_boundary():
    args, cwd = broker.validate_request(
        request("download", "audio", "--output=/workspace/projects/out/file.mp3", cwd="/workspace/projects/demo")
    )
    assert cwd == "/home/centos/data/projects/demo"
    assert args[-1] == "--output=/home/centos/data/projects/out/file.mp3"
    with pytest.raises(broker.RequestError):
        broker.validate_request(request("download", "audio", "--output=/etc/passwd"))


def test_dotdot_cannot_escape_project_root():
    with pytest.raises(broker.RequestError):
        broker.validate_request(request("download", "audio", "/workspace/projects/../../etc/passwd"))
    with pytest.raises(broker.RequestError):
        broker.validate_request(request("source", "add", "--file", "../../.notebooklm-mcp-cli/auth.json"))


def test_relative_file_options_are_canonicalized_inside_current_project():
    args, _ = broker.validate_request(
        request("source", "add", "--file", "paper.pdf", cwd="/workspace/projects/study")
    )
    assert args[-1] == "/home/centos/data/projects/study/paper.pdf"


def test_home_relative_file_options_are_rejected():
    with pytest.raises(broker.RequestError):
        broker.validate_request(request("download", "audio", "--output=~/.ssh/key"))


def test_broker_passes_an_argv_not_a_shell_string(monkeypatch):
    observed = {}

    def fake_run(args, cwd):
        observed["args"] = args
        observed["cwd"] = cwd
        return 0, b"ok", b""

    monkeypatch.setattr(broker, "run_cli", fake_run)
    response = broker.handle_request(request("query", "abc; touch /tmp/pwned"))
    assert response["exit_code"] == 0
    assert observed == {
        "args": ["query", "abc; touch /tmp/pwned"],
        "cwd": "/home/centos/data/projects",
    }
    assert base64.b64decode(response["stdout_b64"]) == b"ok"


def test_help_and_version_are_available_without_a_command():
    assert broker.validate_request(request("--help"))[0] == ["--help"]
    assert broker.validate_request(request("--version"))[0] == ["--version"]


def test_malformed_protocol_is_rejected():
    with pytest.raises(broker.RequestError):
        broker.validate_request({"version": 1, "args": ["list"], "cwd": "/workspace/projects", "extra": True})


def test_socket_activation_requires_exactly_one_fd(monkeypatch):
    monkeypatch.setenv("LISTEN_PID", str(broker.os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "0")
    assert broker.systemd_activated_server() is None


def test_socket_unit_owns_stable_private_listener():
    socket_unit = (SSH_DIR / "systemd" / "claude-nlm-broker.socket").read_text()
    service_unit = (SSH_DIR / "systemd" / "claude-nlm-broker.service").read_text()
    assert "ListenStream=/run/claude-nlm/nlm-v2.sock" in socket_unit
    assert "SocketMode=0660" in socket_unit
    assert "SocketGroup=claude-shell" in socket_unit
    assert "RuntimeDirectory=" not in service_unit


def test_chroot_exposes_only_its_own_procfd_view():
    mounts = (SSH_DIR / "claude_shell_mounts.sh").read_text()
    sync = (SSH_DIR.parent / "sync.sh").read_text()
    assert 'ln -s /proc/self/fd "$ROOT/dev/fd"' in mounts
    assert 'ln -s /proc/self/fd "$CHROOT_DIR/dev/fd"' in sync
    assert "unexpected /dev/fd" in sync


def test_runner_transfers_standard_descriptor_ownership_before_dropping_uid():
    runner = (SSH_DIR / "claude_shell_runner.py").read_text()
    assert "def make_standard_fds_reopenable" in runner
    assert "for descriptor in (0, 1, 2)" in runner
    assert "make_standard_fds_reopenable(identity)" in runner
    assert runner.index("make_standard_fds_reopenable(identity)") < runner.index("os.setuid(identity.pw_uid)")


def test_chroot_git_policy_trusts_only_the_approved_project_mount():
    config = (SSH_DIR / "claude-shell.gitconfig").read_text()
    mounts = (SSH_DIR / "claude_shell_mounts.sh").read_text()
    assert "directory = /workspace/projects/*" in config
    assert 'claude-shell.gitconfig "$ROOT/etc/gitconfig"' in mounts
    assert "/home/centos/.gitconfig" not in mounts


def test_git_push_broker_is_approval_bound_and_has_no_host_credential_mount():
    broker = (SSH_DIR / "claude_git_push_broker.py").read_text()
    launcher = (SSH_DIR / "claude_shell_launcher.py").read_text()
    assert 'if command.startswith("push ")' in launcher
    assert "def resolve_repo" in broker
    assert "repository ID must resolve to exactly one GitHub origin under projects" in broker
    assert "consume_approval(approval)" in broker
    assert '"GIT_ASKPASS": ASKPASS' in broker
    assert '"GIT_CONFIG_GLOBAL": "/dev/null"' in broker
    assert '"/usr/bin/gh", "auth", "token"' in broker
    assert "/home/centos/.config/gh" not in broker


def test_sync_hot_deploys_the_shell_launcher_that_dispatches_pushes():
    sync = (SSH_DIR.parent / "sync.sh").read_text()
    assert 'atomic_install "$SSH_DIR/claude_shell_launcher.py" "$LIBEXEC_DIR/claude-shell-launch" 0755' in sync


def test_nsight_compute_runtime_is_narrowly_mounted_read_only():
    mounts = (SSH_DIR / "claude_shell_mounts.sh").read_text()
    sync = (SSH_DIR.parent / "sync.sh").read_text()
    assert "NSIGHT_COMPUTE_ROOT=/opt/nvidia/nsight-compute" in mounts
    assert 'mount_bind "$NSIGHT_COMPUTE_ROOT" "$ROOT/opt/nvidia/nsight-compute" ro' in mounts
    assert 'mount --bind "$NSIGHT_COMPUTE_ROOT" "$CHROOT_DIR/opt/nvidia/nsight-compute"' in sync
    assert 'mount -o remount,bind,ro "$CHROOT_DIR/opt/nvidia/nsight-compute"' in sync
