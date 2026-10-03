from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_start_requires_real_local_and_public_health():
    script = (ROOT / "start.sh").read_text(encoding="utf-8")
    assert 'health_is_ok "$LOCAL_HEALTH"' in script
    assert 'health_is_ok "$endpoint/healthz"' in script
    assert 'Existing bridge is stale or unreachable' in script
    assert 'sudo systemctl "$action" "$UNIT"' in script


def test_start_clears_stale_url_before_service_transition():
    script = (ROOT / "start.sh").read_text(encoding="utf-8")
    clear_position = script.index(': > "$URL_FILE"')
    transition_position = script.index('sudo systemctl "$action" "$UNIT"')
    assert clear_position < transition_position


def test_start_wait_uses_a_wall_clock_deadline():
    script = (ROOT / "start.sh").read_text(encoding="utf-8")
    assert "deadline=$((SECONDS + 120))" in script
    assert 'while [ "$SECONDS" -lt "$deadline" ]' in script
    assert "for _ in $(seq 1 120)" not in script


def test_test_command_has_bounded_non_retrying_health_checks():
    script = (ROOT / "start-test.sh").read_text(encoding="utf-8")
    assert "--retry" not in script
    assert "--connect-timeout 3 --max-time 8" in script
    assert "pending (" not in script
    assert 'public_status="reachable and healthy"' in script
    assert '"$ROOT_DIR/start.sh" >/dev/null' not in script


def test_two_hour_key_is_authorized_for_sftp_without_widening_mount_writes():
    script = (ROOT / "start-test.sh").read_text(encoding="utf-8")
    assert "for account in claude-shell claude-sync claude-playwright" in script

    units = ROOT / "ssh" / "systemd"
    projects = (units / "projects.mount").read_text(encoding="utf-8")
    skills = (units / "skills.mount").read_text(encoding="utf-8")
    agents = (units / "agents.mount").read_text(encoding="utf-8")
    assert "Options=bind,nosuid,nodev,noexec" in projects
    assert "Options=bind,ro,nosuid,nodev,noexec" in skills
    assert "Options=bind,ro,nosuid,nodev,noexec" in agents


def test_test_command_rotates_only_when_expired_or_explicitly_requested():
    script = (ROOT / "start-test.sh").read_text(encoding="utf-8")
    assert '--rotate) force_rotate=1' in script
    assert '[ "$force_rotate" -eq 0 ]' in script


def test_sync_reloads_only_capable_supervisor_and_waits_for_public_adoption():
    sync = (ROOT / "sync.sh").read_text(encoding="utf-8")
    bridge = (ROOT / "https_bridge" / "start.sh").read_text(encoding="utf-8")
    assert "reload-capable.pid" in sync
    assert "reload-capable.pid" in bridge
    assert "public_gateway_ready" in sync
    assert 'systemctl kill --kill-who=main --signal=HUP' in sync


def test_sync_preserves_sftp_write_boundary():
    sync = (ROOT / "sync.sh").read_text(encoding="utf-8")
    assert "SFTP_CHROOT_DIR=/srv/claude-remote" in sync
    assert "u:claude-sync:rwX /home/centos/data/projects" in sync
    assert 'for name in skills agents' in sync
    assert 'mount -o remount,bind,ro "$target"' in sync
    assert 'nsenter -t "$sshd_pid" -m -- mount -o remount,bind,ro "$target"' in sync
