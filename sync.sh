#!/usr/bin/env bash
# Hot-deploy reviewed bridge helpers without replacing the live tunnel/session.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_DIR="$ROOT_DIR/ssh"
LIBEXEC_DIR=/usr/local/libexec
CHROOT_DIR=/srv/claude-shell-root
SFTP_CHROOT_DIR=/srv/claude-remote
NSIGHT_COMPUTE_ROOT=/opt/nvidia/nsight-compute
PY312_SITE=/home/centos/.local/lib/python3.12/site-packages
PY312_TARGET=opt/pyuser/lib/python3.12/site-packages
UNIT=remote-claude-bridge.service
LOCK_FILE="$HOME/.remote-gateway/sync.lock"

mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "Another remote-gateway-sync is already running." >&2; exit 1; }

bridge_pid_before=""
bridge_url_before=""
if systemctl is-active --quiet "$UNIT"; then
    bridge_pid_before=$(systemctl show -p MainPID --value "$UNIT")
fi
if [ -r "$HOME/.remote-gateway/https-bridge/url.txt" ]; then
    bridge_url_before=$(tr -d '\r\n' < "$HOME/.remote-gateway/https-bridge/url.txt")
fi

# Fail before deployment if the source contract is broken.
/usr/local/bin/python3 -m pytest -q "$SSH_DIR/tests"
/usr/local/bin/python3 -m pytest -q "$ROOT_DIR/https_bridge/tests" "$ROOT_DIR/tests"
for source in "$SSH_DIR"/*.py; do
    /usr/bin/python3 - "$source" <<'PY'
import pathlib, sys
compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], "exec")
PY
done

# Boot the exact new gateway code on a private test port before touching the
# live listener. No Cloudflare route points at this port.
set -a
source "$HOME/.remote-gateway/secrets.env"
set +a
: "${REMOTE_GATEWAY_TOKEN:?REMOTE_GATEWAY_TOKEN is required}"
candidate_log="$HOME/.remote-gateway/https-bridge/logs/gateway-candidate.log"
env REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" REMOTE_GATEWAY_HOST=127.0.0.1 REMOTE_GATEWAY_PORT=8799 \
    PYTHONPATH="$ROOT_DIR" /usr/local/bin/python3 "$ROOT_DIR/gateway/server.py" >"$candidate_log" 2>&1 &
candidate_pid=$!
candidate_ready=0
for _ in $(seq 1 30); do
    if curl --connect-timeout 1 --max-time 2 --fail --silent http://127.0.0.1:8799/healthz \
        | jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' >/dev/null 2>&1; then
        candidate_ready=1
        break
    fi
    kill -0 "$candidate_pid" 2>/dev/null || break
    sleep 1
done
kill "$candidate_pid" 2>/dev/null || true
wait "$candidate_pid" 2>/dev/null || true
[ "$candidate_ready" -eq 1 ] || { echo "Candidate MCP gateway failed validation; see $candidate_log" >&2; exit 1; }

atomic_install() {
    local source=$1 destination=$2 mode=$3
    local destination_dir temporary
    destination_dir=$(dirname "$destination")
    sudo install -d -o root -g root -m 0755 "$destination_dir"
    temporary=$(sudo mktemp "$destination_dir/.remote-gateway-sync.XXXXXX")
    sudo install -o root -g root -m "$mode" "$source" "$temporary"
    sudo mv -f "$temporary" "$destination"
}

broker_changed=0
unit_changed=0
socket_unit_changed=0
mount_units_changed=0
if ! sudo cmp -s "$SSH_DIR/claude_nlm_broker.py" "$LIBEXEC_DIR/claude-nlm-broker"; then
    broker_changed=1
fi
if ! sudo cmp -s "$SSH_DIR/systemd/claude-nlm-broker.service" /etc/systemd/system/claude-nlm-broker.service; then
    unit_changed=1
fi
if ! sudo cmp -s "$SSH_DIR/systemd/claude-nlm-broker.socket" /etc/systemd/system/claude-nlm-broker.socket; then
    socket_unit_changed=1
fi
for name in projects skills agents; do
    installed="/etc/systemd/system/srv-claude\\x2dremote-${name}.mount"
    if ! sudo cmp -s "$SSH_DIR/systemd/${name}.mount" "$installed"; then
        mount_units_changed=1
    fi
done

# These are hot-safe: existing sessions keep their current process, while new
# invocations see the atomically replaced root-owned helper.
atomic_install "$SSH_DIR/claude_nlm_broker.py" "$LIBEXEC_DIR/claude-nlm-broker" 0755
atomic_install "$SSH_DIR/claude_nlm_client.py" "$LIBEXEC_DIR/claude-nlm-client" 0755
atomic_install "$SSH_DIR/claude_shell_mounts.sh" "$LIBEXEC_DIR/claude-shell-mounts" 0755
atomic_install "$SSH_DIR/claude_shell_launcher.py" "$LIBEXEC_DIR/claude-shell-launch" 0755
atomic_install "$SSH_DIR/claude_shell_runner.py" "$LIBEXEC_DIR/claude-shell-runner" 0755
atomic_install "$SSH_DIR/claude-shell.gitconfig" "$LIBEXEC_DIR/claude-shell.gitconfig" 0644
atomic_install "$SSH_DIR/claude_git_push_broker.py" "$LIBEXEC_DIR/claude-git-push-broker" 0755
atomic_install "$SSH_DIR/claude-git-push-askpass" "$LIBEXEC_DIR/claude-git-push-askpass" 0755
atomic_install "$SSH_DIR/claude-git-push.sudoers" /etc/sudoers.d/claude-git-push 0440
atomic_install "$SSH_DIR/remote-gateway-git-authorize" /usr/local/bin/remote-gateway-git-authorize 0755
atomic_install "$SSH_DIR/systemd/claude-nlm-broker.service" /etc/systemd/system/claude-nlm-broker.service 0644
atomic_install "$SSH_DIR/systemd/claude-nlm-broker.socket" /etc/systemd/system/claude-nlm-broker.socket 0644
atomic_install "$SSH_DIR/claude-nlm.tmpfiles.conf" /usr/lib/tmpfiles.d/claude-nlm.conf 0644
for name in projects skills agents; do
    atomic_install "$SSH_DIR/systemd/${name}.mount" "/etc/systemd/system/srv-claude\\x2dremote-${name}.mount" 0644
done

# This is chroot-only Git safety policy. It makes no change to any repository,
# host Git configuration, credential helper, remote, or authentication state.
atomic_install "$SSH_DIR/claude-shell.gitconfig" "$CHROOT_DIR/etc/gitconfig" 0644

# Seed only an empty, root-owned policy. Existing user-approved GitHub App
# configuration is never overwritten by sync.
if ! sudo test -e /etc/claude-remote/git-push-policy.json; then
    atomic_install "$SSH_DIR/git-push-policy.example.json" /etc/claude-remote/git-push-policy.json 0600
fi
sudo visudo -cf /etc/sudoers.d/claude-git-push

if [ "$unit_changed" -eq 1 ] || [ "$socket_unit_changed" -eq 1 ] || [ "$mount_units_changed" -eq 1 ]; then
    sudo systemctl daemon-reload
fi

# SFTP may write projects, but skills and agents remain read-only. Correct both
# the backing ACL and the live bind-mount flags without restarting sshd or
# disturbing the Cloudflare tunnel.
sudo setfacl -R -m u:claude-sync:rwX /home/centos/data/projects
sudo find /home/centos/data/projects -type d -exec setfacl -m d:u:claude-sync:rwX,d:m::rwx {} +
for name in skills agents; do
    source_dir="/home/centos/.claude/$name"
    target="$SFTP_CHROOT_DIR/$name"
    sudo setfacl -R -m u:claude-sync:rX "$source_dir"
    sudo find "$source_dir" -type d -exec setfacl -m d:u:claude-sync:rX,d:m::r-x {} +
    sudo mount -o remount,bind,ro "$target"
    findmnt -no OPTIONS "$target" | tr ',' '\n' | grep -qx ro || {
        echo "Safety check failed: $target is not read-only." >&2
        exit 1
    }
done
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/claude-nlm.conf
sudo systemctl disable claude-nlm-broker.service >/dev/null 2>&1 || true
if [ "$socket_unit_changed" -eq 1 ] || ! systemctl is-active --quiet claude-nlm-broker.socket; then
    # One-time migration from a process-owned socket to a systemd-owned socket.
    # Only NLM pauses; SSH and the Cloudflare bridge stay untouched.
    sudo systemctl stop claude-nlm-broker.service || true
    if [ -S /run/claude-nlm/nlm-v2.sock ]; then
        sudo rm -f /run/claude-nlm/nlm-v2.sock
    fi
    sudo systemctl enable --now claude-nlm-broker.socket >/dev/null
elif [ "$broker_changed" -eq 1 ] || [ "$unit_changed" -eq 1 ]; then
    # The socket remains listening while the implementation is restarted.
    sudo systemctl restart claude-nlm-broker.service
fi

# Add only the new socket and command to the existing chroot. Do not rerun the
# complete mount provisioner, which could perturb unrelated active tool mounts.
if mountpoint -q "$CHROOT_DIR/run/claude-nlm" && [ ! -S "$CHROOT_DIR/run/claude-nlm/nlm-v2.sock" ]; then
    # Older unit revisions recreated RuntimeDirectory during a broker restart,
    # leaving this bind attached to the deleted inode. Refresh this one mount.
    sudo umount "$CHROOT_DIR/run/claude-nlm"
fi
if ! mountpoint -q "$CHROOT_DIR/run/claude-nlm"; then
    sudo install -d -o root -g root -m 0755 "$CHROOT_DIR/run/claude-nlm"
    sudo mount --bind /run/claude-nlm "$CHROOT_DIR/run/claude-nlm"
    sudo mount -o remount,bind,ro "$CHROOT_DIR/run/claude-nlm"
fi
sudo install -d -o root -g root -m 0755 "$CHROOT_DIR/opt/bridge-tools/bin"
atomic_install "$LIBEXEC_DIR/claude-nlm-client" "$CHROOT_DIR/opt/bridge-tools/bin/nlm-v2" 0755

# ncu is only a launcher under /opt/cuda; the real host-managed profiler is a
# versioned companion tree. Bind exactly that tree, read-only.
if [ -d "$NSIGHT_COMPUTE_ROOT" ]; then
    sudo install -d -o root -g root -m 0755 "$CHROOT_DIR/opt/nvidia/nsight-compute"
    if ! mountpoint -q "$CHROOT_DIR/opt/nvidia/nsight-compute"; then
        sudo mount --bind "$NSIGHT_COMPUTE_ROOT" "$CHROOT_DIR/opt/nvidia/nsight-compute"
        sudo mount -o remount,bind,ro "$CHROOT_DIR/opt/nvidia/nsight-compute"
    fi
    test -x "$CHROOT_DIR/opt/nvidia/nsight-compute/2025.2.1/ncu" || { echo "Safety check failed: Nsight Compute runtime is incomplete." >&2; exit 1; }
fi

# The host's CUDA-enabled Python 3.12 packages, read-only (see claude_shell_mounts.sh).
if [ -d "$PY312_SITE" ]; then
    # Once mounted read-only the target cannot be chmod/chowned; only prepare it when unmounted.
    if ! mountpoint -q "$CHROOT_DIR/$PY312_TARGET"; then
        sudo install -d -o root -g root -m 0755 "$CHROOT_DIR/$PY312_TARGET"
        sudo mount --bind "$PY312_SITE" "$CHROOT_DIR/$PY312_TARGET"
        sudo mount -o remount,bind,ro "$CHROOT_DIR/$PY312_TARGET"
    fi
fi

# /dev/fd is a conventional symlink into the chroot's own procfs. Validate an
# existing entry rather than replacing it, so sync never widens a device mount.
if sudo test -L "$CHROOT_DIR/dev/fd"; then
    [ "$(sudo readlink "$CHROOT_DIR/dev/fd")" = /proc/self/fd ] || { echo "Safety check failed: unexpected /dev/fd target." >&2; exit 1; }
elif sudo test -e "$CHROOT_DIR/dev/fd"; then
    echo "Safety check failed: unexpected /dev/fd entry." >&2
    exit 1
else
    sudo ln -s /proc/self/fd "$CHROOT_DIR/dev/fd"
fi

# sshd intentionally has a private mount namespace (PrivateTmp=yes). If this
# capability was added after sshd started, the host bind above is not visible
# to Cloud sessions. Add only this exact read-only bind to the live namespace;
# do not restart sshd or disturb existing sessions.
if systemctl is-active --quiet claude-remote-sshd.service; then
    sshd_pid=$(systemctl show -p MainPID --value claude-remote-sshd.service)
    if [[ "$sshd_pid" =~ ^[1-9][0-9]*$ ]] && [ -d "/proc/$sshd_pid" ]; then
        for name in skills agents; do
            target="$SFTP_CHROOT_DIR/$name"
            sudo nsenter -t "$sshd_pid" -m -- mount -o remount,bind,ro "$target"
            sudo nsenter -t "$sshd_pid" -m -- findmnt -no OPTIONS "$target" | tr ',' '\n' | grep -qx ro || {
                echo "Safety check failed: SSH namespace $target is not read-only." >&2
                exit 1
            }
        done
        if ! sudo nsenter -t "$sshd_pid" -m -- test -S "$CHROOT_DIR/run/claude-nlm/nlm-v2.sock"; then
            if sudo nsenter -t "$sshd_pid" -m -- mountpoint -q "$CHROOT_DIR/run/claude-nlm"; then
                sudo nsenter -t "$sshd_pid" -m -- umount "$CHROOT_DIR/run/claude-nlm"
            fi
            sudo nsenter -t "$sshd_pid" -m -- mount --bind /run/claude-nlm "$CHROOT_DIR/run/claude-nlm"
            sudo nsenter -t "$sshd_pid" -m -- mount -o remount,bind,ro "$CHROOT_DIR/run/claude-nlm"
        fi
        sudo nsenter -t "$sshd_pid" -m -- test -S "$CHROOT_DIR/run/claude-nlm/nlm-v2.sock"
        if [ -d "$NSIGHT_COMPUTE_ROOT" ]; then
            if ! sudo nsenter -t "$sshd_pid" -m -- mountpoint -q "$CHROOT_DIR/opt/nvidia/nsight-compute"; then
                sudo nsenter -t "$sshd_pid" -m -- mkdir -p "$CHROOT_DIR/opt/nvidia/nsight-compute"
                sudo nsenter -t "$sshd_pid" -m -- mount --bind "$NSIGHT_COMPUTE_ROOT" "$CHROOT_DIR/opt/nvidia/nsight-compute"
                sudo nsenter -t "$sshd_pid" -m -- mount -o remount,bind,ro "$CHROOT_DIR/opt/nvidia/nsight-compute"
            fi
            sudo nsenter -t "$sshd_pid" -m -- test -x "$CHROOT_DIR/opt/nvidia/nsight-compute/2025.2.1/ncu"
        fi
        if [ -d "$PY312_SITE" ] && ! sudo nsenter -t "$sshd_pid" -m -- mountpoint -q "$CHROOT_DIR/$PY312_TARGET"; then
            sudo nsenter -t "$sshd_pid" -m -- mkdir -p "$CHROOT_DIR/$PY312_TARGET"
            sudo nsenter -t "$sshd_pid" -m -- mount --bind "$PY312_SITE" "$CHROOT_DIR/$PY312_TARGET"
            sudo nsenter -t "$sshd_pid" -m -- mount -o remount,bind,ro "$CHROOT_DIR/$PY312_TARGET"
        fi
        if sudo nsenter -t "$sshd_pid" -m -- test -L "$CHROOT_DIR/dev/fd"; then
            [ "$(sudo nsenter -t "$sshd_pid" -m -- readlink "$CHROOT_DIR/dev/fd")" = /proc/self/fd ] || { echo "Safety check failed: SSH namespace has unexpected /dev/fd target." >&2; exit 1; }
        elif sudo nsenter -t "$sshd_pid" -m -- test -e "$CHROOT_DIR/dev/fd"; then
            echo "Safety check failed: SSH namespace has unexpected /dev/fd entry." >&2
            exit 1
        else
            sudo nsenter -t "$sshd_pid" -m -- ln -s /proc/self/fd "$CHROOT_DIR/dev/fd"
        fi
    else
        echo "Safety check failed: could not resolve the restricted SSH daemon PID." >&2
        exit 1
    fi
fi

# The main service process and Cloudflare child stay alive. HUP asks its Bash
# supervisor to replace only the loopback gateway child with the validated code.
if systemctl is-active --quiet "$UNIT"; then
    reload_marker="$HOME/.remote-gateway/https-bridge/reload-capable.pid"
    live_main_pid=$(systemctl show -p MainPID --value "$UNIT")
    if [ ! -r "$reload_marker" ] || [ "$(tr -d '\r\n' < "$reload_marker")" != "$live_main_pid" ]; then
        echo "Live supervisor predates hot-reload support; run remote-gateway-start once." >&2
        exit 1
    fi
    sudo systemctl kill --kill-who=main --signal=HUP "$UNIT"
    gateway_ready=0
    for _ in $(seq 1 30); do
        if curl --connect-timeout 1 --max-time 2 --fail --silent http://127.0.0.1:8798/healthz \
            | jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' >/dev/null 2>&1; then
            gateway_ready=1
            break
        fi
        sleep 1
    done
    [ "$gateway_ready" -eq 1 ] || { echo "Live MCP gateway did not return after reload." >&2; exit 1; }
    if [ -n "$bridge_url_before" ]; then
        public_gateway_ready=0
        for _ in $(seq 1 30); do
            if curl --connect-timeout 2 --max-time 4 --fail --silent "$bridge_url_before/healthz" \
                | jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' >/dev/null 2>&1; then
                public_gateway_ready=1
                break
            fi
            sleep 1
        done
        [ "$public_gateway_ready" -eq 1 ] || { echo "Public tunnel did not adopt the reloaded MCP gateway." >&2; exit 1; }
    fi
fi

# A sync must never recycle the public endpoint or its credential material.
bridge_pid_after=""
if systemctl is-active --quiet "$UNIT"; then
    bridge_pid_after=$(systemctl show -p MainPID --value "$UNIT")
fi
if [ -n "$bridge_pid_before" ] && [ "$bridge_pid_after" != "$bridge_pid_before" ]; then
    echo "Safety check failed: live bridge PID changed during sync." >&2
    exit 1
fi
if [ -n "$bridge_url_before" ]; then
    bridge_url_after=$(tr -d '\r\n' < "$HOME/.remote-gateway/https-bridge/url.txt")
    if [ "$bridge_url_after" != "$bridge_url_before" ]; then
        echo "Safety check failed: live bridge URL changed during sync." >&2
        exit 1
    fi
fi

echo "Live bridge helpers synchronized without restarting the tunnel or SSH service."
if [ -n "$bridge_url_before" ]; then
    echo "Endpoint preserved: $bridge_url_before"
fi
echo "Credentials preserved: current token and SSH key were not read or modified."
