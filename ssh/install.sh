#!/usr/bin/env bash
# Provision the dedicated, restricted SSH service. Run as centos with passwordless sudo.
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR=/etc/claude-remote
LIBEXEC_DIR=/usr/local/libexec
CHROOT_DIR=/srv/claude-remote
KEY_DIR=/home/centos/.remote-gateway/ssh

sudo -n true

for account in claude-sync claude-mcp claude-playwright claude-shell; do
    if ! getent passwd "$account" >/dev/null; then
        sudo /usr/sbin/useradd --system --create-home --home-dir "/var/lib/$account" --shell /bin/bash "$account"
    fi
    # SSH only accepts a public key and disallows empty passwords, but OpenSSH
    # rejects a Unix account marked as locked before it even checks that key.
    sudo passwd -d "$account" >/dev/null
done

# Let the SFTP-only identity traverse centos's private home. It can write only
# projects; skills and agents are read-only. ACLs preserve local ownership and
# grant matching defaults to files and directories created later.
sudo setfacl -m u:claude-sync:--x /home/centos
sudo setfacl -m u:claude-sync:--x /home/centos/.claude
sudo setfacl -R -m u:claude-sync:rwX /home/centos/data/projects
sudo find /home/centos/data/projects -type d -exec setfacl -m d:u:claude-sync:rwX,d:m::rwx {} +
for readonly_dir in /home/centos/.claude/skills /home/centos/.claude/agents; do
    sudo setfacl -R -m u:claude-sync:rX "$readonly_dir"
    sudo find "$readonly_dir" -type d -exec setfacl -m d:u:claude-sync:rX,d:m::r-x {} +
done
# The shell identity receives write access only to projects. Skills and agents
# are mounted read-only in its namespace and have only read/traverse ACLs.
sudo setfacl -R -m u:claude-shell:rwX /home/centos/data/projects
sudo find /home/centos/data/projects -type d -exec setfacl -m d:u:claude-shell:rwX,d:m::rwx {} +
for readonly_dir in /home/centos/.claude/skills /home/centos/.claude/agents; do
    sudo setfacl -R -m u:claude-shell:rX "$readonly_dir"
    sudo find "$readonly_dir" -type d -exec setfacl -m d:u:claude-shell:rX,d:m::rwx {} +
done

sudo install -d -o root -g root -m 0755 "$CONFIG_DIR" "$CONFIG_DIR/authorized_keys" "$LIBEXEC_DIR" "$CHROOT_DIR"
# Ephemeral bridge credentials are appended by start-test.sh.  Create the
# root-owned file here so re-provisioning cannot accidentally make it writable
# by the restricted identity.
if [ ! -e "$CONFIG_DIR/authorized_keys/claude-playwright" ]; then
    sudo install -o root -g root -m 0644 /dev/null "$CONFIG_DIR/authorized_keys/claude-playwright"
fi
for mount_point in "$CHROOT_DIR/projects" "$CHROOT_DIR/skills" "$CHROOT_DIR/agents"; do
    # Once mounted read-only, install(1) cannot (and must not) chmod/chown it.
    if [ ! -d "$mount_point" ]; then
        sudo install -d -o root -g root -m 0755 "$mount_point"
    fi
done
# These must be executable by their two unprivileged service identities. Their
# behavior is secured by the immutable root-owned allowlist and sudo rule.
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_mcp_launcher.py" "$LIBEXEC_DIR/claude-mcp-launch"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_playwright_launcher.py" "$LIBEXEC_DIR/claude-playwright-launch"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_playwright_original.py" "$LIBEXEC_DIR/claude-playwright-original"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_mcp_runner.py" "$LIBEXEC_DIR/claude-mcp-runner"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_shell_launcher.py" "$LIBEXEC_DIR/claude-shell-launch"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_shell_runner.py" "$LIBEXEC_DIR/claude-shell-runner"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_shell_mounts.sh" "$LIBEXEC_DIR/claude-shell-mounts"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_nlm_broker.py" "$LIBEXEC_DIR/claude-nlm-broker"
sudo install -o root -g root -m 0755 "$SOURCE_DIR/claude_nlm_client.py" "$LIBEXEC_DIR/claude-nlm-client"
sudo install -o root -g root -m 0644 "$SOURCE_DIR/claude-nlm.tmpfiles.conf" /usr/lib/tmpfiles.d/claude-nlm.conf
# This registry contains no credentials. It is readable so the runner, which
# deliberately executes as centos, can load it; only root can modify it.
sudo install -o root -g root -m 0644 "$SOURCE_DIR/mcp-allowlist.json" "$CONFIG_DIR/mcp-allowlist.json"
sudo install -o root -g root -m 0600 "$SOURCE_DIR/sshd_config" "$CONFIG_DIR/sshd_config"
sudo install -o root -g root -m 0440 "$SOURCE_DIR/claude-mcp.sudoers" /etc/sudoers.d/claude-mcp
sudo install -o root -g root -m 0440 "$SOURCE_DIR/claude-playwright.sudoers" /etc/sudoers.d/claude-playwright
sudo install -o root -g root -m 0440 "$SOURCE_DIR/claude-shell.sudoers" /etc/sudoers.d/claude-shell

if [ ! -f "$CONFIG_DIR/ssh_host_ed25519_key" ]; then
    sudo ssh-keygen -q -t ed25519 -N '' -f "$CONFIG_DIR/ssh_host_ed25519_key"
fi
sudo chmod 0600 "$CONFIG_DIR/ssh_host_ed25519_key"
sudo chmod 0644 "$CONFIG_DIR/ssh_host_ed25519_key.pub"

install -d -m 0700 "$KEY_DIR"
for account in claude-sync claude-mcp; do
    private_key="$KEY_DIR/${account}_ed25519"
    if [ ! -f "$private_key" ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$private_key" -C "${account}@$(hostname -s)"
    fi
    chmod 0600 "$private_key"
    chmod 0644 "${private_key}.pub"
    sed 's/^/restrict /' "${private_key}.pub" | sudo tee "$CONFIG_DIR/authorized_keys/$account" >/dev/null
    sudo chown root:root "$CONFIG_DIR/authorized_keys/$account"
    # sshd reads AuthorizedKeysFile after dropping privileges. Public keys are
    # intentionally non-secret; root ownership prevents either restricted user
    # from replacing its own authorization file.
    sudo chmod 0644 "$CONFIG_DIR/authorized_keys/$account"
done

for name in projects skills agents; do
    unit_name="srv-claude\\x2dremote-${name}.mount"
    sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/${name}.mount" "/etc/systemd/system/$unit_name"
done
sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/claude-remote-sshd.service" /etc/systemd/system/claude-remote-sshd.service
sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/claude-shell-sandbox.service" /etc/systemd/system/claude-shell-sandbox.service
sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/claude-nlm-broker.service" /etc/systemd/system/claude-nlm-broker.service
sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/claude-nlm-broker.socket" /etc/systemd/system/claude-nlm-broker.socket

sudo visudo -cf /etc/sudoers.d/claude-mcp
sudo visudo -cf /etc/sudoers.d/claude-playwright
sudo visudo -cf /etc/sudoers.d/claude-shell
sudo /usr/sbin/sshd -t -f "$CONFIG_DIR/sshd_config"
sudo systemctl daemon-reload
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/claude-nlm.conf
sudo systemctl disable claude-nlm-broker.service >/dev/null 2>&1 || true
if ! systemctl is-active --quiet claude-nlm-broker.socket; then
    # Safe upgrade from the older process-owned socket design.
    sudo systemctl stop claude-nlm-broker.service >/dev/null 2>&1 || true
    if [ -S /run/claude-nlm/nlm-v2.sock ]; then
        sudo rm -f /run/claude-nlm/nlm-v2.sock
    fi
fi
sudo systemctl enable --now claude-nlm-broker.socket
sudo systemctl enable claude-shell-sandbox.service
sudo systemctl restart claude-shell-sandbox.service
sudo systemctl enable srv-claude\\x2dremote-projects.mount srv-claude\\x2dremote-skills.mount srv-claude\\x2dremote-agents.mount
sudo systemctl stop claude-remote-sshd.service
sudo systemctl restart srv-claude\\x2dremote-projects.mount srv-claude\\x2dremote-skills.mount srv-claude\\x2dremote-agents.mount
sudo systemctl enable claude-remote-sshd.service
sudo systemctl restart claude-remote-sshd.service

echo "Restricted SSH service is listening on TCP port 2223."
echo "Private client keys (do not copy into chat):"
echo "  $KEY_DIR/claude-sync_ed25519"
echo "  $KEY_DIR/claude-mcp_ed25519"
