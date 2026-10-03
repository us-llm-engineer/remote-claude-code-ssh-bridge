#!/usr/bin/env bash
set -euo pipefail

ROOT=/srv/claude-shell-root
CUDA_ROOT=/usr/local/cuda-12.9
PY312_SITE=/home/centos/.local/lib/python3.12/site-packages
NSIGHT_COMPUTE_ROOT=/opt/nvidia/nsight-compute
mkdir -p "$ROOT"/{usr,bin,lib,lib64,proc,dev,tmp,run/claude-nlm,etc/ssl,etc/pki/tls,etc/pki/ca-trust,opt/tools/bin,opt/bridge-tools/bin,opt/python-site,opt/vcpkg,workspace/projects,workspace/skills,workspace/agents}
mkdir -p "$ROOT/etc/pki/tls/certs" "$ROOT/opt/python-site/cmake"
[ -e "$ROOT/etc/resolv.conf" ] || : > "$ROOT/etc/resolv.conf"
# Git runs as the restricted UID while the approved project bind is owned by
# the host user. Provide a root-owned chroot system config which trusts only
# repositories below that bind; never import host Git configuration or secrets.
install -o root -g root -m 0644 /usr/local/libexec/claude-shell.gitconfig "$ROOT/etc/gitconfig"

mount_bind() {
    local source=$1 target=$2 mode=$3
    if ! mountpoint -q "$target"; then mount --bind "$source" "$target"; fi
    if [ "$mode" = ro ]; then mount -o remount,bind,ro "$target"; fi
}

for path in /usr /bin /lib /lib64; do [ -e "$path" ] && mount_bind "$path" "$ROOT$path" ro; done
# WSL exposes NVIDIA's runtime files through a nested mount. Re-bind it after
# /usr so the chroot sees the populated mount rather than its empty directory.
[ -d /usr/lib/wsl/lib ] && mount_bind /usr/lib/wsl/lib "$ROOT/usr/lib/wsl/lib" ro
[ -d /usr/lib/wsl/drivers ] && mount_bind /usr/lib/wsl/drivers "$ROOT/usr/lib/wsl/drivers" ro
mount_bind /home/centos/data/projects "$ROOT/workspace/projects" rw
mount_bind /home/centos/.claude/skills "$ROOT/workspace/skills" ro
mount_bind /home/centos/.claude/agents "$ROOT/workspace/agents" ro
# The NotebookLM bridge is a local Unix socket, not a network listener.  Only
# the socket enters the chroot; its host CLI and authentication state do not.
install -d -o centos -g claude-shell -m 0750 /run/claude-nlm
mount_bind /run/claude-nlm "$ROOT/run/claude-nlm" ro

# Developer-toolchain profile: specific host-managed build tools and packages,
# never the user's home directory. Extend this list deliberately per tool.
mount_bind /home/centos/.local/bin "$ROOT/opt/tools/bin" ro
# Keep toolchain shims outside the user-mounted tool directory.  In the host
# namespace /usr/bin/ld is an alternatives symlink whose target lives under
# /etc; that path is deliberately not exposed in this chroot.  Point directly
# at the real linker instead of exposing the host alternatives tree.
chown root:root "$ROOT/opt/bridge-tools" "$ROOT/opt/bridge-tools/bin"
chmod 0755 "$ROOT/opt/bridge-tools" "$ROOT/opt/bridge-tools/bin"
rm -f "$ROOT/opt/bridge-tools/bin/ld" "$ROOT/opt/bridge-tools/bin/ld.bfd" "$ROOT/opt/bridge-tools/bin/ld.gold"
ln -s /usr/bin/ld.bfd "$ROOT/opt/bridge-tools/bin/ld"
ln -s /usr/bin/ld.bfd "$ROOT/opt/bridge-tools/bin/ld.bfd"
ln -s /usr/bin/ld.gold "$ROOT/opt/bridge-tools/bin/ld.gold"
install -o root -g root -m 0755 /usr/local/libexec/claude-nlm-client "$ROOT/opt/bridge-tools/bin/nlm-v2"
# CMake's Python entry points require both its module and distribution metadata.
# Mount only those public package directories, not the private site-packages tree.
CMAKE_SITE=/home/centos/.local/lib/python3.9/site-packages
CMAKE_METADATA=$(find "$CMAKE_SITE" -maxdepth 1 -type d -name 'cmake-*.dist-info' -print -quit)
umount "$ROOT/opt/python-site/cmake" 2>/dev/null || true
umount "$ROOT/opt/python-site" 2>/dev/null || true
mkdir -p "$ROOT/opt/python-site/cmake"
mount_bind "$CMAKE_SITE/cmake" "$ROOT/opt/python-site/cmake" ro
if [ -n "$CMAKE_METADATA" ]; then
    mkdir -p "$ROOT/opt/python-site/${CMAKE_METADATA##*/}"
    mount_bind "$CMAKE_METADATA" "$ROOT/opt/python-site/${CMAKE_METADATA##*/}" ro
fi
mount_bind /home/centos/vcpkg/installed/x64-linux "$ROOT/opt/vcpkg" ro

# Network profile: DNS and CA data only. It shares host networking without
# exposing host configuration generally.
[ -e /etc/resolv.conf ] && mount_bind /etc/resolv.conf "$ROOT/etc/resolv.conf" ro
[ -d /etc/pki/ca-trust ] && mount_bind /etc/pki/ca-trust "$ROOT/etc/pki/ca-trust" ro
[ -d /etc/pki/tls/certs ] && mount_bind /etc/pki/tls/certs "$ROOT/etc/pki/tls/certs" ro
mountpoint -q "$ROOT/proc" || mount -t proc proc "$ROOT/proc"
mountpoint -q "$ROOT/dev" || mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$ROOT/dev"
# Programs commonly use /dev/fd/N for already-open streams. It is a view of
# this chroot process's own procfs descriptors, not a bind of the host's /dev.
if [ -L "$ROOT/dev/fd" ]; then
    [ "$(readlink "$ROOT/dev/fd")" = /proc/self/fd ] || { echo "unsafe $ROOT/dev/fd" >&2; exit 1; }
elif [ -e "$ROOT/dev/fd" ]; then
    echo "unsafe $ROOT/dev/fd" >&2
    exit 1
else
    ln -s /proc/self/fd "$ROOT/dev/fd"
fi
if mountpoint -q "$ROOT/tmp"; then
    mount -o remount,size=4G,mode=1777,nosuid,nodev "$ROOT/tmp"
else
    mount -t tmpfs -o size=4G,mode=1777,nosuid,nodev tmpfs "$ROOT/tmp"
fi
for device in null zero random urandom; do
    [ -e "$ROOT/dev/$device" ] || : > "$ROOT/dev/$device"
    mount_bind "/dev/$device" "$ROOT/dev/$device" rw
done

# WSL exposes the NVIDIA GPU through this one device. No other host device is
# mounted in the chroot. The WSL driver libraries are already covered by the
# read-only /usr bind; mount the CUDA toolkit separately and read-only.
if [ -e /dev/dxg ]; then
    [ -e "$ROOT/dev/dxg" ] || : > "$ROOT/dev/dxg"
    mount_bind /dev/dxg "$ROOT/dev/dxg" rw
fi
if [ -d "$CUDA_ROOT" ]; then
    mkdir -p "$ROOT/opt/cuda"
    mount_bind "$CUDA_ROOT" "$ROOT/opt/cuda" ro
fi
# The host's CUDA-enabled Python 3.12 packages (torch, numpy, ...), read-only.
# It is the user site of PYTHONUSERBASE=/opt/pyuser in the runner, so only
# python3.12 picks it up; pip --user cannot write to it.
if [ -d "$PY312_SITE" ]; then
    mkdir -p "$ROOT/opt/pyuser/lib/python3.12/site-packages"
    mount_bind "$PY312_SITE" "$ROOT/opt/pyuser/lib/python3.12/site-packages" ro
fi
# ncu is a CUDA launcher; its versioned profiler runtime lives separately.
# Expose only that host-managed tree and keep it read-only.
if [ -d "$NSIGHT_COMPUTE_ROOT" ]; then
    mkdir -p "$ROOT/opt/nvidia/nsight-compute"
    mount_bind "$NSIGHT_COMPUTE_ROOT" "$ROOT/opt/nvidia/nsight-compute" ro
fi
