#!/bin/sh
set -eu
# Run after: go build -o bin/agentguard-launcher ./cmd/agentguard-launcher
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test "$(id -u)" -eq 0 || { echo 'Run this installation script with sudo.' >&2; exit 1; }
test -x "$repo/bin/agentguard-launcher"
apparmor_parser -Q -K "$repo/contrib/apparmor/agentguard-launcher"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$repo/bin/agentguard-launcher" /usr/local/libexec/agentguard-launcher.new
install -o root -g root -m 0644 "$repo/contrib/apparmor/agentguard-launcher" /etc/apparmor.d/agentguard-launcher
apparmor_parser -r /etc/apparmor.d/agentguard-launcher
mv -f /usr/local/libexec/agentguard-launcher.new /usr/local/libexec/agentguard-launcher
