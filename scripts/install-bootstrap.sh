#!/bin/sh
set -eu
# Installs the independent C artifact without reloading AppArmor.
# Run only after operator approval.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test "$(id -u)" -eq 0 || { echo 'Bootstrap installation requires a host administrator.' >&2; exit 1; }
test -f "$repo/bin/agentguard-bootstrap" && test ! -L "$repo/bin/agentguard-bootstrap"
install -d -o root -g root -m 0755 /usr/local/libexec
temporary=$(mktemp /usr/local/libexec/.agentguard-bootstrap.XXXXXX)
trap 'rm -f "$temporary"' EXIT HUP INT TERM
# Same root-owned installation convention as the launcher. Validate the copied
# artifact so a changed build output cannot bypass the ELF check.
install -o root -g root -m 0755 "$repo/bin/agentguard-bootstrap" "$temporary"
sh "$repo/scripts/check-bootstrap.sh" "$temporary"
mv -f "$temporary" /usr/local/libexec/agentguard-bootstrap
