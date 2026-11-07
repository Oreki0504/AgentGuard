#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
mkdir -p bin/bootstrap-validation
# Test entry points are compiled only into this test artifact. No production
# build tag, environment switch or alternate launcher entry is introduced.
CGO_ENABLED=0 go test -c -o bin/agentguard-phase2c-probe ./internal/runtime/sandbox/linux
# Derive the probe attachment from the same policy installed in production.
sed 's@/usr/local/libexec/agentguard-launcher@/usr/local/libexec/agentguard-phase2c-probe@g' \
  contrib/apparmor/agentguard-launcher > bin/bootstrap-validation/phase2c-probe.apparmor
apparmor_parser -Q -K bin/bootstrap-validation/phase2c-probe.apparmor
