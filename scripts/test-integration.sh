#!/bin/sh
set -eu
# Invoke inside: systemd-run --user --scope -p Delegate=yes -- sh scripts/test-integration.sh
# A delegated scope starts populated, so move this process into a manager leaf
# before enabling controllers for the sibling Workload cgroups.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AGENTGUARD_LAUNCHER=${AGENTGUARD_LAUNCHER:-/usr/local/libexec/agentguard-launcher}
export AGENTGUARD_LAUNCHER
# Reject stale or missing installed artifacts before changing any cgroup state.
cmp "$repo/bin/agentguard-launcher" "$AGENTGUARD_LAUNCHER"
cmp "$repo/bin/agentguard-bootstrap" /usr/local/libexec/agentguard-bootstrap
if [ -z "${AGENTGUARD_CGROUP_ROOT:-}" ]; then
  scope=$(sed -n 's/^0:://p' /proc/self/cgroup)
  case "$scope" in */run-*.scope) ;; *) echo 'Use a dedicated systemd-run --user --scope -p Delegate=yes scope.' >&2; exit 1;; esac
  AGENTGUARD_CGROUP_ROOT=/sys/fs/cgroup$scope
  mkdir "$AGENTGUARD_CGROUP_ROOT/manager"
  read -r manager_pid ignored < /proc/self/stat
  printf '%s\n' "$manager_pid" > "$AGENTGUARD_CGROUP_ROOT/manager/cgroup.procs"
  printf '+cpu +memory +pids\n' > "$AGENTGUARD_CGROUP_ROOT/cgroup.subtree_control"
  export AGENTGUARD_CGROUP_ROOT
fi
cd "$repo"
exec go test ./... -count=1 -v "$@"
