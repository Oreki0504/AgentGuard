#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test "$(id -u)" -ne 0 || { echo 'Run Bootstrap unit tests as a non-root user.' >&2; exit 1; }
include=${SECCOMP_INCLUDE_DIR:-/usr/include}
library=${SECCOMP_STATIC_LIB:-/usr/lib/x86_64-linux-gnu/libseccomp.a}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
cd "$repo"
sh scripts/check-bootstrap.sh bin/agentguard-bootstrap
if sh scripts/check-bootstrap.sh /bin/sh; then
  echo 'ELF checker accepted a dynamic executable.' >&2; exit 1
fi
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=3 -I "$include" cmd/agentguard-bootstrap/bootstrap_test.c \
  "$library" -Wl,--wrap=prctl,--wrap=seccomp_load -o "$temporary/bootstrap-test"
CGO_ENABLED=0 go build -o "$temporary/go-guest" ./cmd/agentguard-bootstrap/testdata/guest.go
"$temporary/bootstrap-test" "$temporary/go-guest"
# The actual artifact has no export/fault-injection/test bypass modes.
set +e
env -i bin/agentguard-bootstrap > "$temporary/stdout" 2> "$temporary/stderr"
result=$?
set -e
test "$result" -eq 125
test ! -s "$temporary/stdout"
grep -qx 'agentguard-bootstrap: invocation' "$temporary/stderr"
