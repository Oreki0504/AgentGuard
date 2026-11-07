#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test "$(uname -sm)" = 'Linux x86_64' || { echo 'Bootstrap requires Linux amd64.' >&2; exit 1; }
include=${SECCOMP_INCLUDE_DIR:-/usr/include}
library=${SECCOMP_STATIC_LIB:-/usr/lib/x86_64-linux-gnu/libseccomp.a}
test -r "$include/seccomp.h" && test -r "$library" || {
  echo 'Install libseccomp-dev, or set SECCOMP_INCLUDE_DIR and SECCOMP_STATIC_LIB to an approved development package.' >&2
  exit 1
}
mkdir -p "$repo/bin"
output=$(mktemp "$repo/bin/.agentguard-bootstrap.XXXXXX")
trap 'rm -f "$output"' EXIT HUP INT TERM
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
  -D_FORTIFY_SOURCE=3 -static-pie -Wl,-z,relro,-z,now,-z,noexecstack \
  -I "$include" "$repo/cmd/agentguard-bootstrap/bootstrap.c" "$library" -o "$output"
sh "$repo/scripts/check-bootstrap.sh" "$output"
chmod 0755 "$output"
mv -f "$output" "$repo/bin/agentguard-bootstrap"
