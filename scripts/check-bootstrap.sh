#!/bin/sh
set -eu
test "$#" -eq 1 || { echo 'usage: check-bootstrap.sh ELF' >&2; exit 1; }
export LC_ALL=C
# Check the resulting ELF, not just compiler options. Never execute the input.
header=$(readelf -hW "$1")
program=$(readelf -lW "$1")
dynamic=$(readelf -dW "$1")
printf '%s\n' "$header" | grep -Eq 'Class: +ELF64$'
printf '%s\n' "$header" | grep -Eq 'Data: +2.s complement, little endian$'
printf '%s\n' "$header" | grep -Eq 'Type: +DYN '
printf '%s\n' "$header" | grep -Eq 'Machine: +Advanced Micro Devices X86-64$'
if printf '%s\n' "$program" | grep -q ' INTERP '; then
  echo 'Bootstrap must not have a dynamic interpreter.' >&2; exit 1
fi
if printf '%s\n' "$dynamic" | grep -Eq '\((NEEDED|TEXTREL)\)'; then
  echo 'Bootstrap must not have shared dependencies or text relocations.' >&2; exit 1
fi
printf '%s\n' "$program" | grep -Eq ' GNU_STACK .* RW +0x'
printf '%s\n' "$program" | grep -q ' GNU_RELRO '
printf '%s\n' "$dynamic" | grep -Eq '\(FLAGS\).*BIND_NOW'
printf '%s\n' "$dynamic" | grep -Eq '\(FLAGS_1\).*PIE'
