#!/usr/bin/env bash
set -euo pipefail

min="${1:-90}"

total="$(
  go tool cover -func=coverage.out \
    | awk '$1 == "total:" { print $3 }' \
    | tr -d '%'
)"

if [[ -z "${total}" ]]; then
  echo "failed to parse coverage" >&2
  exit 1
fi

awk -v total="${total}" -v min="${min}" 'BEGIN {
  if (total + 0 < min + 0) {
    printf("coverage %.1f%% < %d%%\n", total, min) > "/dev/stderr";
    exit 1;
  }
  printf("coverage %.1f%% >= %d%%\n", total, min);
}'

