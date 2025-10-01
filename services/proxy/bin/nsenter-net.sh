#!/usr/bin/env bash
set -euo pipefail
exec nsenter -t 1 -n -- "$@"

