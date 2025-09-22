#!/usr/bin/env sh
set -eu
exec nsenter -t 1 -n -- "$@"
