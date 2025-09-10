#!/usr/bin/env bash
set -euo pipefail
exec nsenter --net=/proc/1/ns/net -- python -m handler.app
