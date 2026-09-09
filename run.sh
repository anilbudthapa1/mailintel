#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [ ! -x .venv/bin/mailintel ]; then bash install.sh; fi
exec .venv/bin/mailintel "$@"
