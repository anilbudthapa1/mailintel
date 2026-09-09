#!/usr/bin/env bash
set -euo pipefail
if ! command -v uv >/dev/null; then
  echo 'Install uv from https://docs.astral.sh/uv/getting-started/installation/ then rerun this script.'
  exit 1
fi
# Separate tool environment; this download includes third-party code and Python 3.14.
uv tool install --python 3.14 --from 'git+https://github.com/laramies/theHarvester.git@78a78f08d4a0d6d9bf6058effa8ddafb9e2d070b' theHarvester
uv tool update-shell
printf '\nOpen a new terminal so theHarvester is on PATH. Hunter source keys are managed by theHarvester itself.\n'
