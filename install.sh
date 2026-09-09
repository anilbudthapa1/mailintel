#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v python3 >/dev/null; then
  echo 'Python 3.10+ is required. On Kali/Ubuntu: sudo apt-get install python3 python3-venv python3-pip'
  exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
if [ ! -x .venv/bin/python ]; then
  if ! python3 -m venv .venv; then
    echo 'Install venv support: sudo apt-get install python3-venv python3-pip'
    exit 1
  fi
fi
.venv/bin/python -m pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-index --no-deps dist/mailintel_cli-1.4.0-py3-none-any.whl
if [ "${MAILINTEL_NO_LAUNCHER:-0}" != 1 ]; then
mkdir -p "$HOME/.local/bin"
launcher="$HOME/.local/bin/mailintel"
if [ -e "$launcher" ] || [ -L "$launcher" ]; then
  echo 'Existing ~/.local/bin/mailintel left in place. Use ./run.sh for this copy.'
else
  printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$PWD/.venv/bin/mailintel" > "$launcher"
  chmod 700 "$launcher"
fi
fi
printf '\nInstalled. Run ./run.sh doctor, or mailintel if ~/.local/bin is in PATH.\n'
