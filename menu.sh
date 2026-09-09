#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
while true; do
  printf '\nMailIntel 1.4\n1) Offline training demo\n2) Create case\n3) List cases\n4) Analyse EML/MBOX\n5) Extract document emails\n6) Offline email scan\n7) Export report\n8) Show all commands\n0) Exit\n'
  read -r -p 'Choose: ' choice || exit 0
  case "$choice" in
    1) bash demo.sh ;;
    2) read -r -p 'Case name: ' name; bash run.sh case new --name "$name" ;;
    3) bash run.sh case list ;;
    4|5) read -r -p 'Case ID: ' cid; read -r -p 'File path: ' file; command=mailbox; [ "$choice" = 5 ] && command=extract; bash run.sh "$command" "$file" --case "$cid" || true ;;
    6) read -r -p 'Case ID: ' cid; read -r -p 'Email: ' address; bash run.sh scan email "$address" --case "$cid" --profile offline || true ;;
    7) read -r -p 'Case ID: ' cid; read -r -p 'New output directory: ' out; bash run.sh report --case "$cid" --out "$out" || true ;;
    8) bash run.sh --help ;;
    0) exit 0 ;;
    *) echo 'Choose 0–8.' ;;
  esac
done
