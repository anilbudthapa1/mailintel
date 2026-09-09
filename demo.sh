#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [ ! -x .venv/bin/mailintel ]; then bash install.sh; fi
workspace=$(mktemp -d "${TMPDIR:-/tmp}/mailintel-training.XXXXXXXX")
cli=(.venv/bin/mailintel --data-dir "$workspace/data")
case_id=$("${cli[@]}" case new --name 'MailIntel fictional training')
"${cli[@]}" scan email 'student@example.com' --case "$case_id" --profile offline > "$workspace/scan.log"
"${cli[@]}" mailbox examples/training.mbox --case "$case_id" > "$workspace/mailbox.log"
"${cli[@]}" extract examples/contacts.txt --case "$case_id" > "$workspace/extract.log"
"${cli[@]}" import-claims examples/claims.json --case "$case_id" > "$workspace/claims.log"
"${cli[@]}" dmarc examples/dmarc.xml --case "$case_id" > "$workspace/dmarc.log"
"${cli[@]}" patterns examples/names.csv --case "$case_id" > "$workspace/patterns.log"
"${cli[@]}" insights --case "$case_id" > "$workspace/insights.json"
"${cli[@]}" graph --case "$case_id" --out "$workspace/graph"
"${cli[@]}" report --case "$case_id" --out "$workspace/report"
"${cli[@]}" redact --case "$case_id" --out "$workspace/redacted"
"${cli[@]}" bundle --case "$case_id" --out "$workspace/evidence.zip"
"${cli[@]}" verify --case "$case_id"
printf '\nOffline training complete. Open %s/report/report.html\nGraph: %s/graph/graph.html\n' "$workspace" "$workspace"
