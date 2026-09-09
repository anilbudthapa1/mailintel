#!/usr/bin/env bash
# Prepare or publish the reviewed MailIntel 1.4.0 snapshot into a NEW GitHub repo.
set -euo pipefail
umask 077
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=''
visibility=private
publish=0
release=0
output=''
usage() {
  cat <<'HELP'
Usage:
  bash upload_github.sh --repo OWNER/REPOSITORY [options]

Default: local preparation only. No GitHub API calls or upload.

Options:
  --repo OWNER/REPOSITORY   Destination NEW repository on github.com (required)
  --visibility private|public  Default: private
  --publish                Create repository and push main and tag v1.4.0
  --release                Also publish a GitHub release with ZIP and checksum
                           Requires --publish
  --output PATH            New persistent staging directory; must not exist
                           Default: a new temporary directory printed at the end
  --help                   Print help

Requires bash, python3 and git. Publishing also requires authenticated gh.
Only files in PUBLISH_MANIFEST.sha256 are copied after checksum verification.
The source directory, existing repositories and global git config are not changed.
HELP
}
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo|--visibility|--output)
      [ "$#" -ge 2 ] || fail "Missing value for $1"
      case "$1" in --repo) repo=$2;; --visibility) visibility=$2;; --output) output=$2;; esac
      shift 2 ;;
    --publish) publish=1; shift ;;
    --release) release=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done
[[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'Use --repo OWNER/REPOSITORY, not a URL.'
[ "$visibility" = private ] || [ "$visibility" = public ] || fail 'Visibility must be private or public.'
[ "$release" -eq 0 ] || [ "$publish" -eq 1 ] || fail '--release requires --publish.'
for dependency in python3 git; do command -v "$dependency" >/dev/null || fail "Install $dependency first."; done
[ -f "$source_dir/PUBLISH_MANIFEST.sha256" ] || fail 'Missing manifest. Extract the complete GitHub-ready package.'
if [ "$publish" -eq 1 ]; then
  command -v gh >/dev/null || fail 'Install GitHub CLI (gh) first.'
  export GH_HOST=github.com
  gh auth status --hostname github.com >/dev/null 2>&1 || fail 'Authenticate first: gh auth login --hostname github.com --git-protocol https --web'
fi
if [ -n "$output" ]; then
  [ ! -e "$output" ] && [ ! -L "$output" ] || fail 'Output already exists; choose a new path.'
  mkdir -- "$output"
  staging=$(cd -- "$output" && pwd -P)
else
  staging=$(mktemp -d "${TMPDIR:-/tmp}/mailintel-github.XXXXXXXX")
fi
printf 'Preparing %s for %s (%s).\n' "$staging" "$repo" "$visibility"
# Never glob-copy the working directory or reuse its Git history.
python3 - "$source_dir" "$staging" <<'PY'
import hashlib, pathlib, re, shutil, sys, zipfile
root=pathlib.Path(sys.argv[1]).resolve(); output=pathlib.Path(sys.argv[2]).resolve()
manifest=root/'PUBLISH_MANIFEST.sha256'
if manifest.is_symlink():raise SystemExit('Manifest must not be a symlink.')
files=[];seen=set()
for line in manifest.read_text().splitlines():
    match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
    if not match:raise SystemExit('Invalid manifest line.')
    expected,name=match.groups();rel=pathlib.PurePosixPath(name)
    if rel.is_absolute() or any(x in ('..','.') for x in rel.parts) or '\\' in name or name.startswith('-'):
        raise SystemExit('Unsafe manifest path.')
    if name in seen:raise SystemExit('Duplicate manifest path.')
    seen.add(name)
    if any(x in ('.git','.venv','__pycache__') or x.startswith('.env') for x in rel.parts):raise SystemExit('Forbidden manifest path.')
    src=root/name
    if any((root.joinpath(*rel.parts[:i])).is_symlink() for i in range(1,len(rel.parts)+1)):
        raise SystemExit('Symlink rejected: '+name)
    if not src.is_file() or not src.resolve().is_relative_to(root):raise SystemExit('Missing or unsafe source: '+name)
    if src.stat().st_size>50*1024*1024:raise SystemExit('Unexpected large file: '+name)
    raw=src.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('File differs from reviewed snapshot: '+name+'; use an untouched release copy.')
    files.append((name,raw))
required={'README.md','upload_github.sh','pyproject.toml','install.sh','requirements.lock','dist/mailintel_cli-1.4.0-py3-none-any.whl'}
if not required.issubset(seen):raise SystemExit('Manifest missing required release files.')
for name,raw in files:
    dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
    dst.chmod(0o755 if name.endswith('.sh') else 0o644)
shutil.copyfile(manifest,output/manifest.name)
print(f'Verified and copied {len(files)} files plus manifest. Unlisted files excluded.')
PY
git -C "$staging" init -b main >/dev/null
git -C "$staging" add --all
printf '\nFiles prepared for GitHub:\n'
git -C "$staging" diff --cached --stat
if [ "$publish" -eq 0 ]; then
  printf '\nPreparation complete. Nothing uploaded. Review: %s\n' "$staging"
  printf 'Run this script again with --publish to create the repository; use a new --output path or omit it.\n'
  exit 0
fi
# Use the authenticated GitHub identity without changing global author settings.
login=$(gh api user --jq .login)
user_id=$(gh api user --jq .id)
[[ "$login" =~ ^[A-Za-z0-9-]+$ && "$user_id" =~ ^[0-9]+$ ]] || fail 'Could not resolve GitHub account identity.'
git -C "$staging" -c user.name="$login" -c user.email="${user_id}+${login}@users.noreply.github.com" commit -m 'Release MailIntel v1.4.0' >/dev/null
git -C "$staging" tag v1.4.0
# Repo creation fails for an existing name. No force pushes, merges or deletion.
gh repo create "$repo" "--$visibility" --source "$staging" --remote origin \
  --description 'Email OSINT and evidence-analysis CLI for Linux; MailIntel v1.4.0'
git -C "$staging" remote set-url origin "https://github.com/$repo.git"
git -C "$staging" config --local credential.https://github.com.helper ''
git -C "$staging" config --local --add credential.https://github.com.helper '!gh auth git-credential'
git -C "$staging" push --set-upstream origin main
git -C "$staging" push origin refs/tags/v1.4.0
if [ "$release" -eq 1 ]; then
  assets=$(mktemp -d "${TMPDIR:-/tmp}/mailintel-release.XXXXXXXX")
  # Build the download strictly from committed files, not the staging working tree.
  git -C "$staging" archive --format=zip --prefix=mailintel-v1.4/ \
    --output="$assets/MailIntel-v1.4.0-linux.zip" v1.4.0
  python3 - "$assets" <<'PY'
import hashlib,pathlib,sys
root=pathlib.Path(sys.argv[1]);p=root/'MailIntel-v1.4.0-linux.zip'
(root/'MailIntel-v1.4.0-linux.zip.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
PY
  gh release create v1.4.0 --repo "$repo" --verify-tag --title 'MailIntel v1.4.0' \
    --notes-file "$staging/RELEASE_NOTES.md" \
    "$assets/MailIntel-v1.4.0-linux.zip" "$assets/MailIntel-v1.4.0-linux.zip.sha256"
  printf 'Release assets retained at: %s\n' "$assets"
fi
printf '\nUploaded: https://github.com/%s\nLocal Git checkout: %s\n' "$repo" "$staging"
