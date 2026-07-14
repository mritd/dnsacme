#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: task release -- <tag> [--notes-file <path> | --notes <text>]

Examples:
  task release -- v1.2.3
  task release -- v1.2.3 --notes-file /tmp/release.md
  RELEASE_NOTES='AI generated notes' task release -- v1.2.3

Environment:
  RELEASE_NOTES         Release body. Overrides the latest commit message.
  RELEASE_NOTES_FILE    File containing the release body.
  RELEASE_TITLE         Release title. Defaults to '<tag> - <commit subject>'.
  RELEASE_REMOTE        Git remote to tag and publish. Defaults to origin.
EOF
}

die() {
  printf 'release: %s\n' "$*" >&2
  exit 1
}

is_semver_tag() {
  printf '%s\n' "$1" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

tag=${1:-}
if [[ -z "$tag" || "$tag" == "-h" || "$tag" == "--help" ]]; then
  usage
  [[ -n "$tag" ]] && exit 0
  exit 2
fi
shift

notes_file=${RELEASE_NOTES_FILE:-}
notes_text=${RELEASE_NOTES:-}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --notes-file)
      [[ $# -ge 2 ]] || die "--notes-file requires a path"
      notes_file=$2
      notes_text=
      shift 2
      ;;
    --notes)
      [[ $# -ge 2 ]] || die "--notes requires text"
      notes_text=$2
      notes_file=
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

is_semver_tag "$tag" || die "tag must be semantic version such as v1.0.0"

for command_name in git task gh; do
  command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "required SHA256 command not found: sha256sum or shasum"
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$repo_root"

[[ -z "$(git status --porcelain)" ]] || die "working tree must be clean"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated"

remote=${RELEASE_REMOTE:-origin}
git remote get-url "$remote" >/dev/null 2>&1 || die "git remote not found: $remote"

commit=$(git rev-parse HEAD)
subject=$(git log -1 --format=%s)
title=${RELEASE_TITLE:-"$tag - $subject"}

local_commit=$(git rev-list -n 1 "$tag" 2>/dev/null || true)
if [[ -n "$local_commit" && "$local_commit" != "$commit" ]]; then
  die "local tag $tag points to $local_commit, not current commit $commit"
fi

remote_refs=$(git ls-remote "$remote" "refs/tags/$tag" "refs/tags/$tag^{}")
remote_commit=$(printf '%s\n' "$remote_refs" | awk '$2 ~ /\^\{\}$/ { print $1; found=1 } END { if (!found && NR == 1) print first } NR == 1 { first=$1 }')
if [[ -n "$remote_commit" && "$remote_commit" != "$commit" ]]; then
  die "remote tag $tag points to $remote_commit, not current commit $commit"
fi
if gh release view "$tag" >/dev/null 2>&1; then
  die "GitHub release already exists: $tag"
fi

temporary_notes=
cleanup() {
  if [[ -n "$temporary_notes" ]]; then
    rm -f "$temporary_notes"
  fi
}
trap cleanup EXIT

if [[ -n "$notes_file" ]]; then
  [[ -f "$notes_file" ]] || die "release notes file not found: $notes_file"
elif [[ -n "$notes_text" ]]; then
  temporary_notes=$(mktemp "${TMPDIR:-/tmp}/dnsacme-release-notes.XXXXXX")
  printf '%s\n' "$notes_text" > "$temporary_notes"
  notes_file=$temporary_notes
else
  temporary_notes=$(mktemp "${TMPDIR:-/tmp}/dnsacme-release-notes.XXXXXX")
  git log -1 --pretty=%B > "$temporary_notes"
  notes_file=$temporary_notes
fi

printf 'Building release assets for %s at %s\n' "$tag" "$commit"
DNSACME_BUILD_VERSION="$tag" DNSACME_PACKAGE_VERSION="${tag#v}" task release-build
[[ "$(git rev-parse HEAD)" == "$commit" ]] || die "HEAD changed during the build"

checksum_file=build/SHA256SUMS
: > "$checksum_file"
while IFS= read -r asset; do
  (
    cd build
    sha256_file "${asset#build/}"
  ) >> "$checksum_file"
done < <(find build -maxdepth 1 -type f ! -name SHA256SUMS -print | LC_ALL=C sort)
[[ -s "$checksum_file" ]] || die "no build assets were produced"

if [[ -z "$local_commit" ]]; then
  git tag -a "$tag" -m "Release $tag" "$commit"
fi
if [[ -z "$remote_commit" ]]; then
  git push "$remote" "refs/tags/$tag"
fi

assets=()
for asset in build/*; do
  [[ -f "$asset" ]] && assets+=("$asset")
done
[[ ${#assets[@]} -gt 1 ]] || die "release assets are incomplete"

gh release create "$tag" "${assets[@]}" --title "$title" --notes-file "$notes_file" --verify-tag
printf 'Published GitHub release %s with %d assets\n' "$tag" "${#assets[@]}"
