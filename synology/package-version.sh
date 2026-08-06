#!/bin/sh

set -eu

ROOT=${1:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}

# Keep git describe's ancestry-aware tag selection, but skip tags that cannot
# be represented as Synology package versions. Both vX.Y.Z and X.Y.Z are valid.
find_release_tag() {
  while release_tag=$(git -C "$ROOT" describe --tags --abbrev=0 "$@" 2>/dev/null); do
    release_base=${release_tag#v}
    if printf '%s' "$release_base" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
      printf '%s\n' "$release_tag"
      return 0
    fi
    set -- "$@" --exclude "$release_tag"
  done
  return 1
}

release_tag=$(find_release_tag || true)
if [ -z "$release_tag" ]; then
  exit 0
fi

release_base=${release_tag#v}
commits_ahead=$(git -C "$ROOT" rev-list "${release_tag}..HEAD" --count)
if [ "$commits_ahead" -gt 0 ]; then
  printf '%s-%s\n' "$release_base" "$commits_ahead"
else
  printf '%s\n' "$release_base"
fi
