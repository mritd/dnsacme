#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OUT_ARG=${1:-build}
OUT=$OUT_ARG
BUILD_VERSION=${DNSACME_BUILD_VERSION:-$(git -C "$ROOT" rev-parse HEAD)}
PACKAGE_VERSION=${DNSACME_PACKAGE_VERSION:-}

case "$OUT" in
  /*) ;;
  *) OUT="$ROOT/$OUT" ;;
esac

mkdir -p "$OUT"

build_pkg() (
  arch=$1
  goamd64=$2
  dsm_arch=$3
  work=$(mktemp -d "$OUT/.dnsacme-synology-${arch}.XXXXXX")
  pkg="$OUT/dnsacme-synology-${arch}.spk"
  display_pkg="${OUT_ARG%/}/dnsacme-synology-${arch}.spk"

  cleanup() {
    rm -rf "$work"
  }
  trap cleanup 0
  trap 'exit 1' 1 2 15

  mkdir -p "$work/package/bin" "$work/package/scripts" "$work/package/ui" "$work/conf"
  GOOS=linux GOARCH="$arch" GOAMD64="$goamd64" CGO_ENABLED=0 \
    go build -tags synology -trimpath -ldflags "-s -w -X main.commit=${BUILD_VERSION}" -o "$work/package/bin/dnsacme" "$ROOT"

  cp -R "$ROOT/synology/spk/conf/." "$work/conf/"
  if [ -n "$PACKAGE_VERSION" ]; then
    sed -e "s/^arch=.*/arch=\"${dsm_arch}\"/" \
      -e "s/^version=.*/version=\"${PACKAGE_VERSION}\"/" \
      "$ROOT/synology/spk/INFO" > "$work/package/INFO"
  else
    sed "s/^arch=.*/arch=\"${dsm_arch}\"/" \
      "$ROOT/synology/spk/INFO" > "$work/package/INFO"
  fi
  cp -R "$ROOT/synology/spk/scripts/." "$work/package/scripts/"
  cp -R "$ROOT/synology/spk/ui/." "$work/package/ui/"

  chmod +x "$work/package/scripts/start-stop-status"
  chmod +x "$work/package/scripts/postinst" "$work/package/scripts/preupgrade"
  chmod +x "$work/package/scripts/postupgrade" "$work/package/scripts/repair-ownership"
  chmod +x "$work/package/scripts/postuninst"
  chmod +x "$work/package/ui/api.cgi"

  (cd "$work/package" && tar -czf package.tgz bin ui)
  mv "$work/package/package.tgz" "$work/package.tgz"
  cp "$work/package/INFO" "$work/INFO"

  {
    printf 'package_icon="%s"\n' "$(base64 < "$ROOT/synology/spk/PACKAGE_ICON.PNG" | tr -d '\n')"
    printf 'package_icon_256="%s"\n' "$(base64 < "$ROOT/synology/spk/PACKAGE_ICON_256.PNG" | tr -d '\n')"
  } >> "$work/INFO"

  cp -R "$work/package/scripts" "$work/scripts"
  (cd "$work" && tar -cf "$pkg" INFO package.tgz scripts conf)
  printf '%s\n' "$display_pkg"
)

cd "$ROOT"
build_pkg amd64 v2 x86_64
build_pkg arm64 "" aarch64
