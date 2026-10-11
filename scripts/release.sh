#!/usr/bin/env bash
# Reproducible release builds of lootr. Produces the assets of the release
# contract ("Release artifacts" in PLAN.md) except the Sigstore bundles,
# which only the release workflow can create (GitHub OIDC).
#
# Run inside the release shell (pinned Rust toolchain with all targets, GNU
# tar/gzip, cargo-cyclonedx):
#
#   nix develop .#release -c scripts/release.sh build <target> <outdir>
#   nix develop .#release -c scripts/release.sh reproduce <target> <outdir>
#   nix develop .#release -c scripts/release.sh sbom <outdir>
#   nix develop .#release -c scripts/release.sh checksums <outdir>
#   nix develop .#release -c scripts/release.sh version
#
# <target>: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl (any host:
# linked by rust-lld against the toolchain's bundled musl, fully static) or
# universal-apple-darwin (macOS host with Xcode: both architectures linked by
# /usr/bin/cc, merged with lipo).
#
# Reproducibility: --locked, the pinned toolchain from flake.lock, one
# codegen unit and stripped symbols (Cargo.toml), --remap-path-prefix for the
# source, target and cargo home directories (no machine paths in panic
# locations), no build script and no timestamps in the binary, and archives
# with sorted entries, fixed owner/mode and mtime = SOURCE_DATE_EPOCH (the
# commit time, see below) and gzip without name/time. `reproduce` builds
# twice from two copies of the source in different directories with
# separate target directories and fails unless the archives are identical.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
[ -n "$version" ] || { echo "release.sh: no version in Cargo.toml" >&2; exit 2; }

# Files the release build reads (src/ incl. the embedded default config) and
# the files every archive ships.
build_inputs=(Cargo.toml Cargo.lock src)
shipped=(LICENSE README.md THIRD_PARTY.md)

export LC_ALL=C TZ=UTC CARGO_INCREMENTAL=0
# Archive mtimes (nothing in the binary depends on the time). Nix shells
# always set SOURCE_DATE_EPOCH=315532800 (1980), so the commit time is taken
# from LOOTR_SOURCE_DATE_EPOCH (set by the release workflow) or git first.
epoch=${LOOTR_SOURCE_DATE_EPOCH:-}
[ -n "$epoch" ] || epoch=$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)
[ -n "$epoch" ] || epoch=${SOURCE_DATE_EPOCH:-}
[[ "$epoch" =~ ^[0-9]+$ ]] || {
  echo "release.sh: set LOOTR_SOURCE_DATE_EPOCH (no commit to take it from)" >&2
  exit 2
}
export SOURCE_DATE_EPOCH=$epoch
# The deployment target is fixed (the dev shell would otherwise leak its own).
export MACOSX_DEPLOYMENT_TARGET=11.0

# cargo_build <source dir> <target dir> <rust target>: prints the binary path.
cargo_build() {
  local src=$1 tdir=$2 rtarget=$3
  local cargo_home=${CARGO_HOME:-$HOME/.cargo}
  local linker_var flags
  linker_var="CARGO_TARGET_$(echo "$rtarget" | tr 'a-z-' 'A-Z_')_LINKER"
  # Later --remap-path-prefix flags win: the most specific paths go last.
  flags="--remap-path-prefix=$src=/lootr --remap-path-prefix=$tdir=/target --remap-path-prefix=$cargo_home=/cargo"
  case "$rtarget" in
    *-apple-darwin)
      export "$linker_var=/usr/bin/cc"
      # ld64 hashes the debug map (absolute object file paths) into LC_UUID
      # before rustc strips it: -S leaves the debug map out.
      flags="$flags -C link-arg=-Wl,-S"
      ;;
    *-linux-musl) export "$linker_var=rust-lld" ;;
  esac
  RUSTFLAGS="$flags" \
    CARGO_TARGET_DIR="$tdir" \
    cargo build --release --locked --target "$rtarget" --manifest-path "$src/Cargo.toml" >&2
  echo "$tdir/$rtarget/release/lootr"
}

# build_binary <source dir> <target dir> <release target> <output file>
build_binary() {
  local src=$1 tdir=$2 target=$3 out=$4
  case "$target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl)
      cp "$(cargo_build "$src" "$tdir" "$target")" "$out"
      ;;
    universal-apple-darwin)
      [ "$(uname -s)" = Darwin ] || { echo "release.sh: $target needs a macOS host" >&2; exit 2; }
      local arm x86
      arm=$(cargo_build "$src" "$tdir" aarch64-apple-darwin)
      x86=$(cargo_build "$src" "$tdir" x86_64-apple-darwin)
      lipo -create -output "$out" "$arm" "$x86"
      ;;
    *)
      echo "release.sh: unknown target $target" >&2
      exit 2
      ;;
  esac
}

# package <source dir> <binary> <target> <outdir>: writes the archive.
package() {
  local src=$1 bin=$2 target=$3 outdir=$4
  local name="lootr-$version-$target" stage
  stage=$(mktemp -d)
  mkdir -m 0755 "$stage/$name"
  install -m 0755 "$bin" "$stage/$name/lootr"
  for f in "${shipped[@]}"; do
    install -m 0644 "$src/$f" "$stage/$name/$f"
  done
  mkdir -p "$outdir"
  tar -C "$stage" --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner -cf - "$name" | gzip -9 -n >"$outdir/$name.tar.gz"
  rm -rf "$stage"
  echo "$outdir/$name.tar.gz"
}

cmd_build() {
  local target=$1 outdir=$2 bin
  bin=$(mktemp -d)/lootr
  build_binary "$root" "${CARGO_TARGET_DIR:-$root/target}/release-build" "$target" "$bin"
  package "$root" "$bin" "$target" "$outdir"
}

# Two builds from copies of the source in different directories (different
# path lengths), separate target directories: the archives must be equal.
cmd_reproduce() {
  local target=$1 outdir=$2 work n archive
  work=$(mktemp -d)
  local -a sums=()
  for n in a bb; do
    local src="$work/$n/src-$n/lootr"
    mkdir -p "$src"
    (cd "$root" && cp -R "${build_inputs[@]}" "${shipped[@]}" "$src/")
    build_binary "$src" "$work/$n/target" "$target" "$work/$n/lootr"
    archive=$(package "$src" "$work/$n/lootr" "$target" "$work/$n/out")
    sums+=("$(sha256sum "$archive" | cut -d' ' -f1)")
    echo "build $n: ${sums[-1]}  $(basename "$archive")" >&2
  done
  if [ "${sums[0]}" != "${sums[1]}" ]; then
    echo "release.sh: $target is not reproducible" >&2
    exit 1
  fi
  mkdir -p "$outdir"
  cp "$archive" "$outdir/"
  rm -rf "$work"
  echo "$outdir/$(basename "$archive")"
}

cmd_sbom() {
  local outdir=$1
  mkdir -p "$outdir"
  # All platforms (a superset of the release targets' dependencies), with
  # build dependencies (they run at build time).
  cargo cyclonedx --manifest-path "$root/Cargo.toml" --format json --spec-version 1.5 \
    --target all --override-filename "lootr-$version.cdx" >&2
  mv "$root/lootr-$version.cdx.json" "$outdir/"
  echo "$outdir/lootr-$version.cdx.json"
}

cmd_checksums() {
  local outdir=$1
  (cd "$outdir" && sha256sum -- lootr-*.tar.gz >SHA256SUMS && cat SHA256SUMS)
}

case "${1:-}" in
  build) [ $# -eq 3 ] || { echo "usage: $0 build <target> <outdir>" >&2; exit 2; }; cmd_build "$2" "$3" ;;
  reproduce) [ $# -eq 3 ] || { echo "usage: $0 reproduce <target> <outdir>" >&2; exit 2; }; cmd_reproduce "$2" "$3" ;;
  sbom) [ $# -eq 2 ] || { echo "usage: $0 sbom <outdir>" >&2; exit 2; }; cmd_sbom "$2" ;;
  checksums) [ $# -eq 2 ] || { echo "usage: $0 checksums <outdir>" >&2; exit 2; }; cmd_checksums "$2" ;;
  version) echo "$version" ;;
  *)
    echo "usage: $0 build|reproduce <target> <outdir> | sbom|checksums <outdir> | version" >&2
    exit 2
    ;;
esac
