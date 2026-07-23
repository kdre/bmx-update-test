#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
STAGE_ARGS=()
BUILD_PROFILE="${BMC64_BUILD_PROFILE:-release}"
BUILD_ONLY=0
STAGE_DIR_SET=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--profile release|debug] [--debug-uart] [--build-only] [--stage-dir DIR]

Builds Pi5/Pi500 VICE 3.10 kernels and stages a boot tree.

Options:
  --profile      staging boot config profile (default: release)
  --debug-uart   alias for --profile debug
  --build-only   build kernels without creating an SD-card stage
  --stage-dir    override the output staging directory
EOF
}

while (($# > 0)); do
  case "$1" in
    --profile)
      if [ -z "${2:-}" ]; then
        echo "--profile requires release or debug" >&2
        exit 1
      fi
      case "$2" in
        release|debug) ;;
        *)
          echo "--profile requires release or debug" >&2
          exit 1
          ;;
      esac
      BUILD_PROFILE="$2"
      STAGE_ARGS+=("--profile" "$2")
      shift 2
      ;;
    --debug-uart)
      BUILD_PROFILE=debug
      STAGE_ARGS+=("--profile" "debug")
      shift
      ;;
    --build-only)
      BUILD_ONLY=1
      shift
      ;;
    --stage-dir)
      if [ -z "${2:-}" ]; then
        echo "--stage-dir requires a directory" >&2
        exit 1
      fi
      STAGE_ARGS+=("--stage-dir" "$2")
      STAGE_DIR_SET=1
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ "$BUILD_ONLY" -eq 1 ] && [ "$STAGE_DIR_SET" -eq 1 ]; then
  echo "--build-only cannot be combined with --stage-dir" >&2
  exit 1
fi

. "$SRC_DIR/tools/lib/serialize_vice_target_build.sh"
bmx_acquire_vice_target_build_lock

cat <<'EOF'
Building Pi5/Pi500 VICE 3.10 kernels with pinned Mbed TLS support.

Currently wired VICE 3.10 machines: C64 (x64/x64sc), SCPU64, C128, VIC20, Plus/4, PET.
EOF

. "$SRC_DIR/tools/pi5/vice310_build_common.sh"

export BMC64_BUILD_PROFILE="$BUILD_PROFILE"
BMX_PI5_MACHINE_LIST="$(
  python3 "$SRC_DIR/tools/sd_layout.py" kernel-machines --board pi5
)"
[[ -n "$BMX_PI5_MACHINE_LIST" ]] || {
  echo "sd-layout.toml defines no required Pi 5 machine kernels" >&2
  exit 1
}
mapfile -t BMX_PI5_MACHINES <<<"$BMX_PI5_MACHINE_LIST"
build_vice310_machines "${BMX_PI5_MACHINES[@]}"
if [ "$BUILD_ONLY" -eq 0 ]; then
  "$SRC_DIR/tools/pi5/stage_pi5_sd.sh" "${STAGE_ARGS[@]}"
fi
