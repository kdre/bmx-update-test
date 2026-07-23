#!/bin/bash

# Shared Pi4/Pi400 VICE 3.10 build helpers.
# Scripts sourcing this file may define SRC_DIR first; otherwise it is derived
# from this file location.

set -euo pipefail

if [ -z "${SRC_DIR:-}" ]; then
  _BMC64_VICE310_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  SRC_DIR="$(cd "$_BMC64_VICE310_COMMON_DIR/../.." && pwd)"
fi

. "$SRC_DIR/tools/lib/build_paths.sh"
. "$SRC_DIR/tools/lib/circle_patches.sh"
. "$SRC_DIR/tools/lib/circle_source_archive.sh"
. "$SRC_DIR/tools/lib/mbedtls_source_archive.sh"

TOOLS_BIN="$SRC_DIR/tools/autotools-stubs/bin"
CIRCLE_STDLIB_HOME="$BMC64_BUILD_ROOT/pi4/circle-stdlib"
CIRCLE_STDLIB_SOURCE_ARCHIVE="$SRC_DIR/third_party/source-cache/circle-stdlib-v20-a4fbed9b-full.tar.gz"
CIRCLE_STDLIB_SOURCE_SHA256="$SRC_DIR/third_party/source-cache/SHA256SUMS"
CIRCLE_STDLIB_PATCH_DIR="$SRC_DIR/third_party/circle-stdlib-patches"
NEWLIBDIR="$CIRCLE_STDLIB_HOME/install/arm-none-circle"
TOOLCHAIN_ROOT="$SRC_DIR/.toolchains"
TOOLCHAIN_NAME="arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi"
TOOLCHAIN_DIR="$TOOLCHAIN_ROOT/$TOOLCHAIN_NAME"
TOOLCHAIN_TARBALL="$TOOLCHAIN_NAME.tar.xz"
TOOLCHAIN_URL="https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/$TOOLCHAIN_TARBALL"
VICE_DIR="$SRC_DIR/third_party/vice-3.10"
VICE_SRC="$VICE_DIR/src"

rename_wpa_supplicant_sha1_symbols() {
  local lib="$CIRCLE_STDLIB_HOME/libs/circle/addon/wlan/hostap/wpa_supplicant/libwpa_supplicant.a"
  arm-none-eabi-objcopy \
    --redefine-sym SHA1Transform=wpa_SHA1Transform \
    --redefine-sym SHA1Init=wpa_SHA1Init \
    --redefine-sym SHA1Update=wpa_SHA1Update \
    --redefine-sym SHA1Final=wpa_SHA1Final \
    "$lib"
}

ensure_toolchain() {
  export PATH="$TOOLS_BIN:$PATH"

  if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    return
  fi

  mkdir -p "$TOOLCHAIN_ROOT"
  if [ ! -d "$TOOLCHAIN_DIR" ]; then
    curl -L --fail "$TOOLCHAIN_URL" -o "$TOOLCHAIN_ROOT/$TOOLCHAIN_TARBALL"
    tar -C "$TOOLCHAIN_ROOT" -xf "$TOOLCHAIN_ROOT/$TOOLCHAIN_TARBALL"
  fi

  export PATH="$TOOLCHAIN_DIR/bin:$PATH"
  command -v arm-none-eabi-gcc >/dev/null 2>&1
}

ensure_circle_stdlib() {
  local patchset_hash

  patchset_hash="$(circle_patchset_hash "$CIRCLE_STDLIB_PATCH_DIR")"
  if ! circle_stdlib_patchset_matches "$CIRCLE_STDLIB_HOME" "$patchset_hash"; then
    echo "Circle patch set changed; refreshing $CIRCLE_STDLIB_HOME"
    rm -rf "$CIRCLE_STDLIB_HOME"
  fi

  circle_stdlib_extract_from_archive \
    "$CIRCLE_STDLIB_SOURCE_ARCHIVE" \
    "$CIRCLE_STDLIB_SOURCE_SHA256" \
    "$CIRCLE_STDLIB_HOME"
  apply_circle_stdlib_patches "$CIRCLE_STDLIB_HOME" "$CIRCLE_STDLIB_PATCH_DIR"
  circle_stdlib_install_pinned_mbedtls "$SRC_DIR" "$CIRCLE_STDLIB_HOME"
  record_circle_stdlib_patchset "$CIRCLE_STDLIB_HOME" "$patchset_hash"
}

configure_circle_profile_flags() {
  local config2="$CIRCLE_STDLIB_HOME/libs/circle/Config2.mk"
  local wrote_config2=0

  if [ "${BMC64_BUILD_PROFILE:-release}" = debug ]; then
    printf 'DEFINE += -DBMC64_DEBUG_PROFILE\n' > "$config2"
    wrote_config2=1
    if [ -n "${BMC64_TCP_LOG_LEVEL:-}" ]; then
      printf 'DEFINE += -DBMC64_TCP_LOG_LEVEL=%s\n' "$BMC64_TCP_LOG_LEVEL" >> "$config2"
    fi
  else
    : > "$config2"
  fi
  if [ -n "${BMC64_WLAN_TRACE:-}" ]; then
    printf 'DEFINE += -DBMC64_WLAN_TRACE\n' >> "$config2"
    wrote_config2=1
  fi
  if [ -n "${BMC64_WLAN_LOW_IMPACT_TRACE:-}" ]; then
    printf 'DEFINE += -DBMC64_WLAN_LOW_IMPACT_TRACE\n' >> "$config2"
    wrote_config2=1
  fi
  if [ -n "${BMC64_WLAN_LOW_IMPACT_TRACE_LOG:-}" ]; then
    printf 'DEFINE += -DBMC64_WLAN_LOW_IMPACT_TRACE_LOG\n' >> "$config2"
    wrote_config2=1
  fi
  if [ "$wrote_config2" -eq 0 ]; then
    rm -f "$config2"
  fi
}

build_circle_stdlib() {
  cd "$CIRCLE_STDLIB_HOME"
  make mrproper >/dev/null 2>&1 || true
  ./configure --raspberrypi=4 --kernel-max-size 48 \
    --option ARM_ALLOW_MULTI_CORE --option USE_USB_SOF_INTR \
    --opt-tls \
    --prefix arm-none-eabi-
  configure_circle_profile_flags
  make -j"$(nproc)"
  make -C libs/circle/addon/fatfs clean
  make -C libs/circle/addon/fatfs
  make -C libs/circle/addon/linux clean
  make -C libs/circle/addon/linux
  make -C libs/circle/addon/wlan clean
  make -C libs/circle/addon/wlan
  make -C libs/circle/addon/wlan/hostap/wpa_supplicant -f Makefile.circle clean
  rm -f libs/circle/addon/wlan/hostap/wpa_supplicant/libwpa_supplicant.a
  make -C libs/circle/addon/wlan/hostap/wpa_supplicant -f Makefile.circle libwpa_supplicant.a
  rename_wpa_supplicant_sha1_symbols
  make -C libs/circle/addon/vc4/vchiq clean
  make -C libs/circle/addon/vc4/vchiq
  make -C libs/circle/addon/vc4/interface/bcm_host
  make -C libs/circle/addon/vc4/interface/khronos
  make -C libs/circle/addon/vc4/interface/vcos
  make -C libs/circle/addon/vc4/interface/vmcs_host
  ar d "$NEWLIBDIR/lib/libcirclenewlib.a" io.o errno.o getpid.o || true
}

build_common() {
  make -C "$SRC_DIR/third_party/common" clean CIRCLE_STDLIB_HOME="$CIRCLE_STDLIB_HOME" \
    BMC64_BUILD_PROFILE="${BMC64_BUILD_PROFILE:-release}" \
    BMC64_MENU_LOG_LEVEL="${BMC64_MENU_LOG_LEVEL:-}"
  (
    cd "$SRC_DIR/third_party/common"
    BOARD=pi4 CIRCLE_STDLIB_HOME="$CIRCLE_STDLIB_HOME" \
      BMC64_BUILD_PROFILE="${BMC64_BUILD_PROFILE:-release}" \
      BMC64_MENU_LOG_LEVEL="${BMC64_MENU_LOG_LEVEL:-}" make
  )
}

set_vice310_make_args() {
  local vice_cppflags vice_cflags vice_cxxflags vice_ldflags
  local debug_define=""
  local diag_defines=""

  if [ "${BMC64_BUILD_PROFILE:-release}" = debug ]; then
    debug_define=" -DBMC64_DEBUG_PROFILE"
  fi
  if [ -n "${BMC64_RS232_LOG_LEVEL:-}" ]; then
    diag_defines="$diag_defines -DBMC64_RS232_LOG_LEVEL=$BMC64_RS232_LOG_LEVEL"
  fi
  if [ -n "${BMC64_ACIA_LOG_LEVEL:-}" ]; then
    diag_defines="$diag_defines -DBMC64_ACIA_LOG_LEVEL=$BMC64_ACIA_LOG_LEVEL"
  fi
  if [ -n "${BMC64_TCP_LOG_LEVEL:-}" ]; then
    diag_defines="$diag_defines -DBMC64_TCP_LOG_LEVEL=$BMC64_TCP_LOG_LEVEL"
  fi
  if [ -n "${BMC64_NET_LOG_LEVEL:-}" ]; then
    diag_defines="$diag_defines -DBMC64_NET_LOG_LEVEL=$BMC64_NET_LOG_LEVEL"
  fi

  vice_cppflags="-DRASPI_COMPILE$debug_define$diag_defines -I$VICE_SRC -I$VICE_SRC/arch/shared -I$VICE_SRC/arch/raspi"
  vice_cflags="-O3 -std=gnu11 -ffreestanding -nostdlib -fno-exceptions -Wno-incompatible-pointer-types -march=armv8-a -mtune=cortex-a72 -marm -mfpu=neon-fp-armv8 -mfloat-abi=hard$debug_define$diag_defines -I$VICE_SRC -I$SRC_DIR/src -I$SRC_DIR -I$SRC_DIR/third_party/common -I$NEWLIBDIR/include -I$CIRCLE_STDLIB_HOME/include -I$CIRCLE_STDLIB_HOME/libs/circle/addon -I$CIRCLE_STDLIB_HOME/libs/circle/addon/fatfs"
  vice_cxxflags="-O3 -ffreestanding -nostdlib -fno-exceptions -fcheck-new -march=armv8-a -mtune=cortex-a72 -marm -mfpu=neon-fp-armv8 -mfloat-abi=hard -std=c++11 -fno-rtti -nostdinc++$debug_define$diag_defines -I$VICE_SRC -I$SRC_DIR/src -I$SRC_DIR -I$SRC_DIR/third_party/common -I$NEWLIBDIR/include -I$CIRCLE_STDLIB_HOME/include -I$CIRCLE_STDLIB_HOME/libs/circle/addon -I$CIRCLE_STDLIB_HOME/libs/circle/addon/fatfs"
  vice_ldflags="-L$NEWLIBDIR/lib"

  vice_configure_args=(
    "--host=arm-none-eabi"
    "--with-fastsid"
    "--disable-realdevice"
    "--disable-ipv6"
    "--disable-ssi2001"
    "--disable-catweasel"
    "--disable-hardsid"
    "--disable-parsid"
    "--disable-portaudio"
    "--disable-ahi"
    "--disable-bundle"
    "--disable-lame"
    "--disable-midi"
    "--disable-hidmgr"
    "--disable-hidutils"
    "--without-oss"
    "--without-alsa"
    "--without-pulse"
    "--without-zlib"
    "--without-png"
    "--without-libcurl"
    "--disable-sdlui"
    "--disable-sdlui2"
    "--enable-raspiui"
  )
  vice_make_args=(
    "CC=arm-none-eabi-gcc"
    "CXX=arm-none-eabi-g++"
    "CPP=arm-none-eabi-gcc -E"
    "CXXCPP=arm-none-eabi-g++ -E"
    "AR=arm-none-eabi-ar"
    "RANLIB=arm-none-eabi-ranlib"
    "STRIP=arm-none-eabi-strip"
    "XA=true"
    "DOS2UNIX=true"
    "ac_cv_lib_lex=none needed"
    "ac_cv_search_yywrap=none required"
    "ac_cv_header_arpa_inet_h=yes"
    "ac_cv_header_netdb_h=yes"
    "ac_cv_header_netinet_in_h=yes"
    "ac_cv_header_netinet_tcp_h=yes"
    "ac_cv_header_sys_select_h=yes"
    "ac_cv_header_sys_socket_h=yes"
    "ac_cv_header_sys_time_h=yes"
    "ac_cv_header_sys_types_h=yes"
    "ac_cv_header_unistd_h=yes"
    "ac_cv_func_accept=yes"
    "ac_cv_func_bind=yes"
    "ac_cv_func_connect=yes"
    "ac_cv_func_getaddrinfo=yes"
    "ac_cv_func_gethostbyname=yes"
    "ac_cv_func_htonl=yes"
    "ac_cv_func_htons=yes"
    "ac_cv_func_listen=yes"
    "ac_cv_func_recv=yes"
    "ac_cv_func_send=yes"
    "ac_cv_func_socket=yes"
    "CPPFLAGS=$vice_cppflags"
    "CFLAGS=$vice_cflags"
    "CXXFLAGS=$vice_cxxflags"
    "LDFLAGS=$vice_ldflags"
  )
}

configure_vice310() {
  cd "$VICE_DIR"
  find . -name 'config.cache' -delete
  ./configure "${vice_configure_args[@]}" "${vice_make_args[@]}"
  find src -name '*.o' -delete
  find src -name '*.a' -delete
}

preserve_vice310_generated_monitor_parser() {
  local monitor_dir="$VICE_SRC/monitor"

  # A clean checkout can give mon_parse.y a newer timestamp than VICE's
  # checked-in BYACC output. Do not silently replace it with output from the
  # host's yacc implementation during a release build.
  touch -r "$monitor_dir/mon_parse.y" \
    "$monitor_dir/mon_parse.c" "$monitor_dir/mon_parse.h"
}

vice310_machine_config() {
  local machine="$1"

  VICE310_VARIANT_ARCHIVES=()

  case "$machine" in
    c64)
      VICE310_TARGET="x64"
      VICE310_MAKEFILE="mk/machines/Makefile-C64-310"
      VICE310_CLASS="RASPI_C64"
      VICE310_ARCH_DIR="c64"
      VICE310_ARCH_LIB="libarch_c64.a"
      VICE310_IMAGE_SUFFIX="c64"
      VICE310_COPY_DEFAULT=1
      VICE310_VARIANT_ARCHIVES=(
        "$VICE_SRC/c64/libc64.a"
        "$VICE_SRC/vicii/libvicii.a"
        "$VICE_SRC/c64/libc64stubs.a"
      )
      ;;
    c64sc)
      VICE310_TARGET="x64sc"
      VICE310_MAKEFILE="mk/machines/Makefile-C64SC-310"
      VICE310_CLASS="RASPI_C64SC"
      VICE310_ARCH_DIR="c64"
      VICE310_ARCH_LIB="libarch_c64.a"
      VICE310_IMAGE_SUFFIX="c64sc"
      VICE310_COPY_DEFAULT=0
      VICE310_VARIANT_ARCHIVES=(
        "$VICE_SRC/c64/libc64sc.a"
        "$VICE_SRC/viciisc/libviciisc.a"
        "$VICE_SRC/c64/libc64scstubs.a"
      )
      ;;
    scpu64)
      VICE310_TARGET="xscpu64"
      VICE310_MAKEFILE="mk/machines/Makefile-SCPU64-310"
      VICE310_CLASS="RASPI_SCPU64"
      VICE310_ARCH_DIR="c64"
      VICE310_ARCH_LIB="libarch_c64.a"
      VICE310_IMAGE_SUFFIX="scpu64"
      VICE310_COPY_DEFAULT=0
      ;;
    c128)
      VICE310_TARGET="x128"
      VICE310_MAKEFILE="mk/machines/Makefile-C128-310"
      VICE310_CLASS="RASPI_C128"
      VICE310_ARCH_DIR="c128"
      VICE310_ARCH_LIB="libarch_c128.a"
      VICE310_IMAGE_SUFFIX="c128"
      VICE310_COPY_DEFAULT=0
      ;;
    vic20)
      VICE310_TARGET="xvic"
      VICE310_MAKEFILE="mk/machines/Makefile-VIC20-310"
      VICE310_CLASS="RASPI_VIC20"
      VICE310_ARCH_DIR="vic20"
      VICE310_ARCH_LIB="libarch_vic20.a"
      VICE310_IMAGE_SUFFIX="vic20"
      VICE310_COPY_DEFAULT=0
      ;;
    plus4)
      VICE310_TARGET="xplus4"
      VICE310_MAKEFILE="mk/machines/Makefile-PLUS4-310"
      VICE310_CLASS="RASPI_PLUS4"
      VICE310_ARCH_DIR="plus4"
      VICE310_ARCH_LIB="libarch_plus4.a"
      VICE310_IMAGE_SUFFIX="plus4"
      VICE310_COPY_DEFAULT=0
      ;;
    pet)
      VICE310_TARGET="xpet"
      VICE310_MAKEFILE="mk/machines/Makefile-PET-310"
      VICE310_CLASS="RASPI_PET"
      VICE310_ARCH_DIR="pet"
      VICE310_ARCH_LIB="libarch_pet.a"
      VICE310_IMAGE_SUFFIX="pet"
      VICE310_COPY_DEFAULT=0
      ;;
    *)
      echo "unsupported VICE 3.10 machine: $machine" >&2
      return 1
      ;;
  esac
}

build_vice310_archives() {
  local machine="$1"
  vice310_machine_config "$machine"

  cd "$VICE_DIR"
  if [ "${#VICE310_VARIANT_ARCHIVES[@]}" -gt 0 ]; then
    rm -f "${VICE310_VARIANT_ARCHIVES[@]}"
  fi
  make -k "$VICE310_TARGET" "${vice_make_args[@]}" || true
  make -C src infocontrib.h "${vice_make_args[@]}"
  make -C src/resid libresid.a "${vice_make_args[@]}"
  make -C src/hvsc libhvsc.a "${vice_make_args[@]}"

  (
    cd "$SRC_DIR"
    while IFS= read -r archive; do
      if [ -f "$archive" ]; then
        continue
      fi
      make -C "$(dirname "$archive")" "$(basename "$archive")" "${vice_make_args[@]}"
    done < <(
      awk '
        /^\t\$\(VICE\)\// {
          gsub(/\\/, "")
          gsub(/\$\(VICE\)/, "third_party/vice-3.10/src")
          print $1
        }
      ' "$VICE310_MAKEFILE" | grep '\.a$' | sort -u
    )
  )

  make -C src/arch/shared/sounddrv libsounddrv.a "${vice_make_args[@]}"
  make -C src/arch/raspi libarch.a "${vice_make_args[@]}"
  make -C "src/arch/raspi/$VICE310_ARCH_DIR" "$VICE310_ARCH_LIB" "${vice_make_args[@]}"
}

build_vice310_kernel() {
  local machine="$1"
  local image_dir

  vice310_machine_config "$machine"
  cd "$SRC_DIR"
  BOARD=pi4 SRC_DIR=src CIRCLE_STDLIB_HOME="$CIRCLE_STDLIB_HOME" \
    BMC64_BUILD_PROFILE="${BMC64_BUILD_PROFILE:-release}" \
    make -f "$VICE310_MAKEFILE" clean
  BOARD=pi4 SRC_DIR=src CIRCLE_STDLIB_HOME="$CIRCLE_STDLIB_HOME" \
    BMC64_BUILD_PROFILE="${BMC64_BUILD_PROFILE:-release}" \
    make -f "$VICE310_MAKEFILE"

  image_dir="$(bmc64_vice310_image_dir pi4)"
  mkdir -p "$image_dir"
  cp "build/pi4/$VICE310_CLASS/kernel7l.img" \
    "$image_dir/kernel7l.img.$VICE310_IMAGE_SUFFIX"

  if [ "$VICE310_COPY_DEFAULT" -eq 1 ]; then
    cp "build/pi4/$VICE310_CLASS/kernel7l.img" \
      "$image_dir/kernel7l.img"
  fi
}

build_vice310_machines() {
  local machine

  [ "$#" -gt 0 ] || {
    echo "build_vice310_machines requires the sd-layout machine list" >&2
    return 2
  }

  ensure_toolchain
  ensure_circle_stdlib
  build_circle_stdlib
  set_vice310_make_args
  configure_vice310
  preserve_vice310_generated_monitor_parser
  build_common

  for machine in "$@"; do
    build_vice310_archives "$machine"
    build_vice310_kernel "$machine"
  done
}
