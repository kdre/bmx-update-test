#!/bin/bash

# Pi 4 and Pi 5 configure the same VICE source tree and therefore mutate the
# same generated Makefiles and headers. Keep one descriptor open for the
# lifetime of the calling wrapper, so a second target build fails before it can
# reconfigure the source tree underneath the first one.
bmx_acquire_vice_target_build_lock() {
  local lock_file="$SRC_DIR/build/.vice310-target-build.lock"
  command -v flock >/dev/null 2>&1 || {
    echo "flock is required to serialize Pi 4 and Pi 5 target builds" >&2
    return 1
  }
  mkdir -p -- "$SRC_DIR/build"
  exec 9>"$lock_file"
  if ! flock -n 9; then
    echo "another Pi 4/Pi 5 target build is already running; build the targets separately" >&2
    return 1
  fi
}
