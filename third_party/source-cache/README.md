# Source Cache

This directory stores pinned upstream source archives that BMX extracts into
board-local build directories. The archive contents are unmodified upstream
sources plus submodules; BMX-specific changes are kept as patches outside the
archive.

## circle-stdlib

`circle-stdlib-v20-a4fbed9b-full.tar.gz.part-*` contains a split copy of
`circle-stdlib-v20-a4fbed9b-full.tar.gz`. The build scripts concatenate the
parts into `build/source-cache/` before extraction and verify the original
archive SHA256 listed in `SHA256SUMS`.

The archive contains:

- `smuehlst/circle-stdlib` tag `v20`
- commit `a4fbed9b369e8285e4a12b2bb0588511210b83a6`
- initialized submodules, including Circle `Step51`
- no `.git` directories

Build scripts extract this single archive into:

- `build/pi4/circle-stdlib`
- `build/pi5/circle-stdlib`

The extracted trees are separate because Pi4 and Pi5 use different Circle
configuration, toolchains and install directories.

## Mbed TLS

Circle stdlib v20 embeds an old Mbed TLS source snapshot. BMX replaces it with
the official Mbed TLS 3.6.7 release archive before configuration and build.
The verified upstream archive is tracked here as `mbedtls-3.6.7.tar.bz2`, and
its SHA-256 is recorded in the adjacent `SHA256SUMS`. The version is pinned by
the archive name and build helper. The helper requires this repository archive,
verifies its checksum and single-root layout, and never downloads source code.

The upstream release is available at:

<https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2>

Its license is copied byte-for-byte to `sdcard/licenses/mbedtls.txt` so SD
staging does not depend on a generated Circle build tree.
