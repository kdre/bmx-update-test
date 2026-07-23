# Circle stdlib patches

This directory contains the local patch set for the pinned Circle stdlib v20
source archive in `third_party/source-cache/`.

The Pi4 and Pi5 VICE 3.10 build helpers apply these patches when preparing
their generated Circle stdlib trees under `build/pi4/circle-stdlib` and
`build/pi5/circle-stdlib`.

Patch `0011-mbedtls-3.6.7-compat.patch` contains only the Circle integration
changes needed for the pinned Mbed TLS 3.6.7 source: the bare-metal feature
overlay, entropy C linkage, monotonic millisecond timer, fail-closed client
certificate policy, finite blocking receive/handshake deadlines and wrapper
Makefile update. It intentionally does not contain the upstream Mbed TLS
source. The verified release archive replaces `libs/mbedtls` through
`tools/lib/mbedtls_source_archive.sh`.

When changing Circle, regenerate the affected patch from a diff between a clean
archive extraction and the modified generated Circle tree, then verify the
patch applies cleanly to a fresh extraction before building.
