Keymap Runtime Sources
======================

`raspi/` contains hand-maintained Raspberry Pi keyboard maps that are staged
onto the SD card for the enabled VICE machines.

Keep `sdcard/` for the minimal static boot tree (`config.txt`, `cmdline.txt`,
`machines.ini` and bootstat files). Keymaps live here because some are used as
generator input and should not be mixed with the pre-stage SD-card skeleton.

Every runtime source-to-target mapping is declared explicitly in
`sd-layout.toml`; the staging code has no second keymap inventory.
`generate_raspi_keymaps.py` remains the development tool that derives the
checked-in per-machine positional US/DE maps from the C64 reference maps in
`tools/keymaps/raspi/c64/`.
