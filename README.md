# BMX

BMX is a bare-metal Commodore emulator derived from BMC64 for the Raspberry PI 4/5 family.
The current focus of this project is to provide a smooth user experience on the Raspberry Pi 400 and 500. It should kinda feel like a modern breadbin. Support for Raspberry Pi <= 3 is removed and left to the original BMC64 project.

These are the main features of BMX:

Core features:
* Based on VICE 3.10 (C64, C128, VIC20, Plus/4 and PET machines are supported)
* A unified `Machine` menu selects the emulator (`x64`, `x64sc`, `xscpu64`,
  `x128`, `xvic`, `xplus4` or `xpet`) and one compatible video mode. The mode
  label includes video standard, output, resolution and exact refresh rate.
  Changes are applied together after confirmation when leaving the BMX menu.
  The configuration format is documented in
  [`docs/MACHINES.md`](docs/MACHINES.md).
* `System > Reboot...` and `System > Power Off...` restart or shut down the
  Raspberry Pi after explicit confirmation. Pending machine and network
  changes are validated and saved before the selected action.
* Circle v20, Step 51 to support the Raspberry Pi4/5 family
* Pi5/Pi500 HDMI modesetting with RGB565 framebuffer and hardware scaling, providing HDMI resolution switching, which is currently not supported in Circle.
* Integrated network support (Ethernet/Wi-Fi)
* A hardware-validated build can use the explicit `System > Update...`
  workflow to inspect the newest stable release published by `kdre/bmx`. BMX
  never checks for updates at boot, in the background, when networking becomes
  ready, or merely because a menu is opened. The workflow is entered only
  after the user selects it; it refuses to connect unless networking is
  already enabled and ready.
* Added a popup screen to select available Wi-Fi access points
* Integrated RS232 over TCP/IP (think connecting two computers with an emulated RS232 cable over an internet connection)
* RS232 supports Userport, UP9600/EZ232 and Swift/Turbo Interfaces
* Ported tcpser-based Hayes-Modem connected to the RS232 interface (within a terminal you can call a BBS like this: "ATDTbmxbbs.de:6510")
* Added authentic sound options for the Hayes modem
* Added support for a user selectable phonebook for BBS connections which can be dialed using the "ATDT" command within a terminal (e.g. ATDT0, ATDTMYBBS or ATDT515123456). The format of the .pb file is: `shortcut=addr`, e.g. `0=bmxbbs.de:6510`
* Improvements and bug fixes in the networking stack
* Support for two partitions on the SD card (a mandatory system/boot partition and an optional user partition for disk images, phonebooks etc.)
* Added support for a configurable default utility disk. `Drives > Default disk` selects the image and target drive; the machine-specific utility image and drive 8 are the initial defaults, while `None` disables automatic insertion. Utility disks for the other machines do not exist yet.
* The C64 utility disk currently only contains the terminal program "ccgms", modified to default to modem type "Swift/Turbo DE". Enable networking and RS232 in the BMX menu, load ccgms (`LOAD "ccgms",8,1` followed by `RUN`), and you can call a BBS without changing any terminal settings.
* With the release of the first BMX version a dedicated bbs (bmxbbs.de:6510) was launched. It is the default BBS, which is called when you enter "ATDT" (without any "number") in a terminal program.

## Current Status

Development is mainly carried out on a PI 400 with a German keyboard layout followed by a PI 500 with German keyboard layout. "Positional DE" is the default layout on a freshly created sdcard. I expect that these two machines will run out of the box. Besides "Positional DE", I integrated "Positional US" in the BMX menu. Because I dont have a US machine to test it, I consider "Positional US" as work in progress. Other keyboard layouts are currently not supported. I removed the "Symbolic" option in the menu, because in my opinion on a bare metal machine it doesnt make sense.

## Building

Build, staging, installation and SD-card creation are documented in
[`BUILDING.md`](BUILDING.md).

The C64 core selection, separate kernel layout and hardware validation checklist
are documented in [`docs/C64-CORES.md`](docs/C64-CORES.md).

The board-specific reboot, power-off and wake behaviour is documented in
[`docs/POWER-CONTROL.md`](docs/POWER-CONTROL.md).

## Updating BMX

GitHub Releases are the only online update source. The updater considers only
the newest stable release and does not provide an online downgrade or arbitrary
version selector. Discovery downloads only release metadata; the board ZIP is
downloaded after a separate confirmation. Signed manifests bind the board,
version, ZIP hash, exact file inventory, immediate signed predecessor and
configuration compatibility data. The automated release process signs with a
P-256 key stored locally outside the repository on the release workstation;
this does not change the ZIP format or require online installation.

An incompatible configuration format is never silently discarded. BMX lists
the affected configuration areas, creates a snapshot, defaults to cancel, and
requires a second explicit reset confirmation whose digest is bound to the
current local files. A changed file invalidates that consent.

The normal, directly extractable Pi 4/Pi 400 and Pi 5/Pi 500 ZIP files remain
the supported offline/bootstrap path. See `UPDATE-MANUAL.txt` inside a release
ZIP. Host-side verification and the release process are documented in
[`docs/release-HOWTO.md`](docs/release-HOWTO.md); the threat model, trust store
and hardware release gates are documented in
[`docs/UPDATE_SECURITY.md`](docs/UPDATE_SECURITY.md). The exact implemented
versus target-only validation state is tracked in
[`docs/UPDATE_IMPLEMENTATION_STATUS.md`](docs/UPDATE_IMPLEMENTATION_STATUS.md).

The SD-card tooling requires and creates at least a 512 MiB boot partition for
new and updater-capable cards. Existing smaller cards must be recreated for
this update generation; every online attempt also performs an exact
fail-closed peak-space calculation.

The default build keeps `BMX_UPDATE_TARGET_UI_VALIDATED` closed, so even an
explicit Update action returns before DNS/HTTPS and does not authenticate or
display an online offer. Once that separate TLS/progress/cancel gate has real
target evidence, discovery may be enabled; ZIP download and installation still
remain fail-closed until the independent one-shot boot, watchdog, filesystem
durability and power-cut recovery gates have passed on every supported
Raspberry Pi family. The online path is therefore not release-ready yet.

## Repository Layout

```text
src/                  BMX source and headers
mk/machines/          per-machine link makefiles
tools/pi4/            Pi4 build, stage, install and UART helpers
tools/pi5/            Pi5 build, stage, install and UART helpers
tools/lib/            shared shell helpers
third_party/          vendored upstream projects, generated checkouts and patch sets
third_party/circle-stdlib-patches/
                      Circle stdlib patch set applied by Pi4/Pi5 build helpers
build/                generated object files and kernel images
```

## Known Gaps

Pi5 VIC20 builds, stages and reaches the start screen on hardware; disk and
sound testing are still pending.
Pi5 Plus/4 reaches the start screen on hardware with keyboard input and HDMI
audio initialization; disk and audible sound testing are still pending.
Pi5 PET reaches the start screen on hardware; keyboard, disk and sound testing
are still pending.

Composite video is a retained but unverified legacy target. Original BMC64
used Raspberry Pi firmware `sdtv_mode` settings and dedicated composite timing
profiles; BMX keeps those menu entries marked as `EXPERIMENTAL` until
Pi4/Pi5 composite hardware can be tested.

CRT/DPI-oriented features from original BMC64 are not a Pi4/Pi5 target yet.
