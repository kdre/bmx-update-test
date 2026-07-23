# Building BMX

This document covers the Pi4/Pi400 and Pi5/Pi500 BMX build paths. The
original BMC64 build instructions for Pi0/Pi2/Pi3 are kept as legacy scripts
under `tools/legacy/`.

## Prerequisites

Install the normal build tools:

```sh
sudo apt-get install git build-essential automake autoconf libtool pkg-config autoconf-archive autotools-dev curl
```

For SD-card creation and install helpers also install the normal Linux block and
FAT tools:

```sh
sudo apt-get install util-linux dosfstools
```

The Pi4 and Pi5 scripts manage their board-specific Arm toolchains under
`.toolchains/` if the expected compiler is not already available.

## Pi4 / Pi400

Build Circle, VICE and all currently enabled machine kernels:

```sh
tools/pi4/build_pi4.sh
```

Kernel outputs:

```text
build/pi4/vice310-images/kernel7l.img
build/pi4/vice310-images/kernel7l.img.c64
build/pi4/vice310-images/kernel7l.img.c64sc
build/pi4/vice310-images/kernel7l.img.scpu64
build/pi4/vice310-images/kernel7l.img.c128
build/pi4/vice310-images/kernel7l.img.vic20
build/pi4/vice310-images/kernel7l.img.plus4
build/pi4/vice310-images/kernel7l.img.pet
```

Stage a boot partition tree:

```sh
tools/pi4/stage_pi4_sd.sh
```

By default, Pi4 staging writes to `pi4-test/sdcard`.

Public source exports do not contain ROM files. In that case staging still
copies kernels, boot files, keymaps, menus and the SD skeleton, then writes
`MISSING-ROMS.txt` into the staged tree. Add the listed files before booting.
Each machine directory also contains `ROMS.txt` with the required machine ROMs.

Install the staged files to a mounted FAT boot partition:

```sh
tools/install_sd.sh pi4 /path/to/mounted/boot
```

The install target must be the exact mounted FAT/vfat boot partition, not a
directory below it. The script checks that the stage contains `cmdline.txt`,
`config.txt` and `kernel7l.img`, refuses targets on the current system disk,
then clears the top level of the target partition before copying the staged
tree.

## Pi5 / Pi500

Build Circle, VICE and all currently enabled machine kernels:

```sh
tools/pi5/build_pi5.sh
```

Kernel outputs:

```text
build/pi5/vice310-images/kernel_2712.img
build/pi5/vice310-images/kernel_2712.img.c64
build/pi5/vice310-images/kernel_2712.img.c64sc
build/pi5/vice310-images/kernel_2712.img.scpu64
build/pi5/vice310-images/kernel_2712.img.c128
build/pi5/vice310-images/kernel_2712.img.vic20
build/pi5/vice310-images/kernel_2712.img.plus4
build/pi5/vice310-images/kernel_2712.img.pet
```

Stage a boot partition tree:

```sh
tools/pi5/stage_pi5_sd.sh
```

By default, Pi5 staging writes to `pi5-test/sdcard`.

Public source exports do not contain ROM files. In that case staging still
copies kernels, boot files, keymaps, menus and the SD skeleton, then writes
`MISSING-ROMS.txt` into the staged tree. Add the listed files before booting.
Each machine directory also contains `ROMS.txt` with the required machine ROMs.

Install the staged files to a mounted FAT boot partition:

```sh
tools/install_sd.sh pi5 /path/to/mounted/boot
```

The install target must be the exact mounted FAT/vfat boot partition, not a
directory below it. The script checks that the stage contains `cmdline.txt`,
`config.txt` and `kernel_2712.img`, refuses targets on the current system disk,
then clears the top level of the target partition before copying the staged
tree.

Pi5/Pi500 staging enables Pi5KMS by default through `pi5kms=1` in
`cmdline.txt`. If a monitor or capture device does not work with Pi5KMS, set
`pi5kms=0` or remove the option to use the firmware-provided framebuffer path.

For Raspberry Pi 5 boards, staging also adds `gpiofanpin=45` to `cmdline.txt`
so the Raspberry Pi 5 case fan / Active Cooler can be driven by Circle's CPU
throttling support.

## Staging Profiles

The Pi4 and Pi5 staging scripts support two boot config profiles:

```sh
tools/pi4/stage_pi4_sd.sh --profile release
tools/pi4/stage_pi4_sd.sh --profile debug
tools/pi5/stage_pi5_sd.sh --profile release
tools/pi5/stage_pi5_sd.sh --profile debug
```

`release` is the default and does not enable staged UART diagnostics. `debug`
enables UART diagnostics, second-stage firmware UART logging and
`enable_serial=1`. The old `--debug-uart` option remains as an alias for
`--profile debug`.

## Full SD Card Creation

`tools/create_bmx_sd.py` prepares a complete two-partition BMX card from a
staged boot tree. It creates a 512 MiB FAT32 `BMX BOOT` partition by default,
a FAT32 `BMX USER` partition using the remaining space, copies the staged boot
files, and creates the standard user directories for disks, tapes, carts,
snapshots and phonebooks. Values below 512 MiB are rejected for new BMX cards;
this reserves space for transactional updates and the planned large Amiga
kernels.

Run it once without `--yes` to verify the target device and layout:

```sh
tools/create_bmx_sd.py --device /dev/sdX --stage-dir pi5-test/sdcard
```

Then run the destructive write explicitly:

```sh
sudo tools/create_bmx_sd.py --device /dev/sdX --stage-dir pi5-test/sdcard --yes --unmount
```

Use the whole block device, for example `/dev/sdX` or `/dev/mmcblk0`, not a
partition such as `/dev/sdX1`. `--unmount` allows the script to unmount already
mounted target partitions before repartitioning. For a Pi4/Pi400 card, pass the
Pi4 stage directory, for example `--stage-dir pi4-test/sdcard`.

## Shared Paths

The build, stage and install scripts share this path contract:

| Variable | Meaning |
| --- | --- |
| `BMC64_BUILD_ROOT` | Build root, defaults to `build` |
| `BMC64_STAGE_DIR` | Shared stage directory override |
| `PI4_STAGE_DIR` | Pi4-specific stage directory override |
| `PI5_STAGE_DIR` | Pi5-specific stage directory override |
| `BMC64_KERNEL_DIR` | Stage input override for prebuilt kernels |
| `BMC64_BUILD_PROFILE` | Boot config profile for staging, `release` or `debug` |
