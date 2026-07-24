#ifndef BMX_UPDATE_TRYBOOT_CONTROL_H
#define BMX_UPDATE_TRYBOOT_CONTROL_H

#include <stdint.h>

namespace bmx {
namespace update {

enum class TrybootStatus : uint8_t {
    Armed = 0,
    Cleared,
    InvalidArgument,
    HardwareGateClosed,
    ReadFlagsFailed,
    SetFlagsFailed,
    ReadbackFailed,
    NotifyFailed
};

// Arms the Raspberry Pi firmware's one-shot tryboot flag. Production builds
// remain fail-closed until BMX_UPDATE_TRYBOOT_HARDWARE_VALIDATED is set after
// the documented Pi4/Pi400/Pi5/Pi500 recovery matrix has passed.
TrybootStatus ArmOneShotTryboot();
// Clears a stale one-shot flag before deliberately returning to the previous
// installation. Like Arm, this is inert until the hardware gate is open.
TrybootStatus ClearOneShotTryboot();

bool TrybootHardwareGateEnabled();

// The firmware consumes and clears the reboot flag before loading BMX. The
// authoritative current-boot observation is the firmware-provided
// `/chosen/bootloader/tryboot` u32 in the device tree. This separate gate is
// enabled only after that property has passed the target hardware matrix.
bool TrybootObservationHardwareGateEnabled();
bool RunningBootWasOneShotTryboot();

const char *TrybootStatusString(TrybootStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_TRYBOOT_CONTROL_H
