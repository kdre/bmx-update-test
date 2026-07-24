#include "update/tryboot_control.h"

#include "update/update_fault_injection.h"
#include "update/update_hardware_test_mode.h"

#if defined(RASPI_COMPILE)
#include <circle/bcmpropertytags.h>
#include <circle/devicetreeblob.h>
#include <circle/machineinfo.h>
#include <circle/types.h>
#include <string.h>
#endif

namespace bmx {
namespace update {

namespace {

#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_TRYBOOT)
static const u32 kGetRebootFlags = 0x00030064U;
static const u32 kSetRebootFlags = 0x00038064U;
static const u32 kNotifyReboot = 0x00030048U;
static const u32 kTrybootFlag = 0x00000001U;

bool ReadFlags(u32 *flags) {
    TPropertyTagSimple tag;
    memset(&tag, 0, sizeof(tag));
    CBcmPropertyTags tags;
    if (!tags.GetTag(kGetRebootFlags, &tag, sizeof(tag))) return false;
    *flags = tag.nValue;
    return true;
}

bool SetFlags(u32 flags) {
    TPropertyTagSimple tag;
    memset(&tag, 0, sizeof(tag));
    tag.nValue = flags;
    CBcmPropertyTags tags;
    return tags.GetTag(kSetRebootFlags, &tag, sizeof(tag), sizeof(tag.nValue));
}

bool NotifyReboot() {
    // The firmware property has a zero-byte request/response. Circle's generic
    // GetTags transport requires a simple-tag-sized buffer, so the value slot
    // is present but its declared request length remains zero.
    TPropertyTagSimple tag;
    memset(&tag, 0, sizeof(tag));
    tag.Tag.nTagId = kNotifyReboot;
    tag.Tag.nValueBufSize = sizeof(tag.nValue);
    tag.Tag.nValueLength = 0U;
    CBcmPropertyTags tags;
    return tags.GetTags(&tag, sizeof(tag));
}
#endif

}  // namespace

bool TrybootHardwareGateEnabled() {
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_TRYBOOT)
    return true;
#else
    return false;
#endif
}

bool TrybootObservationHardwareGateEnabled() {
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_TRYBOOT_OBSERVATION)
    return true;
#else
    return false;
#endif
}

bool RunningBootWasOneShotTryboot() {
#if !defined(RASPI_COMPILE) || \
    !defined(BMX_UPDATE_ENABLE_TRYBOOT_OBSERVATION)
    return false;
#else
    const CDeviceTreeBlob *tree = CMachineInfo::Get()->GetDTB();
    if (tree == 0) return false;
    const TDeviceTreeNode *bootloader =
        tree->FindNode("/chosen/bootloader");
    if (bootloader == 0) return false;
    const TDeviceTreeProperty *tryboot =
        tree->FindProperty(bootloader, "tryboot");
    return tryboot != 0 && tree->GetPropertyValueLength(tryboot) == 4U &&
           tree->GetPropertyValueWord(tryboot, 0U) == 1U;
#endif
}

TrybootStatus ArmOneShotTryboot() {
#if !defined(RASPI_COMPILE) || !defined(BMX_UPDATE_ENABLE_TRYBOOT)
    return TrybootStatus::HardwareGateClosed;
#else
    u32 flags = 0U;
    if (!ReadFlags(&flags)) return TrybootStatus::ReadFlagsFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootBeforeFlagSet);
    if (!SetFlags(flags | kTrybootFlag)) return TrybootStatus::SetFlagsFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFlagSet);
    u32 readback = 0U;
    if (!ReadFlags(&readback) || (readback & kTrybootFlag) == 0U) {
        return TrybootStatus::ReadbackFailed;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFlagReadback);
    if (!NotifyReboot()) return TrybootStatus::NotifyFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFirmwareNotify);
    return TrybootStatus::Armed;
#endif
}

TrybootStatus ClearOneShotTryboot() {
#if !defined(RASPI_COMPILE) || !defined(BMX_UPDATE_ENABLE_TRYBOOT)
    return TrybootStatus::HardwareGateClosed;
#else
    u32 flags = 0U;
    if (!ReadFlags(&flags)) return TrybootStatus::ReadFlagsFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootBeforeFlagSet);
    if (!SetFlags(flags & ~kTrybootFlag)) return TrybootStatus::SetFlagsFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFlagSet);
    u32 readback = 0U;
    if (!ReadFlags(&readback) || (readback & kTrybootFlag) != 0U) {
        return TrybootStatus::ReadbackFailed;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFlagReadback);
    if (!NotifyReboot()) return TrybootStatus::NotifyFailed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterFirmwareNotify);
    return TrybootStatus::Cleared;
#endif
}

const char *TrybootStatusString(TrybootStatus status) {
    switch (status) {
    case TrybootStatus::Armed: return "tryboot armed";
    case TrybootStatus::Cleared: return "tryboot cleared";
    case TrybootStatus::InvalidArgument: return "invalid argument";
    case TrybootStatus::HardwareGateClosed:
        return "tryboot hardware validation gate is closed";
    case TrybootStatus::ReadFlagsFailed: return "cannot read reboot flags";
    case TrybootStatus::SetFlagsFailed: return "cannot set tryboot flag";
    case TrybootStatus::ReadbackFailed: return "tryboot flag readback failed";
    case TrybootStatus::NotifyFailed: return "firmware reboot notification failed";
    }
    return "unknown tryboot error";
}

}  // namespace update
}  // namespace bmx
