#include "update/tryboot_reboot_control.h"

#include "update/tryboot_control.h"
#include "update/update_fault_injection.h"

#include <string.h>

#if defined(RASPI_COMPILE)
#include <circle/startup.h>

extern "C" int emux_prepare_shutdown(void);
extern "C" int circle_prepare_system_shutdown(void);
#endif

namespace bmx {
namespace update {

namespace {

bool ProductionSupported(void *)
{
    return TrybootHardwareGateEnabled();
}

TrybootStatus ProductionArm(void *)
{
    return ArmOneShotTryboot();
}

TrybootStatus ProductionClear(void *)
{
    return ClearOneShotTryboot();
}

bool ProductionPrepare(void *)
{
#if defined(RASPI_COMPILE)
    return emux_prepare_shutdown() == 0 &&
           circle_prepare_system_shutdown() == 0;
#else
    return false;
#endif
}

void ProductionReboot(void *)
{
#if defined(RASPI_COMPILE)
    reboot();
#endif
}

}  // namespace

TrybootUpdateRebootControl::TrybootUpdateRebootControl(
    const TrybootRebootOperations &operations)
    : operations_(operations),
      last_status_(TrybootRebootControlStatus::InvalidOperations),
      last_tryboot_status_(TrybootStatus::InvalidArgument)
{
}

bool TrybootUpdateRebootControl::OperationsValid() const
{
    return operations_.supported != 0 && operations_.arm_one_shot != 0 &&
           operations_.clear_one_shot != 0 &&
           operations_.prepare_shutdown != 0 && operations_.reboot != 0;
}

bool TrybootUpdateRebootControl::OneShotRecoverySupported() const
{
    return OperationsValid() && operations_.supported(operations_.context);
}

bool TrybootUpdateRebootControl::RequestReboot(
    UpdateRebootTarget target, const AuthenticatedUpdateBinding &binding)
{
    // The candidate request must carry a fully bound nonzero transaction.
    // Previous/failsafe selection deliberately ignores caller-controlled
    // identity and is handled by the same binding-independent path below.
    if (!OperationsValid()) {
        last_status_ = TrybootRebootControlStatus::InvalidOperations;
        return false;
    }
    if (!OneShotRecoverySupported()) {
        last_status_ = TrybootRebootControlStatus::GateClosed;
        return false;
    }
    if (target == UpdateRebootTarget::PreviousInstallation) {
        return RequestPrevious();
    }
    bool transaction_nonzero = false;
    for (size_t index = 0U; index < kTransactionIdBytes; ++index) {
        transaction_nonzero = transaction_nonzero ||
                              binding.transaction_id[index] != 0U;
    }
    if (!transaction_nonzero || binding.target_release_sequence == 0U ||
        binding.source_release_sequence == 0U ||
        binding.target_release_sequence <= binding.source_release_sequence) {
        last_status_ = TrybootRebootControlStatus::InvalidOperations;
        return false;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootBeforeShutdownPrepare);
    if (!operations_.prepare_shutdown(operations_.context)) {
        last_status_ = TrybootRebootControlStatus::PrepareFailed;
        return false;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootAfterShutdownPrepare);
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootBeforeArm);
    last_tryboot_status_ = operations_.arm_one_shot(operations_.context);
    if (last_tryboot_status_ != TrybootStatus::Armed) {
        last_status_ = TrybootRebootControlStatus::ArmFailed;
        return false;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterArm);
    last_status_ = TrybootRebootControlStatus::Ok;
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootBeforeCandidateReboot);
    operations_.reboot(operations_.context);
    return true;
}

bool TrybootUpdateRebootControl::RequestPrevious()
{
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootBeforeShutdownPrepare);
    if (!operations_.prepare_shutdown(operations_.context)) {
        last_status_ = TrybootRebootControlStatus::PrepareFailed;
        return false;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootAfterShutdownPrepare);
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootBeforeClear);
    last_tryboot_status_ = operations_.clear_one_shot(operations_.context);
    if (last_tryboot_status_ != TrybootStatus::Cleared) {
        last_status_ = TrybootRebootControlStatus::ClearFailed;
        return false;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::TrybootAfterClear);
    last_status_ = TrybootRebootControlStatus::Ok;
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::TrybootBeforePreviousReboot);
    operations_.reboot(operations_.context);
    return true;
}

bool TrybootUpdateRebootControl::RequestPreviousBootFailSafe()
{
    if (!OperationsValid()) {
        last_status_ = TrybootRebootControlStatus::InvalidOperations;
        return false;
    }
    if (!OneShotRecoverySupported()) {
        last_status_ = TrybootRebootControlStatus::GateClosed;
        return false;
    }
    return RequestPrevious();
}

TrybootRebootOperations ProductionTrybootRebootOperations()
{
    TrybootRebootOperations operations;
    memset(&operations, 0, sizeof(operations));
    operations.supported = ProductionSupported;
    operations.arm_one_shot = ProductionArm;
    operations.clear_one_shot = ProductionClear;
    operations.prepare_shutdown = ProductionPrepare;
    operations.reboot = ProductionReboot;
    return operations;
}

const char *TrybootRebootControlStatusString(
    TrybootRebootControlStatus status)
{
    switch (status) {
    case TrybootRebootControlStatus::Ok: return "ok";
    case TrybootRebootControlStatus::InvalidOperations:
        return "invalid reboot operations";
    case TrybootRebootControlStatus::GateClosed:
        return "tryboot/recovery hardware gate closed";
    case TrybootRebootControlStatus::PrepareFailed:
        return "shutdown preparation failed";
    case TrybootRebootControlStatus::ArmFailed:
        return "one-shot tryboot arm failed";
    case TrybootRebootControlStatus::ClearFailed:
        return "one-shot tryboot clear failed";
    }
    return "unknown reboot control error";
}

}  // namespace update
}  // namespace bmx
