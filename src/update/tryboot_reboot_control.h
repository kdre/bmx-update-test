#ifndef BMX_UPDATE_TRYBOOT_REBOOT_CONTROL_H
#define BMX_UPDATE_TRYBOOT_REBOOT_CONTROL_H

#include "update/tryboot_control.h"
#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

typedef bool (*TrybootGateFunction)(void *context);
typedef TrybootStatus (*TrybootOperationFunction)(void *context);
typedef bool (*PrepareUpdateRebootFunction)(void *context);
typedef void (*PerformUpdateRebootFunction)(void *context);

struct TrybootRebootOperations {
    TrybootGateFunction supported;
    TrybootOperationFunction arm_one_shot;
    TrybootOperationFunction clear_one_shot;
    PrepareUpdateRebootFunction prepare_shutdown;
    PerformUpdateRebootFunction reboot;
    void *context;
};

enum class TrybootRebootControlStatus : uint8_t {
    Ok = 0,
    InvalidOperations,
    GateClosed,
    PrepareFailed,
    ArmFailed,
    ClearFailed
};

class TrybootUpdateRebootControl : public UpdateRebootControl {
public:
    explicit TrybootUpdateRebootControl(
        const TrybootRebootOperations &operations);

    bool OneShotRecoverySupported() const;
    bool RequestReboot(UpdateRebootTarget target,
                       const AuthenticatedUpdateBinding &binding);
    bool RequestPreviousBootFailSafe();

    TrybootRebootControlStatus last_status() const { return last_status_; }
    TrybootStatus last_tryboot_status() const { return last_tryboot_status_; }

private:
    bool OperationsValid() const;
    bool RequestPrevious();

    TrybootRebootOperations operations_;
    TrybootRebootControlStatus last_status_;
    TrybootStatus last_tryboot_status_;
};

// Target factory. It binds emulator/file-system shutdown, the gated mailbox
// operations and Circle's reboot routine. The returned callbacks remain
// fail-closed in non-target or non-validated builds.
TrybootRebootOperations ProductionTrybootRebootOperations();

const char *TrybootRebootControlStatusString(
    TrybootRebootControlStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_TRYBOOT_REBOOT_CONTROL_H
