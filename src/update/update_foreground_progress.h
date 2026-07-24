#ifndef BMX_UPDATE_UPDATE_FOREGROUND_PROGRESS_H
#define BMX_UPDATE_UPDATE_FOREGROUND_PROGRESS_H

#include "update/update_recovery_progress.h"

namespace bmx {
namespace update {

// These are the only labels exposed to the target menu.  In particular, the
// foreground UI never receives a URL, path, manifest string or configuration
// value.
enum class UpdateForegroundPhase : uint8_t {
    Discovery = 0,
    Manifest,
    Zip,
    Hash,
    Stage,
    Reboot
};

enum class UpdateForegroundCancelBehavior : uint8_t {
    // The caller is at a transaction boundary at which returning false causes
    // an immediate abort/rollback.  Download callers must remove their .part
    // object before returning to the menu.
    CancelAtCheckpoint = 0,
    // The current operation is mandatory cleanup, commit or rollback work.
    // Cancellation is recorded and displayed, but Report() continues to
    // return true until a later caller-owned safe boundary.
    MandatoryCompletion
};

struct UpdateForegroundUiEvent {
    UpdateForegroundPhase phase;
    // A deliberately bounded presentation value.  1000 means 100.0%.
    uint16_t progress_per_mille;
    bool determinate;
    bool cancel_enabled;
    bool cancel_pending;
};

class UpdateForegroundUi {
public:
    virtual ~UpdateForegroundUi() {}
    virtual bool Begin() = 0;
    virtual void Present(const UpdateForegroundUiEvent &event) = 0;
    // Pumps one target UI/input iteration and returns true when the user has
    // requested cancellation.  Implementations must not perform update or
    // network work from this callback.
    virtual bool PumpAndReadCancel() = 0;
    virtual void End() = 0;
};

// One instance belongs to one synchronous, explicitly selected Update menu
// action.  Merely constructing it is inert.  BeginExplicit() is intentionally
// separate so background, boot and menu-rendering paths cannot start UI or
// network work by accident.
class UpdateForegroundProgress : public UpdateRecoveryProgress {
public:
    explicit UpdateForegroundProgress(UpdateForegroundUi *ui);

    bool BeginExplicit();
    void EndExplicit();

    bool Checkpoint(
        UpdateForegroundPhase phase,
        uint64_t completed_bytes = 0U,
        uint64_t total_bytes = 0U,
        UpdateForegroundCancelBehavior behavior =
            UpdateForegroundCancelBehavior::CancelAtCheckpoint);

    // Maps bounded installer/orchestrator work onto Hash, Stage and Reboot.
    // A foreground cancel stops at a safe stage checkpoint; mandatory
    // rollback/cleanup reports remain non-interruptible.
    bool Report(const UpdateRecoveryProgressEvent &event) override;

    // Called by the owner of rollback/cleanup, never inferred from a progress
    // event.  While one or more scopes are active, newly arriving cancel is
    // latched and displayed but cannot interrupt the safety operation.
    void BeginMandatoryOperation() override;
    void EndMandatoryOperation() override;

    bool active() const { return active_; }
    bool cancel_requested() const { return cancel_requested_; }
    bool cancel_deferred() const { return cancel_deferred_; }
    bool mandatory_operation_active() const {
        return mandatory_operation_depth_ != 0U ||
               mandatory_operation_overflowed_;
    }
    UpdateForegroundPhase phase() const { return phase_; }

private:
    UpdateForegroundProgress(const UpdateForegroundProgress &);
    UpdateForegroundProgress &operator=(const UpdateForegroundProgress &);

    UpdateForegroundUiEvent BuildEvent(
        UpdateForegroundPhase phase,
        uint64_t completed_bytes,
        uint64_t total_bytes,
        UpdateForegroundCancelBehavior behavior) const;

    UpdateForegroundUi *ui_;
    UpdateForegroundPhase phase_;
    bool active_;
    bool cancel_requested_;
    bool cancel_deferred_;
    uint16_t hash_progress_per_mille_;
    bool hash_contents_complete_;
    uint16_t stage_progress_per_mille_;
    uint32_t mandatory_operation_depth_;
    bool mandatory_operation_overflowed_;
    // Set after a cancelable checkpoint has returned false to its owner. All
    // later recovery/installer reports belong to caller-mandated cleanup and
    // must no longer interrupt rollback, even if that rollback hashes files
    // before emitting its first explicit rollback-step event.
    bool stop_signaled_;
};

const char *UpdateForegroundPhaseString(UpdateForegroundPhase phase);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_FOREGROUND_PROGRESS_H
