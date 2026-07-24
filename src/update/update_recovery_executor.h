#ifndef BMX_UPDATE_UPDATE_RECOVERY_EXECUTOR_H
#define BMX_UPDATE_UPDATE_RECOVERY_EXECUTOR_H

#include "update/update_transaction_store.h"

namespace bmx {
namespace update {

typedef bool (*UpdateRecoveryCandidateBootProbe)(void *context);

struct UpdateRecoveryExecutorScratch {
    // Mandatory caller-owned output for UpdateTransactionRequestStore::Load.
    // ValidatedReleaseDownload embeds a roughly 27 KiB ReleaseOffer and must
    // remain outside the 128 KiB Circle kernel stack.  Its raw byte views
    // remain valid because their storage is supplied by request_buffers.
    ValidatedReleaseDownload *release_download;
};

enum class UpdateRecoveryExecutorStatus : uint8_t {
    NoPendingTransaction = 0,
    ResumeFinished,
    RejectedStateDiscarded,
    PreviousBootFailSafeRequested,
    InvalidArgument,
    AlreadyRun,
    LoadFailed,
    LoadWorkspaceTooSmall,
    DiscardFailed,
    PreviousBootFailSafeFailed,
    RecoveryProgressFailed
};

// A compact result deliberately retains only the two ResumeAfterBoot fields
// needed by the early boot integration. The complete orchestrator result is
// synchronous and remains owned by that call; no unbounded state is retained.
struct UpdateRecoveryExecutorResult {
    UpdateRecoveryExecutorStatus status;
    UpdateTransactionStoreStatus load_status;
    UpdateTransactionStoreStatus discard_status;
    UpdateOrchestratorStatus resume_status;
    UpdateOrchestratorPhase resume_phase;
    bool resume_called;
    bool discard_attempted;
    bool candidate_boot;
    bool previous_boot_failsafe_requested;
};

// Executes the network-free post-boot half of one actively persisted update
// exactly once per object/boot. It deliberately loads only
// request-state.bin: a post-commit committed-state.bin is inert and remains
// reserved for a later, explicit foreground retirement action. It always
// addresses kUpdateTransactionRoot; no path, URL, release identity or digest
// is accepted from the boot environment.
class UpdateRecoveryExecutor {
public:
    UpdateRecoveryExecutor(
        UpdateTransactionRequestStore *request_store,
        UpdateOrchestrator *orchestrator,
        UpdateRebootControl *reboot,
        BoardFamily running_board,
        const PersistedUpdateRequestBuffers &request_buffers,
        const UpdateOrchestratorWorkspace &orchestrator_workspace,
        const UpdateRecoveryExecutorScratch &scratch,
        UpdateRecoveryCandidateBootProbe candidate_boot_probe,
        void *candidate_boot_context);

    UpdateRecoveryExecutorResult Run();
    bool has_run() const { return has_run_; }

private:
    UpdateRecoveryExecutor(const UpdateRecoveryExecutor &);
    UpdateRecoveryExecutor &operator=(const UpdateRecoveryExecutor &);

    UpdateTransactionRequestStore *request_store_;
    UpdateOrchestrator *orchestrator_;
    UpdateRebootControl *reboot_;
    BoardFamily running_board_;
    PersistedUpdateRequestBuffers request_buffers_;
    UpdateOrchestratorWorkspace orchestrator_workspace_;
    UpdateRecoveryExecutorScratch scratch_;
    UpdateRecoveryCandidateBootProbe candidate_boot_probe_;
    void *candidate_boot_context_;
    bool has_run_;
};

const char *UpdateRecoveryExecutorStatusString(
    UpdateRecoveryExecutorStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_RECOVERY_EXECUTOR_H
