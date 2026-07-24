#include "update/update_recovery_executor.h"

#include <string.h>

namespace bmx {
namespace update {
namespace {

UpdateRecoveryExecutorResult InitialResult()
{
    UpdateRecoveryExecutorResult result;
    memset(&result, 0, sizeof(result));
    result.status = UpdateRecoveryExecutorStatus::InvalidArgument;
    result.load_status = UpdateTransactionStoreStatus::InvalidArgument;
    result.discard_status = UpdateTransactionStoreStatus::InvalidArgument;
    result.resume_status = UpdateOrchestratorStatus::InvalidArgument;
    result.resume_phase = UpdateOrchestratorPhase::None;
    return result;
}

bool BuffersValid(const PersistedUpdateRequestBuffers &buffers)
{
    return buffers.installed_build_info != 0 &&
           buffers.installed_build_info_capacity != 0U &&
           buffers.github_response != 0 &&
           buffers.github_response_capacity != 0U &&
           buffers.manifest != 0 && buffers.manifest_capacity != 0U &&
           buffers.signature != 0 && buffers.signature_capacity != 0U;
}

bool WorkspaceValid(const UpdateOrchestratorWorkspace &workspace)
{
    return workspace.release_offer != 0 &&
           workspace.installer.io_buffer != 0 &&
           workspace.installer.io_buffer_size >=
               kInstallerMinimumIoBufferBytes &&
           workspace.verification_buffer != 0 &&
           workspace.verification_buffer_size >= 4096U &&
           workspace.recovery_progress != 0;
}

bool MustDeactivate(UpdateTransactionStoreStatus status)
{
    return status == UpdateTransactionStoreStatus::InvalidIdentity ||
           status == UpdateTransactionStoreStatus::Conflict ||
           status == UpdateTransactionStoreStatus::FileSystemError ||
           status == UpdateTransactionStoreStatus::Corrupt ||
           status == UpdateTransactionStoreStatus::HashMismatch;
}

}  // namespace

UpdateRecoveryExecutor::UpdateRecoveryExecutor(
    UpdateTransactionRequestStore *request_store,
    UpdateOrchestrator *orchestrator,
    UpdateRebootControl *reboot,
    BoardFamily running_board,
    const PersistedUpdateRequestBuffers &request_buffers,
    const UpdateOrchestratorWorkspace &orchestrator_workspace,
    const UpdateRecoveryExecutorScratch &scratch,
    UpdateRecoveryCandidateBootProbe candidate_boot_probe,
    void *candidate_boot_context)
    : request_store_(request_store), orchestrator_(orchestrator),
      reboot_(reboot), running_board_(running_board),
      request_buffers_(request_buffers),
      orchestrator_workspace_(orchestrator_workspace),
      scratch_(scratch),
      candidate_boot_probe_(candidate_boot_probe),
      candidate_boot_context_(candidate_boot_context), has_run_(false)
{
}

UpdateRecoveryExecutorResult UpdateRecoveryExecutor::Run()
{
    UpdateRecoveryExecutorResult result = InitialResult();
    if (has_run_) {
        result.status = UpdateRecoveryExecutorStatus::AlreadyRun;
        return result;
    }
    // Mark before touching local state so re-entrant or retried callers cannot
    // execute a second recovery transition during the same boot.
    has_run_ = true;

    if (request_store_ == 0 || orchestrator_ == 0 || reboot_ == 0 ||
        !IsKnownBoardFamily(running_board_) ||
        !BuffersValid(request_buffers_) ||
        !WorkspaceValid(orchestrator_workspace_) ||
        scratch_.release_download == 0 ||
        candidate_boot_probe_ == 0) {
        return result;
    }

    ValidatedReleaseDownload &release = *scratch_.release_download;
    AuthenticatedUpdateRequest request;
    result.load_status = request_store_->Load(
        kUpdateTransactionRoot, running_board_, request_buffers_, &release,
        &request, orchestrator_workspace_.recovery_progress);
    // Load() considers only the active request-state.bin. In particular, an
    // inert committed-state.bin must neither resume recovery nor cause a
    // candidate probe/reboot on later normal boots.
    if (result.load_status == UpdateTransactionStoreStatus::NotFound) {
        result.status = UpdateRecoveryExecutorStatus::NoPendingTransaction;
        return result;
    }
    if (result.load_status == UpdateTransactionStoreStatus::Ok) {
        result.resume_called = true;
        const UpdateOrchestratorResult resumed =
            orchestrator_->ResumeAfterBoot(request, orchestrator_workspace_);
        result.resume_status = resumed.status;
        result.resume_phase = resumed.phase;
        result.previous_boot_failsafe_requested =
            resumed.previous_boot_failsafe_requested;
        result.status = UpdateRecoveryExecutorStatus::ResumeFinished;
        return result;
    }
    if (result.load_status ==
            UpdateTransactionStoreStatus::RecoveryProgressFailed) {
        result.status = UpdateRecoveryExecutorStatus::RecoveryProgressFailed;
        return result;
    }
    if (result.load_status ==
            UpdateTransactionStoreStatus::WorkspaceTooSmall) {
        result.status = UpdateRecoveryExecutorStatus::LoadWorkspaceTooSmall;
        return result;
    }
    if (!MustDeactivate(result.load_status)) {
        result.status = UpdateRecoveryExecutorStatus::LoadFailed;
        return result;
    }

    // The fixed activation record is removed first by Discard(). Partial
    // cleanup therefore leaves only inert payload bytes and cannot retrigger
    // ResumeAfterBoot on a later boot.
    result.discard_attempted = true;
    result.discard_status = request_store_->Discard(
        kUpdateTransactionRoot, orchestrator_workspace_.recovery_progress);
    if (result.discard_status ==
            UpdateTransactionStoreStatus::RecoveryProgressFailed) {
        result.status = UpdateRecoveryExecutorStatus::RecoveryProgressFailed;
        return result;
    }
    if (result.discard_status != UpdateTransactionStoreStatus::Ok) {
        result.status = UpdateRecoveryExecutorStatus::DiscardFailed;
        return result;
    }

    result.candidate_boot = candidate_boot_probe_(candidate_boot_context_);
    if (!result.candidate_boot) {
        result.status =
            UpdateRecoveryExecutorStatus::RejectedStateDiscarded;
        return result;
    }

    result.previous_boot_failsafe_requested = true;
    if (!reboot_->RequestPreviousBootFailSafe()) {
        result.status =
            UpdateRecoveryExecutorStatus::PreviousBootFailSafeFailed;
        return result;
    }
    result.status =
        UpdateRecoveryExecutorStatus::PreviousBootFailSafeRequested;
    return result;
}

const char *UpdateRecoveryExecutorStatusString(
    UpdateRecoveryExecutorStatus status)
{
    switch (status) {
    case UpdateRecoveryExecutorStatus::NoPendingTransaction:
        return "no pending transaction";
    case UpdateRecoveryExecutorStatus::ResumeFinished:
        return "resume finished";
    case UpdateRecoveryExecutorStatus::RejectedStateDiscarded:
        return "rejected state discarded";
    case UpdateRecoveryExecutorStatus::PreviousBootFailSafeRequested:
        return "previous boot failsafe requested";
    case UpdateRecoveryExecutorStatus::InvalidArgument:
        return "invalid argument";
    case UpdateRecoveryExecutorStatus::AlreadyRun: return "already run";
    case UpdateRecoveryExecutorStatus::LoadFailed: return "load failed";
    case UpdateRecoveryExecutorStatus::LoadWorkspaceTooSmall:
        return "load workspace too small";
    case UpdateRecoveryExecutorStatus::DiscardFailed:
        return "discard failed";
    case UpdateRecoveryExecutorStatus::PreviousBootFailSafeFailed:
        return "previous boot failsafe failed";
    case UpdateRecoveryExecutorStatus::RecoveryProgressFailed:
        return "recovery progress failed";
    }
    return "unknown recovery executor status";
}

}  // namespace update
}  // namespace bmx
