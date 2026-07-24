#ifndef BMX_UPDATE_UPDATE_RECOVERY_PROGRESS_H
#define BMX_UPDATE_UPDATE_RECOVERY_PROGRESS_H

#include "update/update_types.h"

namespace bmx {
namespace update {

// Recovery is deliberately synchronous.  A progress report is emitted only
// after a bounded unit of local work completed successfully; it is never a
// timer or permission to feed a watchdog in the background.
enum class UpdateRecoveryProgressKind : uint8_t {
    BootInitializationMilestone = 0,
    RecoveryPrecheck,
    TransactionStateRead,
    TransactionPayloadRead,
    TransactionCleanup,
    PreparedEvidenceRead,
    PreparedFileVerified,
    PreparedCleanup,
    CandidateFileHashed,
    CandidateJournalRead,
    InstallerFileHashed,
    InstallerFileCopied,
    InstallerJournalPersisted,
    InstallerCommitStep,
    InstallerRollbackStep,
    ArchiveCleanup,
    // Foreground-only checkpoints.  Boot recovery never synthesizes them;
    // they reuse the same synchronous callback so logging/watchdog/UI
    // delegates can be composed without a timer or background worker.
    StoredArchiveHashed,
    CandidateRebootCheckpoint,
    // Cancelable foreground safe points immediately before the first
    // persistent mutation of a new download or retained installation.
    ForegroundDownloadMutationCheckpoint,
    ForegroundRetireMutationCheckpoint,
    // Foreground archive-integrity passes are deliberately distinct so the
    // UI can compose them into one monotone Hash phase without guessing
    // which full-media pass an otherwise identical byte counter belongs to.
    PreparedArchiveInitialHashed,
    PreparedArchiveFinalHashed,
    InstallerArchiveHashed,
    // Aggregate/decision events appended to preserve the numeric identity of
    // all existing callbacks.  Health and rollback details are low-frequency
    // and are persisted before recovery can reboot away from the candidate.
    CandidateEvidenceRead,
    CandidateHealthEvaluated,
    CandidateRollbackDecision,
    ForegroundStageComplete,
    CandidateRollbackComplete,
    InstallerStageOverall,
    // One low-frequency Stage planning event. completed_bytes is the number
    // of changed files; total_bytes is the number of content no-ops.
    InstallerContentPlanSummary
};

struct UpdateRecoveryProgressEvent {
    UpdateRecoveryProgressKind kind;
    uint64_t completed_bytes;
    uint64_t total_bytes;
};

class UpdateRecoveryProgress {
public:
    virtual ~UpdateRecoveryProgress() {}

    // The operation owner brackets work which must run to its own durable
    // completion once entered (for example rollback or post-mutation
    // cleanup).  Decorators must forward these calls to their delegate.
    // Implementations must support nesting because one mandatory operation
    // may invoke another cleanup helper.
    virtual void BeginMandatoryOperation() {}
    virtual void EndMandatoryOperation() {}

    // Returning false is terminal for the current recovery call.  Callers
    // must stop doing work and leave the owned watchdog armed so reset falls
    // back through the already-cleared normal boot path.
    virtual bool Report(const UpdateRecoveryProgressEvent &event) = 0;
};

// Keeps the mandatory-completion policy tied to the actual synchronous
// operation instead of inferring ownership from individual progress kinds.
// Destruction on every return path balances the operation latch even though
// target builds use neither exceptions nor RTTI.
class ScopedMandatoryUpdateRecoveryOperation {
public:
    explicit ScopedMandatoryUpdateRecoveryOperation(
        UpdateRecoveryProgress *progress)
        : progress_(progress)
    {
        if (progress_ != 0) progress_->BeginMandatoryOperation();
    }

    ~ScopedMandatoryUpdateRecoveryOperation()
    {
        if (progress_ != 0) progress_->EndMandatoryOperation();
    }

private:
    ScopedMandatoryUpdateRecoveryOperation(
        const ScopedMandatoryUpdateRecoveryOperation &);
    ScopedMandatoryUpdateRecoveryOperation &operator=(
        const ScopedMandatoryUpdateRecoveryOperation &);

    UpdateRecoveryProgress *progress_;
};

inline bool ReportUpdateRecoveryProgress(
    UpdateRecoveryProgress *progress, UpdateRecoveryProgressKind kind,
    uint64_t completed_bytes = 0U, uint64_t total_bytes = 0U)
{
    if (progress == 0) return true;
    UpdateRecoveryProgressEvent event;
    event.kind = kind;
    event.completed_bytes = completed_bytes;
    event.total_bytes = total_bytes;
    return progress->Report(event);
}

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_RECOVERY_PROGRESS_H
