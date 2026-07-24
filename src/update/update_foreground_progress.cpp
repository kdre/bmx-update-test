#include "update/update_foreground_progress.h"

namespace bmx {
namespace update {
namespace {

// Four whole-archive bindings form one user-visible verification operation.
// The final pass authenticates the downloaded bytes against the signed asset;
// unchanged members therefore need not be inflated a second time.
static const uint16_t kStoredArchiveHashEndPerMille = 160U;
static const uint16_t kPreparedInitialHashEndPerMille = 320U;
static const uint16_t kPreparedFinalHashEndPerMille = 480U;
static const uint16_t kInstallerArchiveHashEndPerMille = 1000U;

uint16_t RatioPerMille(uint64_t completed_bytes, uint64_t total_bytes)
{
    if (total_bytes == 0U) return 0U;
    if (completed_bytes >= total_bytes) return 1000U;
    const uint64_t whole = completed_bytes / total_bytes;
    const uint64_t remainder = completed_bytes % total_bytes;
    uint64_t scaled = whole * 1000U;
    if (remainder <= UINT64_MAX / 1000U) {
        scaled += (remainder * 1000U) / total_bytes;
    } else {
        scaled += remainder / (total_bytes / 1000U + 1U);
    }
    return static_cast<uint16_t>(scaled > 1000U ? 1000U : scaled);
}

bool HashPhaseSpan(UpdateRecoveryProgressKind kind, uint16_t *begin,
                   uint16_t *end)
{
    if (begin == 0 || end == 0) return false;
    switch (kind) {
    case UpdateRecoveryProgressKind::StoredArchiveHashed:
        *begin = 0U;
        *end = kStoredArchiveHashEndPerMille;
        return true;
    case UpdateRecoveryProgressKind::PreparedArchiveInitialHashed:
        *begin = kStoredArchiveHashEndPerMille;
        *end = kPreparedInitialHashEndPerMille;
        return true;
    case UpdateRecoveryProgressKind::PreparedArchiveFinalHashed:
        *begin = kPreparedInitialHashEndPerMille;
        *end = kPreparedFinalHashEndPerMille;
        return true;
    case UpdateRecoveryProgressKind::InstallerArchiveHashed:
        *begin = kPreparedFinalHashEndPerMille;
        *end = kInstallerArchiveHashEndPerMille;
        return true;
    default:
        return false;
    }
}

uint16_t HashPhasePerMille(const UpdateRecoveryProgressEvent &event,
                           uint16_t begin, uint16_t end)
{
    const uint16_t ratio = RatioPerMille(event.completed_bytes,
                                         event.total_bytes);
    const uint16_t span = end - begin;
    return static_cast<uint16_t>(
        begin +
        (static_cast<uint32_t>(ratio) * span) / 1000U);
}

bool IsMandatoryProgress(UpdateRecoveryProgressKind kind)
{
    switch (kind) {
    case UpdateRecoveryProgressKind::InstallerCommitStep:
    case UpdateRecoveryProgressKind::InstallerRollbackStep:
    case UpdateRecoveryProgressKind::ArchiveCleanup:
    case UpdateRecoveryProgressKind::PreparedCleanup:
    case UpdateRecoveryProgressKind::TransactionCleanup:
        return true;
    default:
        return false;
    }
}

UpdateForegroundPhase MapProgressPhase(UpdateRecoveryProgressKind kind,
                                       UpdateForegroundPhase current)
{
    switch (kind) {
    case UpdateRecoveryProgressKind::ForegroundDownloadMutationCheckpoint:
        return UpdateForegroundPhase::Zip;
    case UpdateRecoveryProgressKind::ForegroundRetireMutationCheckpoint:
        return UpdateForegroundPhase::Stage;
    case UpdateRecoveryProgressKind::StoredArchiveHashed:
    case UpdateRecoveryProgressKind::PreparedArchiveInitialHashed:
    case UpdateRecoveryProgressKind::PreparedArchiveFinalHashed:
    case UpdateRecoveryProgressKind::InstallerArchiveHashed:
        return UpdateForegroundPhase::Hash;
    case UpdateRecoveryProgressKind::ForegroundStageComplete:
    case UpdateRecoveryProgressKind::InstallerStageOverall:
    case UpdateRecoveryProgressKind::InstallerContentPlanSummary:
        return UpdateForegroundPhase::Stage;
    case UpdateRecoveryProgressKind::CandidateRebootCheckpoint:
        return UpdateForegroundPhase::Reboot;
    case UpdateRecoveryProgressKind::InstallerFileHashed:
        // Installer validation can hash a file after staging has started.
        // Never make the six-phase display jump backwards in that case.
        return current == UpdateForegroundPhase::Stage
                   ? UpdateForegroundPhase::Stage
                   : UpdateForegroundPhase::Hash;
    case UpdateRecoveryProgressKind::InstallerFileCopied:
    case UpdateRecoveryProgressKind::InstallerJournalPersisted:
    case UpdateRecoveryProgressKind::InstallerCommitStep:
    case UpdateRecoveryProgressKind::InstallerRollbackStep:
    case UpdateRecoveryProgressKind::PreparedFileVerified:
    case UpdateRecoveryProgressKind::PreparedCleanup:
    case UpdateRecoveryProgressKind::ArchiveCleanup:
        return UpdateForegroundPhase::Stage;
    default:
        return current;
    }
}

}  // namespace

UpdateForegroundProgress::UpdateForegroundProgress(UpdateForegroundUi *ui)
    : ui_(ui), phase_(UpdateForegroundPhase::Discovery), active_(false),
      cancel_requested_(false), cancel_deferred_(false),
      hash_progress_per_mille_(0U), hash_contents_complete_(false),
      stage_progress_per_mille_(0U),
      mandatory_operation_depth_(0U),
      mandatory_operation_overflowed_(false), stop_signaled_(false)
{
}

bool UpdateForegroundProgress::BeginExplicit()
{
    if (active_ || ui_ == 0 || !ui_->Begin()) return false;
    phase_ = UpdateForegroundPhase::Discovery;
    active_ = true;
    cancel_requested_ = false;
    cancel_deferred_ = false;
    hash_progress_per_mille_ = 0U;
    hash_contents_complete_ = false;
    stage_progress_per_mille_ = 0U;
    mandatory_operation_depth_ = 0U;
    mandatory_operation_overflowed_ = false;
    stop_signaled_ = false;
    (void) Checkpoint(UpdateForegroundPhase::Discovery);
    return true;
}

void UpdateForegroundProgress::EndExplicit()
{
    if (active_ && ui_ != 0) ui_->End();
    active_ = false;
    mandatory_operation_depth_ = 0U;
    mandatory_operation_overflowed_ = false;
}

void UpdateForegroundProgress::BeginMandatoryOperation()
{
    if (!active_) return;
    // Saturation is fail-safe: an impossible nesting overflow keeps
    // cancellation deferred instead of accidentally reopening a mandatory
    // operation.
    if (mandatory_operation_overflowed_) return;
    if (mandatory_operation_depth_ == UINT32_MAX) {
        mandatory_operation_overflowed_ = true;
        return;
    }
    ++mandatory_operation_depth_;
}

void UpdateForegroundProgress::EndMandatoryOperation()
{
    if (mandatory_operation_overflowed_) return;
    if (mandatory_operation_depth_ != 0U) --mandatory_operation_depth_;
}

UpdateForegroundUiEvent UpdateForegroundProgress::BuildEvent(
    UpdateForegroundPhase phase, uint64_t completed_bytes,
    uint64_t total_bytes, UpdateForegroundCancelBehavior behavior) const
{
    UpdateForegroundUiEvent event;
    event.phase = phase;
    event.progress_per_mille = 0U;
    event.determinate = total_bytes != 0U;
    if (event.determinate) {
        event.progress_per_mille = RatioPerMille(completed_bytes,
                                                  total_bytes);
    }
    event.cancel_enabled =
        behavior == UpdateForegroundCancelBehavior::CancelAtCheckpoint;
    event.cancel_pending = cancel_requested_;
    return event;
}

bool UpdateForegroundProgress::Checkpoint(
    UpdateForegroundPhase phase, uint64_t completed_bytes,
    uint64_t total_bytes, UpdateForegroundCancelBehavior behavior)
{
    if (!active_) return true;
    if (ui_ == 0) return false;
    if (mandatory_operation_active() || stop_signaled_) {
        behavior = UpdateForegroundCancelBehavior::MandatoryCompletion;
    }
    phase_ = phase;
    UpdateForegroundUiEvent event = BuildEvent(
        phase, completed_bytes, total_bytes, behavior);
    ui_->Present(event);
    if (ui_->PumpAndReadCancel()) cancel_requested_ = true;
    if (cancel_requested_) {
        if (behavior == UpdateForegroundCancelBehavior::MandatoryCompletion) {
            cancel_deferred_ = true;
        }
        event = BuildEvent(phase, completed_bytes, total_bytes, behavior);
        ui_->Present(event);
    }
    const bool may_continue = !cancel_requested_ ||
        behavior == UpdateForegroundCancelBehavior::MandatoryCompletion;
    if (!may_continue) stop_signaled_ = true;
    return may_continue;
}

bool UpdateForegroundProgress::Report(
    const UpdateRecoveryProgressEvent &event)
{
    if (!active_) return true;
    const UpdateForegroundCancelBehavior behavior =
        mandatory_operation_active() || stop_signaled_ ||
                IsMandatoryProgress(event.kind)
            ? UpdateForegroundCancelBehavior::MandatoryCompletion
            : UpdateForegroundCancelBehavior::CancelAtCheckpoint;
    UpdateForegroundPhase mapped = MapProgressPhase(event.kind, phase_);
    if (event.kind == UpdateRecoveryProgressKind::InstallerFileHashed &&
        hash_contents_complete_) {
        // The aggregate archive-content pass already completed. Later file
        // hashes belong to configuration/staging checks and must not restart
        // the user-visible Hash bar.
        mapped = UpdateForegroundPhase::Stage;
    }
    uint16_t hash_begin = 0U;
    uint16_t hash_end = 0U;
    if (mapped == UpdateForegroundPhase::Hash &&
        HashPhaseSpan(event.kind, &hash_begin, &hash_end)) {
        // Never let a repeated, retried or malformed lower-level counter move
        // the composite bar backwards.  Each writing/extracting pass still
        // performs its own full integrity check; this state is presentation
        // only and grants no security permission.
        const uint16_t candidate = HashPhasePerMille(
            event, hash_begin, hash_end);
        if (candidate > hash_progress_per_mille_) {
            hash_progress_per_mille_ = candidate;
        }
        const bool continued = Checkpoint(
            UpdateForegroundPhase::Hash, hash_progress_per_mille_, 1000U,
            behavior);
        if (continued &&
            event.kind == UpdateRecoveryProgressKind::InstallerArchiveHashed &&
            event.total_bytes != 0U &&
            event.completed_bytes >= event.total_bytes) {
            hash_contents_complete_ = true;
        }
        return continued;
    }
    if (!hash_contents_complete_ && phase_ == UpdateForegroundPhase::Hash &&
        event.kind == UpdateRecoveryProgressKind::PreparedFileVerified) {
        // Configuration verification runs between the two prepared-archive
        // bindings.  It remains cancelable and pumps every callback, but it
        // must not switch to Stage or replace the composite Hash counter with
        // a per-config-file percentage.
        return Checkpoint(UpdateForegroundPhase::Hash,
                          hash_progress_per_mille_, 1000U, behavior);
    }
    if (mapped == UpdateForegroundPhase::Stage) {
        // Installer file-copy/hash callbacks are local counters and restart
        // for every file. InstallerStageOverall is the one transaction-wide,
        // byte-weighted Stage counter. Every callback still pumps input and
        // the watchdog while the displayed high-water mark stays monotone.
        uint16_t candidate = stage_progress_per_mille_;
        if (event.kind ==
                UpdateRecoveryProgressKind::InstallerStageOverall &&
            event.total_bytes != 0U) {
            candidate = RatioPerMille(event.completed_bytes,
                                       event.total_bytes);
        } else if (event.kind ==
                   UpdateRecoveryProgressKind::ForegroundStageComplete) {
            candidate = 1000U;
        }
        if (candidate > stage_progress_per_mille_) {
            stage_progress_per_mille_ = candidate;
        }
        return Checkpoint(UpdateForegroundPhase::Stage,
                          stage_progress_per_mille_, 1000U, behavior);
    }
    return Checkpoint(mapped, event.completed_bytes, event.total_bytes,
                      behavior);
}

const char *UpdateForegroundPhaseString(UpdateForegroundPhase phase)
{
    switch (phase) {
    case UpdateForegroundPhase::Discovery: return "discovery";
    case UpdateForegroundPhase::Manifest: return "manifest";
    case UpdateForegroundPhase::Zip: return "zip";
    case UpdateForegroundPhase::Hash: return "hash";
    case UpdateForegroundPhase::Stage: return "stage";
    case UpdateForegroundPhase::Reboot: return "reboot";
    }
    return "unknown";
}

}  // namespace update
}  // namespace bmx
