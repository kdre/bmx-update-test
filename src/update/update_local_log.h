#ifndef BMX_UPDATE_UPDATE_LOCAL_LOG_H
#define BMX_UPDATE_UPDATE_LOCAL_LOG_H

#include "update/update_filesystem.h"
#include "update/update_recovery_progress.h"

namespace bmx {
namespace update {

// The local updater log is deliberately a diagnostic aid, never transaction
// state.  Its writer is best-effort and must not be used to decide whether an
// update or recovery operation may continue.
static const size_t kUpdateLocalLogPageBytes = 4096U;
static const size_t kUpdateLocalLogRecordBytes = 32U;
static const size_t kUpdateLocalLogHeaderBytes = 32U;
static const size_t kUpdateLocalLogMaximumRecords =
    (kUpdateLocalLogPageBytes - kUpdateLocalLogHeaderBytes - 4U) /
    kUpdateLocalLogRecordBytes;
static const size_t kUpdateLocalLogStableDiskBytes =
    2U * kUpdateLocalLogPageBytes;
static const size_t kUpdateLocalLogMaximumTransientDiskBytes =
    3U * kUpdateLocalLogPageBytes;

extern const char kUpdateLocalLogRoot[];
extern const char kUpdateLocalLogPathA[];
extern const char kUpdateLocalLogPathB[];
extern const char kUpdateLocalLogTemporaryPath[];

// Explicit values are part of the on-disk v1 diagnostic format.  Do not
// renumber them.  New meanings require a new value rather than reuse.
enum class UpdateLocalLogScope : uint8_t {
    Online = 1,
    BootRecovery = 2
};

enum class UpdateLocalLogRecordKind : uint8_t {
    Invocation = 1,
    State = 2,
    Progress = 3,
    Result = 4,
    Error = 5
};

enum class UpdateLocalLogCode : uint16_t {
    OnlineRequested = 0x0101,
    OnlineDiscoveryStarted = 0x0102,
    OnlineDiscoveryAccepted = 0x0103,
    OnlineInstallConfirmed = 0x0104,
    RecoveryStarted = 0x0110,

    StateDiscovered = 0x0201,
    StateDownloaded = 0x0202,
    StatePrepared = 0x0203,
    StateStaged = 0x0204,
    StateCandidatePending = 0x0205,
    StateCandidateHealthy = 0x0206,
    StateCommitting = 0x0207,
    StateCommitted = 0x0208,
    StateRollingBack = 0x0209,
    // completed=CandidateHealthStatus, total=CandidateHealthProbeStatus.
    StateCandidateHealthEvaluated = 0x020A,

    // All explicit progress codes remain readable for v1 compatibility.
    // LoggingUpdateRecoveryProgress emits only the three low-frequency
    // boundary codes; repeated byte/file/journal/commit/rollback/cleanup
    // callbacks stay delegate-only.
    ProgressBootInitializationMilestone = 0x1001,
    ProgressRecoveryPrecheck = 0x1002,
    ProgressTransactionStateRead = 0x1003,
    ProgressTransactionPayloadRead = 0x1004,
    ProgressTransactionCleanup = 0x1005,
    ProgressPreparedEvidenceRead = 0x1006,
    ProgressPreparedFileVerified = 0x1007,
    ProgressPreparedCleanup = 0x1008,
    ProgressCandidateFileHashed = 0x1009,
    ProgressCandidateJournalRead = 0x100A,
    ProgressInstallerFileHashed = 0x100B,
    ProgressInstallerFileCopied = 0x100C,
    ProgressInstallerJournalPersisted = 0x100D,
    ProgressInstallerCommitStep = 0x100E,
    ProgressInstallerRollbackStep = 0x100F,
    ProgressArchiveCleanup = 0x1010,

    ResultOnlineCompleted = 0x3001,
    ResultOnlineCanceled = 0x3002,
    ResultRecoveryNoPending = 0x3010,
    ResultRecoveryCompleted = 0x3011,
    ResultRecoveryRejected = 0x3012,
    ResultPreviousBootFailSafeRequested = 0x3013,

    ErrorPrecondition = 0x4001,
    ErrorNetwork = 0x4002,
    ErrorAuthentication = 0x4003,
    ErrorConfiguration = 0x4004,
    ErrorStorage = 0x4005,
    ErrorIntegrity = 0x4006,
    ErrorJournal = 0x4007,
    ErrorWatchdog = 0x4008,
    ErrorRecovery = 0x4009,
    ErrorInternal = 0x400A,
    // completed=UpdateOrchestratorStatus rollback trigger,
    // total=InstallerStatus from the failed transition (or Ok).
    ErrorCandidateRollbackDecision = 0x400B,
    // completed=UpdateOrchestratorStatus. total packs InstallerStatus in bits
    // 0..15, rollback InstallerStatus in 16..31 and rollback-cleanup
    // InstallerStatus in 32..47.
    ErrorOnlineInstallation = 0x400C,
    // completed=UpdateOrchestratorStatus. total packs
    // AuthorizationConsentStatus in bits 0..15, UpdateStartDecision in
    // 16..31 and CurrentConfigConsentStatus in 32..47.
    ErrorOnlineAuthorization = 0x400D
};

struct UpdateLocalLogRecord {
    UpdateLocalLogScope scope;
    UpdateLocalLogRecordKind kind;
    UpdateLocalLogCode code;
    uint64_t ordinal;
    uint64_t completed;
    uint64_t total;
};

// Caller-owned scratch keeps the 4 KiB persistence buffer off critical boot
// stacks.  It may be reused only by one synchronous logger at a time.
struct UpdateLocalLogWorkspace {
    uint8_t page[kUpdateLocalLogPageBytes];
};

enum class UpdateLocalLogReadStatus : uint8_t {
    Ok = 0,
    NoLog,
    InvalidArgument,
    BufferTooSmall,
    Corrupt,
    IoError
};

class UpdateLocalLog {
public:
    UpdateLocalLog(UpdateFileSystem *file_system,
                   UpdateLocalLogWorkspace *workspace);

    // Best effort by contract: callers receive no success value and must not
    // gate update/recovery on diagnostic persistence.  last_record_persisted
    // exists only for diagnostics and tests.
    void Record(UpdateLocalLogScope scope, UpdateLocalLogCode code,
                uint64_t completed = 0U, uint64_t total = 0U);
    bool last_record_persisted() const { return last_record_persisted_; }

    UpdateLocalLogReadStatus Read(UpdateLocalLogRecord *records,
                                  size_t capacity, size_t *count,
                                  uint64_t *generation);

private:
    UpdateLocalLog(const UpdateLocalLog &);
    UpdateLocalLog &operator=(const UpdateLocalLog &);

    UpdateFileSystem *file_system_;
    UpdateLocalLogWorkspace *workspace_;
    bool last_record_persisted_;
};

// Composes the existing synchronous progress callback with best-effort local
// persistence.  Delegate refusal remains terminal; a logging failure never
// changes the delegate result.  No filesystem work is attempted after a
// delegate/watchdog refusal.  Repeated byte/file/journal/commit/rollback and
// cleanup checkpoints always reach the delegate but are deliberately not
// persisted. Three low-frequency progress boundaries plus the candidate-health
// and rollback-decision records are added to the diagnostic log.
// CandidateJournalRead is also delegate-only because validated journal
// readback occurs after every durable installer transition.
// Durable state, result and error records remain available through Record().
class LoggingUpdateRecoveryProgress : public UpdateRecoveryProgress {
public:
    LoggingUpdateRecoveryProgress(UpdateLocalLog *log,
                                  UpdateLocalLogScope scope,
                                  UpdateRecoveryProgress *delegate = 0);

    bool Report(const UpdateRecoveryProgressEvent &event) override;
    void BeginMandatoryOperation() override;
    void EndMandatoryOperation() override;

private:
    UpdateLocalLog *log_;
    UpdateLocalLogScope scope_;
    UpdateRecoveryProgress *delegate_;
};

const char *UpdateLocalLogReadStatusString(UpdateLocalLogReadStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_LOCAL_LOG_H
