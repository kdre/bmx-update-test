#ifndef BMX_UPDATE_UPDATE_JOURNAL_H
#define BMX_UPDATE_UPDATE_JOURNAL_H

#include "update_types.h"

namespace bmx {
namespace update {

static const size_t kTransactionIdBytes = 16U;
static const size_t kJournalEncodedSize = 188U;
static const uint32_t kMaximumJournalSteps = 65535U;

enum class JournalState : uint8_t {
    Idle = 0,
    Discovered = 1,
    Downloaded = 2,
    Prepared = 3,
    Staged = 4,
    CandidatePending = 5,
    CandidateHealthy = 6,
    Committing = 7,
    Committed = 8,
    RollingBack = 9
};

typedef uint16_t JournalFlags;
static const JournalFlags kJournalFlagUserApproved = UINT16_C(1) << 0U;
static const JournalFlags kJournalFlagResetRequired = UINT16_C(1) << 1U;
static const JournalFlags kJournalFlagResetApproved = UINT16_C(1) << 2U;
static const JournalFlags kJournalFlagDownloadVerified = UINT16_C(1) << 3U;
static const JournalFlags kJournalFlagSnapshotComplete = UINT16_C(1) << 4U;
static const JournalFlags kJournalFlagStagingComplete = UINT16_C(1) << 5U;
static const JournalFlags kJournalFlagTrybootArmed = UINT16_C(1) << 6U;
static const JournalFlags kJournalFlagCandidateHealthy = UINT16_C(1) << 7U;
static const JournalFlags kJournalFlagSelectorCommitted = UINT16_C(1) << 8U;
static const JournalFlags kJournalFlagRollbackRequested = UINT16_C(1) << 9U;
static const JournalFlags kKnownJournalFlags =
    kJournalFlagUserApproved | kJournalFlagResetRequired |
    kJournalFlagResetApproved | kJournalFlagDownloadVerified |
    kJournalFlagSnapshotComplete | kJournalFlagStagingComplete |
    kJournalFlagTrybootArmed | kJournalFlagCandidateHealthy |
    kJournalFlagSelectorCommitted | kJournalFlagRollbackRequested;

struct JournalRecord {
    uint64_t generation;
    uint8_t transaction_id[kTransactionIdBytes];
    JournalState state;
    uint8_t substate;
    JournalFlags flags;
    uint64_t source_release_sequence;
    uint64_t target_release_sequence;
    BoardFamily board;
    uint8_t manifest_sha256[kSha256DigestBytes];
    uint8_t zip_sha256[kSha256DigestBytes];
    uint8_t consent_sha256[kSha256DigestBytes];
    uint64_t old_boot_generation;
    uint64_t new_boot_generation;
    uint32_t completed_steps;
    uint32_t total_steps;
};

JournalRecord MakeIdleJournalRecord(uint64_t generation);

enum class JournalCodecStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    WrongSize,
    InvalidRecord,
    BadMagic,
    UnsupportedVersion,
    BadCrc,
    NonZeroReservedBytes
};

JournalCodecStatus SerializeJournal(const JournalRecord &record,
                                    MutableByteView output);
JournalCodecStatus ParseJournal(ByteView encoded, JournalRecord *record);
bool JournalRecordsEqual(const JournalRecord &left, const JournalRecord &right);

struct JournalCopy {
    bool present;
    ByteView encoded;
};

enum class JournalSelectionStatus : uint8_t {
    NoJournal = 0,
    SelectedA,
    SelectedB,
    SelectedEquivalentCopies,
    NoValidCopy,
    AmbiguousSameGeneration
};

struct JournalSelectionResult {
    JournalSelectionStatus status;
    JournalCodecStatus copy_a_status;
    JournalCodecStatus copy_b_status;
    JournalRecord record;
};

JournalSelectionResult SelectJournalCopy(const JournalCopy &copy_a,
                                         const JournalCopy &copy_b);

enum class JournalTransitionStatus : uint8_t {
    Allowed = 0,
    InvalidCurrentRecord,
    InvalidNextRecord,
    GenerationMismatch,
    StateTransitionDenied,
    TransactionMismatch,
    ImmutableFieldChanged,
    FlagsRegressed,
    ProgressRegressed
};

JournalTransitionStatus ValidateJournalTransition(const JournalRecord &current,
                                                  const JournalRecord &next);

// Installation capabilities are deliberately narrower than state ordering.
// Snapshot/staging writes happen while PREPARED and finish by entering STAGED.
bool JournalStateAllowsSnapshotOrStagingWrites(JournalState state);
bool JournalStateAllowsCandidateArm(JournalState state);
bool JournalStateAllowsCandidateHealthMark(JournalState state);
bool JournalStateAllowsSelectorCommit(JournalState state);
bool JournalStateAllowsRollbackWrites(JournalState state);
bool JournalStateAllowsCleanup(JournalState state);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_JOURNAL_H
