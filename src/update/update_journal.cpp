#include "update_journal.h"

#include "crc32.h"

#include <string.h>

namespace bmx {
namespace update {

namespace {

static const uint8_t kJournalMagic[8] = {'B', 'M', 'X', 'J', 'N', 'L', '1', 0};
static const uint16_t kJournalFormatVersion = 1U;
static const size_t kJournalCrcOffset = kJournalEncodedSize - 4U;

bool IsKnownState(JournalState state)
{
    return state == JournalState::Idle || state == JournalState::Discovered ||
           state == JournalState::Downloaded || state == JournalState::Prepared ||
           state == JournalState::Staged || state == JournalState::CandidatePending ||
           state == JournalState::CandidateHealthy || state == JournalState::Committing ||
           state == JournalState::Committed || state == JournalState::RollingBack;
}

bool BytesAreZero(const uint8_t *bytes, size_t size)
{
    uint8_t combined = 0U;
    for (size_t i = 0U; i < size; ++i) {
        combined = static_cast<uint8_t>(combined | bytes[i]);
    }
    return combined == 0U;
}

bool BytesAreNonZero(const uint8_t *bytes, size_t size)
{
    return !BytesAreZero(bytes, size);
}

JournalFlags RequiredFlagsForState(JournalState state)
{
    const JournalFlags downloaded = kJournalFlagUserApproved |
                                    kJournalFlagDownloadVerified;
    const JournalFlags staged = downloaded | kJournalFlagSnapshotComplete |
                                 kJournalFlagStagingComplete;
    switch (state) {
    case JournalState::Downloaded:
    case JournalState::Prepared:
        return downloaded;
    case JournalState::Staged:
        return staged;
    case JournalState::CandidatePending:
        return staged | kJournalFlagTrybootArmed;
    case JournalState::CandidateHealthy:
    case JournalState::Committing:
        return staged | kJournalFlagTrybootArmed | kJournalFlagCandidateHealthy;
    case JournalState::Committed:
        return staged | kJournalFlagTrybootArmed | kJournalFlagCandidateHealthy |
               kJournalFlagSelectorCommitted;
    case JournalState::RollingBack:
        return downloaded | kJournalFlagRollbackRequested;
    case JournalState::Idle:
    case JournalState::Discovered:
    default:
        return 0U;
    }
}

JournalFlags AllowedFlagsForState(JournalState state)
{
    const JournalFlags consent = kJournalFlagResetRequired | kJournalFlagResetApproved;
    switch (state) {
    case JournalState::Idle:
        return 0U;
    case JournalState::Discovered:
        return kJournalFlagResetRequired;
    case JournalState::Downloaded:
        return RequiredFlagsForState(state) | consent;
    case JournalState::Prepared:
        return RequiredFlagsForState(state) | consent | kJournalFlagSnapshotComplete;
    case JournalState::Staged:
        return RequiredFlagsForState(state) | consent;
    case JournalState::CandidatePending:
        return RequiredFlagsForState(state) | consent;
    case JournalState::CandidateHealthy:
        return RequiredFlagsForState(state) | consent;
    case JournalState::Committing:
        return RequiredFlagsForState(state) | consent | kJournalFlagSelectorCommitted;
    case JournalState::Committed:
        return RequiredFlagsForState(state) | consent;
    case JournalState::RollingBack:
        return kKnownJournalFlags;
    default:
        return 0U;
    }
}

bool RecordIsValid(const JournalRecord &record)
{
    if (record.generation == 0U || record.generation == UINT64_MAX ||
        !IsKnownState(record.state) || record.substate > 31U ||
        (record.flags & static_cast<JournalFlags>(~kKnownJournalFlags)) != 0U ||
        record.completed_steps > record.total_steps ||
        record.total_steps > kMaximumJournalSteps) {
        return false;
    }

    if (record.state == JournalState::Idle) {
        return record.flags == 0U && record.substate == 0U &&
               BytesAreZero(record.transaction_id, sizeof(record.transaction_id)) &&
               record.source_release_sequence == 0U &&
               record.target_release_sequence == 0U &&
               record.board == BoardFamily::Unknown &&
               BytesAreZero(record.manifest_sha256, sizeof(record.manifest_sha256)) &&
               BytesAreZero(record.zip_sha256, sizeof(record.zip_sha256)) &&
               BytesAreZero(record.consent_sha256, sizeof(record.consent_sha256)) &&
               record.old_boot_generation == 0U && record.new_boot_generation == 0U &&
               record.completed_steps == 0U && record.total_steps == 0U;
    }

    if (!BytesAreNonZero(record.transaction_id, sizeof(record.transaction_id)) ||
        record.source_release_sequence == 0U ||
        record.target_release_sequence <= record.source_release_sequence ||
        !IsKnownBoardFamily(record.board) ||
        !BytesAreNonZero(record.manifest_sha256, sizeof(record.manifest_sha256)) ||
        !BytesAreNonZero(record.zip_sha256, sizeof(record.zip_sha256)) ||
        !BytesAreNonZero(record.consent_sha256, sizeof(record.consent_sha256)) ||
        record.old_boot_generation == 0U || record.new_boot_generation == 0U ||
        record.old_boot_generation == record.new_boot_generation ||
        record.total_steps == 0U) {
        return false;
    }

    const JournalFlags required = RequiredFlagsForState(record.state);
    const JournalFlags allowed = AllowedFlagsForState(record.state);
    if ((record.flags & required) != required || (record.flags & ~allowed) != 0U) {
        return false;
    }
    const bool reset_required = (record.flags & kJournalFlagResetRequired) != 0U;
    const bool reset_approved = (record.flags & kJournalFlagResetApproved) != 0U;
    if (reset_approved && !reset_required) {
        return false;
    }
    if (reset_required && record.state != JournalState::Discovered && !reset_approved) {
        return false;
    }
    return true;
}

void WriteU16(uint8_t *destination, uint16_t value)
{
    destination[0] = static_cast<uint8_t>(value & 0xffU);
    destination[1] = static_cast<uint8_t>((value >> 8U) & 0xffU);
}

void WriteU32(uint8_t *destination, uint32_t value)
{
    for (unsigned i = 0U; i < 4U; ++i) {
        destination[i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

void WriteU64(uint8_t *destination, uint64_t value)
{
    for (unsigned i = 0U; i < 8U; ++i) {
        destination[i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

uint16_t ReadU16(const uint8_t *source)
{
    return static_cast<uint16_t>(source[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(source[1]) << 8U);
}

uint32_t ReadU32(const uint8_t *source)
{
    uint32_t value = 0U;
    for (unsigned i = 0U; i < 4U; ++i) {
        value |= static_cast<uint32_t>(source[i]) << (8U * i);
    }
    return value;
}

uint64_t ReadU64(const uint8_t *source)
{
    uint64_t value = 0U;
    for (unsigned i = 0U; i < 8U; ++i) {
        value |= static_cast<uint64_t>(source[i]) << (8U * i);
    }
    return value;
}

bool SameTransaction(const JournalRecord &left, const JournalRecord &right)
{
    return memcmp(left.transaction_id, right.transaction_id,
                  sizeof(left.transaction_id)) == 0;
}

bool SameImmutableFields(const JournalRecord &left, const JournalRecord &right)
{
    return left.source_release_sequence == right.source_release_sequence &&
           left.target_release_sequence == right.target_release_sequence &&
           left.board == right.board &&
           memcmp(left.manifest_sha256, right.manifest_sha256,
                  sizeof(left.manifest_sha256)) == 0 &&
           memcmp(left.zip_sha256, right.zip_sha256, sizeof(left.zip_sha256)) == 0 &&
           memcmp(left.consent_sha256, right.consent_sha256,
                  sizeof(left.consent_sha256)) == 0 &&
           left.old_boot_generation == right.old_boot_generation &&
           left.new_boot_generation == right.new_boot_generation;
}

bool StateEdgeAllowed(JournalState current, JournalState next)
{
    if (current == next && current != JournalState::Idle) {
        return true;
    }
    if (next == JournalState::Idle) {
        return current == JournalState::Discovered || current == JournalState::Downloaded ||
               current == JournalState::Committed || current == JournalState::RollingBack;
    }
    if (next == JournalState::RollingBack) {
        return current == JournalState::Prepared || current == JournalState::Staged ||
               current == JournalState::CandidatePending ||
               current == JournalState::CandidateHealthy ||
               current == JournalState::Committing || current == JournalState::Committed;
    }
    switch (current) {
    case JournalState::Idle:
        return next == JournalState::Discovered;
    case JournalState::Discovered:
        return next == JournalState::Downloaded;
    case JournalState::Downloaded:
        return next == JournalState::Prepared;
    case JournalState::Prepared:
        return next == JournalState::Staged;
    case JournalState::Staged:
        return next == JournalState::CandidatePending;
    case JournalState::CandidatePending:
        return next == JournalState::CandidateHealthy;
    case JournalState::CandidateHealthy:
        return next == JournalState::Committing;
    case JournalState::Committing:
        return next == JournalState::Committed;
    case JournalState::RollingBack:
    case JournalState::Committed:
    default:
        return false;
    }
}

}  // namespace

JournalRecord MakeIdleJournalRecord(uint64_t generation)
{
    JournalRecord record;
    memset(&record, 0, sizeof(record));
    record.generation = generation;
    record.state = JournalState::Idle;
    record.board = BoardFamily::Unknown;
    return record;
}

JournalCodecStatus SerializeJournal(const JournalRecord &record,
                                    MutableByteView output)
{
    if (output.data == 0) {
        return JournalCodecStatus::InvalidArgument;
    }
    if (output.size != kJournalEncodedSize) {
        return JournalCodecStatus::WrongSize;
    }
    if (!RecordIsValid(record)) {
        return JournalCodecStatus::InvalidRecord;
    }

    memset(output.data, 0, output.size);
    memcpy(output.data, kJournalMagic, sizeof(kJournalMagic));
    WriteU16(output.data + 8U, kJournalFormatVersion);
    WriteU16(output.data + 10U, static_cast<uint16_t>(kJournalEncodedSize));
    WriteU64(output.data + 12U, record.generation);
    memcpy(output.data + 20U, record.transaction_id, sizeof(record.transaction_id));
    output.data[36U] = static_cast<uint8_t>(record.state);
    output.data[37U] = record.substate;
    WriteU16(output.data + 38U, record.flags);
    WriteU64(output.data + 40U, record.source_release_sequence);
    WriteU64(output.data + 48U, record.target_release_sequence);
    output.data[56U] = static_cast<uint8_t>(record.board);
    // Bytes 57..63 are reserved and remain zero.
    memcpy(output.data + 64U, record.manifest_sha256, sizeof(record.manifest_sha256));
    memcpy(output.data + 96U, record.zip_sha256, sizeof(record.zip_sha256));
    memcpy(output.data + 128U, record.consent_sha256, sizeof(record.consent_sha256));
    WriteU64(output.data + 160U, record.old_boot_generation);
    WriteU64(output.data + 168U, record.new_boot_generation);
    WriteU32(output.data + 176U, record.completed_steps);
    WriteU32(output.data + 180U, record.total_steps);
    WriteU32(output.data + kJournalCrcOffset,
             CalculateCrc32(ByteView(output.data, kJournalCrcOffset)));
    return JournalCodecStatus::Ok;
}

JournalCodecStatus ParseJournal(ByteView encoded, JournalRecord *record)
{
    if (record == 0 || encoded.data == 0) {
        return JournalCodecStatus::InvalidArgument;
    }
    if (encoded.size != kJournalEncodedSize) {
        return JournalCodecStatus::WrongSize;
    }
    if (memcmp(encoded.data, kJournalMagic, sizeof(kJournalMagic)) != 0) {
        return JournalCodecStatus::BadMagic;
    }
    if (ReadU16(encoded.data + 8U) != kJournalFormatVersion) {
        return JournalCodecStatus::UnsupportedVersion;
    }
    if (ReadU16(encoded.data + 10U) != kJournalEncodedSize) {
        return JournalCodecStatus::WrongSize;
    }
    if (!BytesAreZero(encoded.data + 57U, 7U)) {
        return JournalCodecStatus::NonZeroReservedBytes;
    }
    if (ReadU32(encoded.data + kJournalCrcOffset) !=
        CalculateCrc32(ByteView(encoded.data, kJournalCrcOffset))) {
        return JournalCodecStatus::BadCrc;
    }

    JournalRecord parsed;
    memset(&parsed, 0, sizeof(parsed));
    parsed.generation = ReadU64(encoded.data + 12U);
    memcpy(parsed.transaction_id, encoded.data + 20U, sizeof(parsed.transaction_id));
    parsed.state = static_cast<JournalState>(encoded.data[36U]);
    parsed.substate = encoded.data[37U];
    parsed.flags = ReadU16(encoded.data + 38U);
    parsed.source_release_sequence = ReadU64(encoded.data + 40U);
    parsed.target_release_sequence = ReadU64(encoded.data + 48U);
    parsed.board = static_cast<BoardFamily>(encoded.data[56U]);
    memcpy(parsed.manifest_sha256, encoded.data + 64U, sizeof(parsed.manifest_sha256));
    memcpy(parsed.zip_sha256, encoded.data + 96U, sizeof(parsed.zip_sha256));
    memcpy(parsed.consent_sha256, encoded.data + 128U, sizeof(parsed.consent_sha256));
    parsed.old_boot_generation = ReadU64(encoded.data + 160U);
    parsed.new_boot_generation = ReadU64(encoded.data + 168U);
    parsed.completed_steps = ReadU32(encoded.data + 176U);
    parsed.total_steps = ReadU32(encoded.data + 180U);
    if (!RecordIsValid(parsed)) {
        return JournalCodecStatus::InvalidRecord;
    }
    *record = parsed;
    return JournalCodecStatus::Ok;
}

bool JournalRecordsEqual(const JournalRecord &left, const JournalRecord &right)
{
    return left.generation == right.generation && SameTransaction(left, right) &&
           left.state == right.state && left.substate == right.substate &&
           left.flags == right.flags && SameImmutableFields(left, right) &&
           left.completed_steps == right.completed_steps &&
           left.total_steps == right.total_steps;
}

JournalSelectionResult SelectJournalCopy(const JournalCopy &copy_a,
                                         const JournalCopy &copy_b)
{
    JournalSelectionResult result;
    memset(&result, 0, sizeof(result));
    result.status = JournalSelectionStatus::NoJournal;
    result.copy_a_status = JournalCodecStatus::WrongSize;
    result.copy_b_status = JournalCodecStatus::WrongSize;

    if (!copy_a.present && !copy_b.present) {
        return result;
    }

    JournalRecord record_a;
    JournalRecord record_b;
    const bool valid_a = copy_a.present &&
        (result.copy_a_status = ParseJournal(copy_a.encoded, &record_a)) ==
            JournalCodecStatus::Ok;
    const bool valid_b = copy_b.present &&
        (result.copy_b_status = ParseJournal(copy_b.encoded, &record_b)) ==
            JournalCodecStatus::Ok;

    if (!valid_a && !valid_b) {
        result.status = JournalSelectionStatus::NoValidCopy;
        return result;
    }
    if (valid_a && !valid_b) {
        result.status = JournalSelectionStatus::SelectedA;
        result.record = record_a;
        return result;
    }
    if (!valid_a && valid_b) {
        result.status = JournalSelectionStatus::SelectedB;
        result.record = record_b;
        return result;
    }
    if (record_a.generation == record_b.generation) {
        if (!JournalRecordsEqual(record_a, record_b)) {
            result.status = JournalSelectionStatus::AmbiguousSameGeneration;
            return result;
        }
        result.status = JournalSelectionStatus::SelectedEquivalentCopies;
        result.record = record_a;
        return result;
    }
    if (record_a.generation > record_b.generation) {
        result.status = JournalSelectionStatus::SelectedA;
        result.record = record_a;
    } else {
        result.status = JournalSelectionStatus::SelectedB;
        result.record = record_b;
    }
    return result;
}

JournalTransitionStatus ValidateJournalTransition(const JournalRecord &current,
                                                  const JournalRecord &next)
{
    if (!RecordIsValid(current)) {
        return JournalTransitionStatus::InvalidCurrentRecord;
    }
    if (!RecordIsValid(next)) {
        return JournalTransitionStatus::InvalidNextRecord;
    }
    if (current.generation == UINT64_MAX || next.generation != current.generation + 1U) {
        return JournalTransitionStatus::GenerationMismatch;
    }
    if (!StateEdgeAllowed(current.state, next.state)) {
        return JournalTransitionStatus::StateTransitionDenied;
    }
    if (current.state == JournalState::Idle) {
        return JournalTransitionStatus::Allowed;
    }
    if (next.state == JournalState::Idle) {
        return JournalTransitionStatus::Allowed;
    }
    if (!SameTransaction(current, next)) {
        return JournalTransitionStatus::TransactionMismatch;
    }
    if (!SameImmutableFields(current, next)) {
        return JournalTransitionStatus::ImmutableFieldChanged;
    }
    if ((next.flags & current.flags) != current.flags) {
        return JournalTransitionStatus::FlagsRegressed;
    }
    if (next.completed_steps < current.completed_steps ||
        next.total_steps != current.total_steps) {
        return JournalTransitionStatus::ProgressRegressed;
    }
    return JournalTransitionStatus::Allowed;
}

bool JournalStateAllowsSnapshotOrStagingWrites(JournalState state)
{
    return state == JournalState::Prepared;
}

bool JournalStateAllowsCandidateArm(JournalState state)
{
    return state == JournalState::Staged;
}

bool JournalStateAllowsCandidateHealthMark(JournalState state)
{
    return state == JournalState::CandidatePending;
}

bool JournalStateAllowsSelectorCommit(JournalState state)
{
    return state == JournalState::CandidateHealthy || state == JournalState::Committing;
}

bool JournalStateAllowsRollbackWrites(JournalState state)
{
    return state == JournalState::RollingBack;
}

bool JournalStateAllowsCleanup(JournalState state)
{
    return state == JournalState::Committed || state == JournalState::RollingBack;
}

}  // namespace update
}  // namespace bmx
