#include "update/update_local_log.h"

#include "update/crc32.h"

#include <limits.h>
#include <string.h>

namespace bmx {
namespace update {

const char kUpdateLocalLogRoot[] = ".bmx-update";
const char kUpdateLocalLogPathA[] = ".bmx-update/log.a";
const char kUpdateLocalLogPathB[] = ".bmx-update/log.b";
const char kUpdateLocalLogTemporaryPath[] = ".bmx-update/log.next";

namespace {

static const uint8_t kLogMagic[8U] = {
    'B', 'M', 'X', 'U', 'L', 'O', 'G', 0U};
static const uint16_t kLogFormatVersion = 1U;
static const size_t kLogCrcOffset = kUpdateLocalLogPageBytes - 4U;

enum class Slot : uint8_t {
    None = 0,
    A,
    B
};

struct SlotInfo {
    bool present;
    bool valid;
    bool io_error;
    uint64_t generation;
    uint16_t count;
    uint32_t crc;
};

struct CurrentLog {
    Slot selected;
    bool any_present;
    bool io_error;
    bool ambiguous;
    uint64_t generation;
    uint16_t count;
};

void WriteU16(uint8_t *destination, uint16_t value)
{
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8U);
}

void WriteU32(uint8_t *destination, uint32_t value)
{
    destination[0] = static_cast<uint8_t>(value);
    destination[1] = static_cast<uint8_t>(value >> 8U);
    destination[2] = static_cast<uint8_t>(value >> 16U);
    destination[3] = static_cast<uint8_t>(value >> 24U);
}

void WriteU64(uint8_t *destination, uint64_t value)
{
    for (size_t index = 0U; index < 8U; ++index) {
        destination[index] = static_cast<uint8_t>(value >> (index * 8U));
    }
}

uint16_t ReadU16(const uint8_t *source)
{
    return static_cast<uint16_t>(source[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(source[1]) << 8U);
}

uint32_t ReadU32(const uint8_t *source)
{
    return static_cast<uint32_t>(source[0]) |
           (static_cast<uint32_t>(source[1]) << 8U) |
           (static_cast<uint32_t>(source[2]) << 16U) |
           (static_cast<uint32_t>(source[3]) << 24U);
}

uint64_t ReadU64(const uint8_t *source)
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value |= static_cast<uint64_t>(source[index]) << (index * 8U);
    }
    return value;
}

bool ValidScope(UpdateLocalLogScope scope)
{
    return scope == UpdateLocalLogScope::Online ||
           scope == UpdateLocalLogScope::BootRecovery;
}

bool ClassifyCode(UpdateLocalLogCode code, UpdateLocalLogRecordKind *kind)
{
    if (kind == 0) return false;
    switch (code) {
    case UpdateLocalLogCode::OnlineRequested:
    case UpdateLocalLogCode::RecoveryStarted:
        *kind = UpdateLocalLogRecordKind::Invocation;
        return true;
    case UpdateLocalLogCode::OnlineDiscoveryStarted:
    case UpdateLocalLogCode::OnlineDiscoveryAccepted:
    case UpdateLocalLogCode::OnlineInstallConfirmed:
    case UpdateLocalLogCode::StateDiscovered:
    case UpdateLocalLogCode::StateDownloaded:
    case UpdateLocalLogCode::StatePrepared:
    case UpdateLocalLogCode::StateStaged:
    case UpdateLocalLogCode::StateCandidatePending:
    case UpdateLocalLogCode::StateCandidateHealthy:
    case UpdateLocalLogCode::StateCommitting:
    case UpdateLocalLogCode::StateCommitted:
    case UpdateLocalLogCode::StateRollingBack:
    case UpdateLocalLogCode::StateCandidateHealthEvaluated:
        *kind = UpdateLocalLogRecordKind::State;
        return true;
    case UpdateLocalLogCode::ProgressBootInitializationMilestone:
    case UpdateLocalLogCode::ProgressRecoveryPrecheck:
    case UpdateLocalLogCode::ProgressTransactionStateRead:
    case UpdateLocalLogCode::ProgressTransactionPayloadRead:
    case UpdateLocalLogCode::ProgressTransactionCleanup:
    case UpdateLocalLogCode::ProgressPreparedEvidenceRead:
    case UpdateLocalLogCode::ProgressPreparedFileVerified:
    case UpdateLocalLogCode::ProgressPreparedCleanup:
    case UpdateLocalLogCode::ProgressCandidateFileHashed:
    case UpdateLocalLogCode::ProgressCandidateJournalRead:
    case UpdateLocalLogCode::ProgressInstallerFileHashed:
    case UpdateLocalLogCode::ProgressInstallerFileCopied:
    case UpdateLocalLogCode::ProgressInstallerJournalPersisted:
    case UpdateLocalLogCode::ProgressInstallerCommitStep:
    case UpdateLocalLogCode::ProgressInstallerRollbackStep:
    case UpdateLocalLogCode::ProgressArchiveCleanup:
        *kind = UpdateLocalLogRecordKind::Progress;
        return true;
    case UpdateLocalLogCode::ResultOnlineCompleted:
    case UpdateLocalLogCode::ResultOnlineCanceled:
    case UpdateLocalLogCode::ResultRecoveryNoPending:
    case UpdateLocalLogCode::ResultRecoveryCompleted:
    case UpdateLocalLogCode::ResultRecoveryRejected:
    case UpdateLocalLogCode::ResultPreviousBootFailSafeRequested:
        *kind = UpdateLocalLogRecordKind::Result;
        return true;
    case UpdateLocalLogCode::ErrorPrecondition:
    case UpdateLocalLogCode::ErrorNetwork:
    case UpdateLocalLogCode::ErrorAuthentication:
    case UpdateLocalLogCode::ErrorConfiguration:
    case UpdateLocalLogCode::ErrorStorage:
    case UpdateLocalLogCode::ErrorIntegrity:
    case UpdateLocalLogCode::ErrorJournal:
    case UpdateLocalLogCode::ErrorWatchdog:
    case UpdateLocalLogCode::ErrorRecovery:
    case UpdateLocalLogCode::ErrorInternal:
    case UpdateLocalLogCode::ErrorCandidateRollbackDecision:
    case UpdateLocalLogCode::ErrorOnlineInstallation:
    case UpdateLocalLogCode::ErrorOnlineAuthorization:
        *kind = UpdateLocalLogRecordKind::Error;
        return true;
    }
    return false;
}

bool ProgressCode(UpdateRecoveryProgressKind kind, UpdateLocalLogCode *code)
{
    if (code == 0) return false;
    switch (kind) {
    case UpdateRecoveryProgressKind::BootInitializationMilestone:
        *code = UpdateLocalLogCode::ProgressBootInitializationMilestone;
        return true;
    case UpdateRecoveryProgressKind::RecoveryPrecheck:
        *code = UpdateLocalLogCode::ProgressRecoveryPrecheck;
        return true;
    case UpdateRecoveryProgressKind::TransactionStateRead:
        *code = UpdateLocalLogCode::ProgressTransactionStateRead;
        return true;
    case UpdateRecoveryProgressKind::TransactionPayloadRead:
    case UpdateRecoveryProgressKind::TransactionCleanup:
    case UpdateRecoveryProgressKind::PreparedEvidenceRead:
    case UpdateRecoveryProgressKind::PreparedFileVerified:
    case UpdateRecoveryProgressKind::PreparedCleanup:
    case UpdateRecoveryProgressKind::CandidateFileHashed:
    case UpdateRecoveryProgressKind::CandidateJournalRead:
    case UpdateRecoveryProgressKind::InstallerFileHashed:
    case UpdateRecoveryProgressKind::InstallerFileCopied:
    case UpdateRecoveryProgressKind::InstallerJournalPersisted:
    case UpdateRecoveryProgressKind::InstallerCommitStep:
    case UpdateRecoveryProgressKind::InstallerRollbackStep:
    case UpdateRecoveryProgressKind::ArchiveCleanup:
    case UpdateRecoveryProgressKind::StoredArchiveHashed:
    case UpdateRecoveryProgressKind::CandidateRebootCheckpoint:
    case UpdateRecoveryProgressKind::ForegroundDownloadMutationCheckpoint:
    case UpdateRecoveryProgressKind::ForegroundRetireMutationCheckpoint:
    case UpdateRecoveryProgressKind::PreparedArchiveInitialHashed:
    case UpdateRecoveryProgressKind::PreparedArchiveFinalHashed:
    case UpdateRecoveryProgressKind::InstallerArchiveHashed:
    case UpdateRecoveryProgressKind::CandidateEvidenceRead:
    case UpdateRecoveryProgressKind::ForegroundStageComplete:
    case UpdateRecoveryProgressKind::CandidateRollbackComplete:
    case UpdateRecoveryProgressKind::InstallerStageOverall:
    case UpdateRecoveryProgressKind::InstallerContentPlanSummary:
        // These can repeat per chunk, file, journal step, mutation step or
        // cleanup step.  Some duplicate state already protected by the
        // transaction journal.  Persisting a crash-safe 4 KiB diagnostic page
        // here would make update/recovery latency proportional to callback
        // cardinality.  The delegate already observed the event and may have
        // canceled or fed a watchdog, so no log I/O is needed.
        return false;
    case UpdateRecoveryProgressKind::CandidateHealthEvaluated:
        *code = UpdateLocalLogCode::StateCandidateHealthEvaluated;
        return true;
    case UpdateRecoveryProgressKind::CandidateRollbackDecision:
        *code = UpdateLocalLogCode::ErrorCandidateRollbackDecision;
        return true;
    }
    return false;
}

bool DecodeRecord(const uint8_t *encoded, UpdateLocalLogRecord *record)
{
    if (encoded == 0 || record == 0 || encoded[6U] != 0U ||
        encoded[7U] != 0U) {
        return false;
    }
    const UpdateLocalLogScope scope =
        static_cast<UpdateLocalLogScope>(encoded[0U]);
    const UpdateLocalLogRecordKind stored_kind =
        static_cast<UpdateLocalLogRecordKind>(encoded[1U]);
    const UpdateLocalLogCode code =
        static_cast<UpdateLocalLogCode>(ReadU16(encoded + 2U));
    UpdateLocalLogRecordKind expected_kind;
    const uint64_t completed = ReadU64(encoded + 16U);
    const uint64_t total = ReadU64(encoded + 24U);
    if (!ValidScope(scope) || !ClassifyCode(code, &expected_kind) ||
        stored_kind != expected_kind ||
        (stored_kind == UpdateLocalLogRecordKind::Progress &&
         total != 0U && completed > total)) {
        return false;
    }
    record->scope = scope;
    record->kind = stored_kind;
    record->code = code;
    record->ordinal = ReadU64(encoded + 8U);
    record->completed = completed;
    record->total = total;
    return record->ordinal != 0U;
}

void EncodeRecord(const UpdateLocalLogRecord &record, uint8_t *encoded)
{
    memset(encoded, 0, kUpdateLocalLogRecordBytes);
    encoded[0U] = static_cast<uint8_t>(record.scope);
    encoded[1U] = static_cast<uint8_t>(record.kind);
    WriteU16(encoded + 2U, static_cast<uint16_t>(record.code));
    WriteU64(encoded + 8U, record.ordinal);
    WriteU64(encoded + 16U, record.completed);
    WriteU64(encoded + 24U, record.total);
}

bool ParsePage(const uint8_t *page, SlotInfo *info)
{
    if (page == 0 || info == 0 ||
        memcmp(page, kLogMagic, sizeof(kLogMagic)) != 0 ||
        ReadU16(page + 8U) != kLogFormatVersion ||
        ReadU16(page + 10U) != kUpdateLocalLogHeaderBytes ||
        ReadU16(page + 12U) != kUpdateLocalLogRecordBytes) {
        return false;
    }
    const uint16_t count = ReadU16(page + 14U);
    const uint64_t generation = ReadU64(page + 16U);
    if (count == 0U || count > kUpdateLocalLogMaximumRecords ||
        generation == 0U || page[24U] != 0U || page[25U] != 0U ||
        page[26U] != 0U || page[27U] != 0U || page[28U] != 0U ||
        page[29U] != 0U || page[30U] != 0U || page[31U] != 0U) {
        return false;
    }
    const uint32_t crc = ReadU32(page + kLogCrcOffset);
    if (crc != CalculateCrc32(ByteView(page, kLogCrcOffset))) return false;

    uint64_t previous_ordinal = 0U;
    for (uint16_t index = 0U; index < count; ++index) {
        UpdateLocalLogRecord record;
        if (!DecodeRecord(page + kUpdateLocalLogHeaderBytes +
                              static_cast<size_t>(index) *
                                  kUpdateLocalLogRecordBytes,
                          &record) ||
            record.ordinal <= previous_ordinal ||
            record.ordinal > generation) {
            return false;
        }
        previous_ordinal = record.ordinal;
    }
    if (previous_ordinal != generation) return false;

    const size_t unused_begin = kUpdateLocalLogHeaderBytes +
        static_cast<size_t>(count) * kUpdateLocalLogRecordBytes;
    for (size_t index = unused_begin; index < kLogCrcOffset; ++index) {
        if (page[index] != 0U) return false;
    }
    info->valid = true;
    info->generation = generation;
    info->count = count;
    info->crc = crc;
    return true;
}

SlotInfo InspectSlot(UpdateFileSystem *file_system,
                     UpdateLocalLogWorkspace *workspace, const char *path)
{
    SlotInfo info;
    memset(&info, 0, sizeof(info));
    if (file_system == 0 || workspace == 0 || path == 0) {
        info.io_error = true;
        return info;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat)) {
        info.io_error = true;
        return info;
    }
    if (stat.type == UpdateNodeType::Missing) return info;
    info.present = true;
    if (stat.type != UpdateNodeType::RegularFile ||
        stat.size != kUpdateLocalLogPageBytes) {
        return info;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) {
        info.io_error = true;
        return info;
    }
    uint64_t size = 0U;
    bool ok = file->GetSize(&size) && size == kUpdateLocalLogPageBytes &&
              file->ReadAt(0U, workspace->page,
                           kUpdateLocalLogPageBytes);
    if (!file->Close()) ok = false;
    if (!ok) {
        info.io_error = true;
        return info;
    }
    (void)ParsePage(workspace->page, &info);
    return info;
}

CurrentLog LoadCurrent(UpdateFileSystem *file_system,
                       UpdateLocalLogWorkspace *workspace)
{
    CurrentLog current;
    memset(&current, 0, sizeof(current));
    const SlotInfo a = InspectSlot(file_system, workspace,
                                   kUpdateLocalLogPathA);
    const SlotInfo b = InspectSlot(file_system, workspace,
                                   kUpdateLocalLogPathB);
    current.any_present = a.present || b.present;
    current.io_error = a.io_error || b.io_error;
    if (current.io_error) return current;

    if (a.valid && b.valid && a.generation == b.generation) {
        current.generation = a.generation;
        if (a.crc != b.crc) {
            current.ambiguous = true;
            return current;
        }
        current.selected = Slot::A;
    } else if (a.valid && (!b.valid || a.generation > b.generation)) {
        current.selected = Slot::A;
    } else if (b.valid) {
        current.selected = Slot::B;
    }

    if (current.selected == Slot::None) return current;
    const char *path = current.selected == Slot::A
        ? kUpdateLocalLogPathA : kUpdateLocalLogPathB;
    const SlotInfo selected = InspectSlot(file_system, workspace, path);
    if (!selected.valid || selected.io_error) {
        current.io_error = true;
        current.selected = Slot::None;
        return current;
    }
    current.generation = selected.generation;
    current.count = selected.count;
    return current;
}

bool EnsureRoot(UpdateFileSystem *file_system)
{
    if (file_system == 0) return false;
    UpdateFileStat root;
    if (!file_system->Stat(kUpdateLocalLogRoot, &root)) return false;
    if (root.type == UpdateNodeType::Directory) return true;
    if (root.type != UpdateNodeType::Missing ||
        !file_system->CreateDirectory(kUpdateLocalLogRoot)) {
        return false;
    }
    return file_system->SyncContainingDirectory(kUpdateLocalLogRoot);
}

bool PageMatches(UpdateFileSystem *file_system,
                 UpdateLocalLogWorkspace *workspace, const char *path,
                 uint64_t generation, uint16_t count, uint32_t crc)
{
    const SlotInfo info = InspectSlot(file_system, workspace, path);
    return info.valid && !info.io_error && info.generation == generation &&
           info.count == count && info.crc == crc;
}

bool PersistPage(UpdateFileSystem *file_system,
                 UpdateLocalLogWorkspace *workspace, const char *target,
                 uint64_t generation, uint16_t count, uint32_t crc)
{
    if (!file_system->RemoveFile(kUpdateLocalLogTemporaryPath) ||
        !file_system->SyncContainingDirectory(
            kUpdateLocalLogTemporaryPath)) {
        return false;
    }

    UpdateWriteFile *file = 0;
    if (!file_system->CreateFileFresh(kUpdateLocalLogTemporaryPath, &file) ||
        file == 0) {
        return false;
    }
    bool ok = file->Write(ByteView(workspace->page,
                                   kUpdateLocalLogPageBytes));
    if (ok) ok = file->Sync();
    if (!file->Close()) ok = false;
    if (!ok || !PageMatches(file_system, workspace,
                            kUpdateLocalLogTemporaryPath,
                            generation, count, crc)) {
        (void)file_system->RemoveFile(kUpdateLocalLogTemporaryPath);
        return false;
    }

    if (!file_system->RemoveFile(target) ||
        !file_system->SyncContainingDirectory(target) ||
        !file_system->Rename(kUpdateLocalLogTemporaryPath, target, false) ||
        !file_system->SyncContainingDirectory(target)) {
        return false;
    }
    return PageMatches(file_system, workspace, target,
                       generation, count, crc);
}

bool Append(UpdateFileSystem *file_system, UpdateLocalLogWorkspace *workspace,
            UpdateLocalLogScope scope, UpdateLocalLogCode code,
            uint64_t completed, uint64_t total)
{
    UpdateLocalLogRecordKind kind;
    if (file_system == 0 || workspace == 0 || !ValidScope(scope) ||
        !ClassifyCode(code, &kind) ||
        (kind == UpdateLocalLogRecordKind::Progress &&
         total != 0U && completed > total) || !EnsureRoot(file_system)) {
        return false;
    }

    const CurrentLog current = LoadCurrent(file_system, workspace);
    if (current.io_error || current.generation == UINT64_MAX) return false;

    uint16_t count = current.selected == Slot::None ? 0U : current.count;
    if (current.selected == Slot::None) {
        memset(workspace->page, 0, sizeof(workspace->page));
    } else if (count == kUpdateLocalLogMaximumRecords) {
        memmove(workspace->page + kUpdateLocalLogHeaderBytes,
                workspace->page + kUpdateLocalLogHeaderBytes +
                    kUpdateLocalLogRecordBytes,
                (kUpdateLocalLogMaximumRecords - 1U) *
                    kUpdateLocalLogRecordBytes);
        --count;
    }

    UpdateLocalLogRecord record;
    record.scope = scope;
    record.kind = kind;
    record.code = code;
    record.ordinal = current.generation + 1U;
    record.completed = completed;
    record.total = total;
    EncodeRecord(record, workspace->page + kUpdateLocalLogHeaderBytes +
                              static_cast<size_t>(count) *
                                  kUpdateLocalLogRecordBytes);
    ++count;

    memcpy(workspace->page, kLogMagic, sizeof(kLogMagic));
    WriteU16(workspace->page + 8U, kLogFormatVersion);
    WriteU16(workspace->page + 10U,
             static_cast<uint16_t>(kUpdateLocalLogHeaderBytes));
    WriteU16(workspace->page + 12U,
             static_cast<uint16_t>(kUpdateLocalLogRecordBytes));
    WriteU16(workspace->page + 14U, count);
    WriteU64(workspace->page + 16U, record.ordinal);
    memset(workspace->page + 24U, 0, 8U);
    const size_t unused_begin = kUpdateLocalLogHeaderBytes +
        static_cast<size_t>(count) * kUpdateLocalLogRecordBytes;
    memset(workspace->page + unused_begin, 0,
           kLogCrcOffset - unused_begin);
    const uint32_t crc = CalculateCrc32(
        ByteView(workspace->page, kLogCrcOffset));
    WriteU32(workspace->page + kLogCrcOffset, crc);

    const char *target = current.selected == Slot::A
        ? kUpdateLocalLogPathB : kUpdateLocalLogPathA;
    if (!PersistPage(file_system, workspace, target,
                     record.ordinal, count, crc)) {
        return false;
    }

    // A v1 writer can create only exact-size or shorter torn slots.  If both
    // permanent names were already invalid before the first valid publish,
    // remove the other untrusted node only after the new A slot was verified.
    // This restores the advertised hard disk bound without ever deleting a
    // selected generation first.  Ambiguous but individually valid slots have
    // a non-zero baseline generation and remain as the normal fallback copy.
    if (current.selected == Slot::None && current.generation == 0U &&
        current.any_present) {
        const char *other = strcmp(target, kUpdateLocalLogPathA) == 0
            ? kUpdateLocalLogPathB : kUpdateLocalLogPathA;
        if (!file_system->RemoveFile(other) ||
            !file_system->SyncContainingDirectory(other)) {
            return false;
        }
    }
    return true;
}

}  // namespace

UpdateLocalLog::UpdateLocalLog(UpdateFileSystem *file_system,
                               UpdateLocalLogWorkspace *workspace)
    : file_system_(file_system), workspace_(workspace),
      last_record_persisted_(false)
{
}

void UpdateLocalLog::Record(UpdateLocalLogScope scope,
                            UpdateLocalLogCode code,
                            uint64_t completed, uint64_t total)
{
    last_record_persisted_ = Append(file_system_, workspace_, scope, code,
                                    completed, total);
}

UpdateLocalLogReadStatus UpdateLocalLog::Read(
    UpdateLocalLogRecord *records, size_t capacity, size_t *count,
    uint64_t *generation)
{
    if (count == 0 || generation == 0 ||
        (records == 0 && capacity != 0U) ||
        file_system_ == 0 || workspace_ == 0) {
        return UpdateLocalLogReadStatus::InvalidArgument;
    }
    *count = 0U;
    *generation = 0U;
    const CurrentLog current = LoadCurrent(file_system_, workspace_);
    if (current.io_error) return UpdateLocalLogReadStatus::IoError;
    if (current.selected == Slot::None) {
        return current.any_present || current.ambiguous
            ? UpdateLocalLogReadStatus::Corrupt
            : UpdateLocalLogReadStatus::NoLog;
    }
    *count = current.count;
    *generation = current.generation;
    if (capacity < current.count) {
        return UpdateLocalLogReadStatus::BufferTooSmall;
    }
    for (uint16_t index = 0U; index < current.count; ++index) {
        if (!DecodeRecord(workspace_->page + kUpdateLocalLogHeaderBytes +
                              static_cast<size_t>(index) *
                                  kUpdateLocalLogRecordBytes,
                          &records[index])) {
            *count = 0U;
            *generation = 0U;
            return UpdateLocalLogReadStatus::Corrupt;
        }
    }
    return UpdateLocalLogReadStatus::Ok;
}

LoggingUpdateRecoveryProgress::LoggingUpdateRecoveryProgress(
    UpdateLocalLog *log, UpdateLocalLogScope scope,
    UpdateRecoveryProgress *delegate)
    : log_(log), scope_(scope), delegate_(delegate)
{
}

void LoggingUpdateRecoveryProgress::BeginMandatoryOperation()
{
    if (delegate_ != 0) delegate_->BeginMandatoryOperation();
}

void LoggingUpdateRecoveryProgress::EndMandatoryOperation()
{
    if (delegate_ != 0) delegate_->EndMandatoryOperation();
}

bool LoggingUpdateRecoveryProgress::Report(
    const UpdateRecoveryProgressEvent &event)
{
    if (delegate_ != 0 && !delegate_->Report(event)) return false;
    UpdateLocalLogCode code;
    if (log_ != 0 && ProgressCode(event.kind, &code)) {
        log_->Record(scope_, code, event.completed_bytes, event.total_bytes);
    }
    return true;
}

const char *UpdateLocalLogReadStatusString(UpdateLocalLogReadStatus status)
{
    switch (status) {
    case UpdateLocalLogReadStatus::Ok: return "ok";
    case UpdateLocalLogReadStatus::NoLog: return "no-log";
    case UpdateLocalLogReadStatus::InvalidArgument:
        return "invalid-argument";
    case UpdateLocalLogReadStatus::BufferTooSmall:
        return "buffer-too-small";
    case UpdateLocalLogReadStatus::Corrupt: return "corrupt";
    case UpdateLocalLogReadStatus::IoError: return "io-error";
    }
    return "unknown";
}

}  // namespace update
}  // namespace bmx
