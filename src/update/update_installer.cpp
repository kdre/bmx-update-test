#include "update_installer.h"

#include "crc32.h"
#include "fat_path_policy.h"
#include "sha256.h"
#include "update_fault_injection.h"

#include <string.h>

namespace bmx {
namespace update {
namespace {

enum class JournalSlot : uint8_t { None = 0, A, B };

bool CheckedAdd(uint64_t left, uint64_t right, uint64_t *result)
{
    if (result == 0 || left > UINT64_MAX - right) {
        return false;
    }
    *result = left + right;
    return true;
}

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t value = 0U;
    for (size_t index = 0U; index < size; ++index) value |= bytes[index];
    return value != 0U;
}

bool ValidRelativePath(const char *path, size_t maximum_path_bytes)
{
    return ValidateFatRelativePath(path, maximum_path_bytes) ==
           FatPathValidationStatus::Ok;
}

bool CopyText(char *destination, size_t capacity, const char *text)
{
    if (destination == 0 || capacity == 0U || text == 0) return false;
    const size_t length = strlen(text);
    if (length >= capacity) return false;
    memcpy(destination, text, length + 1U);
    return true;
}

bool JoinPath(char *destination, size_t capacity,
              const char *left, const char *right)
{
    if (destination == 0 || left == 0 || right == 0 || right[0] == '\0') {
        return false;
    }
    const size_t left_length = strlen(left);
    const size_t right_length = strlen(right);
    if (left_length == 0U || left_length + 1U + right_length >= capacity) {
        return false;
    }
    memcpy(destination, left, left_length);
    destination[left_length] = '/';
    memcpy(destination + left_length + 1U, right, right_length + 1U);
    return true;
}

bool AddSuffix(char *destination, size_t capacity,
               const char *path, const char *suffix)
{
    if (destination == 0 || path == 0 || suffix == 0) return false;
    const size_t path_length = strlen(path);
    const size_t suffix_length = strlen(suffix);
    if (path_length + suffix_length >= capacity) return false;
    memcpy(destination, path, path_length);
    memcpy(destination + path_length, suffix, suffix_length + 1U);
    return true;
}

bool AppendDecimal(char *destination, size_t capacity,
                   const char *prefix, size_t value)
{
    if (destination == 0 || prefix == 0) return false;
    char digits[24];
    size_t count = 0U;
    do {
        digits[count++] = static_cast<char>('0' + (value % 10U));
        value /= 10U;
    } while (value != 0U && count < sizeof(digits));
    const size_t prefix_length = strlen(prefix);
    if (prefix_length + count >= capacity) return false;
    memcpy(destination, prefix, prefix_length);
    for (size_t index = 0U; index < count; ++index) {
        destination[prefix_length + index] = digits[count - index - 1U];
    }
    destination[prefix_length + count] = '\0';
    return true;
}

void WriteU32(uint8_t *destination, uint32_t value)
{
    for (unsigned index = 0U; index < 4U; ++index) {
        destination[index] = static_cast<uint8_t>(value >> (index * 8U));
    }
}

void WriteU64(uint8_t *destination, uint64_t value)
{
    for (unsigned index = 0U; index < 8U; ++index) {
        destination[index] = static_cast<uint8_t>(value >> (index * 8U));
    }
}

uint32_t ReadU32(const uint8_t *source)
{
    uint32_t value = 0U;
    for (unsigned index = 0U; index < 4U; ++index) {
        value |= static_cast<uint32_t>(source[index]) << (index * 8U);
    }
    return value;
}

uint64_t ReadU64(const uint8_t *source)
{
    uint64_t value = 0U;
    for (unsigned index = 0U; index < 8U; ++index) {
        value |= static_cast<uint64_t>(source[index]) << (index * 8U);
    }
    return value;
}

static const size_t kExistenceEvidenceBytes = 20U;
static const size_t kSnapshotEvidenceBytes = 60U;
static const size_t kContentPlanHeaderBytes = 128U;
static const size_t kContentPlanRecordBytes = 48U;
static const size_t kContentPlanFooterBytes = 80U;
static const size_t kContentPlanNoopBytes =
    (kMaximumManifestFiles + 7U) / 8U;
static const uint64_t kArchiveHashProgressIntervalBytes =
    UINT64_C(256) * UINT64_C(1024);
static const uint8_t kExistenceMagic[8] = {'B','M','X','E','X','S','T','1'};
static const uint8_t kSnapshotMagic[8] = {'B','M','X','S','N','A','P','1'};
static const uint8_t kContentPlanPreparedMagic[8] =
    {'B','M','X','P','L','N','1','P'};
static const uint8_t kContentPlanFinalMagic[8] =
    {'B','M','X','P','L','N','1','F'};
static const uint8_t kContentPlanFooterMagic[8] =
    {'B','M','X','P','L','E','N','D'};
static const char kCandidateSelectorPath[] = "bmx-tryboot-kernel.txt";

enum ContentPlanRecordFlags {
    kContentPlanNoop = 1U << 0,
    kContentPlanSourceExisted = 1U << 1,
    kContentPlanOldDigestValid = 1U << 2
};

struct ContentPlanRecord {
    uint32_t flags;
    uint64_t old_size;
    uint8_t old_digest[kSha256DigestBytes];
};

void EncodeContentPlanRecord(size_t index, const ContentPlanRecord &record,
                             uint8_t encoded[kContentPlanRecordBytes])
{
    memset(encoded, 0, kContentPlanRecordBytes);
    WriteU32(encoded, static_cast<uint32_t>(index));
    WriteU32(encoded + 4U, record.flags);
    WriteU64(encoded + 8U, record.old_size);
    memcpy(encoded + 16U, record.old_digest, kSha256DigestBytes);
}

bool DecodeContentPlanRecord(size_t expected_index, const uint8_t *encoded,
                             ContentPlanRecord *record)
{
    static const uint32_t kKnownFlags = kContentPlanNoop |
        kContentPlanSourceExisted | kContentPlanOldDigestValid;
    if (encoded == 0 || record == 0 ||
        ReadU32(encoded) != expected_index) return false;
    record->flags = ReadU32(encoded + 4U);
    record->old_size = ReadU64(encoded + 8U);
    memcpy(record->old_digest, encoded + 16U, kSha256DigestBytes);
    if ((record->flags & ~kKnownFlags) != 0U ||
        ((record->flags & kContentPlanSourceExisted) == 0U &&
         (record->old_size != 0U ||
          BytesNonZero(record->old_digest, kSha256DigestBytes))) ||
        ((record->flags & kContentPlanOldDigestValid) == 0U &&
         BytesNonZero(record->old_digest, kSha256DigestBytes)) ||
        ((record->flags & kContentPlanOldDigestValid) != 0U &&
         (record->flags & kContentPlanSourceExisted) == 0U) ||
        ((record->flags & kContentPlanNoop) != 0U &&
         (((record->flags & kContentPlanSourceExisted) == 0U) ||
          ((record->flags & kContentPlanOldDigestValid) == 0U)))) {
        return false;
    }
    return true;
}

class InstallerHashSink : public ZipHashSink {
public:
    explicit InstallerHashSink(UpdateRecoveryProgress *progress)
        : progress_(progress), file_completed_(0U), file_total_(0U),
          aggregate_completed_(0U), aggregate_total_(0U),
          aggregate_progress_(false), progress_failed_(false), active_(false)
    {
    }

    InstallerHashSink(UpdateRecoveryProgress *progress, uint64_t aggregate_total)
        : progress_(progress), file_completed_(0U), file_total_(0U),
          aggregate_completed_(0U), aggregate_total_(aggregate_total),
          aggregate_progress_(true), progress_failed_(false), active_(false)
    {
    }

    bool BeginFile(const char *, uint64_t size)
    {
        if (active_ ||
            (aggregate_progress_ &&
             (aggregate_completed_ > aggregate_total_ ||
              size > aggregate_total_ - aggregate_completed_))) return false;
        hash_.Reset();
        file_completed_ = 0U;
        file_total_ = size;
        active_ = true;
        return true;
    }

    bool Update(ByteView bytes)
    {
        if (!active_ || file_completed_ > file_total_ ||
            bytes.size > file_total_ - file_completed_ ||
            (aggregate_progress_ &&
             (aggregate_completed_ > aggregate_total_ ||
              bytes.size > aggregate_total_ - aggregate_completed_)) ||
            !hash_.Update(bytes.data, bytes.size)) return false;
        file_completed_ += bytes.size;
        if (aggregate_progress_) aggregate_completed_ += bytes.size;
        if (!ReportUpdateRecoveryProgress(
                progress_, UpdateRecoveryProgressKind::InstallerFileHashed,
                aggregate_progress_ ? aggregate_completed_ : file_completed_,
                aggregate_progress_ ? aggregate_total_ : file_total_)) {
            progress_failed_ = true;
            return false;
        }
        return true;
    }

    bool FinishFile(uint8_t digest[kSha256DigestBytes])
    {
        if (!active_) return false;
        active_ = false;
        return hash_.Final(digest);
    }

    void AbortFile()
    {
        active_ = false;
        hash_.Reset();
    }

    bool progress_failed() const { return progress_failed_; }

private:
    UpdateRecoveryProgress *progress_;
    uint64_t file_completed_;
    uint64_t file_total_;
    uint64_t aggregate_completed_;
    uint64_t aggregate_total_;
    Sha256 hash_;
    bool aggregate_progress_;
    bool progress_failed_;
    bool active_;
};

struct StepLayout {
    uint32_t snapshot_begin;
    uint32_t file_stage_begin;
    uint32_t directory_activate_begin;
    uint32_t file_activate_begin;
    uint32_t stage_end;
    uint32_t arm_step;
    uint32_t health_step;
    uint32_t kernel_begin;
    uint32_t metadata_begin;
    uint32_t selector_step;
    uint32_t total;
};

bool BuildStepLayout(const ManifestAsset &asset, StepLayout *layout)
{
    if (layout == 0 || asset.file_count > kMaximumManifestFiles ||
        asset.directory_count > kMaximumManifestDirectories) return false;
    uint64_t snapshots = 0U;
    uint64_t non_metadata = 0U;
    uint64_t kernels = 0U;
    uint64_t metadata = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFilePolicy policy = asset.files[index].policy;
        if (policy == ManifestFilePolicy::ManagedReplace ||
            policy == ManifestFilePolicy::ConfigTemplate ||
            policy == ManifestFilePolicy::Kernel) ++snapshots;
        if (policy == ManifestFilePolicy::Kernel) ++kernels;
        if (policy == ManifestFilePolicy::Metadata) ++metadata;
        else if (policy != ManifestFilePolicy::Kernel) ++non_metadata;
    }
    uint64_t cursor = 0U;
    layout->snapshot_begin = 0U;
    cursor += snapshots;
    layout->file_stage_begin = static_cast<uint32_t>(cursor);
    cursor += asset.file_count;
    layout->directory_activate_begin = static_cast<uint32_t>(cursor);
    cursor += asset.directory_count;
    layout->file_activate_begin = static_cast<uint32_t>(cursor);
    cursor += non_metadata;
    if (cursor > kMaximumJournalSteps) return false;
    layout->stage_end = static_cast<uint32_t>(cursor);
    layout->arm_step = static_cast<uint32_t>(cursor++);
    layout->health_step = static_cast<uint32_t>(cursor++);
    layout->kernel_begin = static_cast<uint32_t>(cursor);
    cursor += kernels;
    layout->metadata_begin = static_cast<uint32_t>(cursor);
    cursor += metadata;
    layout->selector_step = static_cast<uint32_t>(cursor++);
    if (cursor == 0U || cursor > kMaximumJournalSteps) return false;
    layout->total = static_cast<uint32_t>(cursor);
    return true;
}

struct OpenJournal {
    JournalSelectionResult selection;
    JournalSlot slot;
};

class Engine;

class TransactionExtractSink : public ZipExtractSink {
public:
    TransactionExtractSink(Engine *engine,
                           const ManifestFile *expected,
                           const char *final_path);
    bool BeginEntry(const ZipEntry &entry);
    bool Write(ByteView bytes);
    bool CommitEntry(const ZipEntry &entry);
    void AbortEntry(const ZipEntry &entry);

private:
    Engine *engine_;
    const ManifestFile *expected_;
    const char *final_path_;
    char temporary_path_[kInstallerMaximumPathBytes + 1U];
    UpdateWriteFile *file_;
    Sha256 hash_;
    uint64_t written_;
    bool active_;
};

class Engine {
public:
    Engine(UpdateFileSystem *file_system, CandidateBackend *backend,
           const InstallerRequest &request, const InstallerWorkspace *workspace)
        : fs_(file_system), backend_(backend), request_(request),
          workspace_(workspace), slot_(JournalSlot::None), have_journal_(false),
          progress_failed_(false), content_plan_loaded_(false),
          content_plan_final_(false), stage_work_tracking_(false),
          stage_work_reporting_(false),
          stage_work_completed_(0U), stage_work_total_(0U),
          content_plan_changed_files_(0U),
          content_plan_unchanged_files_(0U)
    {
        memset(&record_, 0, sizeof(record_));
        memset(content_plan_noop_, 0, sizeof(content_plan_noop_));
        memset(&storage_result_, 0, sizeof(storage_result_));
        storage_result_.decision = StorageDecision::InvalidLimits;
    }

    InstallerResult Stage();
    InstallerResult Arm();
    InstallerResult Healthy();
    InstallerResult Commit();
    InstallerResult Rollback();
    InstallerResult RetireRolledBack();
    InstallerResult RetireCommitted();
    InstallerResult ReadOnlyJournal(JournalRecord *record);

    bool EnsureParents(const char *path);
    bool RemoveIfPresent(const char *path);
    bool RemoveFileAndTemporary(const char *path);
    bool VerifyFile(const char *path, uint64_t size,
                    const uint8_t digest[kSha256DigestBytes],
                    InstallerStatus *failure);
    UpdateFileSystem *fs() const { return fs_; }
    bool Progress(UpdateRecoveryProgressKind kind,
                  uint64_t completed = 0U, uint64_t total = 0U);

private:
    friend class TransactionExtractSink;

    InstallerResult Result(InstallerStatus status, ZipStatus zip_status = ZipStatus::Ok);
    bool DurabilitySupported() const;
    bool BasicRequestValid(bool require_workspace, InstallerStatus *failure,
                           bool require_prepared = true);
    bool IdentityMatches(const JournalRecord &record) const;
    bool BuildPaths(InstallerStatus *failure);
    bool EnsureTransactionDirectories();
    InstallerStatus PrepareArchive(ZipReader *reader,
                                   ZipExpectedInventory *expected,
                                   InstallerHashSink *hash_sink,
                                   StepLayout *layout,
                                   ZipStatus *zip_status);
    InstallerStatus ValidatePreparedConfigs();
    const PreparedConfigTemplate *PreparedConfig(const ManifestFile &file) const;
    uint64_t EffectiveSize(const ManifestFile &file) const;
    const uint8_t *EffectiveDigest(const ManifestFile &file) const;
    InstallerStatus StagePreparedConfig(const ManifestFile &file,
                                        const char *staged_path);
    InstallerStatus BuildContentPlan();
    InstallerStatus LoadContentPlan(bool require_final);
    InstallerStatus FinalizeContentPlan();
    InstallerStatus WriteContentPlanFile(bool final_plan);
    InstallerStatus ReadContentPlanRecord(size_t index,
                                          ContentPlanRecord *record);
    bool ContentPlanPath(bool final_plan, char *path, size_t capacity) const;
    InstallerStatus RemoveSnapshotEvidenceFiles();
    InstallerStatus InitializeStageWork();
    bool AddStageWork(uint64_t bytes);
    InstallerStatus PreflightStorage();
    InstallerStatus LoadJournal(bool allow_missing);
    InstallerStatus ReadJournalFile(const char *path, bool *present,
                                    uint8_t bytes[kJournalEncodedSize]);
    InstallerStatus WriteInitialJournal(const JournalRecord &record);
    InstallerStatus WriteTransition(const JournalRecord &next);
    InstallerStatus WriteJournalBytes(const JournalRecord &next,
                                      JournalSlot destination);
    InstallerStatus InitializeJournal(const StepLayout &layout);
    InstallerStatus AdvancePrepared();
    InstallerStatus AdvancePreparedTo(uint32_t completed_steps);
    InstallerStatus SnapshotFile(size_t index, const ManifestFile &file);
    InstallerStatus StageFile(size_t index, const ManifestFile &file,
                              ZipReader *reader,
                              const ZipExpectedInventory &expected,
                              InstallerHashSink *hash_sink);
    InstallerStatus ActivateDirectory(size_t index,
                                      const ManifestDirectory &directory);
    InstallerStatus ActivateFile(size_t index, const ManifestFile &file);
    InstallerStatus CommitMetadata(size_t index, const ManifestFile &file);
    InstallerStatus VerifyCandidateFiles();
    InstallerStatus RestoreFile(size_t index, const ManifestFile &file);
    InstallerStatus RestoreMetadata(size_t index, const ManifestFile &file);
    InstallerStatus RemoveCreatedDirectories();
    bool RemoveTransactionFile(const char *base, const char *relative);
    void TryRemoveDerivedDirectories(const char *base, const char *relative);
    bool RemoveAndVerifyDirectory(const char *path);
    InstallerStatus RetireObsoleteFiles();
    InstallerStatus RemoveTransactionArtifacts(bool active_request);
    bool MarkerPath(bool directory, size_t index, char *path, size_t capacity) const;
    InstallerStatus EnsureMarker(bool directory, size_t index, bool existed);
    bool MarkerExists(bool directory, size_t index, bool *exists);
    bool SnapshotEvidencePath(size_t index, char *path, size_t capacity) const;
    InstallerStatus IsNoop(size_t index, bool *noop);
    InstallerStatus WriteFreshEvidence(const char *path,
                                       const uint8_t *bytes, size_t size);
    InstallerStatus ReadEvidence(const char *path, uint8_t *bytes,
                                 size_t size, bool *present);
    InstallerStatus WriteSnapshotEvidence(size_t index, bool existed,
                                          uint64_t size,
                                          const uint8_t digest[kSha256DigestBytes]);
    InstallerStatus ReadSnapshotEvidence(size_t index, bool *existed,
                                         uint64_t *size,
                                         uint8_t digest[kSha256DigestBytes]);
    InstallerStatus ReadMetadataEvidence(size_t index, bool *existed,
                                         uint64_t *size,
                                         uint8_t digest[kSha256DigestBytes]);
    bool HashFile(const char *path, uint8_t digest[kSha256DigestBytes],
                  uint64_t *size);
    InstallerStatus CopyFileAtomic(
        const char *source, const char *destination,
        uint64_t *copied_size = 0,
        uint8_t copied_digest[kSha256DigestBytes] = 0);
    InstallerStatus CopyFileAtomicExpected(
        const char *source, const char *destination, uint64_t expected_size,
        const uint8_t expected_digest[kSha256DigestBytes]);
    InstallerStatus ReplaceWithCopy(const char *source, const char *destination);
    CandidateContext Candidate() const;

    UpdateFileSystem *fs_;
    CandidateBackend *backend_;
    const InstallerRequest &request_;
    const InstallerWorkspace *workspace_;
    char root_[kInstallerMaximumPathBytes + 1U];
    char stage_root_[kInstallerMaximumPathBytes + 1U];
    char snapshot_root_[kInstallerMaximumPathBytes + 1U];
    char state_root_[kInstallerMaximumPathBytes + 1U];
    char metadata_old_root_[kInstallerMaximumPathBytes + 1U];
    char journal_a_[kInstallerMaximumPathBytes + 1U];
    char journal_b_[kInstallerMaximumPathBytes + 1U];
    char journal_temp_[kInstallerMaximumPathBytes + 1U];
    JournalRecord record_;
    JournalSlot slot_;
    bool have_journal_;
    bool progress_failed_;
    bool content_plan_loaded_;
    bool content_plan_final_;
    bool stage_work_tracking_;
    bool stage_work_reporting_;
    uint64_t stage_work_completed_;
    uint64_t stage_work_total_;
    uint32_t content_plan_changed_files_;
    uint32_t content_plan_unchanged_files_;
    uint8_t content_plan_noop_[kContentPlanNoopBytes];
    StoragePreflightResult storage_result_;
};

TransactionExtractSink::TransactionExtractSink(Engine *engine,
                                               const ManifestFile *expected,
                                               const char *final_path)
    : engine_(engine), expected_(expected), final_path_(final_path), file_(0),
      written_(0U), active_(false)
{
    temporary_path_[0] = '\0';
}

bool TransactionExtractSink::BeginEntry(const ZipEntry &entry)
{
    if (active_ || engine_ == 0 || expected_ == 0 || final_path_ == 0 ||
        entry.is_directory || strcmp(entry.path, expected_->path) != 0 ||
        entry.size != expected_->size ||
        !engine_->EnsureParents(final_path_) ||
        !AddSuffix(temporary_path_, sizeof(temporary_path_), final_path_, ".part") ||
        !engine_->RemoveIfPresent(temporary_path_) ||
        !engine_->fs()->CreateFileFresh(temporary_path_, &file_) || file_ == 0) {
        return false;
    }
    hash_.Reset();
    written_ = 0U;
    active_ = true;
    return true;
}

bool TransactionExtractSink::Write(ByteView bytes)
{
    if (!active_ || file_ == 0 ||
        bytes.size > expected_->size - written_ ||
        !hash_.Update(bytes.data, bytes.size) || !file_->Write(bytes)) return false;
    written_ += bytes.size;
    return engine_->AddStageWork(bytes.size) &&
           engine_->Progress(UpdateRecoveryProgressKind::InstallerFileCopied,
                             written_, expected_->size);
}

bool TransactionExtractSink::CommitEntry(const ZipEntry &entry)
{
    uint8_t digest[kSha256DigestBytes];
    const bool content_ok = active_ && strcmp(entry.path, expected_->path) == 0 &&
        written_ == expected_->size && hash_.Final(digest) &&
        ConstantTimeDigestEqual(digest, expected_->sha256);
    bool file_ok = false;
    if (file_ != 0) {
        const bool synced = content_ok && file_->Sync();
        const bool closed = file_->Close();
        file_ok = content_ok && synced && closed;
        file_ = 0;
    }
    active_ = false;
    if (!file_ok || !engine_->fs()->Rename(temporary_path_, final_path_, false) ||
        !engine_->fs()->SyncContainingDirectory(final_path_)) {
        engine_->RemoveIfPresent(temporary_path_);
        return false;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    return engine_->VerifyFile(final_path_, expected_->size, expected_->sha256,
                               &failure);
}

void TransactionExtractSink::AbortEntry(const ZipEntry &)
{
    if (file_ != 0) {
        file_->Close();
        file_ = 0;
    }
    active_ = false;
    if (temporary_path_[0] != '\0') engine_->RemoveIfPresent(temporary_path_);
}

bool Engine::BuildPaths(InstallerStatus *failure)
{
    if (!ValidRelativePath(request_.transaction_root,
                           kInstallerMaximumPathBytes) ||
        !CopyText(root_, sizeof(root_), request_.transaction_root) ||
        !JoinPath(stage_root_, sizeof(stage_root_), root_, "stage") ||
        !JoinPath(snapshot_root_, sizeof(snapshot_root_), root_, "snapshot") ||
        !JoinPath(state_root_, sizeof(state_root_), root_, "state") ||
        !JoinPath(metadata_old_root_, sizeof(metadata_old_root_), root_, "metadata-old") ||
        !JoinPath(journal_a_, sizeof(journal_a_), root_, "journal.a") ||
        !JoinPath(journal_b_, sizeof(journal_b_), root_, "journal.b") ||
        !JoinPath(journal_temp_, sizeof(journal_temp_), root_, "journal.tmp")) {
        if (failure != 0) *failure = InstallerStatus::InvalidPath;
        return false;
    }
    return true;
}

bool Engine::BasicRequestValid(bool require_workspace, InstallerStatus *failure,
                               bool require_prepared)
{
    if (failure == 0 || fs_ == 0 || request_.manifest == 0 ||
        request_.transaction_root == 0) {
        if (failure != 0) *failure = InstallerStatus::InvalidArgument;
        return false;
    }
    const ReleaseManifest &manifest = *request_.manifest;
    const ManifestAsset &asset = manifest.asset;
    if (!IsKnownBoardFamily(asset.board) || manifest.release_sequence == 0U ||
        request_.identity.source_release_sequence == 0U ||
        manifest.release_sequence <= request_.identity.source_release_sequence ||
        request_.identity.old_boot_generation == 0U ||
        request_.identity.new_boot_generation == 0U ||
        request_.identity.old_boot_generation == request_.identity.new_boot_generation ||
        !BytesNonZero(request_.identity.transaction_id, kTransactionIdBytes) ||
        !BytesNonZero(request_.identity.manifest_sha256, kSha256DigestBytes) ||
        !BytesNonZero(request_.identity.consent_sha256, kSha256DigestBytes) ||
        !BytesNonZero(asset.sha256, kSha256DigestBytes) ||
        (request_.identity.reset_required && !request_.identity.reset_approved) ||
        (!request_.identity.reset_required && request_.identity.reset_approved) ||
        asset.files == 0 || asset.file_count == 0U ||
        (asset.directory_count != 0U && asset.directories == 0)) {
        *failure = InstallerStatus::InvalidIdentity;
        return false;
    }
    StepLayout unused;
    if (!BuildStepLayout(asset, &unused)) {
        *failure = InstallerStatus::InvalidManifest;
        return false;
    }
    size_t config_count = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (!ValidRelativePath(file.path, kMaximumManifestPathBytes) ||
            (file.compression != ManifestCompression::Store &&
             file.compression != ManifestCompression::Deflate) ||
            !BytesNonZero(file.sha256, kSha256DigestBytes)) {
            *failure = InstallerStatus::InvalidManifest;
            return false;
        }
        if (file.policy == ManifestFilePolicy::ConfigTemplate) ++config_count;
    }
    if (config_count != 0U && require_prepared) {
        const PreparedConfigSet *set = request_.prepared_configs;
        if (set == 0 || set->entries == 0 || set->entry_count != config_count) {
            *failure = InstallerStatus::PreparedConfigRequired;
            return false;
        }
        if (memcmp(set->manifest_sha256, request_.identity.manifest_sha256,
                   kSha256DigestBytes) != 0 ||
            memcmp(set->consent_sha256, request_.identity.consent_sha256,
                   kSha256DigestBytes) != 0 ||
            set->reset_required != request_.identity.reset_required ||
            set->reset_approved != request_.identity.reset_approved) {
            *failure = InstallerStatus::PreparedConfigInvalid;
            return false;
        }
        for (size_t index = 0U; index < set->entry_count; ++index) {
            const PreparedConfigTemplate &entry = set->entries[index];
            if (entry.path == 0 || (require_workspace && entry.content == 0) ||
                !ValidRelativePath(entry.path, kMaximumManifestPathBytes) ||
                !BytesNonZero(entry.prepared_sha256, kSha256DigestBytes) ||
                (entry.original_existed &&
                 !BytesNonZero(entry.original_sha256, kSha256DigestBytes)) ||
                (!entry.original_existed &&
                 (entry.original_size != 0U ||
                  BytesNonZero(entry.original_sha256, kSha256DigestBytes)))) {
                *failure = InstallerStatus::PreparedConfigInvalid;
                return false;
            }
            size_t matches = 0U;
            for (size_t file_index = 0U; file_index < asset.file_count; ++file_index) {
                if (asset.files[file_index].policy ==
                        ManifestFilePolicy::ConfigTemplate &&
                    strcmp(asset.files[file_index].path, entry.path) == 0) ++matches;
            }
            for (size_t prior = 0U; prior < index; ++prior) {
                if (strcmp(set->entries[prior].path, entry.path) == 0) ++matches;
            }
            if (matches != 1U) {
                *failure = InstallerStatus::PreparedConfigInvalid;
                return false;
            }
        }
    } else if (config_count == 0U && request_.prepared_configs != 0 &&
               request_.prepared_configs->entry_count != 0U) {
        *failure = InstallerStatus::PreparedConfigInvalid;
        return false;
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        if (!ValidRelativePath(asset.directories[index].path,
                               kMaximumManifestPathBytes)) {
            *failure = InstallerStatus::InvalidManifest;
            return false;
        }
    }
    if (require_workspace) {
        if (workspace_ == 0 || workspace_->zip_entries == 0 ||
            workspace_->expected_files == 0 || workspace_->zip_workspace == 0 ||
            workspace_->io_buffer == 0 ||
            workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes ||
            workspace_->zip_entry_capacity < asset.file_count + asset.directory_count ||
            workspace_->expected_file_capacity < asset.file_count ||
            (asset.directory_count != 0U &&
             (workspace_->expected_directories == 0 ||
              workspace_->expected_directory_capacity < asset.directory_count))) {
            *failure = InstallerStatus::WorkspaceTooSmall;
            return false;
        }
    } else if (workspace_ != 0 &&
               (workspace_->io_buffer == 0 ||
                workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes)) {
        *failure = InstallerStatus::WorkspaceTooSmall;
        return false;
    }
    return BuildPaths(failure);
}

InstallerResult Engine::Result(InstallerStatus status, ZipStatus zip_status)
{
    InstallerResult result;
    memset(&result, 0, sizeof(result));
    result.status = progress_failed_
        ? InstallerStatus::RecoveryProgressFailed : status;
    result.zip_status = zip_status;
    result.storage = storage_result_;
    result.journal_selection = have_journal_
        ? (slot_ == JournalSlot::A ? JournalSelectionStatus::SelectedA
                                   : JournalSelectionStatus::SelectedB)
        : JournalSelectionStatus::NoJournal;
    result.journal_state = have_journal_ ? record_.state : JournalState::Idle;
    result.completed_steps = have_journal_ ? record_.completed_steps : 0U;
    result.total_steps = have_journal_ ? record_.total_steps : 0U;
    return result;
}

bool Engine::Progress(UpdateRecoveryProgressKind kind,
                      uint64_t completed, uint64_t total)
{
    if (progress_failed_) return false;
    if (!ReportUpdateRecoveryProgress(request_.recovery_progress, kind,
                                      completed, total)) {
        progress_failed_ = true;
        return false;
    }
    return true;
}

bool Engine::AddStageWork(uint64_t bytes)
{
    if (!stage_work_tracking_ || bytes == 0U) return true;
    uint64_t completed = 0U;
    if (!CheckedAdd(stage_work_completed_, bytes, &completed)) {
        return false;
    }
    // The initial total is exact for a clean run. A reset at an unjournalled
    // private-file boundary may require one additional verification pass.
    // Progress accounting must never turn that safe replay into an installer
    // failure; extend the denominator while the UI retains its monotone
    // high-water mark.
    if (completed > stage_work_total_) stage_work_total_ = completed;
    stage_work_completed_ = completed;
    if (!stage_work_reporting_) return true;
    return Progress(UpdateRecoveryProgressKind::InstallerStageOverall,
                    stage_work_completed_, stage_work_total_);
}

bool Engine::DurabilitySupported() const
{
    UpdateDurabilityCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    return fs_ != 0 && fs_->GetDurabilityCapabilities(&capabilities) &&
           capabilities.durable_file_sync &&
           (capabilities.crash_safe_fresh_rename ||
            capabilities.power_loss_recovery_validated) &&
           (capabilities.crash_safe_replace_with_backup ||
            capabilities.power_loss_recovery_validated) &&
           capabilities.durable_directory_updates;
}

bool Engine::EnsureParents(const char *path)
{
    if (path == 0 || strlen(path) > kInstallerMaximumPathBytes) return false;
    char partial[kInstallerMaximumPathBytes + 1U];
    if (!CopyText(partial, sizeof(partial), path)) return false;
    for (size_t index = 0U; partial[index] != '\0'; ++index) {
        if (partial[index] != '/') continue;
        partial[index] = '\0';
        if (partial[0] == '\0' || !fs_->CreateDirectory(partial) ||
            !fs_->SyncContainingDirectory(partial)) return false;
        partial[index] = '/';
    }
    return true;
}

bool Engine::EnsureTransactionDirectories()
{
    const char *const paths[] = {
        root_, stage_root_, snapshot_root_, state_root_, metadata_old_root_
    };
    for (size_t index = 0U; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        if (!EnsureParents(paths[index]) || !fs_->CreateDirectory(paths[index]) ||
            !fs_->SyncContainingDirectory(paths[index])) return false;
    }
    return true;
}

bool Engine::RemoveIfPresent(const char *path)
{
    UpdateFileStat stat;
    if (!fs_->Stat(path, &stat)) return false;
    // A retry after a power cut may observe that the previous unlink reached
    // the FAT but its containing-directory flush did not. Re-acknowledge the
    // already-missing state before advancing to a later durable step.
    if (stat.type == UpdateNodeType::Missing) {
        return fs_->SyncContainingDirectory(path);
    }
    return stat.type == UpdateNodeType::RegularFile && fs_->RemoveFile(path) &&
           fs_->SyncContainingDirectory(path);
}

bool Engine::RemoveFileAndTemporary(const char *path)
{
    if (!RemoveIfPresent(path)) return false;
    const char *const suffixes[] = {".part", ".rollback"};
    for (size_t index = 0U;
         index < sizeof(suffixes) / sizeof(suffixes[0]); ++index) {
        char temporary[kInstallerMaximumPathBytes + 1U];
        if (!AddSuffix(temporary, sizeof(temporary), path, suffixes[index]) ||
            !RemoveIfPresent(temporary)) {
            return false;
        }
    }
    return true;
}

bool Engine::RemoveTransactionFile(const char *base, const char *relative)
{
    char path[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(path, sizeof(path), base, relative) ||
        !RemoveFileAndTemporary(path)) return false;
    return Progress(UpdateRecoveryProgressKind::InstallerRollbackStep);
}

void Engine::TryRemoveDerivedDirectories(const char *base,
                                         const char *relative)
{
    char path[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(path, sizeof(path), base, relative)) return;
    const size_t base_size = strlen(base);
    size_t size = strlen(path);
    while (size > base_size) {
        while (size > base_size && path[size - 1U] != '/') --size;
        if (size <= base_size) break;
        path[size - 1U] = '\0';
        (void) fs_->RemoveDirectory(path);
        (void) fs_->SyncContainingDirectory(path);
        size = strlen(path);
    }
}

bool Engine::RemoveAndVerifyDirectory(const char *path)
{
    if (path == 0 || !fs_->RemoveDirectory(path) ||
        !fs_->SyncContainingDirectory(path)) {
        return false;
    }
    UpdateFileStat stat;
    return fs_->Stat(path, &stat) && stat.type == UpdateNodeType::Missing;
}

InstallerStatus Engine::RemoveTransactionArtifacts(bool active_request)
{
    InstallerStatus source_retirement = RetireObsoleteFiles();
    if (source_retirement != InstallerStatus::Ok) return source_retirement;

    const ManifestAsset &asset = request_.manifest->asset;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const char *path = asset.files[index].path;
        if (!RemoveTransactionFile(stage_root_, path) ||
            !RemoveTransactionFile(snapshot_root_, path) ||
            !RemoveTransactionFile(metadata_old_root_, path)) {
            return progress_failed_ ? InstallerStatus::RecoveryProgressFailed
                                    : InstallerStatus::FileSystemError;
        }
    }

    for (size_t index = 0U; index < asset.file_count; ++index) {
        char path[kInstallerMaximumPathBytes + 1U];
        if (!MarkerPath(false, index, path, sizeof(path)) ||
            !RemoveFileAndTemporary(path)) {
            return InstallerStatus::FileSystemError;
        }
        if (!Progress(UpdateRecoveryProgressKind::InstallerRollbackStep,
                      index + 1U, asset.file_count)) {
            return InstallerStatus::RecoveryProgressFailed;
        }
    }
    const InstallerStatus scratch_cleanup = RemoveSnapshotEvidenceFiles();
    if (scratch_cleanup != InstallerStatus::Ok) return scratch_cleanup;
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        char path[kInstallerMaximumPathBytes + 1U];
        if (!MarkerPath(true, index, path, sizeof(path)) ||
            !RemoveFileAndTemporary(path)) {
            return InstallerStatus::FileSystemError;
        }
    }
    char content_plan[kInstallerMaximumPathBytes + 1U];
    if (!ContentPlanPath(false, content_plan, sizeof(content_plan)) ||
        !RemoveFileAndTemporary(content_plan) ||
        !ContentPlanPath(true, content_plan, sizeof(content_plan)) ||
        !RemoveFileAndTemporary(content_plan)) {
        return InstallerStatus::FileSystemError;
    }

    // All file removals happen before directory attempts.  Only parents
    // derived from authenticated inventory paths are touched; an unknown
    // node keeps a root non-empty and therefore blocks retirement.
    for (size_t index = 0U; index < asset.file_count; ++index) {
        TryRemoveDerivedDirectories(stage_root_, asset.files[index].path);
        TryRemoveDerivedDirectories(snapshot_root_, asset.files[index].path);
        TryRemoveDerivedDirectories(metadata_old_root_,
                                    asset.files[index].path);
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        TryRemoveDerivedDirectories(stage_root_, asset.directories[index].path);
        TryRemoveDerivedDirectories(snapshot_root_,
                                    asset.directories[index].path);
        TryRemoveDerivedDirectories(metadata_old_root_,
                                    asset.directories[index].path);
    }
    if (!RemoveAndVerifyDirectory(stage_root_) ||
        !RemoveAndVerifyDirectory(snapshot_root_) ||
        !RemoveAndVerifyDirectory(state_root_) ||
        !RemoveAndVerifyDirectory(metadata_old_root_)) {
        return InstallerStatus::FileSystemError;
    }

    // At this point the transaction may contain only its two journals plus
    // the fixed authenticated request inputs. A rolled-back transaction still
    // has the active request-state name; a committed transaction has the
    // inert committed-state name. Check this without traversal before deleting
    // the journals. Unknown direct children are preserved and keep cleanup
    // retryable.
    static const char *const kActiveExpectedRootEntries[] = {
        "request-state.bin", "journal.a", "journal.b", "journal.tmp",
        "request-installed.bin", "request-github.bin",
        "request-manifest.bin", "request-signature.bin"
    };
    static const char *const kCommittedExpectedRootEntries[] = {
        "committed-state.bin", "journal.a", "journal.b", "journal.tmp",
        "request-installed.bin", "request-github.bin",
        "request-manifest.bin", "request-signature.bin"
    };
    const char *const *expected = active_request
        ? kActiveExpectedRootEntries : kCommittedExpectedRootEntries;
    const size_t expected_count = active_request
        ? sizeof(kActiveExpectedRootEntries) /
              sizeof(kActiveExpectedRootEntries[0])
        : sizeof(kCommittedExpectedRootEntries) /
              sizeof(kCommittedExpectedRootEntries[0]);
    bool only_expected = false;
    if (!fs_->DirectoryContainsOnly(
            root_, expected, expected_count, &only_expected)) {
        return InstallerStatus::FileSystemError;
    }
    if (!only_expected) return InstallerStatus::RetentionConflict;

    // Journals are the last retirement evidence to disappear.  Removing the
    // non-selected copy first guarantees that a reset before the final unlink
    // still leaves the newest COMMITTED record selectable.
    const char *older = slot_ == JournalSlot::A ? journal_b_ : journal_a_;
    const char *newer = slot_ == JournalSlot::A ? journal_a_ : journal_b_;
    if (!RemoveIfPresent(journal_temp_) || !RemoveIfPresent(older) ||
        !RemoveIfPresent(newer)) {
        return InstallerStatus::FileSystemError;
    }
    have_journal_ = false;
    slot_ = JournalSlot::None;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::RetireObsoleteFiles()
{
    // Manifest v2 uses stable kernel names. Superseded bytes are replaced at
    // those names during commit, so there is no release-suffixed inventory to
    // retire and no writable filesystem scan is permitted here.
    return InstallerStatus::Ok;
}

bool Engine::HashFile(const char *path, uint8_t digest[kSha256DigestBytes],
                      uint64_t *size)
{
    if (workspace_ == 0 || workspace_->io_buffer == 0 || digest == 0 || size == 0) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!fs_->OpenRead(path, &file) || file == 0 || !file->GetSize(size)) {
        if (file != 0) file->Close();
        return false;
    }
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < *size) {
        const uint64_t remaining = *size - offset;
        const size_t bounded_buffer = workspace_->io_buffer_size < 8192U
            ? workspace_->io_buffer_size : 8192U;
        const size_t count = remaining < bounded_buffer
            ? static_cast<size_t>(remaining) : bounded_buffer;
        if (!file->ReadAt(offset, workspace_->io_buffer, count) ||
            !hash.Update(workspace_->io_buffer, count)) {
            ok = false;
            break;
        }
        offset += count;
        if (!AddStageWork(count) ||
            !Progress(UpdateRecoveryProgressKind::InstallerFileHashed,
                      offset, *size)) {
            ok = false;
            break;
        }
    }
    ok = file->Close() && ok && hash.Final(digest);
    return ok;
}

bool Engine::VerifyFile(const char *path, uint64_t expected_size,
                        const uint8_t digest[kSha256DigestBytes],
                        InstallerStatus *failure)
{
    UpdateFileStat stat;
    if (!fs_->Stat(path, &stat)) {
        if (failure != 0) *failure = InstallerStatus::FileSystemError;
        return false;
    }
    if (stat.type != UpdateNodeType::RegularFile || stat.size != expected_size) {
        if (failure != 0) *failure = InstallerStatus::FileHashMismatch;
        return false;
    }
    uint8_t actual[kSha256DigestBytes];
    uint64_t size = 0U;
    if (!HashFile(path, actual, &size)) {
        if (failure != 0) *failure = InstallerStatus::FileSystemError;
        return false;
    }
    if (size != expected_size || !ConstantTimeDigestEqual(actual, digest)) {
        if (failure != 0) *failure = InstallerStatus::FileHashMismatch;
        return false;
    }
    return true;
}

InstallerStatus Engine::CopyFileAtomic(
    const char *source, const char *destination, uint64_t *copied_size,
    uint8_t copied_digest[kSha256DigestBytes])
{
    UpdateFileStat source_stat;
    UpdateFileStat destination_stat;
    if (!fs_->Stat(source, &source_stat) || !fs_->Stat(destination, &destination_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (source_stat.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    if (destination_stat.type == UpdateNodeType::RegularFile) {
        uint8_t source_hash[kSha256DigestBytes];
        uint8_t destination_hash[kSha256DigestBytes];
        uint64_t source_size = 0U;
        uint64_t destination_size = 0U;
        if (!HashFile(source, source_hash, &source_size) ||
            !HashFile(destination, destination_hash, &destination_size)) {
            return InstallerStatus::FileSystemError;
        }
        if (source_size != destination_size ||
            !ConstantTimeDigestEqual(source_hash, destination_hash)) {
            return InstallerStatus::FileHashMismatch;
        }
        if (copied_size != 0) *copied_size = source_size;
        if (copied_digest != 0) {
            memcpy(copied_digest, source_hash, kSha256DigestBytes);
        }
        return InstallerStatus::Ok;
    }
    if (destination_stat.type != UpdateNodeType::Missing || !EnsureParents(destination)) {
        return InstallerStatus::UnexpectedNodeType;
    }
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(temporary, sizeof(temporary), destination, ".part") ||
        !RemoveIfPresent(temporary)) return InstallerStatus::FileSystemError;
    UpdateReadFile *input = 0;
    UpdateWriteFile *output = 0;
    if (!fs_->OpenRead(source, &input) || input == 0 ||
        !fs_->CreateFileFresh(temporary, &output) || output == 0) {
        if (input != 0) input->Close();
        if (output != 0) output->Close();
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    Sha256 input_hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < source_stat.size) {
        const uint64_t remaining = source_stat.size - offset;
        const size_t bounded_buffer = workspace_->io_buffer_size < 8192U
            ? workspace_->io_buffer_size : 8192U;
        const size_t count = remaining < bounded_buffer
            ? static_cast<size_t>(remaining) : bounded_buffer;
        if (!input->ReadAt(offset, workspace_->io_buffer, count) ||
            !input_hash.Update(workspace_->io_buffer, count) ||
            !output->Write(ByteView(workspace_->io_buffer, count))) {
            ok = false;
            break;
        }
        offset += count;
        if (!AddStageWork(static_cast<uint64_t>(count) * 2U) ||
            !Progress(UpdateRecoveryProgressKind::InstallerFileCopied,
                      offset, source_stat.size)) {
            ok = false;
            break;
        }
    }
    uint8_t expected[kSha256DigestBytes];
    ok = input->Close() && ok && input_hash.Final(expected);
    const bool output_synced = output->Sync();
    const bool output_closed = output->Close();
    ok = output_synced && output_closed && ok;
    if (!ok || !fs_->Rename(temporary, destination, false) ||
        !fs_->SyncContainingDirectory(destination)) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    if (!VerifyFile(destination, source_stat.size, expected, &failure)) {
        return failure;
    }
    if (copied_size != 0) *copied_size = source_stat.size;
    if (copied_digest != 0) {
        memcpy(copied_digest, expected, kSha256DigestBytes);
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::CopyFileAtomicExpected(
    const char *source, const char *destination, uint64_t expected_size,
    const uint8_t expected_digest[kSha256DigestBytes])
{
    UpdateFileStat source_stat;
    UpdateFileStat destination_stat;
    if (source == 0 || destination == 0 || expected_digest == 0 ||
        !fs_->Stat(source, &source_stat) ||
        !fs_->Stat(destination, &destination_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (source_stat.type != UpdateNodeType::RegularFile ||
        source_stat.size != expected_size) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    if (destination_stat.type == UpdateNodeType::RegularFile) {
        InstallerStatus failure = InstallerStatus::FileSystemError;
        return VerifyFile(destination, expected_size, expected_digest, &failure)
            ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
    }
    if (destination_stat.type != UpdateNodeType::Missing ||
        !EnsureParents(destination)) {
        return InstallerStatus::UnexpectedNodeType;
    }
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(temporary, sizeof(temporary), destination, ".part") ||
        !RemoveIfPresent(temporary)) {
        return InstallerStatus::FileSystemError;
    }
    UpdateReadFile *input = 0;
    UpdateWriteFile *output = 0;
    if (!fs_->OpenRead(source, &input) || input == 0 ||
        !fs_->CreateFileFresh(temporary, &output) || output == 0) {
        if (input != 0) input->Close();
        if (output != 0) output->Close();
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < expected_size) {
        const uint64_t remaining = expected_size - offset;
        const size_t bounded_buffer = workspace_->io_buffer_size < 8192U
            ? workspace_->io_buffer_size : 8192U;
        const size_t count = remaining < bounded_buffer
            ? static_cast<size_t>(remaining) : bounded_buffer;
        if (!input->ReadAt(offset, workspace_->io_buffer, count) ||
            !output->Write(ByteView(workspace_->io_buffer, count))) {
            ok = false;
            break;
        }
        offset += count;
        if (!AddStageWork(static_cast<uint64_t>(count) * 2U) ||
            !Progress(UpdateRecoveryProgressKind::InstallerFileCopied,
                      offset, expected_size)) {
            ok = false;
            break;
        }
    }
    ok = input->Close() && ok;
    const bool synced = output->Sync();
    const bool closed = output->Close();
    ok = synced && closed && ok;
    if (!ok || !fs_->Rename(temporary, destination, false) ||
        !fs_->SyncContainingDirectory(destination)) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    return VerifyFile(destination, expected_size, expected_digest, &failure)
        ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
}

InstallerStatus Engine::ReplaceWithCopy(const char *source, const char *destination)
{
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(temporary, sizeof(temporary), destination, ".rollback") ||
        !RemoveIfPresent(temporary)) return InstallerStatus::FileSystemError;
    const InstallerStatus copy = CopyFileAtomic(source, temporary);
    if (copy != InstallerStatus::Ok) return copy;
    if (!fs_->Rename(temporary, destination, true) ||
        !fs_->SyncContainingDirectory(destination)) return InstallerStatus::FileSystemError;
    return InstallerStatus::Ok;
}

const PreparedConfigTemplate *Engine::PreparedConfig(
    const ManifestFile &file) const
{
    if (file.policy != ManifestFilePolicy::ConfigTemplate ||
        request_.prepared_configs == 0) return 0;
    for (size_t index = 0U; index < request_.prepared_configs->entry_count; ++index) {
        const PreparedConfigTemplate &entry =
            request_.prepared_configs->entries[index];
        if (entry.path != 0 && strcmp(entry.path, file.path) == 0) return &entry;
    }
    return 0;
}

uint64_t Engine::EffectiveSize(const ManifestFile &file) const
{
    const PreparedConfigTemplate *prepared = PreparedConfig(file);
    return prepared == 0 ? file.size : prepared->prepared_size;
}

const uint8_t *Engine::EffectiveDigest(const ManifestFile &file) const
{
    const PreparedConfigTemplate *prepared = PreparedConfig(file);
    return prepared == 0 ? file.sha256 : prepared->prepared_sha256;
}

InstallerStatus Engine::ValidatePreparedConfigs()
{
    const ManifestAsset &asset = request_.manifest->asset;
    InstallerStatus journal_status = LoadJournal(true);
    if (journal_status != InstallerStatus::Ok) return journal_status;
    const bool resumable = have_journal_ && record_.state != JournalState::Idle &&
                           IdentityMatches(record_);
    if (have_journal_ && record_.state != JournalState::Idle && !resumable) {
        return InstallerStatus::JournalConflict;
    }
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy != ManifestFilePolicy::ConfigTemplate) continue;
        const PreparedConfigTemplate *prepared = PreparedConfig(file);
        if (prepared == 0) return InstallerStatus::PreparedConfigRequired;
        UpdateFileStat current;
        if (!fs_->Stat(file.path, &current)) return InstallerStatus::FileSystemError;
        if (prepared->original_existed) {
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(file.path, prepared->original_size,
                            prepared->original_sha256, &verify_failure)) {
                if (!resumable ||
                    !VerifyFile(file.path, prepared->prepared_size,
                                prepared->prepared_sha256, &verify_failure)) {
                    return verify_failure == InstallerStatus::FileHashMismatch
                        ? InstallerStatus::ConfigChangedSinceConsent : verify_failure;
                }
            }
        } else if (current.type != UpdateNodeType::Missing) {
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            if (!resumable ||
                !VerifyFile(file.path, prepared->prepared_size,
                            prepared->prepared_sha256, &verify_failure)) {
                return InstallerStatus::ConfigChangedSinceConsent;
            }
        }
        uint64_t prepared_size = 0U;
        if (!prepared->content->GetSize(&prepared_size) ||
            prepared_size != prepared->prepared_size) {
            return InstallerStatus::PreparedConfigInvalid;
        }
        Sha256 hash;
        uint64_t offset = 0U;
        while (offset < prepared_size) {
            const uint64_t remaining = prepared_size - offset;
            const size_t count = remaining < workspace_->io_buffer_size
                ? static_cast<size_t>(remaining) : workspace_->io_buffer_size;
            if (!prepared->content->ReadAt(offset, workspace_->io_buffer, count) ||
                !hash.Update(workspace_->io_buffer, count)) {
                return InstallerStatus::PreparedConfigInvalid;
            }
            offset += count;
            if (!Progress(UpdateRecoveryProgressKind::PreparedFileVerified,
                          offset, prepared_size)) {
                return InstallerStatus::RecoveryProgressFailed;
            }
        }
        uint8_t digest[kSha256DigestBytes];
        if (!hash.Final(digest) ||
            !ConstantTimeDigestEqual(digest, prepared->prepared_sha256)) {
            return InstallerStatus::PreparedConfigInvalid;
        }
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::StagePreparedConfig(const ManifestFile &file,
                                            const char *staged_path)
{
    const PreparedConfigTemplate *prepared = PreparedConfig(file);
    if (prepared == 0 || staged_path == 0 || !EnsureParents(staged_path)) {
        return InstallerStatus::PreparedConfigRequired;
    }
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(temporary, sizeof(temporary), staged_path, ".part") ||
        !RemoveIfPresent(temporary)) return InstallerStatus::FileSystemError;
    UpdateWriteFile *output = 0;
    if (!fs_->CreateFileFresh(temporary, &output) || output == 0) {
        return InstallerStatus::FileSystemError;
    }
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < prepared->prepared_size) {
        const uint64_t remaining = prepared->prepared_size - offset;
        const size_t count = remaining < workspace_->io_buffer_size
            ? static_cast<size_t>(remaining) : workspace_->io_buffer_size;
        if (!prepared->content->ReadAt(offset, workspace_->io_buffer, count) ||
            !hash.Update(workspace_->io_buffer, count) ||
            !output->Write(ByteView(workspace_->io_buffer, count))) {
            ok = false;
            break;
        }
        offset += count;
        if (!AddStageWork(count) ||
            !Progress(UpdateRecoveryProgressKind::InstallerFileCopied,
                      offset, prepared->prepared_size)) {
            ok = false;
            break;
        }
    }
    uint8_t digest[kSha256DigestBytes];
    ok = ok && hash.Final(digest) &&
         ConstantTimeDigestEqual(digest, prepared->prepared_sha256);
    const bool synced = ok && output->Sync();
    const bool closed = output->Close();
    if (!ok || !synced || !closed ||
        !fs_->Rename(temporary, staged_path, false) ||
        !fs_->SyncContainingDirectory(staged_path)) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    return VerifyFile(staged_path, prepared->prepared_size,
                      prepared->prepared_sha256, &failure)
        ? InstallerStatus::Ok : failure;
}

InstallerStatus Engine::PrepareArchive(ZipReader *reader,
                                       ZipExpectedInventory *expected,
                                       InstallerHashSink *hash_sink,
                                       StepLayout *layout,
                                       ZipStatus *zip_status)
{
    if (request_.downloaded_zip == 0 || reader == 0 || expected == 0 ||
        hash_sink == 0 || layout == 0 || zip_status == 0) {
        return InstallerStatus::InvalidArgument;
    }
    const ManifestAsset &asset = request_.manifest->asset;
    if (!BuildStepLayout(asset, layout)) return InstallerStatus::InvalidManifest;
    uint64_t archive_size = 0U;
    if (!request_.downloaded_zip->GetSize(&archive_size) ||
        archive_size != asset.download_size) return InstallerStatus::ArchiveIo;
    if (!Progress(UpdateRecoveryProgressKind::InstallerArchiveHashed, 0U,
                  archive_size)) {
        return InstallerStatus::RecoveryProgressFailed;
    }
    Sha256 archive_hash;
    uint64_t offset = 0U;
    uint64_t last_progress = 0U;
    while (offset < archive_size) {
        const uint64_t remaining = archive_size - offset;
        const uint64_t since_progress = offset - last_progress;
        const uint64_t until_progress =
            kArchiveHashProgressIntervalBytes - since_progress;
        uint64_t bounded_count = remaining;
        if (bounded_count > workspace_->io_buffer_size) {
            bounded_count = workspace_->io_buffer_size;
        }
        if (bounded_count > until_progress) bounded_count = until_progress;
        const size_t count = static_cast<size_t>(bounded_count);
        if (!request_.downloaded_zip->ReadAt(offset, workspace_->io_buffer, count) ||
            !archive_hash.Update(workspace_->io_buffer, count)) {
            return InstallerStatus::ArchiveIo;
        }
        offset += count;
        const bool report_due = offset == archive_size ||
            offset - last_progress >= kArchiveHashProgressIntervalBytes;
        if (report_due &&
            !Progress(UpdateRecoveryProgressKind::InstallerArchiveHashed,
                      offset, archive_size)) {
            return InstallerStatus::RecoveryProgressFailed;
        }
        if (report_due) last_progress = offset;
    }
    uint8_t digest[kSha256DigestBytes];
    if (!archive_hash.Final(digest) ||
        !ConstantTimeDigestEqual(digest, asset.sha256)) {
        return InstallerStatus::ArchiveHashMismatch;
    }
    uint64_t maximum_file = 1U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        workspace_->expected_files[index].path = file.path;
        workspace_->expected_files[index].size = file.size;
        workspace_->expected_files[index].compression =
            file.compression == ManifestCompression::Store
                ? ZipCompression::Store : ZipCompression::Deflate;
        workspace_->expected_files[index].sha256 = file.sha256;
        if (file.size > maximum_file) maximum_file = file.size;
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        workspace_->expected_directories[index] = asset.directories[index].path;
    }
    expected->files = workspace_->expected_files;
    expected->file_count = asset.file_count;
    expected->directories = workspace_->expected_directories;
    expected->directory_count = asset.directory_count;
    ZipLimits limits;
    limits.maximum_archive_bytes = asset.download_size;
    limits.maximum_entries = asset.file_count + asset.directory_count;
    limits.maximum_path_bytes = kMaximumManifestPathBytes;
    limits.maximum_file_bytes = maximum_file;
    limits.maximum_installed_bytes = asset.installed_size == 0U ? 1U : asset.installed_size;
    reader->SetWorkspace(workspace_->zip_workspace);
    *zip_status = reader->Open(request_.downloaded_zip, workspace_->zip_entries,
                               workspace_->zip_entry_capacity, limits);
    if (*zip_status != ZipStatus::Ok) return InstallerStatus::ArchiveInvalid;
    if (reader->inventory().archive_size != asset.download_size ||
        reader->inventory().installed_size != asset.installed_size) {
        return InstallerStatus::InventoryMismatch;
    }
    (void) hash_sink;
    *zip_status = reader->BindAuthenticatedInventory(*expected);
    if (*zip_status != ZipStatus::Ok) {
        if (hash_sink->progress_failed()) {
            return InstallerStatus::RecoveryProgressFailed;
        }
        return *zip_status == ZipStatus::InventoryMismatch
            ? InstallerStatus::InventoryMismatch : InstallerStatus::ArchiveInvalid;
    }
    return ValidatePreparedConfigs();
}

bool Engine::ContentPlanPath(bool final_plan, char *path, size_t capacity) const
{
    return JoinPath(path, capacity, state_root_,
                    final_plan ? "content-plan" : "content-plan.prepared");
}

InstallerStatus Engine::LoadContentPlan(bool require_final)
{
    char final_path[kInstallerMaximumPathBytes + 1U];
    char prepared_path[kInstallerMaximumPathBytes + 1U];
    if (!ContentPlanPath(true, final_path, sizeof(final_path)) ||
        !ContentPlanPath(false, prepared_path, sizeof(prepared_path))) {
        return InstallerStatus::InvalidPath;
    }
    UpdateFileStat final_stat;
    UpdateFileStat prepared_stat;
    if (!fs_->Stat(final_path, &final_stat) ||
        !fs_->Stat(prepared_path, &prepared_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if ((final_stat.type != UpdateNodeType::Missing &&
         final_stat.type != UpdateNodeType::RegularFile) ||
        (prepared_stat.type != UpdateNodeType::Missing &&
         prepared_stat.type != UpdateNodeType::RegularFile)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    const bool use_final = final_stat.type == UpdateNodeType::RegularFile;
    if (!use_final && (require_final ||
                       prepared_stat.type != UpdateNodeType::RegularFile)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    const char *path = use_final ? final_path : prepared_path;
    const size_t file_count = request_.manifest->asset.file_count;
    const uint64_t expected_size = kContentPlanHeaderBytes +
        static_cast<uint64_t>(file_count) * kContentPlanRecordBytes +
        kContentPlanFooterBytes;
    const UpdateFileStat &selected_stat = use_final ? final_stat : prepared_stat;
    if (selected_stat.size != expected_size) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    UpdateReadFile *input = 0;
    if (!fs_->OpenRead(path, &input) || input == 0) {
        return InstallerStatus::FileSystemError;
    }
    uint8_t header[kContentPlanHeaderBytes];
    bool ok = input->ReadAt(0U, header, sizeof(header));
    const uint8_t *expected_magic = use_final
        ? kContentPlanFinalMagic : kContentPlanPreparedMagic;
    ok = ok && memcmp(header, expected_magic, 8U) == 0 &&
         ReadU32(header + 8U) == 1U &&
         ReadU32(header + 12U) == kContentPlanHeaderBytes &&
         ReadU32(header + 16U) == kContentPlanRecordBytes &&
         ReadU32(header + 20U) == file_count &&
         memcmp(header + 24U, request_.identity.transaction_id,
                kTransactionIdBytes) == 0 &&
         ReadU64(header + 40U) == request_.identity.source_release_sequence &&
         ReadU64(header + 48U) == request_.manifest->release_sequence &&
         memcmp(header + 56U, request_.identity.manifest_sha256,
                kSha256DigestBytes) == 0 &&
         memcmp(header + 88U, request_.identity.consent_sha256,
                kSha256DigestBytes) == 0 &&
         header[120U] == (request_.identity.reset_required ? 1U : 0U) &&
         header[121U] == (request_.identity.reset_approved ? 1U : 0U);
    for (size_t offset = 122U; ok && offset < sizeof(header); ++offset) {
        ok = header[offset] == 0U;
    }
    Sha256 hash;
    ok = ok && hash.Update(header, sizeof(header));
    uint8_t noop[kContentPlanNoopBytes];
    memset(noop, 0, sizeof(noop));
    uint32_t unchanged_count = 0U;
    uint32_t changed_count = 0U;
    uint64_t unchanged_bytes = 0U;
    uint64_t changed_bytes = 0U;
    uint64_t offset = kContentPlanHeaderBytes;
    for (size_t index = 0U; ok && index < file_count; ++index) {
        uint8_t encoded[kContentPlanRecordBytes];
        ContentPlanRecord record;
        ok = input->ReadAt(offset, encoded, sizeof(encoded)) &&
             hash.Update(encoded, sizeof(encoded)) &&
             DecodeContentPlanRecord(index, encoded, &record);
        if (!ok) break;
        const ManifestFile &file = request_.manifest->asset.files[index];
        const bool unchanged = (record.flags & kContentPlanNoop) != 0U;
        if (unchanged &&
            (record.old_size != EffectiveSize(file) ||
             !ConstantTimeDigestEqual(record.old_digest,
                                      EffectiveDigest(file)))) {
            ok = false;
            break;
        }
        const bool rollback_digest_required =
            (file.policy == ManifestFilePolicy::Metadata ||
             file.policy == ManifestFilePolicy::Kernel ||
             file.policy == ManifestFilePolicy::ManagedReplace ||
             file.policy == ManifestFilePolicy::ConfigTemplate) &&
            (record.flags & kContentPlanSourceExisted) != 0U;
        if (use_final && rollback_digest_required &&
            (record.flags & kContentPlanOldDigestValid) == 0U) {
            ok = false;
            break;
        }
        uint64_t *bytes = unchanged ? &unchanged_bytes : &changed_bytes;
        if (!CheckedAdd(*bytes, EffectiveSize(file), bytes)) {
            ok = false;
            break;
        }
        if (unchanged) {
            noop[index / 8U] |= static_cast<uint8_t>(1U << (index % 8U));
            ++unchanged_count;
        } else {
            ++changed_count;
        }
        offset += sizeof(encoded);
    }
    uint8_t footer[kContentPlanFooterBytes];
    if (ok) {
        ok = input->ReadAt(offset, footer, sizeof(footer)) &&
             memcmp(footer, kContentPlanFooterMagic, 8U) == 0 &&
             ReadU32(footer + 8U) == unchanged_count &&
             ReadU32(footer + 12U) == changed_count &&
             ReadU64(footer + 16U) == unchanged_bytes &&
             ReadU64(footer + 24U) == changed_bytes;
        for (size_t reserved = 32U; ok && reserved < 48U; ++reserved) {
            ok = footer[reserved] == 0U;
        }
        ok = ok && hash.Update(footer, 48U);
        uint8_t digest[kSha256DigestBytes];
        ok = ok && hash.Final(digest) &&
             ConstantTimeDigestEqual(digest, footer + 48U);
    }
    const bool closed = input->Close();
    if (!ok || !closed) return InstallerStatus::RollbackEvidenceMissing;
    memcpy(content_plan_noop_, noop, sizeof(noop));
    content_plan_changed_files_ = changed_count;
    content_plan_unchanged_files_ = unchanged_count;
    content_plan_loaded_ = true;
    content_plan_final_ = use_final;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::ReadContentPlanRecord(size_t index,
                                              ContentPlanRecord *record)
{
    if (record == 0 || index >= request_.manifest->asset.file_count) {
        return InstallerStatus::InvalidArgument;
    }
    if (!content_plan_loaded_) {
        const InstallerStatus loaded = LoadContentPlan(false);
        if (loaded != InstallerStatus::Ok) return loaded;
    }
    char path[kInstallerMaximumPathBytes + 1U];
    if (!ContentPlanPath(content_plan_final_, path, sizeof(path))) {
        return InstallerStatus::InvalidPath;
    }
    UpdateReadFile *input = 0;
    uint8_t encoded[kContentPlanRecordBytes];
    const uint64_t offset = kContentPlanHeaderBytes +
        static_cast<uint64_t>(index) * kContentPlanRecordBytes;
    if (!fs_->OpenRead(path, &input) || input == 0 ||
        !input->ReadAt(offset, encoded, sizeof(encoded))) {
        if (input != 0) input->Close();
        return InstallerStatus::FileSystemError;
    }
    if (!input->Close() ||
        !DecodeContentPlanRecord(index, encoded, record)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::WriteContentPlanFile(bool final_plan)
{
    char path[kInstallerMaximumPathBytes + 1U];
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!ContentPlanPath(final_plan, path, sizeof(path)) ||
        !AddSuffix(temporary, sizeof(temporary), path, ".part") ||
        !RemoveIfPresent(temporary)) {
        return InstallerStatus::FileSystemError;
    }
    UpdateFileStat existing;
    if (!fs_->Stat(path, &existing)) return InstallerStatus::FileSystemError;
    if (existing.type == UpdateNodeType::RegularFile) {
        content_plan_loaded_ = false;
        return LoadContentPlan(final_plan);
    }
    if (existing.type != UpdateNodeType::Missing) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    UpdateWriteFile *output = 0;
    if (!fs_->CreateFileFresh(temporary, &output) || output == 0) {
        return InstallerStatus::FileSystemError;
    }
    uint8_t header[kContentPlanHeaderBytes];
    memset(header, 0, sizeof(header));
    memcpy(header, final_plan ? kContentPlanFinalMagic
                              : kContentPlanPreparedMagic, 8U);
    WriteU32(header + 8U, 1U);
    WriteU32(header + 12U, kContentPlanHeaderBytes);
    WriteU32(header + 16U, kContentPlanRecordBytes);
    WriteU32(header + 20U,
             static_cast<uint32_t>(request_.manifest->asset.file_count));
    memcpy(header + 24U, request_.identity.transaction_id,
           kTransactionIdBytes);
    WriteU64(header + 40U, request_.identity.source_release_sequence);
    WriteU64(header + 48U, request_.manifest->release_sequence);
    memcpy(header + 56U, request_.identity.manifest_sha256,
           kSha256DigestBytes);
    memcpy(header + 88U, request_.identity.consent_sha256,
           kSha256DigestBytes);
    header[120U] = request_.identity.reset_required ? 1U : 0U;
    header[121U] = request_.identity.reset_approved ? 1U : 0U;
    Sha256 hash;
    bool ok = hash.Update(header, sizeof(header)) &&
              output->Write(ByteView(header, sizeof(header)));
    uint32_t unchanged_count = 0U;
    uint32_t changed_count = 0U;
    uint64_t unchanged_bytes = 0U;
    uint64_t changed_bytes = 0U;
    const ManifestAsset &asset = request_.manifest->asset;
    for (size_t index = 0U; ok && index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        ContentPlanRecord record;
        memset(&record, 0, sizeof(record));
        if (final_plan) {
            const InstallerStatus read = ReadContentPlanRecord(index, &record);
            if (read != InstallerStatus::Ok) {
                ok = false;
                break;
            }
            const bool snapshot_policy =
                file.policy == ManifestFilePolicy::Kernel ||
                file.policy == ManifestFilePolicy::ManagedReplace ||
                file.policy == ManifestFilePolicy::ConfigTemplate;
            if (snapshot_policy &&
                (record.flags & kContentPlanSourceExisted) != 0U &&
                (record.flags & kContentPlanOldDigestValid) == 0U) {
                bool existed = false;
                uint64_t old_size = 0U;
                uint8_t old_digest[kSha256DigestBytes];
                const InstallerStatus evidence = ReadSnapshotEvidence(
                    index, &existed, &old_size, old_digest);
                if (evidence != InstallerStatus::Ok || !existed) {
                    ok = false;
                    break;
                }
                record.flags |= kContentPlanOldDigestValid;
                record.old_size = old_size;
                memcpy(record.old_digest, old_digest, sizeof(old_digest));
            }
        } else {
            UpdateFileStat source;
            if (!fs_->Stat(file.path, &source) ||
                (source.type != UpdateNodeType::Missing &&
                 source.type != UpdateNodeType::RegularFile)) {
                ok = false;
                break;
            }
            if (source.type == UpdateNodeType::RegularFile) {
                record.flags |= kContentPlanSourceExisted;
                record.old_size = source.size;
                const PreparedConfigTemplate *prepared = PreparedConfig(file);
                if (prepared != 0 && prepared->original_existed) {
                    record.flags |= kContentPlanOldDigestValid;
                    record.old_size = prepared->original_size;
                    memcpy(record.old_digest, prepared->original_sha256,
                           kSha256DigestBytes);
                } else if (file.policy == ManifestFilePolicy::Metadata ||
                           (file.policy != ManifestFilePolicy::Preserve &&
                            source.size == EffectiveSize(file))) {
                    uint64_t hashed_size = 0U;
                    if (!HashFile(file.path, record.old_digest, &hashed_size) ||
                        hashed_size != source.size) {
                        ok = false;
                        break;
                    }
                    record.flags |= kContentPlanOldDigestValid;
                }
                if (file.policy != ManifestFilePolicy::Preserve &&
                    source.size == EffectiveSize(file) &&
                    (record.flags & kContentPlanOldDigestValid) != 0U &&
                    ConstantTimeDigestEqual(record.old_digest,
                                            EffectiveDigest(file))) {
                    record.flags |= kContentPlanNoop;
                }
            }
        }
        uint8_t encoded[kContentPlanRecordBytes];
        EncodeContentPlanRecord(index, record, encoded);
        ok = hash.Update(encoded, sizeof(encoded)) &&
             output->Write(ByteView(encoded, sizeof(encoded)));
        const bool unchanged = (record.flags & kContentPlanNoop) != 0U;
        uint64_t *bytes = unchanged ? &unchanged_bytes : &changed_bytes;
        ok = ok && CheckedAdd(*bytes, EffectiveSize(file), bytes);
        if (unchanged) ++unchanged_count;
        else ++changed_count;
    }
    uint8_t footer[kContentPlanFooterBytes];
    memset(footer, 0, sizeof(footer));
    memcpy(footer, kContentPlanFooterMagic, 8U);
    WriteU32(footer + 8U, unchanged_count);
    WriteU32(footer + 12U, changed_count);
    WriteU64(footer + 16U, unchanged_bytes);
    WriteU64(footer + 24U, changed_bytes);
    ok = ok && hash.Update(footer, 48U) &&
         hash.Final(footer + 48U) &&
         output->Write(ByteView(footer, sizeof(footer)));
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::ContentPlanBeforeFileSync);
    const bool synced = ok && output->Sync();
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::ContentPlanAfterFileSync);
    const bool closed = output->Close();
    if (!synced || !closed) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::ContentPlanBeforePublish);
    if (!fs_->Rename(temporary, path, false)) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::ContentPlanAfterPublish);
    if (!fs_->SyncContainingDirectory(path)) {
        return InstallerStatus::FileSystemError;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::ContentPlanAfterDirectorySync);
    content_plan_loaded_ = false;
    const InstallerStatus loaded = LoadContentPlan(final_plan);
    if (loaded == InstallerStatus::Ok) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::ContentPlanAfterValidatedReadback);
    }
    return loaded;
}

InstallerStatus Engine::BuildContentPlan()
{
    char final_path[kInstallerMaximumPathBytes + 1U];
    char prepared_path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat final_stat;
    UpdateFileStat prepared_stat;
    if (!ContentPlanPath(true, final_path, sizeof(final_path)) ||
        !ContentPlanPath(false, prepared_path, sizeof(prepared_path)) ||
        !fs_->Stat(final_path, &final_stat) ||
        !fs_->Stat(prepared_path, &prepared_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (final_stat.type == UpdateNodeType::RegularFile ||
        prepared_stat.type == UpdateNodeType::RegularFile) {
        return LoadContentPlan(false);
    }
    if (final_stat.type != UpdateNodeType::Missing ||
        prepared_stat.type != UpdateNodeType::Missing) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    return WriteContentPlanFile(false);
}

InstallerStatus Engine::RemoveSnapshotEvidenceFiles()
{
    for (size_t index = 0U;
         index < request_.manifest->asset.file_count; ++index) {
        char path[kInstallerMaximumPathBytes + 1U];
        char part[kInstallerMaximumPathBytes + 1U];
        char rollback[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat path_stat;
        UpdateFileStat part_stat;
        UpdateFileStat rollback_stat;
        if (!SnapshotEvidencePath(index, path, sizeof(path)) ||
            !AddSuffix(part, sizeof(part), path, ".part") ||
            !AddSuffix(rollback, sizeof(rollback), path, ".rollback") ||
            !fs_->Stat(path, &path_stat) || !fs_->Stat(part, &part_stat) ||
            !fs_->Stat(rollback, &rollback_stat)) {
            return InstallerStatus::FileSystemError;
        }
        if (path_stat.type == UpdateNodeType::Missing &&
            part_stat.type == UpdateNodeType::Missing &&
            rollback_stat.type == UpdateNodeType::Missing) continue;
        if (!RemoveFileAndTemporary(path)) {
            return InstallerStatus::FileSystemError;
        }
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::FinalizeContentPlan()
{
    const InstallerStatus loaded = LoadContentPlan(false);
    if (loaded != InstallerStatus::Ok) return loaded;
    if (!content_plan_final_) {
        const InstallerStatus written = WriteContentPlanFile(true);
        if (written != InstallerStatus::Ok) return written;
    }
    char prepared[kInstallerMaximumPathBytes + 1U];
    if (!ContentPlanPath(false, prepared, sizeof(prepared)) ||
        !RemoveIfPresent(prepared)) {
        return InstallerStatus::FileSystemError;
    }
    return RemoveSnapshotEvidenceFiles();
}

InstallerStatus Engine::InitializeStageWork()
{
    const ManifestAsset &asset = request_.manifest->asset;
    uint64_t remaining = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        bool unchanged = false;
        const InstallerStatus noop = IsNoop(index, &unchanged);
        if (noop != InstallerStatus::Ok) return noop;
        if (unchanged) continue;
        const ManifestFile &file = asset.files[index];
        UpdateFileStat destination;
        UpdateFileStat staged;
        char staged_path[kInstallerMaximumPathBytes + 1U];
        if (!JoinPath(staged_path, sizeof(staged_path), stage_root_, file.path) ||
            !fs_->Stat(file.path, &destination) ||
            !fs_->Stat(staged_path, &staged)) {
            return InstallerStatus::FileSystemError;
        }
        if (file.policy == ManifestFilePolicy::Kernel ||
            file.policy == ManifestFilePolicy::ManagedReplace ||
            file.policy == ManifestFilePolicy::ConfigTemplate) {
            char snapshot_path[kInstallerMaximumPathBytes + 1U];
            UpdateFileStat snapshot;
            if (!JoinPath(snapshot_path, sizeof(snapshot_path), snapshot_root_,
                          file.path) ||
                !fs_->Stat(snapshot_path, &snapshot)) {
                return InstallerStatus::FileSystemError;
            }
            uint64_t snapshot_work = 0U;
            if (snapshot.type == UpdateNodeType::RegularFile) {
                snapshot_work = snapshot.size;
            } else if (snapshot.type == UpdateNodeType::Missing &&
                       destination.type == UpdateNodeType::RegularFile) {
                if (destination.size > UINT64_MAX / 3U) {
                    return InstallerStatus::StorageInsufficient;
                }
                snapshot_work = destination.size * 3U;
            }
            if (file.policy == ManifestFilePolicy::ConfigTemplate &&
                destination.type == UpdateNodeType::RegularFile &&
                !CheckedAdd(snapshot_work, destination.size,
                            &snapshot_work)) {
                return InstallerStatus::StorageInsufficient;
            }
            if (!CheckedAdd(remaining, snapshot_work, &remaining)) {
                return InstallerStatus::StorageInsufficient;
            }
        }
        const bool preserve_existing =
            file.policy == ManifestFilePolicy::Preserve &&
            destination.type == UpdateNodeType::RegularFile;
        if (!preserve_existing) {
            const uint64_t size = EffectiveSize(file);
            if (size > UINT64_MAX / 2U) {
                return InstallerStatus::StorageInsufficient;
            }
            const uint64_t stage_work = staged.type == UpdateNodeType::RegularFile
                ? size : size * 2U;
            if (!CheckedAdd(remaining, stage_work, &remaining)) {
                return InstallerStatus::StorageInsufficient;
            }
            if (file.policy != ManifestFilePolicy::Metadata &&
                file.policy != ManifestFilePolicy::Kernel &&
                !CheckedAdd(remaining, size, &remaining)) {
                return InstallerStatus::StorageInsufficient;
            }
        }
    }
    if (!CheckedAdd(stage_work_completed_, remaining, &stage_work_total_)) {
        return InstallerStatus::StorageInsufficient;
    }
    stage_work_tracking_ = true;
    stage_work_reporting_ = true;
    return Progress(UpdateRecoveryProgressKind::InstallerStageOverall,
                    stage_work_completed_, stage_work_total_)
        ? InstallerStatus::Ok : InstallerStatus::RecoveryProgressFailed;
}

InstallerStatus Engine::PreflightStorage()
{
    const ManifestAsset &asset = request_.manifest->asset;
    uint64_t volume_size = 0U;
    static const uint64_t kMinimumBootVolumeBytes = UINT64_C(512) * 1024U * 1024U;
    if (!fs_->GetVolumeSize(&volume_size) ||
        volume_size < kMinimumBootVolumeBytes) {
        return InstallerStatus::StorageInsufficient;
    }
    uint64_t allocation_unit = 0U;
    if (!fs_->GetAllocationUnit(&allocation_unit)) {
        return InstallerStatus::FileSystemError;
    }
    if (!IsSupportedUpdateAllocationUnit(allocation_unit)) {
        return InstallerStatus::StorageInsufficient;
    }
    // A resumed transaction may already contain verified private staging or
    // snapshot files from an earlier attempt.
    InstallerStatus journal_status = LoadJournal(true);
    if (journal_status != InstallerStatus::Ok) return journal_status;
    const bool resumable = have_journal_ && record_.state != JournalState::Idle &&
                           IdentityMatches(record_);
    if (have_journal_ && record_.state != JournalState::Idle && !resumable) {
        return InstallerStatus::JournalConflict;
    }
    InstallerStatus content_plan = BuildContentPlan();
    if (content_plan != InstallerStatus::Ok) return content_plan;
    StepLayout layout;
    if (!BuildStepLayout(asset, &layout)) {
        return InstallerStatus::InvalidManifest;
    }
    StorageDemand demand;
    memset(&demand, 0, sizeof(demand));
    demand.safety_reserve_bytes = kMinimumUpdateSafetyReserveBytes;
    if (!CalculateUpdateMetadataAllocationBytes(
            asset.file_count, asset.directory_count, allocation_unit,
            &demand.metadata_journal_log_bytes)) {
        return InstallerStatus::StorageInsufficient;
    }
    // The signed peak is the conservative pre-download gate. At this point
    // the ZIP is already present and the content plan calculates the exact
    // remaining demand. Keeping the signed worst case here would reject an
    // update whose large payload files are all content no-ops.
    demand.manifest_required_peak_bytes = 0U;

    uint32_t snapshot_step = layout.snapshot_begin;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        const uint64_t effective_size = EffectiveSize(file);
        uint64_t effective_allocation = 0U;
        if (!RoundUpUpdateAllocation(effective_size, allocation_unit,
                                     &effective_allocation)) {
            return InstallerStatus::StorageInsufficient;
        }
        UpdateFileStat destination;
        if (!fs_->Stat(file.path, &destination)) {
            return InstallerStatus::FileSystemError;
        }
        if (destination.type != UpdateNodeType::Missing &&
            destination.type != UpdateNodeType::RegularFile) {
            return InstallerStatus::UnexpectedNodeType;
        }

        bool unchanged = false;
        InstallerStatus noop_status = IsNoop(index, &unchanged);
        if (noop_status != InstallerStatus::Ok) return noop_status;
        if (unchanged) continue;

        char staged[kInstallerMaximumPathBytes + 1U];
        if (!JoinPath(staged, sizeof(staged), stage_root_, file.path)) {
            return InstallerStatus::InvalidPath;
        }
        UpdateFileStat staged_stat;
        if (!fs_->Stat(staged, &staged_stat)) {
            return InstallerStatus::FileSystemError;
        }
        if (staged_stat.type == UpdateNodeType::RegularFile) {
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(staged, effective_size, EffectiveDigest(file),
                            &verify_failure)) {
                return verify_failure;
            }
        } else if (staged_stat.type != UpdateNodeType::Missing) {
            return InstallerStatus::UnexpectedNodeType;
        }

        const uint32_t stage_step =
            layout.file_stage_begin + static_cast<uint32_t>(index);
        bool stage_allocation_pending =
            staged_stat.type == UpdateNodeType::Missing &&
            (!resumable || record_.completed_steps <= stage_step);
        // Preserve entries already supplied by the user are never staged.
        if (file.policy == ManifestFilePolicy::Preserve &&
            destination.type == UpdateNodeType::RegularFile) {
            stage_allocation_pending = false;
        }
        if (stage_allocation_pending) {
            if (!CheckedAdd(demand.staged_files_bytes,
                            effective_allocation,
                            &demand.staged_files_bytes)) {
                return InstallerStatus::StorageInsufficient;
            }
            if (effective_allocation >
                    demand.largest_temporary_file_bytes) {
                demand.largest_temporary_file_bytes = effective_allocation;
            }
        }

        if (file.policy == ManifestFilePolicy::Kernel ||
            file.policy == ManifestFilePolicy::ManagedReplace ||
            file.policy == ManifestFilePolicy::ConfigTemplate) {
            char snapshot[kInstallerMaximumPathBytes + 1U];
            if (!JoinPath(snapshot, sizeof(snapshot), snapshot_root_,
                          file.path)) {
                return InstallerStatus::InvalidPath;
            }
            UpdateFileStat snapshot_stat;
            if (!fs_->Stat(snapshot, &snapshot_stat)) {
                return InstallerStatus::FileSystemError;
            }
            if (snapshot_stat.type == UpdateNodeType::RegularFile) {
                bool evidence_existed = false;
                uint64_t evidence_size = 0U;
                uint8_t evidence_digest[kSha256DigestBytes];
                const InstallerStatus evidence = ReadSnapshotEvidence(
                    index, &evidence_existed, &evidence_size, evidence_digest);
                InstallerStatus verify_failure =
                    InstallerStatus::FileSystemError;
                if (evidence == InstallerStatus::Ok) {
                    if (!evidence_existed ||
                        !VerifyFile(snapshot, evidence_size, evidence_digest,
                                    &verify_failure)) {
                        return InstallerStatus::RollbackEvidenceMissing;
                    }
                } else if (evidence ==
                           InstallerStatus::RollbackEvidenceMissing) {
                    if (destination.type != UpdateNodeType::RegularFile) {
                        return InstallerStatus::RollbackEvidenceMissing;
                    }
                    uint8_t source_digest[kSha256DigestBytes];
                    uint64_t source_size = 0U;
                    if (!HashFile(file.path, source_digest, &source_size) ||
                        !VerifyFile(snapshot, source_size, source_digest,
                                    &verify_failure)) {
                        return verify_failure;
                    }
                } else {
                    return evidence;
                }
            } else if (snapshot_stat.type == UpdateNodeType::Missing) {
                const bool snapshot_allocation_pending =
                    destination.type == UpdateNodeType::RegularFile &&
                    (!resumable || record_.completed_steps <= snapshot_step);
                if (snapshot_allocation_pending) {
                    uint64_t snapshot_allocation = 0U;
                    if (!RoundUpUpdateAllocation(destination.size,
                                                 allocation_unit,
                                                 &snapshot_allocation) ||
                        !CheckedAdd(demand.snapshot_bytes,
                                    snapshot_allocation,
                                    &demand.snapshot_bytes)) {
                        return InstallerStatus::StorageInsufficient;
                    }
                    if (snapshot_allocation >
                            demand.largest_temporary_file_bytes) {
                        demand.largest_temporary_file_bytes =
                            snapshot_allocation;
                    }
                }
            } else {
                return InstallerStatus::UnexpectedNodeType;
            }
            ++snapshot_step;
        }
    }
    uint64_t free_space = 0U;
    if (!fs_->GetFreeSpace(&free_space)) return InstallerStatus::FileSystemError;
    storage_result_ = EvaluateStoragePreflight(free_space, demand,
                                               StorageLimits::Defaults());
    return storage_result_.decision == StorageDecision::Sufficient
        ? InstallerStatus::Ok : InstallerStatus::StorageInsufficient;
}

InstallerStatus Engine::ReadJournalFile(const char *path, bool *present,
                                        uint8_t bytes[kJournalEncodedSize])
{
    UpdateFileStat stat;
    if (present == 0 || bytes == 0 || !fs_->Stat(path, &stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (stat.type == UpdateNodeType::Missing) {
        *present = false;
        return InstallerStatus::Ok;
    }
    if (stat.type != UpdateNodeType::RegularFile || stat.size != kJournalEncodedSize) {
        *present = true;
        memset(bytes, 0, kJournalEncodedSize);
        return InstallerStatus::Ok;
    }
    UpdateReadFile *file = 0;
    if (!fs_->OpenRead(path, &file) || file == 0 ||
        !file->ReadAt(0U, bytes, kJournalEncodedSize) || !file->Close()) {
        if (file != 0) file->Close();
        return InstallerStatus::FileSystemError;
    }
    if (!Progress(UpdateRecoveryProgressKind::CandidateJournalRead,
                  kJournalEncodedSize, kJournalEncodedSize)) {
        return InstallerStatus::RecoveryProgressFailed;
    }
    *present = true;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::LoadJournal(bool allow_missing)
{
    uint8_t bytes_a[kJournalEncodedSize];
    uint8_t bytes_b[kJournalEncodedSize];
    bool present_a = false;
    bool present_b = false;
    InstallerStatus status = ReadJournalFile(journal_a_, &present_a, bytes_a);
    if (status != InstallerStatus::Ok) return status;
    status = ReadJournalFile(journal_b_, &present_b, bytes_b);
    if (status != InstallerStatus::Ok) return status;
    const JournalCopy copy_a = {present_a, ByteView(bytes_a, kJournalEncodedSize)};
    const JournalCopy copy_b = {present_b, ByteView(bytes_b, kJournalEncodedSize)};
    const JournalSelectionResult selection = SelectJournalCopy(copy_a, copy_b);
    if (selection.status == JournalSelectionStatus::NoJournal) {
        have_journal_ = false;
        slot_ = JournalSlot::None;
        return allow_missing ? InstallerStatus::Ok : InstallerStatus::WrongState;
    }
    if (selection.status == JournalSelectionStatus::NoValidCopy) {
        return InstallerStatus::JournalCorrupt;
    }
    if (selection.status == JournalSelectionStatus::AmbiguousSameGeneration) {
        return InstallerStatus::JournalConflict;
    }
    record_ = selection.record;
    have_journal_ = true;
    slot_ = selection.status == JournalSelectionStatus::SelectedB
        ? JournalSlot::B : JournalSlot::A;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::WriteJournalBytes(const JournalRecord &next,
                                          JournalSlot destination)
{
    uint8_t encoded[kJournalEncodedSize];
    if (SerializeJournal(next, MutableByteView(encoded, sizeof(encoded))) !=
        JournalCodecStatus::Ok) return InstallerStatus::JournalCodecError;
    if (!RemoveIfPresent(journal_temp_)) return InstallerStatus::FileSystemError;
    UpdateWriteFile *file = 0;
    if (!fs_->CreateFileFresh(journal_temp_, &file) || file == 0) {
        return InstallerStatus::FileSystemError;
    }
    const bool wrote = file->Write(ByteView(encoded, sizeof(encoded)));
    bool synced = false;
    if (wrote) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::JournalBeforeTemporaryFileSync);
        synced = file->Sync();
        if (synced) {
            BMX_UPDATE_FAULT_CHECKPOINT(
                UpdateFaultPoint::JournalAfterTemporaryFileSync);
        }
    }
    const bool closed = file->Close();
    bool ok = wrote && synced && closed;
    file = 0;
    const char *path = destination == JournalSlot::A ? journal_a_ : journal_b_;
    bool published = false;
    if (ok) {
        BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::JournalBeforePublish);
        published = fs_->Rename(journal_temp_, path, true);
        if (published) {
            BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::JournalAfterPublish);
        }
    }
    const bool directory_synced = published &&
        fs_->SyncContainingDirectory(path);
    if (directory_synced) {
        BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::JournalAfterDirectorySync);
    }
    ok = ok && published && directory_synced;
    if (!ok) {
        RemoveIfPresent(journal_temp_);
        return InstallerStatus::FileSystemError;
    }
    bool present = false;
    uint8_t reread[kJournalEncodedSize];
    const InstallerStatus read = ReadJournalFile(path, &present, reread);
    JournalRecord parsed;
    if (read != InstallerStatus::Ok || !present ||
        ParseJournal(ByteView(reread, sizeof(reread)), &parsed) !=
            JournalCodecStatus::Ok || !JournalRecordsEqual(next, parsed)) {
        return InstallerStatus::JournalCodecError;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::JournalAfterValidatedReadback);
    record_ = next;
    slot_ = destination;
    have_journal_ = true;
    if (!Progress(UpdateRecoveryProgressKind::InstallerJournalPersisted,
                  next.completed_steps, next.total_steps)) {
        return InstallerStatus::RecoveryProgressFailed;
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::WriteInitialJournal(const JournalRecord &record)
{
    if (have_journal_) return InstallerStatus::JournalConflict;
    return WriteJournalBytes(record, JournalSlot::A);
}

InstallerStatus Engine::WriteTransition(const JournalRecord &next)
{
    if (!have_journal_ ||
        ValidateJournalTransition(record_, next) != JournalTransitionStatus::Allowed) {
        return InstallerStatus::JournalTransitionDenied;
    }
    return WriteJournalBytes(next, slot_ == JournalSlot::A ? JournalSlot::B
                                                            : JournalSlot::A);
}

bool Engine::IdentityMatches(const JournalRecord &record) const
{
    const ManifestAsset &asset = request_.manifest->asset;
    return record.source_release_sequence == request_.identity.source_release_sequence &&
           record.target_release_sequence == request_.manifest->release_sequence &&
           record.board == asset.board &&
           record.old_boot_generation == request_.identity.old_boot_generation &&
           record.new_boot_generation == request_.identity.new_boot_generation &&
           memcmp(record.transaction_id, request_.identity.transaction_id,
                  kTransactionIdBytes) == 0 &&
           memcmp(record.manifest_sha256, request_.identity.manifest_sha256,
                  kSha256DigestBytes) == 0 &&
           memcmp(record.zip_sha256, asset.sha256, kSha256DigestBytes) == 0 &&
           memcmp(record.consent_sha256, request_.identity.consent_sha256,
                  kSha256DigestBytes) == 0;
}

InstallerStatus Engine::InitializeJournal(const StepLayout &layout)
{
    InstallerStatus status = LoadJournal(true);
    if (status != InstallerStatus::Ok) return status;
    bool need_discovered = true;
    if (have_journal_) {
        if (record_.state == JournalState::Idle) {
            // Generation one is the just-created initialization anchor. A
            // reset may happen after its atomic write but before DISCOVERED.
            // Higher-generation Idle records are completed/rolled-back
            // transactions and their root is never silently reused.
            if (record_.generation != 1U) return InstallerStatus::JournalConflict;
        } else {
            if (!IdentityMatches(record_) || record_.total_steps != layout.total) {
                return InstallerStatus::JournalConflict;
            }
            if (record_.state != JournalState::Discovered) {
                return InstallerStatus::Ok;
            }
            // DISCOVERED may itself be the newest durable copy after a reset;
            // complete only the already-approved local initialization edge.
            need_discovered = false;
        }
    } else {
        JournalRecord idle = MakeIdleJournalRecord(1U);
        status = WriteInitialJournal(idle);
        if (status != InstallerStatus::Ok) return status;
    }
    if (need_discovered) {
        JournalRecord discovered;
        memset(&discovered, 0, sizeof(discovered));
        discovered.generation = record_.generation + 1U;
        memcpy(discovered.transaction_id, request_.identity.transaction_id,
               kTransactionIdBytes);
        discovered.state = JournalState::Discovered;
        discovered.flags = request_.identity.reset_required
            ? kJournalFlagResetRequired : 0U;
        discovered.source_release_sequence = request_.identity.source_release_sequence;
        discovered.target_release_sequence = request_.manifest->release_sequence;
        discovered.board = request_.manifest->asset.board;
        memcpy(discovered.manifest_sha256, request_.identity.manifest_sha256,
               kSha256DigestBytes);
        memcpy(discovered.zip_sha256, request_.manifest->asset.sha256,
               kSha256DigestBytes);
        memcpy(discovered.consent_sha256, request_.identity.consent_sha256,
               kSha256DigestBytes);
        discovered.old_boot_generation = request_.identity.old_boot_generation;
        discovered.new_boot_generation = request_.identity.new_boot_generation;
        discovered.total_steps = layout.total;
        status = WriteTransition(discovered);
        if (status != InstallerStatus::Ok) return status;
    }
    JournalRecord downloaded = record_;
    ++downloaded.generation;
    downloaded.state = JournalState::Downloaded;
    downloaded.flags |= kJournalFlagUserApproved | kJournalFlagDownloadVerified;
    if (request_.identity.reset_required) downloaded.flags |= kJournalFlagResetApproved;
    return WriteTransition(downloaded);
}

InstallerStatus Engine::AdvancePrepared()
{
    if (record_.completed_steps == UINT32_MAX) {
        return InstallerStatus::JournalConflict;
    }
    return AdvancePreparedTo(record_.completed_steps + 1U);
}

InstallerStatus Engine::AdvancePreparedTo(uint32_t completed_steps)
{
    if (!have_journal_ || record_.state != JournalState::Prepared ||
        completed_steps < record_.completed_steps ||
        completed_steps > record_.total_steps) {
        return InstallerStatus::JournalConflict;
    }
    if (completed_steps == record_.completed_steps) {
        return InstallerStatus::Ok;
    }
    JournalRecord next = record_;
    ++next.generation;
    next.completed_steps = completed_steps;
    return WriteTransition(next);
}

InstallerStatus Engine::SnapshotFile(size_t index, const ManifestFile &file)
{
    char snapshot[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(snapshot, sizeof(snapshot), snapshot_root_, file.path)) {
        return InstallerStatus::InvalidPath;
    }
    UpdateFileStat source;
    UpdateFileStat target;
    if (!fs_->Stat(file.path, &source) || !fs_->Stat(snapshot, &target)) {
        return InstallerStatus::FileSystemError;
    }
    bool unchanged = false;
    const InstallerStatus noop_status = IsNoop(index, &unchanged);
    if (noop_status != InstallerStatus::Ok) return noop_status;
    if (unchanged) return InstallerStatus::Ok;
    if (file.policy == ManifestFilePolicy::ConfigTemplate) {
        const PreparedConfigTemplate *prepared = PreparedConfig(file);
        if (prepared == 0) return InstallerStatus::PreparedConfigRequired;
        if (prepared->original_existed) {
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(file.path, prepared->original_size,
                            prepared->original_sha256, &verify_failure)) {
                return InstallerStatus::ConfigChangedSinceConsent;
            }
        } else if (source.type != UpdateNodeType::Missing) {
            return InstallerStatus::ConfigChangedSinceConsent;
        }
    }
    bool evidence_existed = false;
    uint64_t evidence_size = 0U;
    uint8_t evidence_digest[kSha256DigestBytes];
    InstallerStatus evidence = ReadSnapshotEvidence(index, &evidence_existed,
                                                     &evidence_size,
                                                     evidence_digest);
    if (evidence == InstallerStatus::Ok) {
        if (!evidence_existed) {
            return source.type == UpdateNodeType::Missing &&
                   target.type == UpdateNodeType::Missing
                ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
        }
        if (target.type == UpdateNodeType::Missing) {
            return CopyFileAtomicExpected(file.path, snapshot, evidence_size,
                                          evidence_digest);
        }
        InstallerStatus verify_failure = InstallerStatus::FileSystemError;
        return VerifyFile(snapshot, evidence_size, evidence_digest, &verify_failure)
            ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
    }
    if (evidence != InstallerStatus::RollbackEvidenceMissing) return evidence;
    if (source.type == UpdateNodeType::Missing) {
        if (target.type != UpdateNodeType::Missing) {
            return InstallerStatus::RollbackEvidenceMissing;
        }
        uint8_t zero[kSha256DigestBytes];
        memset(zero, 0, sizeof(zero));
        return WriteSnapshotEvidence(index, false, 0U, zero);
    }
    if (source.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    uint8_t digest[kSha256DigestBytes];
    uint64_t size = 0U;
    const InstallerStatus copy = CopyFileAtomic(file.path, snapshot, &size,
                                                digest);
    if (copy != InstallerStatus::Ok) return copy;
    if (size != source.size) {
        return InstallerStatus::FileSystemError;
    }
    return WriteSnapshotEvidence(index, true, size, digest);
}

bool Engine::MarkerPath(bool directory, size_t index,
                        char *path, size_t capacity) const
{
    char prefix[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(prefix, sizeof(prefix), state_root_,
                  directory ? "dir-existed-" : "file-existed-")) return false;
    return AppendDecimal(path, capacity, prefix, index);
}

bool Engine::SnapshotEvidencePath(size_t index, char *path, size_t capacity) const
{
    char prefix[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(prefix, sizeof(prefix), state_root_, "snapshot-")) return false;
    return AppendDecimal(path, capacity, prefix, index);
}

InstallerStatus Engine::IsNoop(size_t index, bool *noop)
{
    if (noop == 0 || index >= request_.manifest->asset.file_count) {
        return InstallerStatus::InvalidArgument;
    }
    if (!content_plan_loaded_) {
        const InstallerStatus loaded = LoadContentPlan(false);
        if (loaded != InstallerStatus::Ok) return loaded;
    }
    *noop = (content_plan_noop_[index / 8U] &
             static_cast<uint8_t>(1U << (index % 8U))) != 0U;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::ReadEvidence(const char *path, uint8_t *bytes,
                                     size_t size, bool *present)
{
    UpdateFileStat stat;
    if (path == 0 || bytes == 0 || present == 0 ||
        !fs_->Stat(path, &stat)) return InstallerStatus::FileSystemError;
    if (stat.type == UpdateNodeType::Missing) {
        *present = false;
        return InstallerStatus::Ok;
    }
    if (stat.type != UpdateNodeType::RegularFile || stat.size != size) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    UpdateReadFile *file = 0;
    if (!fs_->OpenRead(path, &file) || file == 0 ||
        !file->ReadAt(0U, bytes, size)) {
        if (file != 0) file->Close();
        return InstallerStatus::FileSystemError;
    }
    if (!file->Close()) return InstallerStatus::FileSystemError;
    *present = true;
    return InstallerStatus::Ok;
}

InstallerStatus Engine::WriteFreshEvidence(const char *path,
                                           const uint8_t *bytes, size_t size)
{
    UpdateFileStat stat;
    if (!fs_->Stat(path, &stat)) return InstallerStatus::FileSystemError;
    if (stat.type == UpdateNodeType::RegularFile) {
        if (stat.size != size) return InstallerStatus::RollbackEvidenceMissing;
        uint8_t existing[kSnapshotEvidenceBytes];
        bool present = false;
        const InstallerStatus read = ReadEvidence(path, existing, size, &present);
        return read == InstallerStatus::Ok && present &&
               memcmp(existing, bytes, size) == 0
            ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
    }
    if (stat.type != UpdateNodeType::Missing || size > kSnapshotEvidenceBytes) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(temporary, sizeof(temporary), path, ".part") ||
        !RemoveIfPresent(temporary)) return InstallerStatus::FileSystemError;
    UpdateWriteFile *file = 0;
    if (!fs_->CreateFileFresh(temporary, &file) || file == 0) {
        return InstallerStatus::FileSystemError;
    }
    const bool wrote = file->Write(ByteView(bytes, size));
    const bool synced = wrote && file->Sync();
    const bool closed = file->Close();
    if (!wrote || !synced || !closed ||
        !fs_->Rename(temporary, path, false) ||
        !fs_->SyncContainingDirectory(path)) {
        RemoveIfPresent(temporary);
        return InstallerStatus::FileSystemError;
    }
    uint8_t reread[kSnapshotEvidenceBytes];
    bool present = false;
    const InstallerStatus read = ReadEvidence(path, reread, size, &present);
    return read == InstallerStatus::Ok && present && memcmp(reread, bytes, size) == 0
        ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
}

InstallerStatus Engine::EnsureMarker(bool directory, size_t index, bool existed)
{
    char marker[kInstallerMaximumPathBytes + 1U];
    if (!MarkerPath(directory, index, marker, sizeof(marker))) {
        return InstallerStatus::InvalidPath;
    }
    uint8_t encoded[kExistenceEvidenceBytes];
    memset(encoded, 0, sizeof(encoded));
    memcpy(encoded, kExistenceMagic, sizeof(kExistenceMagic));
    encoded[8U] = directory ? 1U : 0U;
    encoded[9U] = existed ? 1U : 0U;
    WriteU32(encoded + 12U, static_cast<uint32_t>(index));
    WriteU32(encoded + 16U, CalculateCrc32(ByteView(encoded, 16U)));
    return WriteFreshEvidence(marker, encoded, sizeof(encoded));
}

bool Engine::MarkerExists(bool directory, size_t index, bool *exists)
{
    char marker[kInstallerMaximumPathBytes + 1U];
    uint8_t encoded[kExistenceEvidenceBytes];
    bool present = false;
    if (exists == 0 || !MarkerPath(directory, index, marker, sizeof(marker)) ||
        ReadEvidence(marker, encoded, sizeof(encoded), &present) != InstallerStatus::Ok ||
        !present || memcmp(encoded, kExistenceMagic, sizeof(kExistenceMagic)) != 0 ||
        encoded[8U] != (directory ? 1U : 0U) || encoded[9U] > 1U ||
        encoded[10U] != 0U || encoded[11U] != 0U ||
        ReadU32(encoded + 12U) != index ||
        ReadU32(encoded + 16U) != CalculateCrc32(ByteView(encoded, 16U))) return false;
    *exists = encoded[9U] != 0U;
    return true;
}

InstallerStatus Engine::WriteSnapshotEvidence(
    size_t index, bool existed, uint64_t size,
    const uint8_t digest[kSha256DigestBytes])
{
    char path[kInstallerMaximumPathBytes + 1U];
    if (!SnapshotEvidencePath(index, path, sizeof(path)) || digest == 0) {
        return InstallerStatus::InvalidPath;
    }
    uint8_t encoded[kSnapshotEvidenceBytes];
    memset(encoded, 0, sizeof(encoded));
    memcpy(encoded, kSnapshotMagic, sizeof(kSnapshotMagic));
    encoded[8U] = existed ? 1U : 0U;
    WriteU64(encoded + 16U, size);
    memcpy(encoded + 24U, digest, kSha256DigestBytes);
    WriteU32(encoded + 56U, CalculateCrc32(ByteView(encoded, 56U)));
    return WriteFreshEvidence(path, encoded, sizeof(encoded));
}

InstallerStatus Engine::ReadSnapshotEvidence(
    size_t index, bool *existed, uint64_t *size,
    uint8_t digest[kSha256DigestBytes])
{
    if (existed == 0 || size == 0 || digest == 0) {
        return InstallerStatus::InvalidArgument;
    }
    ContentPlanRecord plan_record;
    const InstallerStatus plan = ReadContentPlanRecord(index, &plan_record);
    if (plan != InstallerStatus::Ok) return plan;
    *existed = (plan_record.flags & kContentPlanSourceExisted) != 0U;
    if (!*existed) {
        *size = 0U;
        memset(digest, 0, kSha256DigestBytes);
        return InstallerStatus::Ok;
    }
    if ((plan_record.flags & kContentPlanOldDigestValid) != 0U) {
        *size = plan_record.old_size;
        memcpy(digest, plan_record.old_digest, kSha256DigestBytes);
        return InstallerStatus::Ok;
    }
    if (content_plan_final_) return InstallerStatus::RollbackEvidenceMissing;
    char path[kInstallerMaximumPathBytes + 1U];
    uint8_t encoded[kSnapshotEvidenceBytes];
    bool present = false;
    if (!SnapshotEvidencePath(index, path, sizeof(path))) {
        return InstallerStatus::InvalidArgument;
    }
    const InstallerStatus read = ReadEvidence(path, encoded, sizeof(encoded), &present);
    if (read != InstallerStatus::Ok) return read;
    if (!present) return InstallerStatus::RollbackEvidenceMissing;
    uint8_t reserved = 0U;
    for (size_t offset = 9U; offset < 16U; ++offset) reserved |= encoded[offset];
    if (memcmp(encoded, kSnapshotMagic, sizeof(kSnapshotMagic)) != 0 ||
        encoded[8U] > 1U || reserved != 0U ||
        ReadU32(encoded + 56U) != CalculateCrc32(ByteView(encoded, 56U))) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    *existed = encoded[8U] != 0U;
    *size = ReadU64(encoded + 16U);
    memcpy(digest, encoded + 24U, kSha256DigestBytes);
    if (!*existed && (*size != 0U || BytesNonZero(digest, kSha256DigestBytes))) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::ReadMetadataEvidence(
    size_t index, bool *existed, uint64_t *size,
    uint8_t digest[kSha256DigestBytes])
{
    if (existed == 0 || size == 0 || digest == 0) {
        return InstallerStatus::InvalidArgument;
    }
    ContentPlanRecord record;
    const InstallerStatus plan = ReadContentPlanRecord(index, &record);
    if (plan != InstallerStatus::Ok) return plan;
    *existed = (record.flags & kContentPlanSourceExisted) != 0U;
    if (*existed && (record.flags & kContentPlanOldDigestValid) == 0U) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    *size = *existed ? record.old_size : 0U;
    if (*existed) memcpy(digest, record.old_digest, kSha256DigestBytes);
    else memset(digest, 0, kSha256DigestBytes);
    return InstallerStatus::Ok;
}

InstallerStatus Engine::StageFile(size_t index, const ManifestFile &file,
                                  ZipReader *reader,
                                  const ZipExpectedInventory &expected,
                                  InstallerHashSink *hash_sink)
{
    bool unchanged = false;
    InstallerStatus noop_status = IsNoop(index, &unchanged);
    if (noop_status != InstallerStatus::Ok) return noop_status;
    if (unchanged) return InstallerStatus::Ok;
    char staged[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(staged, sizeof(staged), stage_root_, file.path)) {
        return InstallerStatus::InvalidPath;
    }
    UpdateFileStat destination;
    UpdateFileStat staged_stat;
    if (!fs_->Stat(file.path, &destination) || !fs_->Stat(staged, &staged_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (file.policy == ManifestFilePolicy::Preserve ||
        file.policy == ManifestFilePolicy::Metadata) {
        if (destination.type != UpdateNodeType::RegularFile &&
            destination.type != UpdateNodeType::Missing) {
            return InstallerStatus::UnexpectedNodeType;
        }
        const InstallerStatus marker = EnsureMarker(
            false, index, destination.type == UpdateNodeType::RegularFile);
        if (marker != InstallerStatus::Ok) return marker;
        if (file.policy == ManifestFilePolicy::Preserve &&
            destination.type == UpdateNodeType::RegularFile) {
            return staged_stat.type == UpdateNodeType::Missing
                ? InstallerStatus::Ok : InstallerStatus::JournalConflict;
        }
    } else if (destination.type != UpdateNodeType::Missing &&
               destination.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    if (staged_stat.type == UpdateNodeType::RegularFile) {
        InstallerStatus failure = InstallerStatus::FileSystemError;
        return VerifyFile(staged, EffectiveSize(file), EffectiveDigest(file), &failure)
            ? InstallerStatus::Ok : failure;
    }
    if (staged_stat.type != UpdateNodeType::Missing) {
        return InstallerStatus::UnexpectedNodeType;
    }
    if (file.policy == ManifestFilePolicy::ConfigTemplate) {
        return StagePreparedConfig(file, staged);
    }
    TransactionExtractSink sink(this, &file, staged);
    const ZipStatus zip_status = reader->ExtractOne(file.path, expected, &sink,
                                                     hash_sink);
    if (zip_status != ZipStatus::Ok && hash_sink->progress_failed()) {
        return InstallerStatus::RecoveryProgressFailed;
    }
    return zip_status == ZipStatus::Ok ? InstallerStatus::Ok
                                       : InstallerStatus::ArchiveInvalid;
}

InstallerStatus Engine::ActivateDirectory(size_t index,
                                          const ManifestDirectory &directory)
{
    UpdateFileStat stat;
    if (!fs_->Stat(directory.path, &stat)) return InstallerStatus::FileSystemError;
    if (stat.type == UpdateNodeType::Directory) {
        char marker_path[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat marker_stat;
        if (!MarkerPath(true, index, marker_path, sizeof(marker_path)) ||
            !fs_->Stat(marker_path, &marker_stat)) return InstallerStatus::FileSystemError;
        if (marker_stat.type == UpdateNodeType::RegularFile) {
            bool ignored = false;
            return MarkerExists(true, index, &ignored)
                ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
        }
        if (marker_stat.type != UpdateNodeType::Missing) {
            return InstallerStatus::RollbackEvidenceMissing;
        }
        return EnsureMarker(true, index, true);
    }
    if (stat.type != UpdateNodeType::Missing) return InstallerStatus::UnexpectedNodeType;
    const InstallerStatus marker = EnsureMarker(true, index, false);
    if (marker != InstallerStatus::Ok) return marker;
    if (!EnsureParents(directory.path) || !fs_->CreateDirectory(directory.path) ||
        !fs_->SyncContainingDirectory(directory.path)) {
        return InstallerStatus::FileSystemError;
    }
    return InstallerStatus::Ok;
}

InstallerStatus Engine::ActivateFile(size_t index, const ManifestFile &file)
{
    bool unchanged = false;
    const InstallerStatus noop_status = IsNoop(index, &unchanged);
    if (noop_status != InstallerStatus::Ok) return noop_status;
    if (unchanged) return InstallerStatus::Ok;
    char staged[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(staged, sizeof(staged), stage_root_, file.path)) {
        return InstallerStatus::InvalidPath;
    }
    UpdateFileStat destination;
    UpdateFileStat staged_stat;
    if (!fs_->Stat(file.path, &destination) || !fs_->Stat(staged, &staged_stat)) {
        return InstallerStatus::FileSystemError;
    }
    if (file.policy == ManifestFilePolicy::Preserve) {
        bool existed = false;
        if (!MarkerExists(false, index, &existed)) return InstallerStatus::JournalConflict;
        if (existed) {
            return destination.type == UpdateNodeType::RegularFile &&
                   staged_stat.type == UpdateNodeType::Missing
                ? InstallerStatus::Ok : InstallerStatus::PreserveChanged;
        }
    }
    if (staged_stat.type == UpdateNodeType::Missing) {
        InstallerStatus failure = InstallerStatus::FileSystemError;
        return VerifyFile(file.path, EffectiveSize(file), EffectiveDigest(file), &failure)
            ? InstallerStatus::Ok : failure;
    }
    if (staged_stat.type != UpdateNodeType::RegularFile ||
        !EnsureParents(file.path)) return InstallerStatus::UnexpectedNodeType;
    const bool replace = file.policy == ManifestFilePolicy::ManagedReplace ||
                         file.policy == ManifestFilePolicy::ConfigTemplate ||
                         file.policy == ManifestFilePolicy::Kernel;
    if (!replace && destination.type != UpdateNodeType::Missing) {
        return InstallerStatus::PreserveChanged;
    }
    if (replace && destination.type != UpdateNodeType::Missing &&
        destination.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    if (!fs_->Rename(staged, file.path, replace) ||
        !fs_->SyncContainingDirectory(file.path)) return InstallerStatus::FileSystemError;
    InstallerStatus failure = InstallerStatus::FileSystemError;
    return VerifyFile(file.path, EffectiveSize(file), EffectiveDigest(file), &failure)
        ? InstallerStatus::Ok : failure;
}

InstallerStatus Engine::CommitMetadata(size_t index, const ManifestFile &file)
{
    bool unchanged = false;
    const InstallerStatus noop_status = IsNoop(index, &unchanged);
    if (noop_status != InstallerStatus::Ok) return noop_status;
    if (unchanged) return InstallerStatus::Ok;
    char staged[kInstallerMaximumPathBytes + 1U];
    char old[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(staged, sizeof(staged), stage_root_, file.path) ||
        !JoinPath(old, sizeof(old), metadata_old_root_, file.path)) {
        return InstallerStatus::InvalidPath;
    }
    UpdateFileStat stage_stat;
    UpdateFileStat destination;
    UpdateFileStat old_stat;
    if (!fs_->Stat(staged, &stage_stat) || !fs_->Stat(file.path, &destination) ||
        !fs_->Stat(old, &old_stat)) return InstallerStatus::FileSystemError;
    if (stage_stat.type == UpdateNodeType::Missing) {
        bool marker_existed = false;
        bool evidence_existed = false;
        uint64_t old_size = 0U;
        uint8_t old_digest[kSha256DigestBytes];
        if (!MarkerExists(false, index, &marker_existed) ||
            ReadMetadataEvidence(index, &evidence_existed, &old_size,
                                 old_digest) != InstallerStatus::Ok ||
            marker_existed != evidence_existed) {
            return InstallerStatus::RollbackEvidenceMissing;
        }
        if (evidence_existed) {
            InstallerStatus old_failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(old, old_size, old_digest, &old_failure)) {
                return InstallerStatus::RollbackEvidenceMissing;
            }
        }
        InstallerStatus failure = InstallerStatus::FileSystemError;
        return VerifyFile(file.path, file.size, file.sha256, &failure)
            ? InstallerStatus::Ok : failure;
    }
    if (stage_stat.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    bool existed = false;
    if (!MarkerExists(false, index, &existed)) return InstallerStatus::JournalConflict;
    bool evidence_existed = false;
    uint64_t evidence_size = 0U;
    uint8_t evidence_digest[kSha256DigestBytes];
    InstallerStatus evidence = ReadMetadataEvidence(
        index, &evidence_existed, &evidence_size, evidence_digest);
    if (evidence != InstallerStatus::Ok || evidence_existed != existed) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    if (existed) {
        const char *evidence_source = old_stat.type == UpdateNodeType::RegularFile
            ? old : file.path;
        InstallerStatus verify_failure = InstallerStatus::FileSystemError;
        if (!VerifyFile(evidence_source, evidence_size, evidence_digest,
                        &verify_failure)) {
            return InstallerStatus::RollbackEvidenceMissing;
        }
    }
    if (destination.type == UpdateNodeType::RegularFile) {
        if (old_stat.type == UpdateNodeType::Missing) {
            if (!existed || !EnsureParents(old) ||
                !fs_->Rename(file.path, old, false) ||
                !fs_->SyncContainingDirectory(old)) return InstallerStatus::FileSystemError;
            destination.type = UpdateNodeType::Missing;
            old_stat.type = UpdateNodeType::RegularFile;
        } else {
            return InstallerStatus::JournalConflict;
        }
    } else if (destination.type != UpdateNodeType::Missing) {
        return InstallerStatus::UnexpectedNodeType;
    }
    if (existed && old_stat.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    if (!existed && old_stat.type != UpdateNodeType::Missing) {
        return InstallerStatus::JournalConflict;
    }
    if (!EnsureParents(file.path) || !fs_->Rename(staged, file.path, false) ||
        !fs_->SyncContainingDirectory(file.path)) return InstallerStatus::FileSystemError;
    InstallerStatus failure = InstallerStatus::FileSystemError;
    return VerifyFile(file.path, file.size, file.sha256, &failure)
        ? InstallerStatus::Ok : failure;
}

CandidateContext Engine::Candidate() const
{
    CandidateContext context;
    memset(&context, 0, sizeof(context));
    context.transaction_root = root_;
    context.staging_root = stage_root_;
    context.asset = &request_.manifest->asset;
    context.board = request_.manifest->asset.board;
    context.source_release_sequence = request_.identity.source_release_sequence;
    context.target_release_sequence = request_.manifest->release_sequence;
    context.old_boot_generation = request_.identity.old_boot_generation;
    context.new_boot_generation = request_.identity.new_boot_generation;
    memcpy(context.transaction_id, request_.identity.transaction_id,
           kTransactionIdBytes);
    return context;
}

InstallerStatus Engine::VerifyCandidateFiles()
{
    const ManifestAsset &asset = request_.manifest->asset;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        // ArmCandidate deliberately changes this signed config template from
        // its stable target selector to the temporary .bmx-next kernel.  The
        // candidate backend validates that transient selector against the
        // authenticated target asset when arming and again before committing,
        // then publishes the stable template value.  Comparing the live file
        // with its prepared stable digest here would reject every changed
        // kernel whose source and target use the same stable filename.
        if (file.policy == ManifestFilePolicy::ConfigTemplate &&
            strcmp(file.path, kCandidateSelectorPath) == 0) {
            if (!Progress(UpdateRecoveryProgressKind::InstallerCommitStep,
                          index + 1U, asset.file_count)) {
                return InstallerStatus::RecoveryProgressFailed;
            }
            continue;
        }
        bool unchanged = false;
        InstallerStatus noop_status = IsNoop(index, &unchanged);
        if (noop_status != InstallerStatus::Ok) return noop_status;
        if (unchanged) {
            InstallerStatus failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(file.path, EffectiveSize(file), EffectiveDigest(file),
                            &failure)) return failure;
        } else if (file.policy == ManifestFilePolicy::Metadata ||
                   file.policy == ManifestFilePolicy::Kernel) {
            char staged[kInstallerMaximumPathBytes + 1U];
            if (!JoinPath(staged, sizeof(staged), stage_root_, file.path)) {
                return InstallerStatus::InvalidPath;
            }
            InstallerStatus failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(staged, EffectiveSize(file), EffectiveDigest(file),
                            &failure)) return failure;
        } else if (file.policy == ManifestFilePolicy::Preserve) {
            bool existed = false;
            if (!MarkerExists(false, index, &existed)) {
                return InstallerStatus::JournalConflict;
            }
            if (!existed) {
                InstallerStatus failure = InstallerStatus::FileSystemError;
                if (!VerifyFile(file.path, file.size, file.sha256, &failure)) return failure;
            }
        } else {
            InstallerStatus failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(file.path, EffectiveSize(file), EffectiveDigest(file),
                            &failure)) return failure;
        }
        if (!Progress(UpdateRecoveryProgressKind::InstallerCommitStep,
                      index + 1U, asset.file_count)) {
            return InstallerStatus::RecoveryProgressFailed;
        }
    }
    return InstallerStatus::Ok;
}

InstallerResult Engine::Stage()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(true, &failure)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    ZipReader reader;
    ZipExpectedInventory expected;
    InstallerHashSink validation_hash_sink(
        request_.recovery_progress, request_.manifest->asset.installed_size);
    InstallerHashSink staging_hash_sink(request_.recovery_progress);
    StepLayout layout;
    ZipStatus zip_status = ZipStatus::Ok;
    failure = PrepareArchive(&reader, &expected, &validation_hash_sink,
                             &layout, &zip_status);
    if (failure != InstallerStatus::Ok) return Result(failure, zip_status);
    if (!EnsureTransactionDirectories()) return Result(InstallerStatus::FileSystemError);
    failure = InitializeJournal(layout);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (record_.state == JournalState::Staged) return Result(InstallerStatus::AlreadyStaged);
    if (record_.state != JournalState::Downloaded &&
        record_.state != JournalState::Prepared) return Result(InstallerStatus::WrongState);
    if (record_.state == JournalState::Downloaded) {
        JournalRecord prepared = record_;
        ++prepared.generation;
        prepared.state = JournalState::Prepared;
        failure = WriteTransition(prepared);
        if (failure != InstallerStatus::Ok) return Result(failure);
    }
    // Content classification hashes are Stage work too. Accumulate their
    // bytes while the plan is built, then publish the first aggregate event
    // once the plan makes the exact remaining denominator knowable.
    stage_work_tracking_ = true;
    stage_work_reporting_ = false;
    stage_work_completed_ = 0U;
    stage_work_total_ = 0U;
    failure = PreflightStorage();
    if (failure != InstallerStatus::Ok) return Result(failure);
    failure = InitializeStageWork();
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (!Progress(UpdateRecoveryProgressKind::InstallerContentPlanSummary,
                  content_plan_changed_files_,
                  content_plan_unchanged_files_)) {
        return Result(InstallerStatus::RecoveryProgressFailed);
    }
    // Snapshot and stage paths are transaction-private. Every completed file
    // and its evidence is independently synced, verified and idempotent, so a
    // journal write after every one only duplicates durability work. Keep an
    // in-memory high-water mark and publish it once, immediately before the
    // first live directory/file mutation. A reset before that checkpoint
    // safely replays and revalidates the private outputs from the last durable
    // PREPARED position; rollback has no live path to restore yet.
    uint32_t prepared_high_water = record_.completed_steps;
    uint32_t step = layout.snapshot_begin;
    const ManifestAsset &asset = request_.manifest->asset;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy != ManifestFilePolicy::ManagedReplace &&
            file.policy != ManifestFilePolicy::ConfigTemplate &&
            file.policy != ManifestFilePolicy::Kernel) continue;
        if (prepared_high_water < step) {
            return Result(InstallerStatus::JournalConflict);
        }
        if (prepared_high_water == step) {
            failure = SnapshotFile(index, file);
            if (failure != InstallerStatus::Ok) return Result(failure);
            ++prepared_high_water;
        }
        ++step;
    }
    failure = FinalizeContentPlan();
    if (failure != InstallerStatus::Ok) return Result(failure);
    step = layout.file_stage_begin;
    for (size_t index = 0U; index < asset.file_count; ++index, ++step) {
        if (prepared_high_water < step) {
            return Result(InstallerStatus::JournalConflict);
        }
        if (prepared_high_water == step) {
            failure = StageFile(index, asset.files[index], &reader, expected,
                                &staging_hash_sink);
            if (failure != InstallerStatus::Ok) return Result(failure);
            ++prepared_high_water;
        }
    }
    if (record_.completed_steps < layout.directory_activate_begin) {
        if (prepared_high_water != layout.directory_activate_begin) {
            return Result(InstallerStatus::JournalConflict);
        }
        failure = AdvancePreparedTo(prepared_high_water);
        if (failure != InstallerStatus::Ok) return Result(failure);
    }
    step = layout.directory_activate_begin;
    for (size_t index = 0U; index < asset.directory_count; ++index, ++step) {
        if (record_.completed_steps < step) return Result(InstallerStatus::JournalConflict);
        if (record_.completed_steps == step) {
            failure = ActivateDirectory(index, asset.directories[index]);
            if (failure != InstallerStatus::Ok) return Result(failure);
            failure = AdvancePrepared();
            if (failure != InstallerStatus::Ok) return Result(failure);
        }
    }
    step = layout.file_activate_begin;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy == ManifestFilePolicy::Metadata ||
            file.policy == ManifestFilePolicy::Kernel) continue;
        if (record_.completed_steps < step) return Result(InstallerStatus::JournalConflict);
        if (record_.completed_steps == step) {
            failure = ActivateFile(index, file);
            if (failure != InstallerStatus::Ok) return Result(failure);
            failure = AdvancePrepared();
            if (failure != InstallerStatus::Ok) return Result(failure);
        }
        ++step;
    }
    if (record_.completed_steps != layout.stage_end) {
        return Result(InstallerStatus::JournalConflict);
    }
    JournalRecord staged = record_;
    ++staged.generation;
    staged.state = JournalState::Staged;
    staged.flags |= kJournalFlagSnapshotComplete | kJournalFlagStagingComplete;
    failure = WriteTransition(staged);
    if (failure == InstallerStatus::Ok &&
        !Progress(UpdateRecoveryProgressKind::InstallerStageOverall,
                  stage_work_total_, stage_work_total_)) {
        failure = InstallerStatus::RecoveryProgressFailed;
    }
    stage_work_tracking_ = false;
    stage_work_reporting_ = false;
    return Result(failure);
}

InstallerResult Engine::Arm()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    failure = LoadJournal(false);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (!IdentityMatches(record_)) return Result(InstallerStatus::JournalConflict);
    if (record_.state == JournalState::CandidatePending) {
        return Result(InstallerStatus::AlreadyArmed);
    }
    if (record_.state != JournalState::Staged) return Result(InstallerStatus::WrongState);
    failure = LoadContentPlan(true);
    if (failure != InstallerStatus::Ok) return Result(failure);
    StepLayout layout;
    if (!BuildStepLayout(request_.manifest->asset, &layout) ||
        record_.completed_steps != layout.arm_step ||
        record_.total_steps != layout.total) return Result(InstallerStatus::JournalConflict);
    if (backend_ == 0 || !backend_->Supported()) {
        return Result(InstallerStatus::CandidateBackendUnsupported);
    }
    if (!backend_->ArmCandidate(Candidate())) {
        return Result(InstallerStatus::CandidateBackendError);
    }
    JournalRecord pending = record_;
    ++pending.generation;
    pending.state = JournalState::CandidatePending;
    pending.flags |= kJournalFlagTrybootArmed;
    ++pending.completed_steps;
    failure = WriteTransition(pending);
    return Result(failure);
}

InstallerResult Engine::Healthy()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    failure = LoadJournal(false);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (!IdentityMatches(record_)) return Result(InstallerStatus::JournalConflict);
    if (record_.state == JournalState::CandidateHealthy) {
        return Result(InstallerStatus::AlreadyHealthy);
    }
    if (record_.state != JournalState::CandidatePending) {
        return Result(InstallerStatus::WrongState);
    }
    StepLayout layout;
    if (!BuildStepLayout(request_.manifest->asset, &layout) ||
        record_.completed_steps != layout.health_step ||
        backend_ == 0 || !backend_->Supported()) {
        return Result(backend_ == 0 || !backend_->Supported()
            ? InstallerStatus::CandidateBackendUnsupported
            : InstallerStatus::JournalConflict);
    }
    JournalRecord healthy = record_;
    ++healthy.generation;
    healthy.state = JournalState::CandidateHealthy;
    healthy.flags |= kJournalFlagCandidateHealthy;
    ++healthy.completed_steps;
    failure = WriteTransition(healthy);
    return Result(failure);
}

InstallerResult Engine::Commit()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    if (workspace_ == 0 || workspace_->io_buffer == 0 ||
        workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes) {
        return Result(InstallerStatus::WorkspaceTooSmall);
    }
    failure = LoadJournal(false);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (!IdentityMatches(record_)) return Result(InstallerStatus::JournalConflict);
    if (record_.state == JournalState::Committed) {
        return Result(InstallerStatus::AlreadyCommitted);
    }
    if (record_.state != JournalState::CandidateHealthy &&
        record_.state != JournalState::Committing) return Result(InstallerStatus::WrongState);
    failure = LoadContentPlan(true);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (backend_ == 0 || !backend_->Supported()) {
        return Result(InstallerStatus::CandidateBackendUnsupported);
    }
    StepLayout layout;
    if (!BuildStepLayout(request_.manifest->asset, &layout) ||
        record_.total_steps != layout.total) return Result(InstallerStatus::JournalConflict);
    if (record_.state == JournalState::CandidateHealthy) {
        failure = VerifyCandidateFiles();
        if (failure != InstallerStatus::Ok) return Result(failure);
        JournalRecord committing = record_;
        ++committing.generation;
        committing.state = JournalState::Committing;
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitBeforeCommittingJournal);
        failure = WriteTransition(committing);
        if (failure != InstallerStatus::Ok) return Result(failure);
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitAfterCommittingJournal);
    }
    const ManifestAsset &asset = request_.manifest->asset;
    uint32_t step = layout.kernel_begin;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy != ManifestFilePolicy::Kernel) continue;
        if (record_.completed_steps < step) {
            return Result(InstallerStatus::JournalConflict);
        }
        if (record_.completed_steps == step) {
            failure = ActivateFile(index, file);
            if (failure != InstallerStatus::Ok) return Result(failure);
            JournalRecord progress = record_;
            ++progress.generation;
            ++progress.completed_steps;
            failure = WriteTransition(progress);
            if (failure != InstallerStatus::Ok) return Result(failure);
            if (!Progress(UpdateRecoveryProgressKind::InstallerCommitStep,
                          progress.completed_steps, progress.total_steps)) {
                return Result(InstallerStatus::RecoveryProgressFailed);
            }
        }
        ++step;
    }
    step = layout.metadata_begin;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy != ManifestFilePolicy::Metadata) continue;
        if (record_.completed_steps < step) return Result(InstallerStatus::JournalConflict);
        if (record_.completed_steps == step) {
            BMX_UPDATE_FAULT_CHECKPOINT(
                UpdateFaultPoint::CommitBeforeMetadataPublish);
            failure = CommitMetadata(index, file);
            if (failure != InstallerStatus::Ok) return Result(failure);
            BMX_UPDATE_FAULT_CHECKPOINT(
                UpdateFaultPoint::CommitAfterMetadataPublish);
            JournalRecord progress = record_;
            ++progress.generation;
            ++progress.completed_steps;
            failure = WriteTransition(progress);
            if (failure != InstallerStatus::Ok) return Result(failure);
            if (!Progress(UpdateRecoveryProgressKind::InstallerCommitStep,
                          progress.completed_steps, progress.total_steps)) {
                return Result(InstallerStatus::RecoveryProgressFailed);
            }
        }
        ++step;
    }
    if ((record_.flags & kJournalFlagSelectorCommitted) == 0U) {
        if (record_.completed_steps != layout.selector_step) {
            return Result(InstallerStatus::JournalConflict);
        }
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitBeforeSelectorPublish);
        if (!backend_->CommitCandidate(Candidate())) {
            return Result(InstallerStatus::CandidateBackendError);
        }
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitAfterSelectorPublish);
        JournalRecord selector = record_;
        ++selector.generation;
        selector.flags |= kJournalFlagSelectorCommitted;
        ++selector.completed_steps;
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitBeforeSelectorJournal);
        failure = WriteTransition(selector);
        if (failure != InstallerStatus::Ok) return Result(failure);
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::CommitAfterSelectorJournal);
        if (!Progress(UpdateRecoveryProgressKind::InstallerCommitStep,
                      selector.completed_steps, selector.total_steps)) {
            return Result(InstallerStatus::RecoveryProgressFailed);
        }
    } else if (record_.completed_steps != layout.total) {
        return Result(InstallerStatus::JournalConflict);
    }
    if (record_.completed_steps != layout.total) {
        return Result(InstallerStatus::JournalConflict);
    }
    JournalRecord committed = record_;
    ++committed.generation;
    committed.state = JournalState::Committed;
    BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::CommitBeforeFinalJournal);
    failure = WriteTransition(committed);
    if (failure == InstallerStatus::Ok) {
        BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::CommitAfterFinalJournal);
    }
    return Result(failure);
}

InstallerStatus Engine::RestoreFile(size_t index, const ManifestFile &file)
{
    bool unchanged = false;
    const InstallerStatus noop_status = IsNoop(index, &unchanged);
    if (noop_status != InstallerStatus::Ok) return noop_status;
    if (unchanged) return InstallerStatus::Ok;
    if (file.policy == ManifestFilePolicy::Metadata) {
        return RestoreMetadata(index, file);
    }
    StepLayout layout;
    if (!BuildStepLayout(request_.manifest->asset, &layout)) {
        return InstallerStatus::InvalidManifest;
    }
    uint32_t activation_step = file.policy == ManifestFilePolicy::Kernel
        ? layout.kernel_begin : layout.file_activate_begin;
    for (size_t cursor = 0U; cursor < index; ++cursor) {
        const ManifestFilePolicy prior =
            request_.manifest->asset.files[cursor].policy;
        if ((file.policy == ManifestFilePolicy::Kernel &&
             prior == ManifestFilePolicy::Kernel) ||
            (file.policy != ManifestFilePolicy::Kernel &&
             prior != ManifestFilePolicy::Metadata &&
             prior != ManifestFilePolicy::Kernel)) {
            ++activation_step;
        }
    }
    // Nothing at the live destination can have been changed before its
    // deterministic activation step. This guard is essential when rollback
    // starts after a power cut in the earlier snapshot phase.
    if (record_.completed_steps < activation_step) return InstallerStatus::Ok;
    if (record_.completed_steps == activation_step) {
        char staged[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat staged_stat;
        if (!JoinPath(staged, sizeof(staged), stage_root_, file.path) ||
            !fs_->Stat(staged, &staged_stat)) return InstallerStatus::FileSystemError;
        if (staged_stat.type == UpdateNodeType::RegularFile) {
            return InstallerStatus::Ok;
        }
        if (staged_stat.type != UpdateNodeType::Missing) {
            return InstallerStatus::UnexpectedNodeType;
        }
        // A preserve entry that existed originally intentionally has no
        // staged file and its activation is a no-op.
        if (file.policy == ManifestFilePolicy::Preserve) {
            bool existed = false;
            if (!MarkerExists(false, index, &existed)) {
                return InstallerStatus::JournalConflict;
            }
            if (existed) return InstallerStatus::Ok;
        }
    }
    if (file.policy == ManifestFilePolicy::Kernel ||
        file.policy == ManifestFilePolicy::ManagedReplace ||
        file.policy == ManifestFilePolicy::ConfigTemplate) {
        char snapshot[kInstallerMaximumPathBytes + 1U];
        if (!JoinPath(snapshot, sizeof(snapshot), snapshot_root_, file.path)) {
            return InstallerStatus::InvalidPath;
        }
        bool existed = false;
        uint64_t old_size = 0U;
        uint8_t old_digest[kSha256DigestBytes];
        const InstallerStatus evidence = ReadSnapshotEvidence(
            index, &existed, &old_size, old_digest);
        if (evidence != InstallerStatus::Ok) return evidence;
        if (existed) {
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            if (!VerifyFile(snapshot, old_size, old_digest, &verify_failure)) {
                return InstallerStatus::RollbackEvidenceMissing;
            }
            const InstallerStatus replace = ReplaceWithCopy(snapshot, file.path);
            if (replace != InstallerStatus::Ok) return replace;
            return VerifyFile(file.path, old_size, old_digest, &verify_failure)
                ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
        }
    } else if (file.policy == ManifestFilePolicy::Preserve) {
        bool existed = false;
        if (!MarkerExists(false, index, &existed)) return InstallerStatus::JournalConflict;
        if (existed) return InstallerStatus::Ok;
    }
    UpdateFileStat destination;
    if (!fs_->Stat(file.path, &destination)) return InstallerStatus::FileSystemError;
    if (destination.type == UpdateNodeType::Missing) return InstallerStatus::Ok;
    if (destination.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    if (!VerifyFile(file.path, EffectiveSize(file), EffectiveDigest(file), &failure)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    return fs_->RemoveFile(file.path) && fs_->SyncContainingDirectory(file.path)
        ? InstallerStatus::Ok : InstallerStatus::FileSystemError;
}

InstallerStatus Engine::RestoreMetadata(size_t index, const ManifestFile &file)
{
    char old[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(old, sizeof(old), metadata_old_root_, file.path)) {
        return InstallerStatus::InvalidPath;
    }
    StepLayout layout;
    if (!BuildStepLayout(request_.manifest->asset, &layout)) {
        return InstallerStatus::InvalidManifest;
    }
    uint32_t metadata_step = layout.metadata_begin;
    for (size_t cursor = 0U; cursor < index; ++cursor) {
        if (request_.manifest->asset.files[cursor].policy ==
            ManifestFilePolicy::Metadata) ++metadata_step;
    }
    if (record_.completed_steps < metadata_step ||
        (record_.state != JournalState::Committing &&
         record_.state != JournalState::Committed &&
         record_.state != JournalState::RollingBack)) {
        return InstallerStatus::Ok;
    }
    bool existed = false;
    if (!MarkerExists(false, index, &existed)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    UpdateFileStat old_stat;
    if (!fs_->Stat(old, &old_stat)) return InstallerStatus::FileSystemError;
    bool evidence_existed = false;
    uint64_t old_size = 0U;
    uint8_t old_digest[kSha256DigestBytes];
    const InstallerStatus evidence = ReadMetadataEvidence(
        index, &evidence_existed, &old_size, old_digest);
    if (evidence == InstallerStatus::RollbackEvidenceMissing) {
        // Commit writes rollback evidence before moving the old name. If the
        // evidence does not exist, no metadata replacement was permitted.
        char staged[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat destination;
        UpdateFileStat staged_stat;
        if (!JoinPath(staged, sizeof(staged), stage_root_, file.path) ||
            !fs_->Stat(file.path, &destination) ||
            !fs_->Stat(staged, &staged_stat)) return InstallerStatus::FileSystemError;
        const bool original_still_live = existed
            ? destination.type == UpdateNodeType::RegularFile
            : destination.type == UpdateNodeType::Missing;
        return original_still_live && staged_stat.type == UpdateNodeType::RegularFile &&
               old_stat.type == UpdateNodeType::Missing
            ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
    }
    if (evidence != InstallerStatus::Ok || evidence_existed != existed) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    if (existed) {
        if (old_stat.type != UpdateNodeType::RegularFile) {
            char staged[kInstallerMaximumPathBytes + 1U];
            UpdateFileStat destination;
            UpdateFileStat staged_stat;
            if (!JoinPath(staged, sizeof(staged), stage_root_, file.path) ||
                !fs_->Stat(file.path, &destination) ||
                !fs_->Stat(staged, &staged_stat)) return InstallerStatus::FileSystemError;
            // At the unjournalled boundary, old metadata is still live only
            // while the verified new copy remains in staging.
            InstallerStatus verify_failure = InstallerStatus::FileSystemError;
            return destination.type == UpdateNodeType::RegularFile &&
                   staged_stat.type == UpdateNodeType::RegularFile &&
                   VerifyFile(file.path, old_size, old_digest, &verify_failure)
                ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
        }
        InstallerStatus verify_failure = InstallerStatus::FileSystemError;
        if (!VerifyFile(old, old_size, old_digest, &verify_failure)) {
            return InstallerStatus::RollbackEvidenceMissing;
        }
        const InstallerStatus replace = ReplaceWithCopy(old, file.path);
        if (replace != InstallerStatus::Ok) return replace;
        return VerifyFile(file.path, old_size, old_digest, &verify_failure)
            ? InstallerStatus::Ok : InstallerStatus::RollbackEvidenceMissing;
    }
    if (old_stat.type != UpdateNodeType::Missing) return InstallerStatus::JournalConflict;
    UpdateFileStat destination;
    if (!fs_->Stat(file.path, &destination)) return InstallerStatus::FileSystemError;
    if (destination.type == UpdateNodeType::Missing) return InstallerStatus::Ok;
    if (destination.type != UpdateNodeType::RegularFile) {
        return InstallerStatus::UnexpectedNodeType;
    }
    InstallerStatus failure = InstallerStatus::FileSystemError;
    if (!VerifyFile(file.path, file.size, file.sha256, &failure)) {
        return InstallerStatus::RollbackEvidenceMissing;
    }
    return fs_->RemoveFile(file.path) && fs_->SyncContainingDirectory(file.path)
        ? InstallerStatus::Ok : InstallerStatus::FileSystemError;
}

InstallerStatus Engine::RemoveCreatedDirectories()
{
    const ManifestAsset &asset = request_.manifest->asset;
    StepLayout layout;
    if (!BuildStepLayout(asset, &layout)) return InstallerStatus::InvalidManifest;
    for (size_t reverse = asset.directory_count; reverse > 0U; --reverse) {
        const size_t index = reverse - 1U;
        const uint32_t step = layout.directory_activate_begin +
                              static_cast<uint32_t>(index);
        if (record_.completed_steps < step) continue;
        char marker_path[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat marker_stat;
        if (!MarkerPath(true, index, marker_path, sizeof(marker_path)) ||
            !fs_->Stat(marker_path, &marker_stat)) {
            return InstallerStatus::FileSystemError;
        }
        if (marker_stat.type == UpdateNodeType::Missing) {
            // completed_steps names the next operation.  At equality the
            // directory activation may not have started yet: this is the
            // durable pre-live batching boundary, and it is also the state
            // immediately after the preceding directory was journaled.
            // ActivateDirectory publishes and validates this marker before
            // it can create a missing directory, so absence proves that no
            // rollback action is required.  Once the journal has advanced
            // beyond this step, however, missing evidence remains a conflict.
            if (record_.completed_steps == step) continue;
            return InstallerStatus::JournalConflict;
        }
        if (marker_stat.type != UpdateNodeType::RegularFile) {
            return InstallerStatus::JournalConflict;
        }
        bool existed = false;
        if (!MarkerExists(true, index, &existed)) return InstallerStatus::JournalConflict;
        if (existed) continue;
        UpdateFileStat stat;
        if (!fs_->Stat(asset.directories[index].path, &stat)) {
            return InstallerStatus::FileSystemError;
        }
        if (!Progress(UpdateRecoveryProgressKind::InstallerRollbackStep,
                      asset.directory_count - reverse + 1U,
                      asset.directory_count)) {
            return InstallerStatus::RecoveryProgressFailed;
        }
        if (stat.type == UpdateNodeType::Missing) continue;
        if (stat.type != UpdateNodeType::Directory) {
            return InstallerStatus::UnexpectedNodeType;
        }
        // A non-empty directory is deliberately retained; implementations
        // report false for RemoveDirectory in that case. Do not turn that into
        // destructive traversal or deletion of unknown user files.
        fs_->RemoveDirectory(asset.directories[index].path);
        fs_->SyncContainingDirectory(asset.directories[index].path);
    }
    return InstallerStatus::Ok;
}

InstallerResult Engine::Rollback()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    if (workspace_ == 0 || workspace_->io_buffer == 0 ||
        workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes) {
        return Result(InstallerStatus::WorkspaceTooSmall);
    }
    failure = LoadJournal(false);
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (record_.state == JournalState::Idle) return Result(InstallerStatus::NothingToRollback);
    if (!IdentityMatches(record_)) return Result(InstallerStatus::JournalConflict);
    if (record_.state == JournalState::Discovered ||
        record_.state == JournalState::Downloaded) {
        JournalRecord idle = MakeIdleJournalRecord(record_.generation + 1U);
        failure = WriteTransition(idle);
        return Result(failure);
    }
    if (record_.state != JournalState::Prepared &&
        record_.state != JournalState::Staged &&
        record_.state != JournalState::CandidatePending &&
        record_.state != JournalState::CandidateHealthy &&
        record_.state != JournalState::Committing &&
        record_.state != JournalState::Committed &&
        record_.state != JournalState::RollingBack) {
        return Result(InstallerStatus::WrongState);
    }
    StepLayout rollback_layout;
    if (!BuildStepLayout(request_.manifest->asset, &rollback_layout)) {
        return Result(InstallerStatus::InvalidManifest);
    }
    // PREPARED does not advance past snapshot_begin until every private
    // snapshot and staged file is durable and the final content plan exists.
    // If creation of the initial prepared plan failed, no live path can have
    // changed and there is consequently no rollback evidence to consume.
    // RetireRolledBack() will remove any private .part files/directories.
    if (record_.state == JournalState::Prepared &&
        record_.completed_steps == rollback_layout.snapshot_begin) {
        char final_plan[kInstallerMaximumPathBytes + 1U];
        char prepared_plan[kInstallerMaximumPathBytes + 1U];
        UpdateFileStat final_stat;
        UpdateFileStat prepared_stat;
        if (!ContentPlanPath(true, final_plan, sizeof(final_plan)) ||
            !ContentPlanPath(false, prepared_plan, sizeof(prepared_plan)) ||
            !fs_->Stat(final_plan, &final_stat) ||
            !fs_->Stat(prepared_plan, &prepared_stat)) {
            return Result(InstallerStatus::FileSystemError);
        }
        if (final_stat.type == UpdateNodeType::Missing &&
            prepared_stat.type == UpdateNodeType::Missing) {
            JournalRecord rolling = record_;
            ++rolling.generation;
            rolling.state = JournalState::RollingBack;
            rolling.flags |= kJournalFlagRollbackRequested;
            failure = WriteTransition(rolling);
            if (failure != InstallerStatus::Ok) return Result(failure);
            JournalRecord idle = MakeIdleJournalRecord(record_.generation + 1U);
            failure = WriteTransition(idle);
            return Result(failure);
        }
    }
    failure = LoadContentPlan(
        record_.completed_steps >= rollback_layout.directory_activate_begin);
    if (failure != InstallerStatus::Ok) return Result(failure);
    const bool may_be_armed = record_.state == JournalState::CandidatePending ||
        record_.state == JournalState::CandidateHealthy ||
        record_.state == JournalState::Committing ||
        record_.state == JournalState::Committed ||
        (record_.flags & kJournalFlagTrybootArmed) != 0U;
    if (may_be_armed && (backend_ == 0 || !backend_->Supported())) {
        return Result(InstallerStatus::CandidateBackendUnsupported);
    }
    if (record_.state != JournalState::RollingBack) {
        JournalRecord rolling = record_;
        ++rolling.generation;
        rolling.state = JournalState::RollingBack;
        rolling.flags |= kJournalFlagRollbackRequested;
        failure = WriteTransition(rolling);
        if (failure != InstallerStatus::Ok) return Result(failure);
    }
    if (may_be_armed && !backend_->DisarmCandidate(Candidate())) {
        return Result(InstallerStatus::CandidateBackendError);
    }
    if (may_be_armed &&
        !Progress(UpdateRecoveryProgressKind::InstallerRollbackStep)) {
        return Result(InstallerStatus::RecoveryProgressFailed);
    }
    const ManifestAsset &asset = request_.manifest->asset;
    for (size_t reverse = asset.file_count; reverse > 0U; --reverse) {
        const size_t index = reverse - 1U;
        failure = RestoreFile(index, asset.files[index]);
        if (failure != InstallerStatus::Ok) return Result(failure);
        if (!Progress(UpdateRecoveryProgressKind::InstallerRollbackStep,
                      asset.file_count - reverse + 1U,
                      asset.file_count)) {
            return Result(InstallerStatus::RecoveryProgressFailed);
        }
    }
    failure = RemoveCreatedDirectories();
    if (failure != InstallerStatus::Ok) return Result(failure);
    JournalRecord idle = MakeIdleJournalRecord(record_.generation + 1U);
    failure = WriteTransition(idle);
    return Result(failure);
}

InstallerResult Engine::RetireRolledBack()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure, false)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    if (workspace_ == 0 || workspace_->io_buffer == 0 ||
        workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes) {
        return Result(InstallerStatus::WorkspaceTooSmall);
    }
    failure = LoadJournal(true);
    const bool already_without_journal =
        failure == InstallerStatus::Ok && !have_journal_;
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (have_journal_ && record_.state != JournalState::Idle) {
        return Result(InstallerStatus::WrongState);
    }
    failure = RemoveTransactionArtifacts(true);
    if (failure != InstallerStatus::Ok) return Result(failure);
    return Result(already_without_journal ? InstallerStatus::AlreadyRetired
                                         : InstallerStatus::Ok);
}

InstallerResult Engine::RetireCommitted()
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (!BasicRequestValid(false, &failure, false)) return Result(failure);
    if (!DurabilitySupported()) {
        return Result(InstallerStatus::FileSystemDurabilityUnsupported);
    }
    if (workspace_ == 0 || workspace_->io_buffer == 0 ||
        workspace_->io_buffer_size < kInstallerMinimumIoBufferBytes) {
        return Result(InstallerStatus::WorkspaceTooSmall);
    }
    failure = LoadJournal(false);
    if (failure == InstallerStatus::WrongState && !have_journal_) {
        // A reset may happen after the last journal unlink but before the
        // inert committed request is discarded. Exact artifact cleanup is
        // still idempotent and the authenticated committed-store filename is
        // the caller's capability for this narrow retry.
        failure = RemoveTransactionArtifacts(false);
        return Result(failure == InstallerStatus::Ok
                          ? InstallerStatus::AlreadyRetired : failure);
    }
    if (failure != InstallerStatus::Ok) return Result(failure);
    if (record_.state != JournalState::Committed) {
        return Result(InstallerStatus::WrongState);
    }
    if (!IdentityMatches(record_)) {
        return Result(InstallerStatus::JournalConflict);
    }
    failure = RemoveTransactionArtifacts(false);
    return Result(failure);
}

InstallerResult Engine::ReadOnlyJournal(JournalRecord *record)
{
    InstallerStatus failure = InstallerStatus::InvalidArgument;
    if (record == 0 || fs_ == 0 || request_.transaction_root == 0) {
        return Result(failure);
    }
    if (!BuildPaths(&failure)) return Result(failure);
    failure = LoadJournal(false);
    if (failure == InstallerStatus::Ok) *record = record_;
    return Result(failure);
}

}  // namespace

UpdateInstaller::UpdateInstaller(UpdateFileSystem *file_system,
                                 CandidateBackend *candidate_backend)
    : file_system_(file_system), candidate_backend_(candidate_backend)
{
}

InstallerResult UpdateInstaller::Stage(const InstallerRequest &request,
                                       const InstallerWorkspace &workspace)
{
    Engine engine(file_system_, candidate_backend_, request, &workspace);
    return engine.Stage();
}

InstallerResult UpdateInstaller::ArmCandidate(const InstallerRequest &request)
{
    Engine engine(file_system_, candidate_backend_, request, 0);
    return engine.Arm();
}

InstallerResult UpdateInstaller::MarkCandidateHealthy(const InstallerRequest &request)
{
    Engine engine(file_system_, candidate_backend_, request, 0);
    return engine.Healthy();
}

InstallerResult UpdateInstaller::Commit(const InstallerRequest &request,
                                        const InstallerWorkspace &workspace)
{
    Engine engine(file_system_, candidate_backend_, request, &workspace);
    return engine.Commit();
}

InstallerResult UpdateInstaller::Rollback(const InstallerRequest &request,
                                          const InstallerWorkspace &workspace)
{
    Engine engine(file_system_, candidate_backend_, request, &workspace);
    return engine.Rollback();
}

InstallerResult UpdateInstaller::RetireRolledBack(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    Engine engine(file_system_, candidate_backend_, request, &workspace);
    return engine.RetireRolledBack();
}

InstallerResult UpdateInstaller::RetireCommitted(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    Engine engine(file_system_, candidate_backend_, request, &workspace);
    return engine.RetireCommitted();
}

InstallerResult UpdateInstaller::ReadJournal(const char *transaction_root,
                                             JournalRecord *record)
{
    InstallerRequest request;
    memset(&request, 0, sizeof(request));
    request.transaction_root = transaction_root;
    Engine engine(file_system_, candidate_backend_, request, 0);
    return engine.ReadOnlyJournal(record);
}

bool UpdateInstaller::ComputeStepCounts(const ManifestAsset &asset,
                                        uint32_t *stage_steps,
                                        uint32_t *total_steps)
{
    StepLayout layout;
    if (stage_steps == 0 || total_steps == 0 || !BuildStepLayout(asset, &layout)) {
        return false;
    }
    *stage_steps = layout.stage_end;
    *total_steps = layout.total;
    return true;
}

const char *InstallerStatusString(InstallerStatus status)
{
    switch (status) {
    case InstallerStatus::Ok: return "ok";
    case InstallerStatus::AlreadyStaged: return "already-staged";
    case InstallerStatus::AlreadyArmed: return "already-armed";
    case InstallerStatus::AlreadyHealthy: return "already-healthy";
    case InstallerStatus::AlreadyCommitted: return "already-committed";
    case InstallerStatus::AlreadyRetired: return "already-retired";
    case InstallerStatus::NothingToRollback: return "nothing-to-rollback";
    case InstallerStatus::InvalidArgument: return "invalid-argument";
    case InstallerStatus::InvalidPath: return "invalid-path";
    case InstallerStatus::InvalidManifest: return "invalid-manifest";
    case InstallerStatus::RetentionInventoryMissing:
        return "retention-inventory-missing";
    case InstallerStatus::RetentionConflict: return "retention-conflict";
    case InstallerStatus::InvalidIdentity: return "invalid-identity";
    case InstallerStatus::WorkspaceTooSmall: return "workspace-too-small";
    case InstallerStatus::ArchiveIo: return "archive-io";
    case InstallerStatus::ArchiveHashMismatch: return "archive-hash-mismatch";
    case InstallerStatus::ArchiveInvalid: return "archive-invalid";
    case InstallerStatus::InventoryMismatch: return "inventory-mismatch";
    case InstallerStatus::StorageInsufficient: return "storage-insufficient";
    case InstallerStatus::PreparedConfigRequired: return "prepared-config-required";
    case InstallerStatus::PreparedConfigInvalid: return "prepared-config-invalid";
    case InstallerStatus::ConfigChangedSinceConsent:
        return "config-changed-since-consent";
    case InstallerStatus::FileSystemDurabilityUnsupported:
        return "filesystem-durability-unsupported";
    case InstallerStatus::FileSystemError: return "filesystem-error";
    case InstallerStatus::UnexpectedNodeType: return "unexpected-node-type";
    case InstallerStatus::KernelCollision: return "kernel-collision";
    case InstallerStatus::PreserveChanged: return "preserve-changed";
    case InstallerStatus::FileHashMismatch: return "file-hash-mismatch";
    case InstallerStatus::JournalCorrupt: return "journal-corrupt";
    case InstallerStatus::JournalConflict: return "journal-conflict";
    case InstallerStatus::JournalCodecError: return "journal-codec-error";
    case InstallerStatus::JournalTransitionDenied: return "journal-transition-denied";
    case InstallerStatus::WrongState: return "wrong-state";
    case InstallerStatus::CandidateBackendUnsupported: return "candidate-backend-unsupported";
    case InstallerStatus::CandidateBackendError: return "candidate-backend-error";
    case InstallerStatus::RollbackEvidenceMissing: return "rollback-evidence-missing";
    case InstallerStatus::RecoveryProgressFailed:
        return "recovery-progress-failed";
    default: return "unknown";
    }
}

}  // namespace update
}  // namespace bmx
