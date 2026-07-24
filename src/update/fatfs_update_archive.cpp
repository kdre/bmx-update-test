#include "update/fatfs_update_archive.h"

#include "update/fat_path_policy.h"
#include "update/github_release_parser.h"
#include "update/url_policy.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {

namespace {

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0 || size == 0U) return false;
    uint8_t aggregate = 0U;
    for (size_t index = 0U; index < size; ++index) aggregate |= bytes[index];
    return aggregate != 0U;
}

bool BoundedLength(const char *text, size_t maximum, size_t *length)
{
    if (text == 0 || length == 0) return false;
    for (size_t index = 0U; index <= maximum; ++index) {
        if (text[index] == '\0') {
            *length = index;
            return index != 0U;
        }
    }
    return false;
}

void EncodeU32(uint32_t value, uint8_t output[4U])
{
    output[0] = static_cast<uint8_t>(value >> 24U);
    output[1] = static_cast<uint8_t>(value >> 16U);
    output[2] = static_cast<uint8_t>(value >> 8U);
    output[3] = static_cast<uint8_t>(value);
}

void EncodeU64(uint64_t value, uint8_t output[8U])
{
    for (unsigned index = 0U; index < 8U; ++index) {
        output[7U - index] = static_cast<uint8_t>(value >> (index * 8U));
    }
}

bool HashU64(Sha256 *hash, uint64_t value)
{
    uint8_t encoded[8U];
    EncodeU64(value, encoded);
    return hash->Update(encoded, sizeof(encoded));
}

bool HashString(Sha256 *hash, const char *text, size_t length)
{
    if (length > UINT32_MAX) return false;
    uint8_t encoded[4U];
    EncodeU32(static_cast<uint32_t>(length), encoded);
    return hash->Update(encoded, sizeof(encoded)) &&
           hash->Update(text, length);
}

FatFsStorageStatus NormalizeVolume(const char *volume, char output[20U])
{
    if (volume == 0 || output == 0) {
        return FatFsStorageStatus::InvalidArgument;
    }
    size_t colon = 0U;
    while (colon < 16U && volume[colon] != ':' && volume[colon] != '\0') {
        const unsigned char value = static_cast<unsigned char>(volume[colon]);
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_')) {
            return FatFsStorageStatus::InvalidPath;
        }
        ++colon;
    }
    if (colon == 0U || colon > 15U || volume[colon] != ':') {
        return FatFsStorageStatus::InvalidPath;
    }
    const char *tail = volume + colon + 1U;
    if (!(tail[0] == '\0' || (tail[0] == '/' && tail[1] == '\0'))) {
        return FatFsStorageStatus::InvalidPath;
    }
    memcpy(output, volume, colon + 1U);
    output[colon + 1U] = '/';
    output[colon + 2U] = '\0';
    return ValidateFatFsAbsolutePath(output);
}

FatFsStorageStatus ValidateAndHashBinding(
    const AuthenticatedUpdateBinding &binding,
    uint8_t digest[kSha256DigestBytes])
{
    size_t url_size = 0U;
    size_t filename_size = 0U;
    size_t root_size = 0U;
    if (digest == 0 ||
        !BoundedLength(binding.archive_url, kMaximumUpdateUrlBytes - 1U,
                       &url_size) ||
        !BoundedLength(binding.archive_filename,
                       kMaximumGitHubAssetNameBytes, &filename_size) ||
        !BoundedLength(binding.transaction_root, kInstallerMaximumPathBytes,
                       &root_size) ||
        !IsKnownBoardFamily(binding.board) ||
        binding.source_release_sequence == 0U ||
        binding.target_release_sequence <= binding.source_release_sequence ||
        binding.old_boot_generation == 0U ||
        binding.new_boot_generation <= binding.old_boot_generation ||
        binding.archive_size == 0U ||
        !BytesNonZero(binding.transaction_id, kTransactionIdBytes) ||
        !BytesNonZero(binding.archive_sha256, kSha256DigestBytes) ||
        !BytesNonZero(binding.manifest_sha256, kSha256DigestBytes) ||
        !BytesNonZero(binding.consent_sha256, kSha256DigestBytes) ||
        binding.reset_required != binding.reset_approved) {
        return FatFsStorageStatus::InvalidArgument;
    }

    if (ValidateFatRelativePath(binding.transaction_root,
                                kInstallerMaximumPathBytes) !=
            FatPathValidationStatus::Ok ||
        ValidateFatRelativePath(binding.archive_filename,
                                kMaximumGitHubAssetNameBytes) !=
            FatPathValidationStatus::Ok ||
        strchr(binding.archive_filename, '/') != 0) {
        return FatFsStorageStatus::InvalidPath;
    }
    ParsedUpdateUrl parsed;
    const UrlPolicyStatus public_url = ParseAndAuthorizeUpdateUrl(
        binding.archive_url, UpdateUrlPurpose::ReleaseAsset, &parsed);
    const bool authenticated_api = public_url != UrlPolicyStatus::Ok &&
        ParseAndAuthorizeUpdateUrl(
            binding.archive_url,
            UpdateUrlPurpose::AuthenticatedReleaseAsset, &parsed) ==
            UrlPolicyStatus::Ok;
    if (public_url != UrlPolicyStatus::Ok && !authenticated_api) {
        return FatFsStorageStatus::InvalidArgument;
    }
    if (!authenticated_api) {
        const char *asset = strrchr(parsed.path_and_query, '/');
        if (asset == 0 || strcmp(asset + 1U, binding.archive_filename) != 0) {
            return FatFsStorageStatus::InvalidArgument;
        }
    }

    static const uint8_t domain[] = {
        'B', 'M', 'X', '-', 'A', 'R', 'C', 'H', 'I', 'V', 'E', '-',
        'B', 'I', 'N', 'D', 'I', 'N', 'G', '-', 'V', '1', 0U};
    Sha256 hash;
    const uint8_t board = static_cast<uint8_t>(binding.board);
    const uint8_t decisions[2U] = {
        binding.reset_required ? static_cast<uint8_t>(1U)
                               : static_cast<uint8_t>(0U),
        binding.reset_approved ? static_cast<uint8_t>(1U)
                               : static_cast<uint8_t>(0U)};
    if (!hash.Update(domain, sizeof(domain)) ||
        !HashString(&hash, binding.archive_url, url_size) ||
        !HashString(&hash, binding.archive_filename, filename_size) ||
        !HashString(&hash, binding.transaction_root, root_size) ||
        !hash.Update(&board, sizeof(board)) ||
        !HashU64(&hash, binding.source_release_sequence) ||
        !HashU64(&hash, binding.target_release_sequence) ||
        !HashU64(&hash, binding.old_boot_generation) ||
        !HashU64(&hash, binding.new_boot_generation) ||
        !HashU64(&hash, binding.archive_size) ||
        !hash.Update(binding.transaction_id, kTransactionIdBytes) ||
        !hash.Update(binding.archive_sha256, kSha256DigestBytes) ||
        !hash.Update(binding.manifest_sha256, kSha256DigestBytes) ||
        !hash.Update(binding.consent_sha256, kSha256DigestBytes) ||
        !hash.Update(decisions, sizeof(decisions)) || !hash.Final(digest)) {
        return FatFsStorageStatus::HashFailed;
    }
    return FatFsStorageStatus::Ok;
}

void HexDigest(const uint8_t digest[kSha256DigestBytes], char output[65U])
{
    static const char alphabet[] = "0123456789abcdef";
    for (size_t index = 0U; index < kSha256DigestBytes; ++index) {
        output[index * 2U] = alphabet[digest[index] >> 4U];
        output[index * 2U + 1U] = alphabet[digest[index] & 0x0fU];
    }
    output[64U] = '\0';
}

ArchiveStorageStatus MapStorageStatus(FatFsStorageStatus status)
{
    switch (status) {
    case FatFsStorageStatus::Ok:
        return ArchiveStorageStatus::Ok;
    case FatFsStorageStatus::NotFound:
        return ArchiveStorageStatus::NotFound;
    case FatFsStorageStatus::Busy:
        return ArchiveStorageStatus::Busy;
    default:
        return ArchiveStorageStatus::Failed;
    }
}

}  // namespace

FatFsStorageStatus BuildFatFsUpdateArchivePaths(
    const char *volume,
    const AuthenticatedUpdateBinding &binding,
    FatFsUpdateArchivePaths *paths)
{
    if (paths == 0) return FatFsStorageStatus::InvalidArgument;
    memset(paths, 0, sizeof(*paths));

    char volume_root[20U];
    FatFsStorageStatus status = NormalizeVolume(volume, volume_root);
    if (status != FatFsStorageStatus::Ok) return status;
    status = ValidateAndHashBinding(binding, paths->binding_sha256);
    if (status != FatFsStorageStatus::Ok) return status;

    char digest[65U];
    HexDigest(paths->binding_sha256, digest);
    char basename[96U];
    const int basename_size = snprintf(basename, sizeof(basename),
                                       "archive-%s.zip", digest);
    if (basename_size <= 0 ||
        static_cast<size_t>(basename_size) >= sizeof(basename)) {
        return FatFsStorageStatus::PathTooLong;
    }
    char part_basename[104U];
    const int part_size = snprintf(part_basename, sizeof(part_basename),
                                   "%s.part", basename);
    if (part_size <= 0 || static_cast<size_t>(part_size) >=
                              sizeof(part_basename)) {
        return FatFsStorageStatus::PathTooLong;
    }

    const int final_size = snprintf(paths->final_path,
                                    sizeof(paths->final_path), "%s%s/%s",
                                    volume_root, binding.transaction_root,
                                    basename);
    const int temporary_size = snprintf(
        paths->part_path, sizeof(paths->part_path), "%s%s/%s", volume_root,
        binding.transaction_root, part_basename);
    if (final_size <= 0 || temporary_size <= 0 ||
        static_cast<size_t>(final_size) >= sizeof(paths->final_path) ||
        static_cast<size_t>(temporary_size) >= sizeof(paths->part_path)) {
        memset(paths, 0, sizeof(*paths));
        return FatFsStorageStatus::PathTooLong;
    }
    status = ValidateFatFsAbsolutePath(paths->final_path);
    if (status == FatFsStorageStatus::Ok) {
        status = ValidateFatFsAbsolutePath(paths->part_path);
    }
    if (status != FatFsStorageStatus::Ok) {
        memset(paths, 0, sizeof(*paths));
    }
    return status;
}

FatFsUpdateArchiveStorage::FatFsUpdateArchiveStorage(const char *volume)
    : volume_(), download_(), source_(), active_paths_(),
      state_(State::Idle), configured_(false), have_active_paths_(false),
      failed_finish_may_have_final_(false),
      last_fatfs_status_(FatFsStorageStatus::InvalidArgument)
{
    last_fatfs_status_ = NormalizeVolume(volume, volume_);
    configured_ = last_fatfs_status_ == FatFsStorageStatus::Ok;
}

FatFsUpdateArchiveStorage::~FatFsUpdateArchiveStorage()
{
    if (state_ == State::Reading) (void)CloseRead();
    if (state_ == State::Writing || state_ == State::CleanupPending) Abort();
}

bool FatFsUpdateArchiveStorage::BindingMatches(
    const FatFsUpdateArchivePaths &paths) const
{
    return have_active_paths_ &&
           ConstantTimeDigestEqual(active_paths_.binding_sha256,
                                   paths.binding_sha256) &&
           strcmp(active_paths_.part_path, paths.part_path) == 0 &&
           strcmp(active_paths_.final_path, paths.final_path) == 0;
}

void FatFsUpdateArchiveStorage::Remember(
    const FatFsUpdateArchivePaths &paths)
{
    memcpy(&active_paths_, &paths, sizeof(active_paths_));
    have_active_paths_ = true;
}

void FatFsUpdateArchiveStorage::ClearRemembered()
{
    memset(&active_paths_, 0, sizeof(active_paths_));
    have_active_paths_ = false;
    failed_finish_may_have_final_ = false;
}

bool FatFsUpdateArchiveStorage::CleanupRemembered(
    bool remove_final, UpdateRecoveryProgress *recovery_progress,
    bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (!have_active_paths_) return true;
    FatFsStorageStatus part =
        FatFsRemoveFileIfPresent(active_paths_.part_path);
    if (part == FatFsStorageStatus::Ok && !ReportUpdateRecoveryProgress(
            recovery_progress,
            UpdateRecoveryProgressKind::ArchiveCleanup)) {
        if (progress_failed != 0) *progress_failed = true;
        last_fatfs_status_ = FatFsStorageStatus::RemoveFailed;
        return false;
    }
    FatFsStorageStatus final = FatFsStorageStatus::Ok;
    if (remove_final) {
        final = FatFsRemoveFileIfPresent(active_paths_.final_path);
        if (final == FatFsStorageStatus::Ok &&
            !ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::ArchiveCleanup)) {
            if (progress_failed != 0) *progress_failed = true;
            last_fatfs_status_ = FatFsStorageStatus::RemoveFailed;
            return false;
        }
    }
    last_fatfs_status_ = part != FatFsStorageStatus::Ok ? part : final;
    return part == FatFsStorageStatus::Ok &&
           final == FatFsStorageStatus::Ok;
}

ArchiveStorageStatus FatFsUpdateArchiveStorage::Begin(
    const AuthenticatedUpdateBinding &binding)
{
    if (!configured_) return ArchiveStorageStatus::Failed;
    if (state_ != State::Idle) {
        last_fatfs_status_ = FatFsStorageStatus::Busy;
        return ArchiveStorageStatus::Busy;
    }
    FatFsUpdateArchivePaths paths;
    last_fatfs_status_ =
        BuildFatFsUpdateArchivePaths(volume_, binding, &paths);
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        return MapStorageStatus(last_fatfs_status_);
    }
    last_fatfs_status_ = download_.Start(
        paths.part_path, paths.final_path, binding.archive_size,
        binding.archive_sha256);
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        return MapStorageStatus(last_fatfs_status_);
    }
    Remember(paths);
    failed_finish_may_have_final_ = false;
    state_ = State::Writing;
    return ArchiveStorageStatus::Ok;
}

bool FatFsUpdateArchiveStorage::Write(const uint8_t *data, size_t size)
{
    if (state_ != State::Writing) {
        last_fatfs_status_ = FatFsStorageStatus::NotOpen;
        return false;
    }
    const bool ok = download_.Write(data, size);
    last_fatfs_status_ = download_.last_status();
    return ok;
}

ArchiveStorageStatus FatFsUpdateArchiveStorage::Finish()
{
    if (state_ != State::Writing) {
        last_fatfs_status_ = FatFsStorageStatus::NotOpen;
        return ArchiveStorageStatus::Failed;
    }
    // A failed Finish may have crossed the part->final rename before its
    // readback failed. Abort is therefore allowed to remove this exact final
    // object, but never a successfully completed archive.
    failed_finish_may_have_final_ = true;
    last_fatfs_status_ = download_.Finish();
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        state_ = State::CleanupPending;
        return MapStorageStatus(last_fatfs_status_);
    }
    failed_finish_may_have_final_ = false;
    state_ = State::Completed;
    return ArchiveStorageStatus::Ok;
}

void FatFsUpdateArchiveStorage::Abort()
{
    if (state_ != State::Writing && state_ != State::CleanupPending) return;
    download_.Abort(false);
    const bool remove_final = failed_finish_may_have_final_;
    if (CleanupRemembered(remove_final)) {
        state_ = State::Idle;
        ClearRemembered();
    } else {
        state_ = State::CleanupPending;
    }
}

ArchiveStorageStatus FatFsUpdateArchiveStorage::OpenRead(
    const AuthenticatedUpdateBinding &binding,
    SeekableZipSource **source)
{
    if (source == 0 || !configured_) return ArchiveStorageStatus::Failed;
    *source = 0;
    if (state_ == State::Writing || state_ == State::Reading ||
        state_ == State::CleanupPending) {
        last_fatfs_status_ = FatFsStorageStatus::Busy;
        return ArchiveStorageStatus::Busy;
    }
    FatFsUpdateArchivePaths paths;
    last_fatfs_status_ =
        BuildFatFsUpdateArchivePaths(volume_, binding, &paths);
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        return MapStorageStatus(last_fatfs_status_);
    }
    if (state_ == State::Completed && !BindingMatches(paths)) {
        last_fatfs_status_ = FatFsStorageStatus::InvalidArgument;
        return ArchiveStorageStatus::Failed;
    }
    last_fatfs_status_ = source_.Open(paths.final_path);
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        return MapStorageStatus(last_fatfs_status_);
    }
    Remember(paths);
    state_ = State::Reading;
    *source = &source_;
    return ArchiveStorageStatus::Ok;
}

ArchiveStorageStatus FatFsUpdateArchiveStorage::CloseRead()
{
    if (state_ == State::Writing || state_ == State::CleanupPending) {
        last_fatfs_status_ = FatFsStorageStatus::Busy;
        return ArchiveStorageStatus::Busy;
    }
    if (state_ != State::Reading) return ArchiveStorageStatus::Ok;
    last_fatfs_status_ = source_.Close();
    state_ = State::Completed;
    return MapStorageStatus(last_fatfs_status_);
}

ArchiveStorageStatus FatFsUpdateArchiveStorage::Discard(
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress)
{
    if (!configured_) return ArchiveStorageStatus::Failed;
    if (state_ == State::Writing || state_ == State::Reading) {
        last_fatfs_status_ = FatFsStorageStatus::Busy;
        return ArchiveStorageStatus::Busy;
    }
    FatFsUpdateArchivePaths paths;
    last_fatfs_status_ =
        BuildFatFsUpdateArchivePaths(volume_, binding, &paths);
    if (last_fatfs_status_ != FatFsStorageStatus::Ok) {
        return MapStorageStatus(last_fatfs_status_);
    }
    if (have_active_paths_ && !BindingMatches(paths)) {
        last_fatfs_status_ = FatFsStorageStatus::InvalidArgument;
        return ArchiveStorageStatus::Failed;
    }
    if (!have_active_paths_) Remember(paths);
    download_.Abort(false);
    bool progress_failed = false;
    if (!CleanupRemembered(true, recovery_progress, &progress_failed)) {
        state_ = State::CleanupPending;
        failed_finish_may_have_final_ = true;
        return progress_failed
            ? ArchiveStorageStatus::RecoveryProgressFailed
            : ArchiveStorageStatus::Failed;
    }
    state_ = State::Idle;
    ClearRemembered();
    return ArchiveStorageStatus::Ok;
}

}  // namespace update
}  // namespace bmx
