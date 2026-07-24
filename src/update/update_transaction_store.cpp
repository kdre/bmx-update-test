#include "update/update_transaction_store.h"

#include "update/crc32.h"
#include "update/fat_path_policy.h"
#include "update/sha256.h"
#include "update/update_fault_injection.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {

const char kUpdateTransactionRoot[] = ".bmx-update/transaction";
const char kUpdateTransactionActivationPath[] =
    ".bmx-update/transaction/request-state.bin";
const char kUpdateTransactionCommittedPath[] =
    ".bmx-update/transaction/committed-state.bin";
const char kUpdateTransactionRetiringPath[] =
    ".bmx-update/transaction/retiring-state.bin";

namespace {

static const uint8_t kStateMagic[8U] = {
    'B', 'M', 'X', 'R', 'E', 'Q', '1', 0U
};
static const uint32_t kStateVersion = 1U;
static const size_t kStateCrcOffset = kPersistedUpdateRequestStateBytes - 4U;
static const char *const kPayloadNames[4U] = {
    "request-installed.bin", "request-github.bin",
    "request-manifest.bin", "request-signature.bin"
};
static const char kStateName[] = "request-state.bin";
static const char kCommittedStateName[] = "committed-state.bin";
static const char kRetiringStateName[] = "retiring-state.bin";

enum StateOffset {
    kMagicOffset = 0U,
    kVersionOffset = 8U,
    kBoardOffset = 12U,
    kInstalledSizeOffset = 16U,
    kGitHubSizeOffset = 20U,
    kManifestSizeOffset = 24U,
    kSignatureSizeOffset = 28U,
    kOldGenerationOffset = 32U,
    kNewGenerationOffset = 40U,
    kTransactionIdOffset = 48U,
    kConsentOffset = 64U,
    kResetRequiredOffset = 96U,
    kResetApprovedOffset = 97U,
    kAcquisitionModeOffset = 98U,
    kInstalledHashOffset = 112U,
    kGitHubHashOffset = 144U,
    kManifestHashOffset = 176U,
    kSignatureHashOffset = 208U,
    kRootHashOffset = 240U
};

bool NonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t value = 0U;
    for (size_t index = 0U; index < size; ++index) value |= bytes[index];
    return value != 0U;
}

void WriteU32(uint8_t *output, uint32_t value)
{
    output[0] = static_cast<uint8_t>(value >> 24U);
    output[1] = static_cast<uint8_t>(value >> 16U);
    output[2] = static_cast<uint8_t>(value >> 8U);
    output[3] = static_cast<uint8_t>(value);
}

uint32_t ReadU32(const uint8_t *input)
{
    return static_cast<uint32_t>(input[0]) << 24U |
           static_cast<uint32_t>(input[1]) << 16U |
           static_cast<uint32_t>(input[2]) << 8U |
           static_cast<uint32_t>(input[3]);
}

void WriteU64(uint8_t *output, uint64_t value)
{
    for (unsigned index = 0U; index < 8U; ++index) {
        output[7U - index] = static_cast<uint8_t>(value >> (index * 8U));
    }
}

uint64_t ReadU64(const uint8_t *input)
{
    uint64_t value = 0U;
    for (unsigned index = 0U; index < 8U; ++index) {
        value = value << 8U | input[index];
    }
    return value;
}

bool BoundedRoot(const char *root)
{
    if (root == 0) return false;
    size_t size = 0U;
    while (size <= kInstallerMaximumPathBytes && root[size] != '\0') ++size;
    return size != 0U && size <= kInstallerMaximumPathBytes &&
           ValidateFatRelativePath(root, kInstallerMaximumPathBytes) ==
               FatPathValidationStatus::Ok;
}

bool Join(const char *root, const char *name, char *output, size_t capacity)
{
    if (!BoundedRoot(root) || name == 0 || output == 0 || capacity == 0U) {
        return false;
    }
    const int written = snprintf(output, capacity, "%s/%s", root, name);
    return written > 0 && static_cast<size_t>(written) < capacity &&
           ValidateFatRelativePath(output, capacity - 1U) ==
               FatPathValidationStatus::Ok;
}

UpdateTransactionStoreStatus DeactivateAtRoot(UpdateFileSystem *file_system,
                                               const char *transaction_root,
                                               UpdateRecoveryProgress *progress)
{
    if (file_system == 0 || !BoundedRoot(transaction_root)) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    char path[kInstallerMaximumPathBytes + 1U];
    if (!Join(transaction_root, kStateName, path, sizeof(path)) ||
        !file_system->RemoveFile(path) ||
        !file_system->SyncContainingDirectory(path)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (!ReportUpdateRecoveryProgress(
            progress, UpdateRecoveryProgressKind::TransactionCleanup)) {
        return UpdateTransactionStoreStatus::RecoveryProgressFailed;
    }
    return UpdateTransactionStoreStatus::Ok;
}

bool HashRoot(const char *root, uint8_t digest[kSha256DigestBytes])
{
    static const uint8_t domain[] = {
        'B', 'M', 'X', '-', 'R', 'E', 'Q', '-', 'R', 'O', 'O', 'T', '-',
        'V', '1', 0U
    };
    if (!BoundedRoot(root)) return false;
    Sha256 hash;
    const size_t size = strlen(root);
    uint8_t encoded[4U];
    WriteU32(encoded, static_cast<uint32_t>(size));
    return hash.Update(domain, sizeof(domain)) &&
           hash.Update(encoded, sizeof(encoded)) &&
           hash.Update(root, size) && hash.Final(digest);
}

bool RequestValid(const AuthenticatedUpdateRequest &request)
{
    if (request.release == 0 || !IsKnownBoardFamily(request.running_board) ||
        !BoundedRoot(request.transaction_root) ||
        !NonZero(request.transaction_id, kTransactionIdBytes) ||
        request.old_boot_generation == 0U ||
        request.new_boot_generation <= request.old_boot_generation ||
        !NonZero(request.consent_sha256, kSha256DigestBytes) ||
        request.reset_required != request.reset_approved) return false;
    const ValidatedReleaseDownload &release = *request.release;
    return (release.acquisition_mode ==
                ReleaseAcquisitionMode::PublishedStable ||
            release.acquisition_mode ==
                ReleaseAcquisitionMode::PreparedDraft) &&
           release.installed_build_info.data != 0 &&
           release.installed_build_info.size != 0U &&
           release.installed_build_info.size <= kMaximumBuildInfoBytes &&
           release.github_response.data != 0 &&
           release.github_response.size != 0U &&
           release.github_response.size <= kMaximumGitHubReleaseResponseBytes &&
           release.manifest.data != 0 && release.manifest.size != 0U &&
           release.manifest.size <= kMaximumReleaseManifestBytes &&
           release.signature.data != 0 && release.signature.size != 0U &&
           release.signature.size <= kMaximumSignatureEnvelopeBytes;
}

bool EnsureParents(UpdateFileSystem *file_system, const char *path)
{
    if (file_system == 0 || path == 0 ||
        strlen(path) > kInstallerMaximumPathBytes) return false;
    char partial[kInstallerMaximumPathBytes + 1U];
    memcpy(partial, path, strlen(path) + 1U);
    for (size_t index = 0U; partial[index] != '\0'; ++index) {
        if (partial[index] != '/') continue;
        partial[index] = '\0';
        const bool ok = partial[0] != '\0' &&
            file_system->CreateDirectory(partial) &&
            file_system->SyncContainingDirectory(partial);
        partial[index] = '/';
        if (!ok) return false;
    }
    return true;
}

bool ReadFile(UpdateFileSystem *file_system, const char *path,
              uint8_t *output, size_t expected_size,
              UpdateRecoveryProgress *progress, bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0 || path == 0 || output == 0 || expected_size == 0U) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size) return false;
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    const bool read = file->ReadAt(0U, output, expected_size);
    const bool reported = read && ReportUpdateRecoveryProgress(
        progress, UpdateRecoveryProgressKind::TransactionStateRead,
        expected_size, expected_size);
    if (read && !reported && progress_failed != 0) *progress_failed = true;
    const bool closed = file->Close();
    return read && reported && closed;
}

UpdateTransactionStoreStatus VerifyFile(
    UpdateFileSystem *file_system, const char *path, uint64_t expected_size,
    const uint8_t expected_hash[kSha256DigestBytes], uint8_t *scratch,
    size_t scratch_size)
{
    if (file_system == 0 || path == 0 || expected_size == 0U ||
        expected_hash == 0 || scratch == 0 || scratch_size == 0U) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (stat.type == UpdateNodeType::Missing) {
        return UpdateTransactionStoreStatus::NotFound;
    }
    if (stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size) return UpdateTransactionStoreStatus::Conflict;
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < expected_size) {
        const uint64_t remaining = expected_size - offset;
        const size_t amount = remaining < scratch_size
            ? static_cast<size_t>(remaining) : scratch_size;
        if (!file->ReadAt(offset, scratch, amount) ||
            !hash.Update(scratch, amount)) {
            ok = false;
            break;
        }
        offset += amount;
    }
    const bool closed = file->Close();
    uint8_t actual[kSha256DigestBytes];
    if (!ok || !closed || !hash.Final(actual)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    return ConstantTimeDigestEqual(actual, expected_hash)
        ? UpdateTransactionStoreStatus::Ok
        : UpdateTransactionStoreStatus::HashMismatch;
}

UpdateTransactionStoreStatus ReadVerifiedFile(
    UpdateFileSystem *file_system, const char *path, uint64_t expected_size,
    const uint8_t expected_hash[kSha256DigestBytes], uint8_t *output,
    size_t output_capacity, UpdateRecoveryProgress *progress)
{
    if (file_system == 0 || path == 0 || expected_size == 0U ||
        expected_size > output_capacity || expected_hash == 0 || output == 0) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (stat.type == UpdateNodeType::Missing) {
        return UpdateTransactionStoreStatus::NotFound;
    }
    if (stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size) return UpdateTransactionStoreStatus::Conflict;
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    bool progress_failed = false;
    while (offset < expected_size) {
        const uint64_t remaining = expected_size - offset;
        const size_t amount = remaining < 4096U
            ? static_cast<size_t>(remaining) : 4096U;
        uint8_t *destination = output + static_cast<size_t>(offset);
        if (!file->ReadAt(offset, destination, amount) ||
            !hash.Update(destination, amount)) {
            ok = false;
            break;
        }
        offset += amount;
        if (!ReportUpdateRecoveryProgress(
                progress,
                UpdateRecoveryProgressKind::TransactionPayloadRead,
                offset, expected_size)) {
            progress_failed = true;
            ok = false;
            break;
        }
    }
    const bool closed = file->Close();
    uint8_t actual[kSha256DigestBytes];
    if (!ok || !closed || !hash.Final(actual)) {
        memset(output, 0, static_cast<size_t>(expected_size));
        return progress_failed
            ? UpdateTransactionStoreStatus::RecoveryProgressFailed
            : UpdateTransactionStoreStatus::FileSystemError;
    }
    if (!ConstantTimeDigestEqual(actual, expected_hash)) {
        memset(output, 0, static_cast<size_t>(expected_size));
        return UpdateTransactionStoreStatus::HashMismatch;
    }
    return UpdateTransactionStoreStatus::Ok;
}

UpdateTransactionStoreStatus WriteFreshVerified(
    UpdateFileSystem *file_system, const char *path, ByteView content,
    const uint8_t expected_hash[kSha256DigestBytes], uint8_t *scratch,
    size_t scratch_size)
{
    UpdateTransactionStoreStatus existing = VerifyFile(
        file_system, path, content.size, expected_hash, scratch, scratch_size);
    if (existing == UpdateTransactionStoreStatus::Ok) {
        // A previous fresh rename may have reached the namespace while its
        // directory barrier failed. Repeating the barrier is required before
        // an idempotent retry may promote that file to durable state.
        return file_system->SyncContainingDirectory(path)
            ? UpdateTransactionStoreStatus::Ok
            : UpdateTransactionStoreStatus::FileSystemError;
    }
    if (existing != UpdateTransactionStoreStatus::NotFound) {
        return existing == UpdateTransactionStoreStatus::HashMismatch
            ? UpdateTransactionStoreStatus::Conflict : existing;
    }
    char temporary[kInstallerMaximumPathBytes + 1U];
    const int written = snprintf(temporary, sizeof(temporary), "%s.part", path);
    if (written <= 0 || static_cast<size_t>(written) >= sizeof(temporary) ||
        !EnsureParents(file_system, path) ||
        !file_system->RemoveFile(temporary)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    UpdateWriteFile *file = 0;
    if (!file_system->CreateFileFresh(temporary, &file) || file == 0) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    const bool wrote = file->Write(content);
    const bool synced = wrote && file->Sync();
    const bool closed = file->Close();
    if (!wrote || !synced || !closed ||
        !file_system->Rename(temporary, path, false) ||
        !file_system->SyncContainingDirectory(path)) {
        file_system->RemoveFile(temporary);
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    return VerifyFile(file_system, path, content.size, expected_hash, scratch,
                      scratch_size);
}

bool DurabilitySupported(UpdateFileSystem *file_system)
{
    UpdateDurabilityCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    return file_system != 0 &&
           file_system->GetDurabilityCapabilities(&capabilities) &&
           capabilities.durable_file_sync &&
           (capabilities.crash_safe_fresh_rename ||
            capabilities.power_loss_recovery_validated) &&
           capabilities.durable_directory_updates;
}

}  // namespace

UpdateTransactionRequestStore::UpdateTransactionRequestStore(
    UpdateFileSystem *file_system)
    : file_system_(file_system), io_buffer_()
{
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::Save(
    const AuthenticatedUpdateRequest &request)
{
    if (file_system_ == 0 || !RequestValid(request)) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    if (!DurabilitySupported(file_system_)) {
        return UpdateTransactionStoreStatus::DurabilityUnsupported;
    }
    char committed_path[kInstallerMaximumPathBytes + 1U];
    char retiring_path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat committed_stat;
    UpdateFileStat retiring_stat;
    if (!Join(request.transaction_root, kCommittedStateName, committed_path,
              sizeof(committed_path)) ||
        !Join(request.transaction_root, kRetiringStateName, retiring_path,
              sizeof(retiring_path)) ||
        !file_system_->Stat(committed_path, &committed_stat) ||
        !file_system_->Stat(retiring_path, &retiring_stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (committed_stat.type != UpdateNodeType::Missing ||
        retiring_stat.type != UpdateNodeType::Missing) {
        return (committed_stat.type == UpdateNodeType::RegularFile ||
                retiring_stat.type == UpdateNodeType::RegularFile)
            ? UpdateTransactionStoreStatus::Conflict
            : UpdateTransactionStoreStatus::FileSystemError;
    }
    const ValidatedReleaseDownload &release = *request.release;
    const ByteView payloads[4U] = {
        release.installed_build_info, release.github_response,
        release.manifest, release.signature
    };
    uint8_t hashes[4U][kSha256DigestBytes];
    for (size_t index = 0U; index < 4U; ++index) {
        if (payloads[index].size > UINT32_MAX ||
            !Sha256Digest(payloads[index], hashes[index])) {
            return UpdateTransactionStoreStatus::InvalidArgument;
        }
    }
    uint8_t root_hash[kSha256DigestBytes];
    if (!HashRoot(request.transaction_root, root_hash)) {
        return UpdateTransactionStoreStatus::InvalidIdentity;
    }

    uint8_t state[kPersistedUpdateRequestStateBytes];
    memset(state, 0, sizeof(state));
    memcpy(state + kMagicOffset, kStateMagic, sizeof(kStateMagic));
    WriteU32(state + kVersionOffset, kStateVersion);
    WriteU32(state + kBoardOffset,
             static_cast<uint32_t>(request.running_board));
    WriteU32(state + kInstalledSizeOffset,
             static_cast<uint32_t>(payloads[0].size));
    WriteU32(state + kGitHubSizeOffset,
             static_cast<uint32_t>(payloads[1].size));
    WriteU32(state + kManifestSizeOffset,
             static_cast<uint32_t>(payloads[2].size));
    WriteU32(state + kSignatureSizeOffset,
             static_cast<uint32_t>(payloads[3].size));
    WriteU64(state + kOldGenerationOffset, request.old_boot_generation);
    WriteU64(state + kNewGenerationOffset, request.new_boot_generation);
    memcpy(state + kTransactionIdOffset, request.transaction_id,
           kTransactionIdBytes);
    memcpy(state + kConsentOffset, request.consent_sha256,
           kSha256DigestBytes);
    state[kResetRequiredOffset] = request.reset_required ? 1U : 0U;
    state[kResetApprovedOffset] = request.reset_approved ? 1U : 0U;
    state[kAcquisitionModeOffset] =
        static_cast<uint8_t>(release.acquisition_mode);
    memcpy(state + kInstalledHashOffset, hashes[0], kSha256DigestBytes);
    memcpy(state + kGitHubHashOffset, hashes[1], kSha256DigestBytes);
    memcpy(state + kManifestHashOffset, hashes[2], kSha256DigestBytes);
    memcpy(state + kSignatureHashOffset, hashes[3], kSha256DigestBytes);
    memcpy(state + kRootHashOffset, root_hash, kSha256DigestBytes);
    WriteU32(state + kStateCrcOffset,
             CalculateCrc32(ByteView(state, kStateCrcOffset)));

    char path[kInstallerMaximumPathBytes + 1U];
    for (size_t index = 0U; index < 4U; ++index) {
        if (!Join(request.transaction_root, kPayloadNames[index], path,
                  sizeof(path))) {
            return UpdateTransactionStoreStatus::InvalidIdentity;
        }
        const UpdateTransactionStoreStatus saved = WriteFreshVerified(
            file_system_, path, payloads[index], hashes[index], io_buffer_,
            sizeof(io_buffer_));
        if (saved != UpdateTransactionStoreStatus::Ok) return saved;
    }
    if (!Join(request.transaction_root, kStateName, path, sizeof(path))) {
        return UpdateTransactionStoreStatus::InvalidIdentity;
    }
    uint8_t state_hash[kSha256DigestBytes];
    if (!Sha256Digest(ByteView(state, sizeof(state)), state_hash)) {
        return UpdateTransactionStoreStatus::Corrupt;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::RequestBeforeActivationStatePublish);
    const UpdateTransactionStoreStatus published = WriteFreshVerified(
        file_system_, path, ByteView(state, sizeof(state)), state_hash,
        io_buffer_, sizeof(io_buffer_));
    if (published == UpdateTransactionStoreStatus::Ok) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::RequestAfterActivationStatePublish);
    }
    return published;
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::LoadNamed(
    const char *transaction_root, const char *state_name,
    BoardFamily expected_board,
    const PersistedUpdateRequestBuffers &buffers,
    ValidatedReleaseDownload *release,
    AuthenticatedUpdateRequest *request,
    UpdateRecoveryProgress *recovery_progress)
{
    if (file_system_ == 0 || !BoundedRoot(transaction_root) ||
        (state_name != kStateName && state_name != kCommittedStateName) ||
        !IsKnownBoardFamily(expected_board) || release == 0 || request == 0 ||
        buffers.installed_build_info == 0 || buffers.github_response == 0 ||
        buffers.manifest == 0 || buffers.signature == 0) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    *release = ValidatedReleaseDownload();
    *request = AuthenticatedUpdateRequest();
    char path[kInstallerMaximumPathBytes + 1U];
    if (!Join(transaction_root, state_name, path, sizeof(path))) {
        return UpdateTransactionStoreStatus::InvalidIdentity;
    }
    UpdateFileStat state_stat;
    if (!file_system_->Stat(path, &state_stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (state_stat.type == UpdateNodeType::Missing) {
        return UpdateTransactionStoreStatus::NotFound;
    }
    uint8_t state[kPersistedUpdateRequestStateBytes];
    bool progress_failed = false;
    if (state_stat.type != UpdateNodeType::RegularFile ||
        state_stat.size != sizeof(state) ||
        !ReadFile(file_system_, path, state, sizeof(state), recovery_progress,
                  &progress_failed)) {
        return progress_failed
            ? UpdateTransactionStoreStatus::RecoveryProgressFailed
            : UpdateTransactionStoreStatus::Corrupt;
    }
    uint8_t reserved = 0U;
    for (size_t index = 99U; index < kInstalledHashOffset; ++index) {
        reserved |= state[index];
    }
    for (size_t index = kRootHashOffset + kSha256DigestBytes;
         index < kStateCrcOffset; ++index) reserved |= state[index];
    if (memcmp(state + kMagicOffset, kStateMagic, sizeof(kStateMagic)) != 0 ||
        ReadU32(state + kVersionOffset) != kStateVersion ||
        ReadU32(state + kBoardOffset) !=
            static_cast<uint32_t>(expected_board) || reserved != 0U ||
        state[kResetRequiredOffset] > 1U ||
        state[kResetApprovedOffset] > 1U ||
        state[kAcquisitionModeOffset] >
            static_cast<uint8_t>(ReleaseAcquisitionMode::PreparedDraft) ||
        state[kResetRequiredOffset] != state[kResetApprovedOffset] ||
        ReadU32(state + kStateCrcOffset) !=
            CalculateCrc32(ByteView(state, kStateCrcOffset))) {
        return UpdateTransactionStoreStatus::Corrupt;
    }
    uint8_t root_hash[kSha256DigestBytes];
    if (!HashRoot(transaction_root, root_hash) ||
        !ConstantTimeDigestEqual(root_hash, state + kRootHashOffset)) {
        return UpdateTransactionStoreStatus::InvalidIdentity;
    }
    const uint32_t sizes[4U] = {
        ReadU32(state + kInstalledSizeOffset),
        ReadU32(state + kGitHubSizeOffset),
        ReadU32(state + kManifestSizeOffset),
        ReadU32(state + kSignatureSizeOffset)
    };
    const size_t capacities[4U] = {
        buffers.installed_build_info_capacity,
        buffers.github_response_capacity,
        buffers.manifest_capacity,
        buffers.signature_capacity
    };
    uint8_t *outputs[4U] = {
        buffers.installed_build_info, buffers.github_response,
        buffers.manifest, buffers.signature
    };
    const size_t maximums[4U] = {
        kMaximumBuildInfoBytes, kMaximumGitHubReleaseResponseBytes,
        kMaximumReleaseManifestBytes, kMaximumSignatureEnvelopeBytes
    };
    const size_t hash_offsets[4U] = {
        kInstalledHashOffset, kGitHubHashOffset,
        kManifestHashOffset, kSignatureHashOffset
    };
    for (size_t index = 0U; index < 4U; ++index) {
        if (sizes[index] == 0U || sizes[index] > maximums[index] ||
            sizes[index] > capacities[index]) {
            return sizes[index] > capacities[index]
                ? UpdateTransactionStoreStatus::WorkspaceTooSmall
                : UpdateTransactionStoreStatus::Corrupt;
        }
        if (!Join(transaction_root, kPayloadNames[index], path, sizeof(path))) {
            return UpdateTransactionStoreStatus::InvalidIdentity;
        }
        const UpdateTransactionStoreStatus verified = ReadVerifiedFile(
            file_system_, path, sizes[index], state + hash_offsets[index],
            outputs[index], capacities[index], recovery_progress);
        if (verified != UpdateTransactionStoreStatus::Ok) return verified;
    }
    const uint64_t old_generation = ReadU64(state + kOldGenerationOffset);
    const uint64_t new_generation = ReadU64(state + kNewGenerationOffset);
    if (old_generation == 0U || new_generation <= old_generation ||
        !NonZero(state + kTransactionIdOffset, kTransactionIdBytes) ||
        !NonZero(state + kConsentOffset, kSha256DigestBytes)) {
        return UpdateTransactionStoreStatus::InvalidIdentity;
    }
    release->installed_build_info = ByteView(outputs[0], sizes[0]);
    release->acquisition_mode = static_cast<ReleaseAcquisitionMode>(
        state[kAcquisitionModeOffset]);
    release->github_response = ByteView(outputs[1], sizes[1]);
    release->manifest = ByteView(outputs[2], sizes[2]);
    release->signature = ByteView(outputs[3], sizes[3]);
    request->release = release;
    request->running_board = expected_board;
    request->transaction_root = transaction_root;
    memcpy(request->transaction_id, state + kTransactionIdOffset,
           kTransactionIdBytes);
    request->old_boot_generation = old_generation;
    request->new_boot_generation = new_generation;
    memcpy(request->consent_sha256, state + kConsentOffset,
           kSha256DigestBytes);
    request->reset_required = state[kResetRequiredOffset] != 0U;
    request->reset_approved = state[kResetApprovedOffset] != 0U;
    request->foreground_authorization_token = 0U;
    return UpdateTransactionStoreStatus::Ok;
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::Load(
    const char *transaction_root, BoardFamily expected_board,
    const PersistedUpdateRequestBuffers &buffers,
    ValidatedReleaseDownload *release,
    AuthenticatedUpdateRequest *request,
    UpdateRecoveryProgress *recovery_progress)
{
    return LoadNamed(transaction_root, kStateName, expected_board, buffers,
                     release, request, recovery_progress);
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::LoadCommitted(
    const char *transaction_root, BoardFamily expected_board,
    const PersistedUpdateRequestBuffers &buffers,
    ValidatedReleaseDownload *release,
    AuthenticatedUpdateRequest *request,
    UpdateRecoveryProgress *recovery_progress)
{
    return LoadNamed(transaction_root, kCommittedStateName, expected_board,
                     buffers, release, request, recovery_progress);
}

bool UpdateTransactionRequestStore::HasCommitted(
    const char *transaction_root) const
{
    if (file_system_ == 0 || !BoundedRoot(transaction_root)) return false;
    char path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat stat;
    return Join(transaction_root, kCommittedStateName, path, sizeof(path)) &&
           file_system_->Stat(path, &stat) &&
           stat.type == UpdateNodeType::RegularFile &&
           stat.size == kPersistedUpdateRequestStateBytes;
}

bool UpdateTransactionRequestStore::HasRetiringCommitted(
    const char *transaction_root) const
{
    if (file_system_ == 0 || !BoundedRoot(transaction_root)) return false;
    char path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat stat;
    return Join(transaction_root, kRetiringStateName, path, sizeof(path)) &&
           file_system_->Stat(path, &stat) &&
           stat.type == UpdateNodeType::RegularFile &&
           stat.size == kPersistedUpdateRequestStateBytes;
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::DiscardNamed(
    const char *transaction_root,
    const char *state_name,
    UpdateRecoveryProgress *recovery_progress)
{
    if (file_system_ == 0 || !BoundedRoot(transaction_root) ||
        (state_name != kStateName && state_name != kCommittedStateName)) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    const char *other_state_name = state_name == kStateName
        ? kCommittedStateName : kStateName;
    char other_state_path[kInstallerMaximumPathBytes + 1U];
    char retiring_state_path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat other_state_stat;
    UpdateFileStat retiring_state_stat;
    if (!Join(transaction_root, other_state_name, other_state_path,
              sizeof(other_state_path)) ||
        !Join(transaction_root, kRetiringStateName, retiring_state_path,
              sizeof(retiring_state_path)) ||
        !file_system_->Stat(other_state_path, &other_state_stat) ||
        !file_system_->Stat(retiring_state_path, &retiring_state_stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    // Never strand a still-authoritative state record while deleting its
    // shared authentication payloads. Both state names at once are corrupt;
    // the caller must not guess which transaction owns the bytes.
    if (other_state_stat.type != UpdateNodeType::Missing ||
        retiring_state_stat.type != UpdateNodeType::Missing) {
        return UpdateTransactionStoreStatus::Conflict;
    }
    char state_path[kInstallerMaximumPathBytes + 1U];
    if (!Join(transaction_root, state_name, state_path, sizeof(state_path)) ||
        !file_system_->RemoveFile(state_path) ||
        !file_system_->SyncContainingDirectory(state_path)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (!ReportUpdateRecoveryProgress(
            recovery_progress,
            UpdateRecoveryProgressKind::TransactionCleanup)) {
        return UpdateTransactionStoreStatus::RecoveryProgressFailed;
    }
    char path[kInstallerMaximumPathBytes + 1U];
    for (size_t index = 0U; index < 4U; ++index) {
        if (!Join(transaction_root, kPayloadNames[index], path, sizeof(path)) ||
            !file_system_->RemoveFile(path) ||
            !file_system_->SyncContainingDirectory(path)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
        if (!ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::TransactionCleanup)) {
            return UpdateTransactionStoreStatus::RecoveryProgressFailed;
        }
        char temporary[kInstallerMaximumPathBytes + 1U];
        const int written = snprintf(temporary, sizeof(temporary), "%s.part", path);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(temporary) ||
            !file_system_->RemoveFile(temporary) ||
            !file_system_->SyncContainingDirectory(temporary)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
        if (!ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::TransactionCleanup)) {
            return UpdateTransactionStoreStatus::RecoveryProgressFailed;
        }
    }
    return UpdateTransactionStoreStatus::Ok;
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::Discard(
    const char *transaction_root,
    UpdateRecoveryProgress *recovery_progress)
{
    return DiscardNamed(transaction_root, kStateName, recovery_progress);
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::DiscardCommitted(
    const char *transaction_root,
    UpdateRecoveryProgress *recovery_progress)
{
    if (file_system_ == 0 || !BoundedRoot(transaction_root)) {
        return UpdateTransactionStoreStatus::InvalidArgument;
    }
    char active_path[kInstallerMaximumPathBytes + 1U];
    char committed_path[kInstallerMaximumPathBytes + 1U];
    char retiring_path[kInstallerMaximumPathBytes + 1U];
    UpdateFileStat active_stat;
    UpdateFileStat committed_stat;
    UpdateFileStat retiring_stat;
    if (!Join(transaction_root, kStateName, active_path,
              sizeof(active_path)) ||
        !Join(transaction_root, kCommittedStateName, committed_path,
              sizeof(committed_path)) ||
        !Join(transaction_root, kRetiringStateName, retiring_path,
              sizeof(retiring_path)) ||
        !file_system_->Stat(active_path, &active_stat) ||
        !file_system_->Stat(committed_path, &committed_stat) ||
        !file_system_->Stat(retiring_path, &retiring_stat)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    if (active_stat.type != UpdateNodeType::Missing) {
        return UpdateTransactionStoreStatus::Conflict;
    }

    if (committed_stat.type == UpdateNodeType::RegularFile &&
        committed_stat.size == kPersistedUpdateRequestStateBytes &&
        retiring_stat.type == UpdateNodeType::Missing) {
        // The fixed inert rename is the durable hand-off from authenticated
        // installer retirement to fixed-name raw-payload finalization. After
        // it, a reset never needs the already-retired manifest again.
        if (!file_system_->Rename(committed_path, retiring_path, false) ||
            !file_system_->SyncContainingDirectory(retiring_path)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
        if (!ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::TransactionCleanup)) {
            return UpdateTransactionStoreStatus::RecoveryProgressFailed;
        }
    } else if (committed_stat.type == UpdateNodeType::Missing &&
               retiring_stat.type == UpdateNodeType::RegularFile &&
               retiring_stat.size == kPersistedUpdateRequestStateBytes) {
        // Retry the namespace barrier before trusting a marker left by an
        // interrupted rename.
        if (!file_system_->SyncContainingDirectory(retiring_path)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
    } else if (committed_stat.type == UpdateNodeType::Missing &&
               retiring_stat.type == UpdateNodeType::Missing) {
        // A fully completed cleanup is idempotent, but never classify stray
        // shared payloads as retired without the fixed marker.
        char fixed[kInstallerMaximumPathBytes + 1U];
        for (size_t index = 0U; index < 4U; ++index) {
            UpdateFileStat payload_stat;
            if (!Join(transaction_root, kPayloadNames[index], fixed,
                      sizeof(fixed)) ||
                !file_system_->Stat(fixed, &payload_stat) ||
                payload_stat.type != UpdateNodeType::Missing) {
                return UpdateTransactionStoreStatus::Conflict;
            }
            char temporary[kInstallerMaximumPathBytes + 1U];
            const int written = snprintf(temporary, sizeof(temporary),
                                         "%s.part", fixed);
            UpdateFileStat temporary_stat;
            if (written <= 0 ||
                static_cast<size_t>(written) >= sizeof(temporary) ||
                !file_system_->Stat(temporary, &temporary_stat) ||
                temporary_stat.type != UpdateNodeType::Missing) {
                return UpdateTransactionStoreStatus::Conflict;
            }
        }
        return UpdateTransactionStoreStatus::Ok;
    } else {
        return UpdateTransactionStoreStatus::Conflict;
    }

    // Keep the retiring marker until all shared raw inputs and temporaries
    // have been durably removed. Every interruption is therefore resumable
    // using only fixed internal names, without reactivating boot recovery.
    char path[kInstallerMaximumPathBytes + 1U];
    for (size_t index = 0U; index < 4U; ++index) {
        if (!Join(transaction_root, kPayloadNames[index], path, sizeof(path)) ||
            !file_system_->RemoveFile(path) ||
            !file_system_->SyncContainingDirectory(path)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
        if (!ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::TransactionCleanup)) {
            return UpdateTransactionStoreStatus::RecoveryProgressFailed;
        }
        char temporary[kInstallerMaximumPathBytes + 1U];
        const int written = snprintf(temporary, sizeof(temporary), "%s.part",
                                     path);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(temporary) ||
            !file_system_->RemoveFile(temporary) ||
            !file_system_->SyncContainingDirectory(temporary)) {
            return UpdateTransactionStoreStatus::FileSystemError;
        }
        if (!ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::TransactionCleanup)) {
            return UpdateTransactionStoreStatus::RecoveryProgressFailed;
        }
    }
    if (!file_system_->RemoveFile(retiring_path) ||
        !file_system_->SyncContainingDirectory(retiring_path)) {
        return UpdateTransactionStoreStatus::FileSystemError;
    }
    return ReportUpdateRecoveryProgress(
               recovery_progress,
               UpdateRecoveryProgressKind::TransactionCleanup)
        ? UpdateTransactionStoreStatus::Ok
        : UpdateTransactionStoreStatus::RecoveryProgressFailed;
}

UpdateTransactionStoreStatus UpdateTransactionRequestStore::Deactivate(
    UpdateRecoveryProgress *recovery_progress)
{
    return DeactivateAtRoot(file_system_, kUpdateTransactionRoot,
                            recovery_progress);
}

UpdateRequestPersistenceStatus UpdateTransactionRequestStore::Persist(
    const AuthenticatedUpdateRequest &request)
{
    return Save(request) == UpdateTransactionStoreStatus::Ok
        ? UpdateRequestPersistenceStatus::Ok
        : UpdateRequestPersistenceStatus::Failed;
}

UpdateRequestPersistenceStatus
UpdateTransactionRequestStore::DiscardPersisted(
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress)
{
    if (binding.transaction_root == 0 ||
        binding.transaction_root[0] == '\0') {
        return UpdateRequestPersistenceStatus::Failed;
    }
    const UpdateTransactionStoreStatus status =
        Discard(binding.transaction_root, recovery_progress);
    if (status == UpdateTransactionStoreStatus::RecoveryProgressFailed) {
        return UpdateRequestPersistenceStatus::RecoveryProgressFailed;
    }
    return status == UpdateTransactionStoreStatus::Ok
        ? UpdateRequestPersistenceStatus::Ok
        : UpdateRequestPersistenceStatus::Failed;
}

UpdateRequestPersistenceStatus
UpdateTransactionRequestStore::DeactivatePersisted(
    UpdateRecoveryProgress *recovery_progress)
{
    const UpdateTransactionStoreStatus status = Deactivate(recovery_progress);
    if (status == UpdateTransactionStoreStatus::RecoveryProgressFailed) {
        return UpdateRequestPersistenceStatus::RecoveryProgressFailed;
    }
    return status == UpdateTransactionStoreStatus::Ok
        ? UpdateRequestPersistenceStatus::Ok
        : UpdateRequestPersistenceStatus::Failed;
}

UpdateRequestPersistenceStatus
UpdateTransactionRequestStore::RetainCommitted(
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress)
{
    if (file_system_ == 0 || !BoundedRoot(binding.transaction_root) ||
        strcmp(binding.transaction_root, kUpdateTransactionRoot) != 0) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    char active[kInstallerMaximumPathBytes + 1U];
    char committed[kInstallerMaximumPathBytes + 1U];
    char retiring[kInstallerMaximumPathBytes + 1U];
    if (!Join(binding.transaction_root, kStateName, active, sizeof(active)) ||
        !Join(binding.transaction_root, kCommittedStateName, committed,
              sizeof(committed)) ||
        !Join(binding.transaction_root, kRetiringStateName, retiring,
              sizeof(retiring))) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    UpdateFileStat active_stat;
    UpdateFileStat committed_stat;
    UpdateFileStat retiring_stat;
    if (!file_system_->Stat(active, &active_stat) ||
        !file_system_->Stat(committed, &committed_stat) ||
        !file_system_->Stat(retiring, &retiring_stat) ||
        retiring_stat.type != UpdateNodeType::Missing) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    if (active_stat.type == UpdateNodeType::Missing &&
        committed_stat.type == UpdateNodeType::RegularFile &&
        committed_stat.size == kPersistedUpdateRequestStateBytes) {
        if (!file_system_->SyncContainingDirectory(committed)) {
            return UpdateRequestPersistenceStatus::Failed;
        }
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::RequestAfterCommitRetentionDirectorySync);
        return ReportUpdateRecoveryProgress(
                   recovery_progress,
                   UpdateRecoveryProgressKind::TransactionCleanup)
            ? UpdateRequestPersistenceStatus::Ok
            : UpdateRequestPersistenceStatus::RecoveryProgressFailed;
    }
    if (active_stat.type != UpdateNodeType::RegularFile ||
        active_stat.size != kPersistedUpdateRequestStateBytes ||
        committed_stat.type != UpdateNodeType::Missing) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::RequestBeforeCommitRetentionRename);
    if (!file_system_->Rename(active, committed, false)) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::RequestAfterCommitRetentionRename);
    if (!file_system_->SyncContainingDirectory(committed)) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    BMX_UPDATE_FAULT_CHECKPOINT(
        UpdateFaultPoint::RequestAfterCommitRetentionDirectorySync);
    UpdateFileStat active_after;
    UpdateFileStat committed_after;
    if (!file_system_->Stat(active, &active_after) ||
        !file_system_->Stat(committed, &committed_after) ||
        active_after.type != UpdateNodeType::Missing ||
        committed_after.type != UpdateNodeType::RegularFile ||
        committed_after.size != kPersistedUpdateRequestStateBytes) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    return ReportUpdateRecoveryProgress(
               recovery_progress,
               UpdateRecoveryProgressKind::TransactionCleanup)
        ? UpdateRequestPersistenceStatus::Ok
        : UpdateRequestPersistenceStatus::RecoveryProgressFailed;
}

UpdateRequestPersistenceStatus
UpdateTransactionRequestStore::DiscardRetainedCommitted(
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress)
{
    if (binding.transaction_root == 0 ||
        strcmp(binding.transaction_root, kUpdateTransactionRoot) != 0) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    const UpdateTransactionStoreStatus status = DiscardCommitted(
        binding.transaction_root, recovery_progress);
    if (status == UpdateTransactionStoreStatus::RecoveryProgressFailed) {
        return UpdateRequestPersistenceStatus::RecoveryProgressFailed;
    }
    return status == UpdateTransactionStoreStatus::Ok
        ? UpdateRequestPersistenceStatus::Ok
        : UpdateRequestPersistenceStatus::Failed;
}

const char *UpdateTransactionStoreStatusString(
    UpdateTransactionStoreStatus status)
{
    switch (status) {
    case UpdateTransactionStoreStatus::Ok: return "ok";
    case UpdateTransactionStoreStatus::InvalidArgument: return "invalid argument";
    case UpdateTransactionStoreStatus::InvalidIdentity: return "invalid identity";
    case UpdateTransactionStoreStatus::DurabilityUnsupported:
        return "durability unsupported";
    case UpdateTransactionStoreStatus::NotFound: return "not found";
    case UpdateTransactionStoreStatus::Conflict: return "conflict";
    case UpdateTransactionStoreStatus::WorkspaceTooSmall:
        return "workspace too small";
    case UpdateTransactionStoreStatus::FileSystemError:
        return "filesystem error";
    case UpdateTransactionStoreStatus::Corrupt: return "corrupt";
    case UpdateTransactionStoreStatus::HashMismatch: return "hash mismatch";
    case UpdateTransactionStoreStatus::RecoveryProgressFailed:
        return "recovery progress failed";
    }
    return "unknown transaction store error";
}

}  // namespace update
}  // namespace bmx
