#include "update/candidate_health_probe.h"

#include "update/fat_path_policy.h"
#include "update/selector_candidate_backend.h"
#include "update/sha256.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {
namespace {

static const uint64_t kMaximumBootReleaseSequence = UINT64_C(2147483647);

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) {
        combined = static_cast<uint8_t>(combined | bytes[index]);
    }
    return combined != 0U;
}

bool ConstantTimeBytesEqual(const uint8_t *left, const uint8_t *right,
                            size_t size)
{
    if (left == 0 || right == 0) return false;
    uint8_t difference = 0U;
    for (size_t index = 0U; index < size; ++index) {
        difference = static_cast<uint8_t>(difference |
                                          (left[index] ^ right[index]));
    }
    return difference == 0U;
}

bool KnownPolicy(ManifestFilePolicy policy)
{
    return policy == ManifestFilePolicy::Kernel ||
           policy == ManifestFilePolicy::ManagedReplace ||
           policy == ManifestFilePolicy::ConfigTemplate ||
           policy == ManifestFilePolicy::Preserve ||
           policy == ManifestFilePolicy::Metadata;
}

bool KnownCompression(ManifestCompression compression)
{
    return compression == ManifestCompression::Store ||
           compression == ManifestCompression::Deflate;
}

bool ManifestBindingValid(const AuthenticatedUpdateBinding &binding,
                          const ReleaseManifest &manifest)
{
    const ManifestAsset &asset = manifest.asset;
    if (binding.archive_url == 0 || binding.archive_url[0] == '\0' ||
        binding.archive_filename == 0 || binding.transaction_root == 0 ||
        !IsKnownBoardFamily(binding.board) || asset.board != binding.board ||
        binding.source_release_sequence == 0U ||
        binding.target_release_sequence != manifest.release_sequence ||
        binding.target_release_sequence <= binding.source_release_sequence ||
        binding.target_release_sequence > kMaximumBootReleaseSequence ||
        binding.old_boot_generation == 0U ||
        binding.new_boot_generation == 0U ||
        binding.new_boot_generation <= binding.old_boot_generation ||
        binding.archive_size == 0U ||
        manifest.minimum_updater_abi == 0U ||
        manifest.maximum_updater_abi < manifest.minimum_updater_abi ||
        asset.download_size != binding.archive_size ||
        binding.archive_filename[0] == '\0' || asset.filename[0] == '\0' ||
        strcmp(asset.filename, binding.archive_filename) != 0 ||
        !BytesNonZero(binding.transaction_id, kTransactionIdBytes) ||
        !BytesNonZero(binding.archive_sha256, kSha256DigestBytes) ||
        !BytesNonZero(binding.manifest_sha256, kSha256DigestBytes) ||
        !BytesNonZero(binding.consent_sha256, kSha256DigestBytes) ||
        !ConstantTimeDigestEqual(asset.sha256, binding.archive_sha256) ||
        (binding.reset_required && !binding.reset_approved) ||
        (!binding.reset_required && binding.reset_approved) ||
        ValidateFatRelativePath(binding.transaction_root,
                                kInstallerMaximumPathBytes) !=
            FatPathValidationStatus::Ok ||
        asset.files == 0 || asset.file_count == 0U ||
        asset.file_count > kMaximumManifestFiles ||
        (asset.directory_count != 0U && asset.directories == 0) ||
        asset.directory_count > kMaximumManifestDirectories) {
        return false;
    }

    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (!KnownPolicy(file.policy) || !KnownCompression(file.compression) ||
            ValidateFatRelativePath(file.path, kMaximumManifestPathBytes) !=
                FatPathValidationStatus::Ok) {
            return false;
        }
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        if (ValidateFatRelativePath(asset.directories[index].path,
                                    kMaximumManifestPathBytes) !=
            FatPathValidationStatus::Ok) {
            return false;
        }
    }
    return true;
}

bool ReadExactFile(UpdateFileSystem *file_system, const char *path,
                   uint8_t *buffer, size_t buffer_size, size_t *size,
                   UpdateRecoveryProgress *recovery_progress,
                   UpdateRecoveryProgressKind progress_kind,
                   bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0 || path == 0 || buffer == 0 || size == 0) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile || stat.size == 0U ||
        stat.size > buffer_size) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint64_t open_size = 0U;
    bool ok = file->GetSize(&open_size) && open_size == stat.size;
    if (ok) {
        ok = file->ReadAt(0U, buffer, static_cast<size_t>(stat.size));
        if (ok && !ReportUpdateRecoveryProgress(
                recovery_progress, progress_kind, stat.size, stat.size)) {
            if (progress_failed != 0) *progress_failed = true;
            ok = false;
        }
    }
    const bool closed = file->Close();
    if (!ok || !closed) return false;
    *size = static_cast<size_t>(stat.size);
    return true;
}

enum class SelectorChainStatus : uint8_t {
    Ok = 0,
    ActiveInvalid,
    CandidateInvalid
};

SelectorChainStatus ValidateSelectorChain(
    UpdateFileSystem *file_system, const char *active_selector_path,
    const char *candidate_selector_path,
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest,
    UpdateRecoveryProgress *recovery_progress,
    bool *progress_failed, ParsedKernelSelector *candidate_output)
{
    if (progress_failed != 0) *progress_failed = false;
    size_t signed_selector_entries = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        const ManifestFile &file = manifest.asset.files[index];
        if (strcmp(file.path, candidate_selector_path) == 0 &&
            file.policy == ManifestFilePolicy::ConfigTemplate) {
            ++signed_selector_entries;
        }
    }
    if (signed_selector_entries != 1U) {
        return SelectorChainStatus::CandidateInvalid;
    }

    uint8_t candidate_encoded[kMaximumKernelSelectorBytes];
    size_t candidate_size = 0U;
    // ParseKernelSelector deliberately rejects a full 128-byte input.
    if (!ReadExactFile(file_system, candidate_selector_path,
                       candidate_encoded, sizeof(candidate_encoded) - 1U,
                       &candidate_size, recovery_progress,
                       UpdateRecoveryProgressKind::CandidateEvidenceRead,
                       progress_failed)) {
        return SelectorChainStatus::CandidateInvalid;
    }
    ParsedKernelSelector candidate;
    if (ParseKernelSelector(ByteView(candidate_encoded, candidate_size),
                            binding.board, &candidate) !=
            KernelSelectorStatus::Ok ||
        ValidateKernelSelectorAgainstAsset(
            candidate, manifest.asset, binding.target_release_sequence) !=
            KernelSelectorStatus::Ok) {
        return SelectorChainStatus::CandidateInvalid;
    }

    uint8_t active_encoded[kMaximumKernelSelectorBytes];
    size_t active_size = 0U;
    if (!ReadExactFile(file_system, active_selector_path, active_encoded,
                       sizeof(active_encoded) - 1U, &active_size,
                       recovery_progress,
                       UpdateRecoveryProgressKind::CandidateEvidenceRead,
                       progress_failed)) {
        return SelectorChainStatus::ActiveInvalid;
    }
    ParsedKernelSelector active;
    if (ParseKernelSelector(ByteView(active_encoded, active_size),
                            binding.board, &active) !=
            KernelSelectorStatus::Ok ||
        active.candidate ||
        strcmp(active.machine, candidate.machine) != 0 ||
        (candidate.candidate &&
         strcmp(active.kernel_path, candidate.kernel_path) == 0)) {
        return SelectorChainStatus::ActiveInvalid;
    }
    // The active selector is the normal-boot rollback target. Its source
    // kernel is intentionally not part of the target manifest, but it must
    // still exist as a non-empty regular file before the candidate is healthy.
    UpdateFileStat active_kernel;
    if (!file_system->Stat(active.kernel_path, &active_kernel) ||
        active_kernel.type != UpdateNodeType::RegularFile ||
        active_kernel.size == 0U) {
        return SelectorChainStatus::ActiveInvalid;
    }
    if (candidate_output != 0) *candidate_output = candidate;
    return SelectorChainStatus::Ok;
}

bool HashInstalledFile(UpdateFileSystem *file_system,
                       const ManifestFile &expected,
                       const char *actual_path,
                       uint8_t *buffer, size_t buffer_size,
                       uint64_t completed_before,
                       uint64_t total_bytes,
                       UpdateRecoveryProgress *recovery_progress,
                       bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    UpdateFileStat stat;
    if (file_system == 0 || buffer == 0 || buffer_size == 0U ||
        actual_path == 0 || !file_system->Stat(actual_path, &stat) ||
        stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected.size) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(actual_path, &file) || file == 0) return false;

    uint64_t open_size = 0U;
    bool ok = file->GetSize(&open_size) && open_size == expected.size;
    Sha256 hash;
    uint64_t offset = 0U;
    while (ok && offset < expected.size) {
        const uint64_t remaining = expected.size - offset;
        const size_t bounded_buffer =
            buffer_size < kCandidateHealthMaximumIoChunkBytes
                ? buffer_size : kCandidateHealthMaximumIoChunkBytes;
        const size_t amount = remaining < bounded_buffer
            ? static_cast<size_t>(remaining) : bounded_buffer;
        ok = file->ReadAt(offset, buffer, amount) &&
             hash.Update(buffer, amount);
        offset += amount;
        if (ok && !ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::CandidateFileHashed,
                completed_before + offset, total_bytes)) {
            if (progress_failed != 0) *progress_failed = true;
            ok = false;
        }
    }
    uint8_t digest[kSha256DigestBytes];
    if (ok) ok = hash.Final(digest);
    const bool closed = file->Close();
    return ok && closed &&
           ConstantTimeDigestEqual(digest, expected.sha256);
}

bool CandidateKernelValid(UpdateFileSystem *file_system,
                        const ManifestAsset &asset,
                        const ParsedKernelSelector &selector,
                        uint8_t *buffer, size_t buffer_size,
                        UpdateRecoveryProgress *recovery_progress,
                        bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    const ManifestFile *expected = 0;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy == ManifestFilePolicy::Kernel &&
            strcmp(file.path, selector.manifest_kernel_path) == 0) {
            if (expected != 0) return false;
            expected = &file;
        }
    }
    return expected != 0 && HashInstalledFile(
        file_system, *expected, selector.kernel_path, buffer, buffer_size,
        0U, expected->size, recovery_progress, progress_failed);
}

bool JoinJournalPath(const char *root, const char *name,
                     char output[kInstallerMaximumPathBytes + 1U])
{
    if (root == 0 || name == 0 || output == 0) return false;
    const int written = snprintf(output, kInstallerMaximumPathBytes + 1U,
                                 "%s/%s", root, name);
    return written > 0 &&
           static_cast<size_t>(written) <= kInstallerMaximumPathBytes &&
           ValidateFatRelativePath(output, kInstallerMaximumPathBytes) ==
               FatPathValidationStatus::Ok;
}

bool ReadJournalCopy(UpdateFileSystem *file_system, const char *path,
                     bool *present,
                     uint8_t encoded[kJournalEncodedSize],
                     UpdateRecoveryProgress *recovery_progress,
                     bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0 || path == 0 || present == 0 || encoded == 0) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat)) return false;
    if (stat.type == UpdateNodeType::Missing) {
        *present = false;
        memset(encoded, 0, kJournalEncodedSize);
        return true;
    }
    *present = true;
    if (stat.type != UpdateNodeType::RegularFile ||
        stat.size != kJournalEncodedSize) {
        memset(encoded, 0, kJournalEncodedSize);
        return true;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint64_t open_size = 0U;
    bool ok = file->GetSize(&open_size) && open_size == kJournalEncodedSize &&
              file->ReadAt(0U, encoded, kJournalEncodedSize);
    if (ok && !ReportUpdateRecoveryProgress(
            recovery_progress,
            UpdateRecoveryProgressKind::CandidateJournalRead,
            kJournalEncodedSize, kJournalEncodedSize)) {
        if (progress_failed != 0) *progress_failed = true;
        ok = false;
    }
    const bool closed = file->Close();
    return ok && closed;
}

bool JournalBindingValid(const JournalRecord &record,
                         const AuthenticatedUpdateBinding &binding,
                         const ReleaseManifest &manifest)
{
    uint32_t stage_steps = 0U;
    uint32_t total_steps = 0U;
    if (!UpdateInstaller::ComputeStepCounts(manifest.asset, &stage_steps,
                                            &total_steps) ||
        stage_steps == UINT32_MAX) {
        return false;
    }
    JournalFlags expected_flags = kJournalFlagUserApproved |
        kJournalFlagDownloadVerified | kJournalFlagSnapshotComplete |
        kJournalFlagStagingComplete | kJournalFlagTrybootArmed;
    if (binding.reset_required) {
        expected_flags = static_cast<JournalFlags>(
            expected_flags | kJournalFlagResetRequired |
            kJournalFlagResetApproved);
    }
    return record.state == JournalState::CandidatePending &&
           record.substate == 0U && record.flags == expected_flags &&
           record.source_release_sequence == binding.source_release_sequence &&
           record.target_release_sequence == binding.target_release_sequence &&
           record.board == binding.board &&
           record.old_boot_generation == binding.old_boot_generation &&
           record.new_boot_generation == binding.new_boot_generation &&
           record.completed_steps == stage_steps + 1U &&
           record.total_steps == total_steps &&
           ConstantTimeBytesEqual(record.transaction_id,
                                  binding.transaction_id,
                                  kTransactionIdBytes) &&
           ConstantTimeDigestEqual(record.manifest_sha256,
                                   binding.manifest_sha256) &&
           ConstantTimeDigestEqual(record.zip_sha256,
                                   binding.archive_sha256) &&
           ConstantTimeDigestEqual(record.consent_sha256,
                                   binding.consent_sha256);
}

bool CandidateJournalValid(UpdateFileSystem *file_system,
                           const AuthenticatedUpdateBinding &binding,
                           const ReleaseManifest &manifest,
                           UpdateRecoveryProgress *recovery_progress,
                           bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    char path_a[kInstallerMaximumPathBytes + 1U];
    char path_b[kInstallerMaximumPathBytes + 1U];
    if (!JoinJournalPath(binding.transaction_root, "journal.a", path_a) ||
        !JoinJournalPath(binding.transaction_root, "journal.b", path_b)) {
        return false;
    }
    bool present_a = false;
    bool present_b = false;
    uint8_t bytes_a[kJournalEncodedSize];
    uint8_t bytes_b[kJournalEncodedSize];
    if (!ReadJournalCopy(file_system, path_a, &present_a, bytes_a,
                         recovery_progress, progress_failed) ||
        !ReadJournalCopy(file_system, path_b, &present_b, bytes_b,
                         recovery_progress, progress_failed)) {
        return false;
    }
    const JournalCopy copy_a = {
        present_a, ByteView(bytes_a, sizeof(bytes_a))};
    const JournalCopy copy_b = {
        present_b, ByteView(bytes_b, sizeof(bytes_b))};
    const JournalSelectionResult selected = SelectJournalCopy(copy_a, copy_b);
    if (selected.status != JournalSelectionStatus::SelectedA &&
        selected.status != JournalSelectionStatus::SelectedB &&
        selected.status != JournalSelectionStatus::SelectedEquivalentCopies) {
        return false;
    }
    return JournalBindingValid(selected.record, binding, manifest);
}

}  // namespace

LocalCandidateHealthProbe::LocalCandidateHealthProbe(
    UpdateFileSystem *file_system,
    CandidateConfigurationHealthSource *configuration,
    CandidateRuntimeHealthSource *runtime,
    uint8_t *io_buffer,
    size_t io_buffer_size,
    UpdateRecoveryProgress *recovery_progress,
    const char *candidate_selector,
    const char *active_selector)
    : file_system_(file_system), configuration_(configuration),
      runtime_(runtime), io_buffer_(io_buffer), io_buffer_size_(io_buffer_size),
      recovery_progress_(recovery_progress),
      candidate_selector_(candidate_selector), active_selector_(active_selector),
      last_status_(LocalCandidateHealthProbeStatus::InvalidArgument),
      last_configuration_status_(
          CandidateConfigurationHealthStatus::Unavailable)
{
}

bool LocalCandidateHealthProbe::Collect(
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest,
    CandidateHealthEvidence *evidence)
{
    if (evidence != 0) {
        memset(evidence, 0, sizeof(*evidence));
        evidence->probe_status =
            LocalCandidateHealthProbeStatus::InvalidArgument;
    }
    last_status_ = LocalCandidateHealthProbeStatus::InvalidArgument;
    last_configuration_status_ =
        CandidateConfigurationHealthStatus::Unavailable;
    if (evidence == 0 || file_system_ == 0 || configuration_ == 0 ||
        runtime_ == 0 || io_buffer_ == 0 ||
        io_buffer_size_ < kCandidateHealthMinimumIoBufferBytes ||
        candidate_selector_ == 0 || active_selector_ == 0 ||
        strcmp(candidate_selector_, active_selector_) == 0 ||
        ValidateFatRelativePath(candidate_selector_,
                                kMaximumManifestPathBytes) !=
            FatPathValidationStatus::Ok ||
        ValidateFatRelativePath(active_selector_,
                                kMaximumManifestPathBytes) !=
            FatPathValidationStatus::Ok) {
        return false;
    }

    CandidateRuntimeHealthObservations observations;
    memset(&observations, 0, sizeof(observations));
    if (!runtime_->CollectLocalObservations(&observations)) {
        last_status_ = LocalCandidateHealthProbeStatus::RuntimeUnavailable;
        evidence->probe_status = last_status_;
        return false;
    }
    evidence->candidate_boot_expected = observations.candidate_boot_expected;
    evidence->firmware_reports_tryboot = observations.firmware_reports_tryboot;
    evidence->running_board = observations.running_board;
    evidence->manifest_board = manifest.asset.board;
    // Use the authenticated transaction binding, not a runtime callback or a
    // cached build-info file, as the expected candidate release identity.
    evidence->target_release_sequence = binding.target_release_sequence;
    evidence->running_updater_abi = observations.running_updater_abi;
    evidence->minimum_updater_abi = manifest.minimum_updater_abi;
    evidence->maximum_updater_abi = manifest.maximum_updater_abi;
    evidence->filesystem_ready = observations.filesystem_ready;
    evidence->menu_core_ready = observations.menu_core_ready;
    evidence->safe_reboot_ready = observations.safe_reboot_ready;
    evidence->hardware_watchdog_ready = observations.hardware_watchdog_ready;

    evidence->local_manifest_trusted =
        ManifestBindingValid(binding, manifest);
    if (!evidence->local_manifest_trusted) {
        last_status_ = LocalCandidateHealthProbeStatus::ManifestBindingInvalid;
        evidence->probe_status = last_status_;
        return true;
    }

    bool progress_failed = false;
    ParsedKernelSelector candidate_selector;
    memset(&candidate_selector, 0, sizeof(candidate_selector));
    const SelectorChainStatus selector_status = ValidateSelectorChain(
        file_system_, active_selector_, candidate_selector_, binding,
        manifest, recovery_progress_, &progress_failed, &candidate_selector);
    if (progress_failed) {
        last_status_ = LocalCandidateHealthProbeStatus::RecoveryProgressFailed;
        evidence->probe_status = last_status_;
        return false;
    }
    evidence->candidate_selector_valid =
        selector_status == SelectorChainStatus::Ok;
    evidence->critical_file_hashes_valid = CandidateKernelValid(
        file_system_, manifest.asset, candidate_selector, io_buffer_, io_buffer_size_,
        recovery_progress_, &progress_failed);
    if (progress_failed) {
        last_status_ = LocalCandidateHealthProbeStatus::RecoveryProgressFailed;
        evidence->probe_status = last_status_;
        return false;
    }
    last_configuration_status_ =
        configuration_->ValidateLocalConfiguration(binding, manifest);
    evidence->configuration_valid =
        last_configuration_status_ ==
        CandidateConfigurationHealthStatus::Valid;
    // This legacy evidence name means that the crash-recoverable dual journal
    // was locally readable, codec-valid and exactly transaction-bound.  The
    // health probe intentionally performs no journal mutation before the
    // installer's MarkCandidateHealthy transition.
    evidence->journal_read_write_verified = CandidateJournalValid(
        file_system_, binding, manifest, recovery_progress_,
        &progress_failed);
    if (progress_failed) {
        last_status_ = LocalCandidateHealthProbeStatus::RecoveryProgressFailed;
        evidence->probe_status = last_status_;
        return false;
    }

    if (selector_status == SelectorChainStatus::ActiveInvalid) {
        last_status_ = LocalCandidateHealthProbeStatus::ActiveSelectorInvalid;
    } else if (!evidence->candidate_selector_valid) {
        last_status_ =
            LocalCandidateHealthProbeStatus::CandidateSelectorInvalid;
    } else if (!evidence->critical_file_hashes_valid) {
        last_status_ = LocalCandidateHealthProbeStatus::CriticalFileInvalid;
    } else if (last_configuration_status_ ==
               CandidateConfigurationHealthStatus::Unavailable) {
        last_status_ =
            LocalCandidateHealthProbeStatus::ConfigurationUnavailable;
    } else if (!evidence->configuration_valid) {
        last_status_ = LocalCandidateHealthProbeStatus::ConfigurationInvalid;
    } else if (!evidence->journal_read_write_verified) {
        last_status_ = LocalCandidateHealthProbeStatus::JournalInvalid;
    } else {
        last_status_ = LocalCandidateHealthProbeStatus::Ok;
    }
    evidence->probe_status = last_status_;
    return true;
}

const char *LocalCandidateHealthProbeStatusString(
    LocalCandidateHealthProbeStatus status)
{
    return CandidateHealthProbeStatusString(status);
}

}  // namespace update
}  // namespace bmx
