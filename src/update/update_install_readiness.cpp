#include "update/update_install_readiness.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {

namespace {

bool Add(uint64_t value, uint64_t *sum)
{
    if (sum == 0 || value > UINT64_MAX - *sum) return false;
    *sum += value;
    return true;
}

bool HasBlocker(const UpdateInstallReadinessResult &result,
                UpdateInstallReadinessBlockers blocker)
{
    return (result.blockers & blocker) != 0U;
}

bool AppendText(char *output, size_t output_size, size_t *used,
                const char *text)
{
    if (output == 0 || used == 0 || text == 0 || *used >= output_size) {
        return false;
    }
    const size_t amount = strlen(text);
    if (amount >= output_size - *used) return false;
    memcpy(output + *used, text, amount + 1U);
    *used += amount;
    return true;
}

bool AppendBlocker(char *output, size_t output_size, size_t *used,
                   bool *first, const char *text)
{
    if (first == 0) return false;
    if (!*first && !AppendText(output, output_size, used, "; ")) return false;
    if (!AppendText(output, output_size, used, text)) return false;
    *first = false;
    return true;
}

bool BoundedNonEmptyText(const char *text, size_t capacity)
{
    return text != 0 && capacity > 1U && text[0] != '\0' &&
           memchr(text, '\0', capacity) != 0;
}

bool KnownPolicy(ManifestFilePolicy policy)
{
    switch (policy) {
    case ManifestFilePolicy::Kernel:
    case ManifestFilePolicy::ManagedReplace:
    case ManifestFilePolicy::ConfigTemplate:
    case ManifestFilePolicy::Preserve:
    case ManifestFilePolicy::Metadata:
        return true;
    }
    return false;
}

bool BasicManifestValid(const ReleaseManifest &manifest)
{
    const ManifestAsset &asset = manifest.asset;
    if (manifest.release_sequence == 0U ||
        !IsKnownBoardFamily(asset.board) ||
        asset.download_size == 0U || asset.installed_size == 0U ||
        asset.required_peak_bytes == 0U || asset.files == 0 ||
        asset.file_count == 0U ||
        asset.file_count > kMaximumManifestFiles ||
        asset.directory_count > kMaximumManifestDirectories ||
        (asset.directory_count != 0U && asset.directories == 0)) {
        return false;
    }
    uint64_t installed_size = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (!BoundedNonEmptyText(file.path, sizeof(file.path)) ||
            !KnownPolicy(file.policy) ||
            (file.compression != ManifestCompression::Store &&
             file.compression != ManifestCompression::Deflate) ||
            !Add(file.size, &installed_size)) {
            return false;
        }
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        if (!BoundedNonEmptyText(asset.directories[index].path,
                                 sizeof(asset.directories[index].path))) {
            return false;
        }
    }
    return installed_size == asset.installed_size;
}

bool ProbeLocalSnapshotBytes(UpdateFileSystem *file_system,
                             const ReleaseManifest &manifest,
                             uint64_t allocation_unit_bytes,
                             uint64_t *snapshot_bytes,
                             uint64_t *largest_snapshot_bytes)
{
    if (file_system == 0 || snapshot_bytes == 0 ||
        largest_snapshot_bytes == 0 ||
        !IsSupportedUpdateAllocationUnit(allocation_unit_bytes) ||
        !BasicManifestValid(manifest)) {
        return false;
    }
    *snapshot_bytes = 0U;
    *largest_snapshot_bytes = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        const ManifestFile &file = manifest.asset.files[index];
        if (file.policy != ManifestFilePolicy::Kernel &&
            file.policy != ManifestFilePolicy::ManagedReplace &&
            file.policy != ManifestFilePolicy::ConfigTemplate) {
            continue;
        }
        UpdateFileStat stat;
        if (!file_system->Stat(file.path, &stat)) return false;
        if (stat.type == UpdateNodeType::Missing) continue;
        uint64_t allocated = 0U;
        if (stat.type != UpdateNodeType::RegularFile ||
            !RoundUpUpdateAllocation(stat.size, allocation_unit_bytes,
                                     &allocated) ||
            !Add(allocated, snapshot_bytes)) {
            return false;
        }
        if (allocated > *largest_snapshot_bytes) {
            *largest_snapshot_bytes = allocated;
        }
    }
    return true;
}

bool FormatReadiness(const UpdateInstallReadinessResult &result,
                     const char *release_version,
                     char *output,
                     size_t output_size)
{
    if (output == 0 || output_size == 0U) return false;
    output[0] = '\0';
    size_t used = 0U;
    if (result.ready()) {
        return AppendText(output, output_size, &used,
                          "Online installation readiness checks passed.");
    }
    if (release_version != 0) {
        char prefix[192];
        const int written = snprintf(
            prefix, sizeof(prefix),
            "BMX %s available; online install blocked pre-ZIP/write. Missing: ",
            release_version);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(prefix) ||
            !AppendText(output, output_size, &used, prefix)) {
            output[0] = '\0';
            return false;
        }
    } else if (!AppendText(output, output_size, &used,
                           "Online install blocked pre-ZIP/write. Missing: ")) {
        output[0] = '\0';
        return false;
    }
    bool first = true;
#define BMX_APPEND_BLOCKER(flag, text)                                      \
    do {                                                                     \
        if (HasBlocker(result, (flag)) &&                                    \
            !AppendBlocker(output, output_size, &used, &first, (text))) {    \
            output[0] = '\0';                                                \
            return false;                                                    \
        }                                                                    \
    } while (0)

    BMX_APPEND_BLOCKER(kInstallBlockerInvalidManifest, "signed inventory");
    BMX_APPEND_BLOCKER(kInstallBlockerStorageProbe, "free-space probe");
    BMX_APPEND_BLOCKER(kInstallBlockerBootVolumeSize,
                       "512 MiB BMX BOOT partition");
    BMX_APPEND_BLOCKER(kInstallBlockerAllocationUnitProbe,
                       "FAT allocation-unit probe");
    BMX_APPEND_BLOCKER(kInstallBlockerAllocationUnitPolicy,
                       "supported FAT allocation unit (max 64 KiB)");
    BMX_APPEND_BLOCKER(kInstallBlockerLocalInventory,
                       "local snapshot inventory");
    BMX_APPEND_BLOCKER(kInstallBlockerStoragePolicy, "storage bounds");
    if (HasBlocker(result, kInstallBlockerStorageSpace)) {
        char storage[96];
        const uint64_t mib = UINT64_C(1024) * 1024U;
        const unsigned long long available = static_cast<unsigned long long>(
            result.storage.available_bytes / mib);
        const unsigned long long required = static_cast<unsigned long long>(
            result.storage.required_peak_bytes / mib +
            (result.storage.required_peak_bytes % mib == 0U ? 0U : 1U));
        const int written = snprintf(storage, sizeof(storage),
                                     "space (%llu/%llu MiB free/need)",
                                     available, required);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(storage) ||
            !AppendBlocker(output, output_size, &used, &first, storage)) {
            output[0] = '\0';
            return false;
        }
    }
    BMX_APPEND_BLOCKER(kInstallBlockerDurabilityProbe, "durability probe");
    BMX_APPEND_BLOCKER(kInstallBlockerDurableFileSync, "durable file sync");
    BMX_APPEND_BLOCKER(kInstallBlockerFreshRename,
                       "crash-safe fresh rename");
    BMX_APPEND_BLOCKER(kInstallBlockerBackupReplace,
                       "crash-safe backup replace");
    BMX_APPEND_BLOCKER(kInstallBlockerDirectoryUpdates,
                       "durable FAT metadata");
    BMX_APPEND_BLOCKER(kInstallBlockerTryboot, "tryboot validation");
    BMX_APPEND_BLOCKER(kInstallBlockerRecovery, "local recovery");
    BMX_APPEND_BLOCKER(kInstallBlockerSelector, "candidate selector");
    BMX_APPEND_BLOCKER(kInstallBlockerKernelLayout,
                       "stable kernel layout");
    BMX_APPEND_BLOCKER(kInstallBlockerConfigPreparation,
                       "consent-bound config prep");
    BMX_APPEND_BLOCKER(kInstallBlockerTargetOrchestration,
                       "target download/stage binding");
#undef BMX_APPEND_BLOCKER

    if (first ||
        !AppendText(output, output_size, &used,
                    ". Manual update: normal GitHub release ZIP.")) {
        output[0] = '\0';
        return false;
    }
    return true;
}

}  // namespace

bool BuildPreDownloadStorageDemand(const ReleaseManifest &manifest,
                                   uint64_t local_snapshot_bytes,
                                   uint64_t largest_local_snapshot_bytes,
                                   uint64_t allocation_unit_bytes,
                                   StorageDemand *demand)
{
    if (demand == 0) return false;
    memset(demand, 0, sizeof(*demand));
    if (!BasicManifestValid(manifest) ||
        !IsSupportedUpdateAllocationUnit(allocation_unit_bytes) ||
        local_snapshot_bytes % allocation_unit_bytes != 0U ||
        largest_local_snapshot_bytes % allocation_unit_bytes != 0U ||
        largest_local_snapshot_bytes > local_snapshot_bytes) {
        return false;
    }

    const ManifestAsset &asset = manifest.asset;
    if (!RoundUpUpdateAllocation(asset.download_size, allocation_unit_bytes,
                                 &demand->zip_download_bytes)) {
        return false;
    }
    // Every payload is materialized as an independent FAT file below the
    // fresh transaction stage before activation, so each member is rounded
    // separately rather than rounding installed_size once.
    demand->staged_files_bytes = 0U;
    demand->snapshot_bytes = local_snapshot_bytes;
    if (!CalculateUpdateMetadataAllocationBytes(
            asset.file_count, asset.directory_count, allocation_unit_bytes,
            &demand->metadata_journal_log_bytes)) {
        return false;
    }
    demand->safety_reserve_bytes = kMinimumUpdateSafetyReserveBytes;
    demand->manifest_required_peak_bytes = asset.required_peak_bytes;
    demand->largest_temporary_file_bytes = largest_local_snapshot_bytes;

    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        // Empty regular files are valid ZIP members (for example an empty
        // optional release note); only the already-authenticated path must be
        // non-empty here.
        uint64_t allocated = 0U;
        if (file.path[0] == '\0' ||
            !RoundUpUpdateAllocation(file.size, allocation_unit_bytes,
                                     &allocated) ||
            !Add(allocated, &demand->staged_files_bytes)) {
            return false;
        }
        if (allocated > demand->largest_temporary_file_bytes) {
            demand->largest_temporary_file_bytes = allocated;
        }
    }
    return true;
}

UpdateInstallReadinessResult EvaluateUpdateInstallReadiness(
    const UpdateInstallReadinessInput &input)
{
    UpdateInstallReadinessResult result;
    memset(&result, 0, sizeof(result));
    result.storage.decision = StorageDecision::InvalidLimits;
    result.storage.available_bytes = input.available_bytes;

    bool has_kernel = false;
    bool has_config_template = false;
    const bool allocation_unit_supported =
        input.allocation_unit_probe_succeeded &&
        IsSupportedUpdateAllocationUnit(input.allocation_unit_bytes);
    if (input.manifest == 0 || !BasicManifestValid(*input.manifest)) {
        result.blockers |= kInstallBlockerInvalidManifest;
    } else if (allocation_unit_supported &&
               !BuildPreDownloadStorageDemand(
                   *input.manifest, input.local_snapshot_bytes,
                   input.largest_local_snapshot_bytes,
                   input.allocation_unit_bytes, &result.storage_demand)) {
        result.blockers |= kInstallBlockerInvalidManifest;
    } else if (allocation_unit_supported) {
        const ManifestAsset &asset = input.manifest->asset;
        for (size_t index = 0U; index < asset.file_count; ++index) {
            has_kernel = has_kernel ||
                asset.files[index].policy == ManifestFilePolicy::Kernel;
            has_config_template = has_config_template ||
                asset.files[index].policy == ManifestFilePolicy::ConfigTemplate;
        }
        if (input.storage_probe_succeeded &&
            input.local_inventory_probe_succeeded) {
            result.storage = EvaluateStoragePreflight(
                input.available_bytes, result.storage_demand,
                StorageLimits::Defaults());
            if (result.storage.decision == StorageDecision::InsufficientSpace) {
                result.blockers |= kInstallBlockerStorageSpace;
            } else if (result.storage.decision != StorageDecision::Sufficient) {
                result.blockers |= kInstallBlockerStoragePolicy;
            }
        }
    }

    if (!input.storage_probe_succeeded) {
        result.blockers |= kInstallBlockerStorageProbe;
    }
    if (!input.volume_size_probe_succeeded ||
        input.volume_size_bytes < UINT64_C(512) * 1024U * 1024U) {
        result.blockers |= kInstallBlockerBootVolumeSize;
    }
    if (!input.allocation_unit_probe_succeeded) {
        result.blockers |= kInstallBlockerAllocationUnitProbe;
    } else if (!IsSupportedUpdateAllocationUnit(input.allocation_unit_bytes)) {
        result.blockers |= kInstallBlockerAllocationUnitPolicy;
    }
    if (!input.local_inventory_probe_succeeded) {
        result.blockers |= kInstallBlockerLocalInventory;
    }
    if (!input.durability_probe_succeeded) {
        result.blockers |= kInstallBlockerDurabilityProbe;
    }
    if (!input.durability.durable_file_sync) {
        result.blockers |= kInstallBlockerDurableFileSync;
    }
    if (!input.durability.crash_safe_fresh_rename &&
        !input.durability.power_loss_recovery_validated) {
        result.blockers |= kInstallBlockerFreshRename;
    }
    if (!input.durability.crash_safe_replace_with_backup &&
        !input.durability.power_loss_recovery_validated) {
        result.blockers |= kInstallBlockerBackupReplace;
    }
    if (!input.durability.durable_directory_updates) {
        result.blockers |= kInstallBlockerDirectoryUpdates;
    }
    if (!input.platform.tryboot_one_shot_validated) {
        result.blockers |= kInstallBlockerTryboot;
    }
    if (!input.platform.recovery_executor_available) {
        result.blockers |= kInstallBlockerRecovery;
    }
    if (!input.platform.candidate_selector_available) {
        result.blockers |= kInstallBlockerSelector;
    }
    if (has_kernel && !input.platform.stable_kernel_layout) {
        result.blockers |= kInstallBlockerKernelLayout;
    }
    if (has_config_template &&
        !input.platform.prepared_config_builder_available) {
        result.blockers |= kInstallBlockerConfigPreparation;
    }
    if (!input.platform.target_orchestrator_available) {
        result.blockers |= kInstallBlockerTargetOrchestration;
    }
    return result;
}

UpdateInstallReadinessResult ProbeUpdateInstallReadiness(
    UpdateFileSystem *file_system,
    const ReleaseManifest *manifest,
    const UpdateInstallPlatformReadiness &platform)
{
    UpdateInstallReadinessInput input;
    memset(&input, 0, sizeof(input));
    input.manifest = manifest;
    input.platform = platform;
    if (file_system != 0) {
        input.storage_probe_succeeded =
            file_system->GetFreeSpace(&input.available_bytes);
        input.volume_size_probe_succeeded =
            file_system->GetVolumeSize(&input.volume_size_bytes);
        input.allocation_unit_probe_succeeded =
            file_system->GetAllocationUnit(&input.allocation_unit_bytes);
        input.durability_probe_succeeded =
            file_system->GetDurabilityCapabilities(&input.durability);
        if (manifest != 0) {
            input.local_inventory_probe_succeeded = ProbeLocalSnapshotBytes(
                file_system, *manifest, input.allocation_unit_bytes,
                &input.local_snapshot_bytes,
                &input.largest_local_snapshot_bytes);
        }
    }
    return EvaluateUpdateInstallReadiness(input);
}

bool FormatUpdateInstallReadiness(const UpdateInstallReadinessResult &result,
                                  char *output,
                                  size_t output_size)
{
    return FormatReadiness(result, 0, output, output_size);
}

bool FormatUpdateInstallReadinessForRelease(
    const UpdateInstallReadinessResult &result,
    const char *release_version,
    char *output,
    size_t output_size)
{
    if (release_version == 0 || release_version[0] == '\0') {
        if (output != 0 && output_size != 0U) output[0] = '\0';
        return false;
    }
    if (memchr(release_version, '\0',
               sizeof(((ReleaseManifest *)0)->version)) == 0) {
        if (output != 0 && output_size != 0U) output[0] = '\0';
        return false;
    }
    return FormatReadiness(result, release_version, output, output_size);
}

}  // namespace update
}  // namespace bmx
