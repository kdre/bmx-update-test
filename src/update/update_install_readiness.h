#ifndef BMX_UPDATE_UPDATE_INSTALL_READINESS_H
#define BMX_UPDATE_UPDATE_INSTALL_READINESS_H

#include "update/release_manifest.h"
#include "update/storage_preflight.h"
#include "update/update_filesystem.h"

namespace bmx {
namespace update {

// The online installer must pass this complete, read-only gate before it may
// create a .part file or otherwise mutate the boot volume.  These flags are
// intentionally independent so a single menu message can report every known
// missing production primitive instead of hiding the next blocker.
typedef uint32_t UpdateInstallReadinessBlockers;

static const UpdateInstallReadinessBlockers kInstallBlockerInvalidManifest =
    UINT32_C(1) << 0U;
static const UpdateInstallReadinessBlockers kInstallBlockerStorageProbe =
    UINT32_C(1) << 1U;
static const UpdateInstallReadinessBlockers kInstallBlockerStoragePolicy =
    UINT32_C(1) << 2U;
static const UpdateInstallReadinessBlockers kInstallBlockerStorageSpace =
    UINT32_C(1) << 3U;
static const UpdateInstallReadinessBlockers kInstallBlockerDurabilityProbe =
    UINT32_C(1) << 4U;
static const UpdateInstallReadinessBlockers kInstallBlockerDurableFileSync =
    UINT32_C(1) << 5U;
static const UpdateInstallReadinessBlockers kInstallBlockerFreshRename =
    UINT32_C(1) << 6U;
static const UpdateInstallReadinessBlockers kInstallBlockerBackupReplace =
    UINT32_C(1) << 7U;
static const UpdateInstallReadinessBlockers kInstallBlockerDirectoryUpdates =
    UINT32_C(1) << 8U;
static const UpdateInstallReadinessBlockers kInstallBlockerTryboot =
    UINT32_C(1) << 9U;
static const UpdateInstallReadinessBlockers kInstallBlockerRecovery =
    UINT32_C(1) << 10U;
static const UpdateInstallReadinessBlockers kInstallBlockerSelector =
    UINT32_C(1) << 11U;
static const UpdateInstallReadinessBlockers kInstallBlockerKernelLayout =
    UINT32_C(1) << 12U;
static const UpdateInstallReadinessBlockers kInstallBlockerConfigPreparation =
    UINT32_C(1) << 13U;
static const UpdateInstallReadinessBlockers kInstallBlockerTargetOrchestration =
    UINT32_C(1) << 14U;
static const UpdateInstallReadinessBlockers kInstallBlockerLocalInventory =
    UINT32_C(1) << 15U;
static const UpdateInstallReadinessBlockers kInstallBlockerAllocationUnitProbe =
    UINT32_C(1) << 16U;
static const UpdateInstallReadinessBlockers kInstallBlockerAllocationUnitPolicy =
    UINT32_C(1) << 17U;
static const UpdateInstallReadinessBlockers kInstallBlockerBootVolumeSize =
    UINT32_C(1) << 18U;

struct UpdateInstallPlatformReadiness {
    bool tryboot_one_shot_validated;
    bool recovery_executor_available;
    bool candidate_selector_available;
    bool stable_kernel_layout;
    bool prepared_config_builder_available;
    bool target_orchestrator_available;
};

struct UpdateInstallReadinessInput {
    const ReleaseManifest *manifest;
    bool storage_probe_succeeded;
    uint64_t available_bytes;
    bool volume_size_probe_succeeded;
    uint64_t volume_size_bytes;
    bool allocation_unit_probe_succeeded;
    uint64_t allocation_unit_bytes;
    bool local_inventory_probe_succeeded;
    // These values are already rounded per independently allocated FAT file.
    uint64_t local_snapshot_bytes;
    uint64_t largest_local_snapshot_bytes;
    bool durability_probe_succeeded;
    UpdateDurabilityCapabilities durability;
    UpdateInstallPlatformReadiness platform;
};

struct UpdateInstallReadinessResult {
    UpdateInstallReadinessBlockers blockers;
    StorageDemand storage_demand;
    StoragePreflightResult storage;

    bool ready() const { return blockers == 0U; }
};

// Computes the conservative pre-download demand from authenticated manifest
// fields plus the exact sizes obtained by a read-only Stat of every existing
// Kernel/ManagedReplace/ConfigTemplate destination.  The generic installer repeats
// the check after download before its first mutation.
bool BuildPreDownloadStorageDemand(const ReleaseManifest &manifest,
                                   uint64_t local_snapshot_bytes,
                                   uint64_t largest_local_snapshot_bytes,
                                   uint64_t allocation_unit_bytes,
                                   StorageDemand *demand);

UpdateInstallReadinessResult EvaluateUpdateInstallReadiness(
    const UpdateInstallReadinessInput &input);

// Performs only UpdateFileSystem's read-only free-space, durability and Stat
// probes and then evaluates the complete gate.  No create/remove/rename/sync
// method is called.
UpdateInstallReadinessResult ProbeUpdateInstallReadiness(
    UpdateFileSystem *file_system,
    const ReleaseManifest *manifest,
    const UpdateInstallPlatformReadiness &platform);

// Produces a bounded, value-free user diagnostic.  It never includes paths,
// configuration contents, URLs or credentials.  False means the destination
// was too small to represent the complete diagnostic.
bool FormatUpdateInstallReadiness(const UpdateInstallReadinessResult &result,
                                  char *output,
                                  size_t output_size);

// Same complete diagnostic, prefixed with the authenticated version so the
// explicit Check action can show an informational result without presenting
// a misleading installation confirmation.
bool FormatUpdateInstallReadinessForRelease(
    const UpdateInstallReadinessResult &result,
    const char *release_version,
    char *output,
    size_t output_size);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_INSTALL_READINESS_H
