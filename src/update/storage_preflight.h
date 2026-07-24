#ifndef BMX_UPDATE_STORAGE_PREFLIGHT_H
#define BMX_UPDATE_STORAGE_PREFLIGHT_H

#include <stdint.h>

namespace bmx {
namespace update {

static const uint64_t kMinimumUpdateSafetyReserveBytes = UINT64_C(16) * 1024U * 1024U;
static const uint64_t kDefaultMaximumStorageComponentBytes = UINT64_C(4) * 1024U * 1024U * 1024U;
static const uint64_t kDefaultMaximumUpdatePeakBytes = UINT64_C(16) * 1024U * 1024U * 1024U;
// FAT allocation units above this bound are deliberately unsupported.  The
// signed host-side peak uses this worst-case value, while the device repeats
// the calculation with the allocation unit reported by its mounted volume.
static const uint64_t kMaximumSupportedUpdateAllocationUnitBytes =
    UINT64_C(64) * 1024U;
// Fixed transaction/journal/log allowance before per-inventory-entry FAT
// cluster slack is added.  The non-cluster-aligned tail is intentional: it
// prevents host and target code from accidentally treating logical bytes as
// allocated bytes.
static const uint64_t kUpdateStorageMetadataLogicalBytes =
    UINT64_C(1024) * 1024U + 1024U;

struct StorageDemand {
    uint64_t zip_download_bytes;
    uint64_t staged_files_bytes;
    uint64_t snapshot_bytes;
    uint64_t largest_temporary_file_bytes;
    uint64_t metadata_journal_log_bytes;
    uint64_t safety_reserve_bytes;
    uint64_t manifest_required_peak_bytes;
};

struct StorageLimits {
    uint64_t maximum_component_bytes;
    uint64_t maximum_peak_bytes;

    static StorageLimits Defaults();
};

enum class StorageDecision : uint8_t {
    Sufficient = 0,
    InvalidLimits,
    InvalidReserve,
    ComponentLimitExceeded,
    ArithmeticOverflow,
    PeakLimitExceeded,
    InsufficientSpace
};

struct StoragePreflightResult {
    StorageDecision decision;
    uint64_t calculated_peak_bytes;
    uint64_t required_peak_bytes;
    uint64_t available_bytes;
    uint64_t shortfall_bytes;
};

StoragePreflightResult EvaluateStoragePreflight(uint64_t available_bytes,
                                               const StorageDemand &demand,
                                               const StorageLimits &limits);

bool IsSupportedUpdateAllocationUnit(uint64_t allocation_unit_bytes);

// Rounds one independently allocated FAT object without overflow.  Zero-byte
// files consume no data cluster; their directory/evidence cost is covered by
// CalculateUpdateMetadataAllocationBytes().
bool RoundUpUpdateAllocation(uint64_t logical_bytes,
                             uint64_t allocation_unit_bytes,
                             uint64_t *allocated_bytes);

// Conservative bounded allowance for journals, evidence files and directory
// entries.  Each manifest file/directory receives one additional cluster on
// top of the fixed transaction allowance.
bool CalculateUpdateMetadataAllocationBytes(uint64_t manifest_file_count,
                                            uint64_t manifest_directory_count,
                                            uint64_t allocation_unit_bytes,
                                            uint64_t *allocated_bytes);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_STORAGE_PREFLIGHT_H
