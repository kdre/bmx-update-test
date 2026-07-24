#include "storage_preflight.h"

#include <limits.h>
#include <stddef.h>

namespace bmx {
namespace update {

namespace {

bool AddWithoutOverflow(uint64_t left, uint64_t right, uint64_t *sum)
{
    if (sum == 0 || right > UINT64_MAX - left) {
        return false;
    }
    *sum = left + right;
    return true;
}

bool ComponentWithinLimit(uint64_t value, const StorageLimits &limits)
{
    return value <= limits.maximum_component_bytes;
}

StoragePreflightResult MakeResult(StorageDecision decision, uint64_t available)
{
    StoragePreflightResult result;
    result.decision = decision;
    result.calculated_peak_bytes = 0U;
    result.required_peak_bytes = 0U;
    result.available_bytes = available;
    result.shortfall_bytes = 0U;
    return result;
}

}  // namespace

bool IsSupportedUpdateAllocationUnit(uint64_t allocation_unit_bytes)
{
    return allocation_unit_bytes != 0U &&
           allocation_unit_bytes <=
               kMaximumSupportedUpdateAllocationUnitBytes &&
           (allocation_unit_bytes & (allocation_unit_bytes - 1U)) == 0U;
}

bool RoundUpUpdateAllocation(uint64_t logical_bytes,
                             uint64_t allocation_unit_bytes,
                             uint64_t *allocated_bytes)
{
    if (allocated_bytes == 0 ||
        !IsSupportedUpdateAllocationUnit(allocation_unit_bytes)) {
        return false;
    }
    if (logical_bytes == 0U) {
        *allocated_bytes = 0U;
        return true;
    }
    const uint64_t remainder = logical_bytes % allocation_unit_bytes;
    const uint64_t padding = remainder == 0U
        ? 0U : allocation_unit_bytes - remainder;
    return AddWithoutOverflow(logical_bytes, padding, allocated_bytes);
}

bool CalculateUpdateMetadataAllocationBytes(uint64_t manifest_file_count,
                                            uint64_t manifest_directory_count,
                                            uint64_t allocation_unit_bytes,
                                            uint64_t *allocated_bytes)
{
    if (allocated_bytes == 0 ||
        !IsSupportedUpdateAllocationUnit(allocation_unit_bytes)) {
        return false;
    }
    uint64_t fixed = 0U;
    if (!RoundUpUpdateAllocation(kUpdateStorageMetadataLogicalBytes,
                                 allocation_unit_bytes, &fixed) ||
        manifest_file_count > UINT64_MAX - manifest_directory_count) {
        return false;
    }
    const uint64_t entries = manifest_file_count + manifest_directory_count;
    if (entries != 0U &&
        allocation_unit_bytes > UINT64_MAX / entries) {
        return false;
    }
    return AddWithoutOverflow(fixed, entries * allocation_unit_bytes,
                              allocated_bytes);
}

StorageLimits StorageLimits::Defaults()
{
    StorageLimits limits;
    limits.maximum_component_bytes = kDefaultMaximumStorageComponentBytes;
    limits.maximum_peak_bytes = kDefaultMaximumUpdatePeakBytes;
    return limits;
}

StoragePreflightResult EvaluateStoragePreflight(uint64_t available_bytes,
                                               const StorageDemand &demand,
                                               const StorageLimits &limits)
{
    if (limits.maximum_component_bytes == 0U || limits.maximum_peak_bytes == 0U ||
        limits.maximum_component_bytes > limits.maximum_peak_bytes) {
        return MakeResult(StorageDecision::InvalidLimits, available_bytes);
    }
    if (demand.safety_reserve_bytes < kMinimumUpdateSafetyReserveBytes) {
        return MakeResult(StorageDecision::InvalidReserve, available_bytes);
    }
    if (!ComponentWithinLimit(demand.zip_download_bytes, limits) ||
        !ComponentWithinLimit(demand.staged_files_bytes, limits) ||
        !ComponentWithinLimit(demand.snapshot_bytes, limits) ||
        !ComponentWithinLimit(demand.largest_temporary_file_bytes, limits) ||
        !ComponentWithinLimit(demand.metadata_journal_log_bytes, limits) ||
        !ComponentWithinLimit(demand.safety_reserve_bytes, limits)) {
        return MakeResult(StorageDecision::ComponentLimitExceeded, available_bytes);
    }

    uint64_t calculated = 0U;
    const uint64_t components[] = {
        demand.zip_download_bytes,
        demand.staged_files_bytes,
        demand.snapshot_bytes,
        demand.largest_temporary_file_bytes,
        demand.metadata_journal_log_bytes,
        demand.safety_reserve_bytes
    };
    for (size_t i = 0U; i < sizeof(components) / sizeof(components[0]); ++i) {
        if (!AddWithoutOverflow(calculated, components[i], &calculated)) {
            return MakeResult(StorageDecision::ArithmeticOverflow, available_bytes);
        }
    }

    StoragePreflightResult result = MakeResult(StorageDecision::Sufficient, available_bytes);
    result.calculated_peak_bytes = calculated;
    result.required_peak_bytes = calculated > demand.manifest_required_peak_bytes
        ? calculated
        : demand.manifest_required_peak_bytes;

    if (result.required_peak_bytes > limits.maximum_peak_bytes) {
        result.decision = StorageDecision::PeakLimitExceeded;
        return result;
    }
    if (available_bytes < result.required_peak_bytes) {
        result.decision = StorageDecision::InsufficientSpace;
        result.shortfall_bytes = result.required_peak_bytes - available_bytes;
    }
    return result;
}

}  // namespace update
}  // namespace bmx
