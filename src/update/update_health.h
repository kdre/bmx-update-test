#ifndef BMX_UPDATE_UPDATE_HEALTH_H
#define BMX_UPDATE_UPDATE_HEALTH_H

#include "update/update_types.h"

namespace bmx {
namespace update {

// Numeric values are persisted in UpdateLocalLog v1. Append only.
enum class CandidateHealthStatus : uint8_t {
    Healthy = 0,
    NotCandidateBoot = 1,
    BoardMismatch = 2,
    ReleaseSequenceMismatch = 3,
    UpdaterAbiMismatch = 4,
    ManifestUntrusted = 5,
    CandidateSelectorInvalid = 6,
    CriticalFileInvalid = 7,
    ConfigurationInvalid = 8,
    JournalUnavailable = 9,
    CoreSubsystemUnavailable = 10,
    WatchdogUnavailable = 11
};

// Stable diagnostic detail produced by the concrete, network-free probe.
// Explicit values are persisted in the updater's local v1 diagnostic log;
// append new values, never renumber or reuse existing ones.
enum class CandidateHealthProbeStatus : uint8_t {
    Unknown = 0,
    Ok = 1,
    InvalidArgument = 2,
    RuntimeUnavailable = 3,
    ManifestBindingInvalid = 4,
    ActiveSelectorInvalid = 5,
    CandidateSelectorInvalid = 6,
    CriticalFileInvalid = 7,
    ConfigurationUnavailable = 8,
    ConfigurationInvalid = 9,
    JournalInvalid = 10,
    RecoveryProgressFailed = 11
};

struct CandidateHealthEvidence {
    CandidateHealthProbeStatus probe_status;
    bool candidate_boot_expected;
    bool firmware_reports_tryboot;
    BoardFamily running_board;
    BoardFamily manifest_board;
    uint64_t target_release_sequence;
    uint32_t running_updater_abi;
    uint32_t minimum_updater_abi;
    uint32_t maximum_updater_abi;
    bool local_manifest_trusted;
    bool candidate_selector_valid;
    bool critical_file_hashes_valid;
    bool configuration_valid;
    bool journal_read_write_verified;
    bool filesystem_ready;
    bool menu_core_ready;
    bool safe_reboot_ready;
    bool hardware_watchdog_ready;
};

CandidateHealthStatus EvaluateCandidateHealth(
    const CandidateHealthEvidence &evidence);
const char *CandidateHealthStatusString(CandidateHealthStatus status);
const char *CandidateHealthProbeStatusString(
    CandidateHealthProbeStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_HEALTH_H
