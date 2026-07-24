#include "update/update_health.h"

namespace bmx {
namespace update {

CandidateHealthStatus EvaluateCandidateHealth(
    const CandidateHealthEvidence &evidence) {
    if (!evidence.candidate_boot_expected ||
        !evidence.firmware_reports_tryboot) {
        return CandidateHealthStatus::NotCandidateBoot;
    }
    if (!IsKnownBoardFamily(evidence.running_board) ||
        evidence.running_board != evidence.manifest_board) {
        return CandidateHealthStatus::BoardMismatch;
    }
    if (evidence.target_release_sequence == 0U) {
        return CandidateHealthStatus::ReleaseSequenceMismatch;
    }
    if (evidence.running_updater_abi == 0U ||
        evidence.minimum_updater_abi == 0U ||
        evidence.maximum_updater_abi < evidence.minimum_updater_abi ||
        evidence.running_updater_abi < evidence.minimum_updater_abi ||
        evidence.running_updater_abi > evidence.maximum_updater_abi) {
        return CandidateHealthStatus::UpdaterAbiMismatch;
    }
    if (!evidence.local_manifest_trusted) {
        return CandidateHealthStatus::ManifestUntrusted;
    }
    if (!evidence.candidate_selector_valid) {
        return CandidateHealthStatus::CandidateSelectorInvalid;
    }
    if (!evidence.critical_file_hashes_valid) {
        return CandidateHealthStatus::CriticalFileInvalid;
    }
    if (!evidence.configuration_valid) {
        return CandidateHealthStatus::ConfigurationInvalid;
    }
    if (!evidence.journal_read_write_verified) {
        return CandidateHealthStatus::JournalUnavailable;
    }
    if (!evidence.filesystem_ready || !evidence.menu_core_ready ||
        !evidence.safe_reboot_ready) {
        return CandidateHealthStatus::CoreSubsystemUnavailable;
    }
    if (!evidence.hardware_watchdog_ready) {
        return CandidateHealthStatus::WatchdogUnavailable;
    }
    return CandidateHealthStatus::Healthy;
}

const char *CandidateHealthStatusString(CandidateHealthStatus status) {
    switch (status) {
    case CandidateHealthStatus::Healthy: return "candidate healthy";
    case CandidateHealthStatus::NotCandidateBoot: return "not a candidate tryboot";
    case CandidateHealthStatus::BoardMismatch: return "candidate board mismatch";
    case CandidateHealthStatus::ReleaseSequenceMismatch:
        return "candidate release sequence mismatch";
    case CandidateHealthStatus::UpdaterAbiMismatch:
        return "candidate updater ABI mismatch";
    case CandidateHealthStatus::ManifestUntrusted:
        return "local candidate manifest untrusted";
    case CandidateHealthStatus::CandidateSelectorInvalid:
        return "candidate kernel selector invalid";
    case CandidateHealthStatus::CriticalFileInvalid:
        return "candidate critical file invalid";
    case CandidateHealthStatus::ConfigurationInvalid:
        return "candidate configuration invalid";
    case CandidateHealthStatus::JournalUnavailable:
        return "candidate journal unavailable";
    case CandidateHealthStatus::CoreSubsystemUnavailable:
        return "candidate core subsystem unavailable";
    case CandidateHealthStatus::WatchdogUnavailable:
        return "candidate watchdog unavailable";
    }
    return "unknown candidate health error";
}

const char *CandidateHealthProbeStatusString(
    CandidateHealthProbeStatus status) {
    switch (status) {
    case CandidateHealthProbeStatus::Unknown: return "unknown";
    case CandidateHealthProbeStatus::Ok: return "ok";
    case CandidateHealthProbeStatus::InvalidArgument:
        return "invalid-argument";
    case CandidateHealthProbeStatus::RuntimeUnavailable:
        return "runtime-unavailable";
    case CandidateHealthProbeStatus::ManifestBindingInvalid:
        return "manifest-binding-invalid";
    case CandidateHealthProbeStatus::ActiveSelectorInvalid:
        return "active-selector-invalid";
    case CandidateHealthProbeStatus::CandidateSelectorInvalid:
        return "candidate-selector-invalid";
    case CandidateHealthProbeStatus::CriticalFileInvalid:
        return "critical-file-invalid";
    case CandidateHealthProbeStatus::ConfigurationUnavailable:
        return "configuration-unavailable";
    case CandidateHealthProbeStatus::ConfigurationInvalid:
        return "configuration-invalid";
    case CandidateHealthProbeStatus::JournalInvalid:
        return "journal-invalid";
    case CandidateHealthProbeStatus::RecoveryProgressFailed:
        return "recovery-progress-failed";
    }
    return "unknown";
}

}  // namespace update
}  // namespace bmx
