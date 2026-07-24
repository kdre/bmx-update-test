#ifndef BMX_UPDATE_CANDIDATE_HEALTH_PROBE_H
#define BMX_UPDATE_CANDIDATE_HEALTH_PROBE_H

#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

// Candidate health is deliberately a local-only operation.  A source must
// validate the configuration which is on the boot volume now; cached menu
// assessment and network data are not admissible at this boundary.
enum class CandidateConfigurationHealthStatus : uint8_t {
    Valid = 0,
    Invalid,
    Unavailable
};

class CandidateConfigurationHealthSource {
public:
    virtual ~CandidateConfigurationHealthSource() {}
    virtual CandidateConfigurationHealthStatus ValidateLocalConfiguration(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest) = 0;
};

// Board integrations collect these observations from the running candidate,
// firmware tryboot state and already-started local subsystems.  Implementors
// must not initiate networking, update discovery, downloads or reboots.
struct CandidateRuntimeHealthObservations {
    BoardFamily running_board;
    uint32_t running_updater_abi;
    bool candidate_boot_expected;
    bool firmware_reports_tryboot;
    bool filesystem_ready;
    bool menu_core_ready;
    bool safe_reboot_ready;
    bool hardware_watchdog_ready;
};

class CandidateRuntimeHealthSource {
public:
    virtual ~CandidateRuntimeHealthSource() {}
    virtual bool CollectLocalObservations(
        CandidateRuntimeHealthObservations *observations) = 0;
};

typedef CandidateHealthProbeStatus LocalCandidateHealthProbeStatus;

static const size_t kCandidateHealthMinimumIoBufferBytes = 512U;
static const size_t kCandidateHealthMaximumIoChunkBytes = 8192U;

// Concrete, network-free candidate probe. It checks the complete selector
// chain (stable active and signed candidate, same board and machine), the selected
// candidate kernel, the
// CandidatePending journal and injected local configuration/runtime evidence
// against one freshly authenticated manifest/binding pair.
class LocalCandidateHealthProbe : public CandidateHealthProbe {
public:
    LocalCandidateHealthProbe(
        UpdateFileSystem *file_system,
        CandidateConfigurationHealthSource *configuration,
        CandidateRuntimeHealthSource *runtime,
        uint8_t *io_buffer,
        size_t io_buffer_size,
        UpdateRecoveryProgress *recovery_progress = 0,
        const char *candidate_selector = "bmx-tryboot-kernel.txt",
        const char *active_selector = "bmx-active-kernel.txt");

    bool Collect(const AuthenticatedUpdateBinding &binding,
                 const ReleaseManifest &manifest,
                 CandidateHealthEvidence *evidence);

    LocalCandidateHealthProbeStatus last_status() const {
        return last_status_;
    }
    CandidateConfigurationHealthStatus last_configuration_status() const {
        return last_configuration_status_;
    }

private:
    LocalCandidateHealthProbe(const LocalCandidateHealthProbe &);
    LocalCandidateHealthProbe &operator=(const LocalCandidateHealthProbe &);

    UpdateFileSystem *file_system_;
    CandidateConfigurationHealthSource *configuration_;
    CandidateRuntimeHealthSource *runtime_;
    uint8_t *io_buffer_;
    size_t io_buffer_size_;
    UpdateRecoveryProgress *recovery_progress_;
    const char *candidate_selector_;
    const char *active_selector_;
    LocalCandidateHealthProbeStatus last_status_;
    CandidateConfigurationHealthStatus last_configuration_status_;
};

const char *LocalCandidateHealthProbeStatusString(
    LocalCandidateHealthProbeStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CANDIDATE_HEALTH_PROBE_H
