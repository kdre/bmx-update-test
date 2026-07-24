#ifndef BMX_UPDATE_CANDIDATE_HEALTH_ADAPTERS_H
#define BMX_UPDATE_CANDIDATE_HEALTH_ADAPTERS_H

#include "update/candidate_health_probe.h"
#include "update/fatfs_config_snapshot.h"
#include "update/selector_candidate_backend.h"
#include "update/update_watchdog.h"

namespace bmx {
namespace update {

#ifndef BMX_UPDATE_UPDATER_ABI
#define BMX_UPDATE_UPDATER_ABI 1
#endif

uint32_t CompiledUpdaterAbi();

enum class ProductionCandidateConfigurationStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    BindingMismatch,
    ManifestPolicyInvalid,
    SnapshotUnavailable,
    AssessmentFailed,
    TargetSchemaMismatch,
    ActiveSourceBuildInfoMismatch
};

// Re-loads SYS: on every validation.  It intentionally does not compare the
// pre-install consent digest: after staging, the active files must instead
// parse as the exact target schema. BMX-BUILD.json is the deliberate
// pre-commit exception: while CandidatePending it must still identify the
// exact authenticated source release. Target metadata is activated only after
// candidate health succeeds.
class ProductionCandidateConfigurationHealthSource
    : public CandidateConfigurationHealthSource {
public:
    explicit ProductionCandidateConfigurationHealthSource(
        const char *volume = "SYS:");

    CandidateConfigurationHealthStatus ValidateLocalConfiguration(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest);

    ProductionCandidateConfigurationStatus last_status() const {
        return last_status_;
    }
    FatFsConfigSnapshotStatus last_snapshot_status() const {
        return last_snapshot_status_;
    }
    ConfigAssessmentStatus last_assessment_status() const {
        return last_assessment_status_;
    }

private:
    ProductionCandidateConfigurationHealthSource(
        const ProductionCandidateConfigurationHealthSource &);
    ProductionCandidateConfigurationHealthSource &operator=(
        const ProductionCandidateConfigurationHealthSource &);

    // Exact build-info v1 has eight root members and at most sixteen schema
    // pairs, so 128 tokens leaves ample bounded headroom without putting the
    // menu service's small stack under pressure.
    static const size_t kBuildInfoTokenCapacity = 128U;

    const char *volume_;
    FatFsConfigSnapshot snapshot_;
    JsonToken build_info_tokens_[kBuildInfoTokenCapacity];
    ProductionCandidateConfigurationStatus last_status_;
    FatFsConfigSnapshotStatus last_snapshot_status_;
    ConfigAssessmentStatus last_assessment_status_;
};

const char *ProductionCandidateConfigurationStatusString(
    ProductionCandidateConfigurationStatus status);

enum class SelectorCandidateBootObservationStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    FileUnavailable,
    SelectorInvalid
};

// A local candidate-boot observation which does not infer firmware mailbox
// state.  Both selectors are re-read and strictly parsed.  A candidate is
// expected only when the candidate selector names this compiled release, the
// active selector names the same machine from an older release, and both
// selectors belong to the running board.  Corrupt/unreadable selectors make
// the observation unavailable rather than silently producing false.
class SelectorCandidateBootObservation {
public:
    SelectorCandidateBootObservation(
        UpdateFileSystem *file_system, BoardFamily board,
        const char *active_selector = "bmx-active-kernel.txt",
        const char *candidate_selector = "bmx-tryboot-kernel.txt");

    bool ReadCandidateBootExpected(bool *expected);
    static bool ReadCallback(void *context, bool *expected);

    SelectorCandidateBootObservationStatus last_status() const {
        return last_status_;
    }

private:
    bool ReadSelector(const char *path, ParsedKernelSelector *selector);

    SelectorCandidateBootObservation(const SelectorCandidateBootObservation &);
    SelectorCandidateBootObservation &operator=(
        const SelectorCandidateBootObservation &);

    UpdateFileSystem *file_system_;
    BoardFamily board_;
    const char *active_selector_;
    const char *candidate_selector_;
    uint8_t selector_bytes_[kMaximumKernelSelectorBytes];
    SelectorCandidateBootObservationStatus last_status_;
};

const char *SelectorCandidateBootObservationStatusString(
    SelectorCandidateBootObservationStatus status);

typedef bool (*ReadCandidateBoardFunction)(void *context,
                                            BoardFamily *board);
typedef bool (*ReadCandidateBooleanObservationFunction)(void *context,
                                                        bool *value);

// Concrete adapter for the firmware-provided current-boot DTB observation.
// Returns unavailable while its independent hardware validation gate is
// closed; a gated, well-formed non-tryboot boot is returned as value=false.
bool ReadFirmwareTrybootObservation(void *context, bool *value);

// Concrete adapter for a watchdog owned by the candidate recovery flow.
// Like the firmware observation, it is unavailable while its independent
// hardware validation gate is closed.
bool ReadCandidateWatchdogObservation(void *context, bool *value);

// Every callback is a read-only, local observation.  It must neither enable
// networking nor initiate discovery, update I/O or a reboot.  The callback
// reports availability with its return value and writes the observed value to
// its output argument; an observed false is valid evidence, not an I/O error.
struct ProductionCandidateRuntimeOperations {
    void *running_board_context;
    ReadCandidateBoardFunction read_running_board;
    void *candidate_boot_context;
    ReadCandidateBooleanObservationFunction read_candidate_boot_expected;
    void *firmware_tryboot_context;
    ReadCandidateBooleanObservationFunction read_firmware_reports_tryboot;
    void *filesystem_context;
    ReadCandidateBooleanObservationFunction read_filesystem_ready;
    void *menu_core_context;
    ReadCandidateBooleanObservationFunction read_menu_core_ready;
    void *safe_reboot_context;
    ReadCandidateBooleanObservationFunction read_safe_reboot_ready;
    void *watchdog_context;
    ReadCandidateBooleanObservationFunction read_hardware_watchdog_ready;
};

struct ProductionCandidateRuntimeReadiness {
    bool compiled_identity_available;
    bool running_board_observation_available;
    bool candidate_boot_observation_validated;
    bool firmware_tryboot_observation_validated;
    bool filesystem_observation_available;
    bool menu_core_observation_available;
    bool safe_reboot_observation_validated;
    bool watchdog_observation_validated;
};

// Returns null operations. A target binding must explicitly install the
// selector, firmware-DTB, watchdog and local subsystem callbacks before this
// source can become ready; construction never infers readiness.
ProductionCandidateRuntimeOperations
EmptyProductionCandidateRuntimeOperations();

// The production readiness factory is deliberately fail-closed.  In addition
// to real callbacks it requires target validation flags:
//
//   BMX_UPDATE_TRYBOOT_OBSERVATION_HARDWARE_VALIDATED
//       for the separate firmware-tryboot observation,
//   BMX_UPDATE_TRYBOOT_HARDWARE_VALIDATED
//       for the safe-reboot observation, and
//   BMX_UPDATE_WATCHDOG_HARDWARE_VALIDATED
//       for watchdog health. This flag also requires evidence that the whole
//       local probe plus commit path completes within Circle's fixed 15 s
//       watchdog timeout on the slowest supported SD card, or that audited
//       feed points exist. IsRunning() alone is not sufficient evidence.
//
// `candidate_boot_expected` can use SelectorCandidateBootObservation and is
// therefore a local software observation; it still requires a real callback.
// All hardware flags are ignored outside a RASPI_COMPILE build.  Merely
// defining a flag never supplies an observation callback.
ProductionCandidateRuntimeReadiness
ProductionCandidateRuntimeReadinessForCallbacks(
    const ProductionCandidateRuntimeOperations &operations);

bool ProductionCandidateRuntimeReady(
    const ProductionCandidateRuntimeReadiness &readiness);

enum class ProductionCandidateRuntimeStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    PlatformNotValidated,
    CompiledIdentityInvalid,
    ObservationUnavailable
};

class ProductionCandidateRuntimeHealthSource
    : public CandidateRuntimeHealthSource {
public:
    explicit ProductionCandidateRuntimeHealthSource(
        const ProductionCandidateRuntimeOperations &operations);

#if defined(BMX_UPDATE_HEALTH_TESTING)
    // Isolated host tests can exercise the collector without pretending that
    // a production hardware validation has taken place.
    ProductionCandidateRuntimeHealthSource(
        const ProductionCandidateRuntimeOperations &operations,
        const ProductionCandidateRuntimeReadiness &test_readiness);
#endif

    bool CollectLocalObservations(
        CandidateRuntimeHealthObservations *observations);

    ProductionCandidateRuntimeStatus last_status() const {
        return last_status_;
    }
    const ProductionCandidateRuntimeReadiness &readiness() const {
        return readiness_;
    }

private:
    ProductionCandidateRuntimeHealthSource(
        const ProductionCandidateRuntimeHealthSource &);
    ProductionCandidateRuntimeHealthSource &operator=(
        const ProductionCandidateRuntimeHealthSource &);

    ProductionCandidateRuntimeOperations operations_;
    ProductionCandidateRuntimeReadiness readiness_;
    ProductionCandidateRuntimeStatus last_status_;
};

const char *ProductionCandidateRuntimeStatusString(
    ProductionCandidateRuntimeStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CANDIDATE_HEALTH_ADAPTERS_H
