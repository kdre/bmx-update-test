#include "update/candidate_health_adapters.h"

#include "update/build_info.h"
#include "update/fat_path_policy.h"
#include "update/tryboot_control.h"
#include "update/update_watchdog.h"

#include <limits.h>
#include <string.h>

namespace bmx {
namespace update {

namespace {

bool CompiledIdentityValid()
{
    return CompiledUpdaterAbi() != 0U &&
           CompiledUpdaterAbi() <= static_cast<uint32_t>(INT32_MAX);
}

bool BindingMatchesManifest(const AuthenticatedUpdateBinding &binding,
                            const ReleaseManifest &manifest)
{
    return IsKnownBoardFamily(binding.board) &&
           binding.board == manifest.asset.board &&
           binding.target_release_sequence != 0U &&
           binding.target_release_sequence == manifest.release_sequence;
}

const ConfigAreaSnapshot *FindArea(const ConfigSnapshot &snapshot,
                                   ConfigArea area)
{
    for (size_t index = 0U; index < snapshot.area_count; ++index) {
        if (snapshot.areas[index].area == area) return &snapshot.areas[index];
    }
    return 0;
}

const ConfigFileView *FindUniqueFile(const ConfigAreaSnapshot &area,
                                     const char *path)
{
    const ConfigFileView *found = 0;
    for (size_t index = 0U; index < area.file_count; ++index) {
        const ConfigFileView &file = area.files[index];
        if (file.path == 0 || strcmp(file.path, path) != 0) continue;
        if (found != 0) return 0;
        found = &file;
    }
    return found;
}

const InstalledSchemaVersion *FindInstalledSchema(
    const InstalledBuildInfo &build, ConfigArea area)
{
    for (size_t index = 0U; index < build.schema_count; ++index) {
        if (build.schemas[index].area == area) return &build.schemas[index];
    }
    return 0;
}

bool BuildInfoMatchesActiveSource(const ConfigSnapshot &snapshot,
                                  const AuthenticatedUpdateBinding &binding,
                                  JsonToken *tokens, size_t token_capacity)
{
    const ConfigAreaSnapshot *update_state =
        FindArea(snapshot, ConfigArea::UpdateState);
    if (update_state == 0) return false;
    const ConfigFileView *build_file =
        FindUniqueFile(*update_state, "BMX-BUILD.json");
    if (build_file == 0 || build_file->content.data == 0 ||
        build_file->content.size == 0U) {
        return false;
    }

    InstalledBuildInfo build;
    JsonParseResult json;
    if (ParseBuildInfo(build_file->content, tokens, token_capacity, &build,
                       &json) != BuildInfoStatus::Ok) {
        return false;
    }
    if (binding.source_release_sequence == 0U ||
        binding.source_release_sequence >= binding.target_release_sequence ||
        build.board != binding.board ||
        build.release_sequence != binding.source_release_sequence ||
        build.updater_abi == 0U ||
        build.schema_count != kConfigMigrationAreaCount) {
        return false;
    }
    for (size_t number = 1U; number <= kConfigMigrationAreaCount; ++number) {
        if (FindInstalledSchema(build, static_cast<ConfigArea>(number)) == 0) {
            return false;
        }
    }
    return true;
}

bool ManifestAcceptsMissing(const ReleaseManifest &manifest, ConfigArea area)
{
    for (size_t index = 0U; index < manifest.schema_count; ++index) {
        const ManifestConfigSchema &schema = manifest.schemas[index];
        if (schema.area != area) continue;
        for (size_t version = 0U;
             version < schema.accepted_version_count; ++version) {
            if (schema.accepted_versions[version] == 0U) return true;
        }
        return false;
    }
    return false;
}

bool PlanIsStagedTarget(const ConfigMigrationPlan &plan,
                        const ReleaseManifest &manifest)
{
    if (plan.area_count != kConfigMigrationAreaCount ||
        plan.blocked_count != 0U ||
        plan.decision == ConfigPlanDecision::BlockedUnknownOrCorrupt ||
        plan.decision == ConfigPlanDecision::BlockedNewerThanTarget ||
        plan.decision == ConfigPlanDecision::InvalidInput) {
        return false;
    }
    for (size_t index = 0U; index < plan.area_count; ++index) {
        const ConfigAreaAssessment &area = plan.areas[index];
        if (area.detection == ConfigDetectionDetail::Missing) {
            // Version zero is the signed representation of an optional
            // absent area.  Pre-install assessment deliberately treats it as
            // compatible when the manifest accepts zero; candidate health
            // must apply the same authenticated policy instead of requiring
            // an unrelated settings*.txt file to appear during staging.
            if (area.area == ConfigArea::UpdateState ||
                area.classification != ConfigClassification::Compatible ||
                area.source_version != 0U ||
                !ManifestAcceptsMissing(manifest, area.area)) {
                return false;
            }
            continue;
        }
        if (area.detection != ConfigDetectionDetail::Valid) return false;
        if (area.area == ConfigArea::UpdateState) {
            // Source metadata remains active until Commit(). The selected
            // CandidatePending journal is validated separately by the local
            // candidate probe against this exact transaction binding.
            if (area.classification != ConfigClassification::Compatible &&
                area.classification !=
                    ConfigClassification::LosslessMigration &&
                area.classification != ConfigClassification::ResetRequired) {
                return false;
            }
        } else if (area.classification !=
                       ConfigClassification::Compatible ||
                   area.source_version != area.target_version) {
            return false;
        }
    }
    return true;
}

bool RuntimeOperationsComplete(
    const ProductionCandidateRuntimeOperations &operations)
{
    return operations.read_running_board != 0 &&
           operations.read_candidate_boot_expected != 0 &&
           operations.read_firmware_reports_tryboot != 0 &&
           operations.read_filesystem_ready != 0 &&
           operations.read_menu_core_ready != 0 &&
           operations.read_safe_reboot_ready != 0 &&
           operations.read_hardware_watchdog_ready != 0;
}

bool ReadSelectorFile(UpdateFileSystem *file_system, const char *path,
                      uint8_t *bytes, size_t capacity, size_t *size)
{
    if (file_system == 0 || path == 0 || bytes == 0 || size == 0 ||
        capacity == 0U ||
        ValidateFatRelativePath(path, kInstallerMaximumPathBytes) !=
            FatPathValidationStatus::Ok) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile || stat.size == 0U ||
        stat.size >= capacity) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint64_t open_size = 0U;
    const size_t amount = static_cast<size_t>(stat.size);
    const bool read = file->GetSize(&open_size) && open_size == stat.size &&
                      file->ReadAt(0U, bytes, amount);
    const bool closed = file->Close();
    if (!read || !closed) return false;
    *size = amount;
    return true;
}

}  // namespace

uint32_t CompiledUpdaterAbi()
{
    return static_cast<uint32_t>(BMX_UPDATE_UPDATER_ABI);
}

ProductionCandidateConfigurationHealthSource::
    ProductionCandidateConfigurationHealthSource(const char *volume)
    : volume_(volume), snapshot_(), build_info_tokens_(),
      last_status_(ProductionCandidateConfigurationStatus::InvalidArgument),
      last_snapshot_status_(FatFsConfigSnapshotStatus::InvalidArgument),
      last_assessment_status_(ConfigAssessmentStatus::InvalidInput)
{
}

CandidateConfigurationHealthStatus
ProductionCandidateConfigurationHealthSource::ValidateLocalConfiguration(
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest)
{
    last_status_ = ProductionCandidateConfigurationStatus::InvalidArgument;
    last_snapshot_status_ = FatFsConfigSnapshotStatus::InvalidArgument;
    last_assessment_status_ = ConfigAssessmentStatus::InvalidInput;
    // The production health boundary is intentionally fixed to the boot
    // volume; accepting a caller-selected volume could validate a stale copy.
    if (volume_ == 0 || strcmp(volume_, "SYS:") != 0 ||
        !CompiledIdentityValid()) {
        return CandidateConfigurationHealthStatus::Unavailable;
    }
    if (!BindingMatchesManifest(binding, manifest)) {
        last_status_ = ProductionCandidateConfigurationStatus::BindingMismatch;
        return CandidateConfigurationHealthStatus::Invalid;
    }
    if (manifest.schema_count != kConfigMigrationAreaCount ||
        manifest.migration_count > kMaximumDeclaredConfigMigrations ||
        manifest.minimum_updater_abi == 0U ||
        manifest.maximum_updater_abi < manifest.minimum_updater_abi) {
        last_status_ =
            ProductionCandidateConfigurationStatus::ManifestPolicyInvalid;
        return CandidateConfigurationHealthStatus::Invalid;
    }

    last_snapshot_status_ = snapshot_.Load(volume_);
    if (last_snapshot_status_ != FatFsConfigSnapshotStatus::Ok) {
        last_status_ =
            ProductionCandidateConfigurationStatus::SnapshotUnavailable;
        return CandidateConfigurationHealthStatus::Unavailable;
    }

    ConfigSchemaRequirement requirements[kConfigMigrationAreaCount];
    for (size_t index = 0U; index < manifest.schema_count; ++index) {
        requirements[index].area = manifest.schemas[index].area;
        requirements[index].target_version =
            manifest.schemas[index].target_version;
        requirements[index].accepted_versions =
            manifest.schemas[index].accepted_versions;
        requirements[index].accepted_version_count =
            manifest.schemas[index].accepted_version_count;
    }
    DeclaredConfigMigration migrations[kMaximumDeclaredConfigMigrations];
    for (size_t index = 0U; index < manifest.migration_count; ++index) {
        migrations[index].id = manifest.migrations[index].id;
        migrations[index].area = manifest.migrations[index].area;
        migrations[index].from_version = manifest.migrations[index].from_version;
        migrations[index].to_version = manifest.migrations[index].to_version;
        migrations[index].lossy = manifest.migrations[index].lossy;
    }
    ConfigMigrationPlan plan;
    last_assessment_status_ = AssessConfigSnapshot(
        snapshot_.snapshot(), requirements, manifest.schema_count, migrations,
        manifest.migration_count, &plan);
    if (last_assessment_status_ != ConfigAssessmentStatus::Ok) {
        last_status_ =
            ProductionCandidateConfigurationStatus::AssessmentFailed;
        return CandidateConfigurationHealthStatus::Invalid;
    }
    if (!PlanIsStagedTarget(plan, manifest)) {
        last_status_ =
            ProductionCandidateConfigurationStatus::TargetSchemaMismatch;
        return CandidateConfigurationHealthStatus::Invalid;
    }
    if (!BuildInfoMatchesActiveSource(snapshot_.snapshot(), binding,
                                      build_info_tokens_,
                                      kBuildInfoTokenCapacity)) {
        last_status_ =
            ProductionCandidateConfigurationStatus::
                ActiveSourceBuildInfoMismatch;
        return CandidateConfigurationHealthStatus::Invalid;
    }
    last_status_ = ProductionCandidateConfigurationStatus::Ok;
    return CandidateConfigurationHealthStatus::Valid;
}

const char *ProductionCandidateConfigurationStatusString(
    ProductionCandidateConfigurationStatus status)
{
    switch (status) {
    case ProductionCandidateConfigurationStatus::Ok: return "ok";
    case ProductionCandidateConfigurationStatus::InvalidArgument:
        return "invalid argument";
    case ProductionCandidateConfigurationStatus::BindingMismatch:
        return "candidate binding mismatch";
    case ProductionCandidateConfigurationStatus::ManifestPolicyInvalid:
        return "candidate manifest configuration policy invalid";
    case ProductionCandidateConfigurationStatus::SnapshotUnavailable:
        return "candidate configuration snapshot unavailable";
    case ProductionCandidateConfigurationStatus::AssessmentFailed:
        return "candidate configuration assessment failed";
    case ProductionCandidateConfigurationStatus::TargetSchemaMismatch:
        return "candidate configuration is not at the target schema";
    case ProductionCandidateConfigurationStatus::ActiveSourceBuildInfoMismatch:
        return "active source build metadata mismatch";
    }
    return "unknown candidate configuration status";
}

SelectorCandidateBootObservation::SelectorCandidateBootObservation(
    UpdateFileSystem *file_system, BoardFamily board,
    const char *active_selector, const char *candidate_selector)
    : file_system_(file_system), board_(board),
      active_selector_(active_selector), candidate_selector_(candidate_selector),
      selector_bytes_(),
      last_status_(SelectorCandidateBootObservationStatus::InvalidArgument)
{
}

bool SelectorCandidateBootObservation::ReadSelector(
    const char *path, ParsedKernelSelector *selector)
{
    size_t size = 0U;
    if (!ReadSelectorFile(file_system_, path, selector_bytes_,
                          sizeof(selector_bytes_), &size)) {
        last_status_ = SelectorCandidateBootObservationStatus::FileUnavailable;
        return false;
    }
    if (ParseKernelSelector(ByteView(selector_bytes_, size), board_, selector) !=
        KernelSelectorStatus::Ok) {
        last_status_ = SelectorCandidateBootObservationStatus::SelectorInvalid;
        return false;
    }
    return true;
}

bool SelectorCandidateBootObservation::ReadCandidateBootExpected(bool *expected)
{
    if (expected != 0) *expected = false;
    last_status_ = SelectorCandidateBootObservationStatus::InvalidArgument;
    if (expected == 0 || file_system_ == 0 ||
        !IsKnownBoardFamily(board_) || active_selector_ == 0 ||
        candidate_selector_ == 0 ||
        strcmp(active_selector_, candidate_selector_) == 0) {
        return false;
    }
    ParsedKernelSelector active;
    ParsedKernelSelector candidate;
    if (!ReadSelector(active_selector_, &active) ||
        !ReadSelector(candidate_selector_, &candidate)) {
        return false;
    }
    *expected = !active.candidate &&
        strcmp(active.machine, candidate.machine) == 0 &&
        (candidate.candidate ||
         strcmp(active.kernel_path, candidate.kernel_path) == 0);
    last_status_ = SelectorCandidateBootObservationStatus::Ok;
    return true;
}

bool SelectorCandidateBootObservation::ReadCallback(void *context,
                                                    bool *expected)
{
    if (context == 0) {
        if (expected != 0) *expected = false;
        return false;
    }
    return static_cast<SelectorCandidateBootObservation *>(context)
        ->ReadCandidateBootExpected(expected);
}

const char *SelectorCandidateBootObservationStatusString(
    SelectorCandidateBootObservationStatus status)
{
    switch (status) {
    case SelectorCandidateBootObservationStatus::Ok: return "ok";
    case SelectorCandidateBootObservationStatus::InvalidArgument:
        return "invalid argument";
    case SelectorCandidateBootObservationStatus::FileUnavailable:
        return "selector file unavailable";
    case SelectorCandidateBootObservationStatus::SelectorInvalid:
        return "selector invalid";
    }
    return "unknown selector candidate observation status";
}

ProductionCandidateRuntimeOperations
EmptyProductionCandidateRuntimeOperations()
{
    ProductionCandidateRuntimeOperations operations;
    memset(&operations, 0, sizeof(operations));
    return operations;
}

bool ReadFirmwareTrybootObservation(void *, bool *value)
{
    if (value != 0) *value = false;
    if (value == 0 || !TrybootObservationHardwareGateEnabled()) return false;
    *value = RunningBootWasOneShotTryboot();
    return true;
}

bool ReadCandidateWatchdogObservation(void *context, bool *value)
{
    if (value != 0) *value = false;
    if (context == 0 || value == 0 ||
        !UpdateWatchdogHardwareGateEnabled()) {
        return false;
    }
    *value = static_cast<CandidateUpdateWatchdog *>(context)->IsRunning();
    return true;
}

ProductionCandidateRuntimeReadiness
ProductionCandidateRuntimeReadinessForCallbacks(
    const ProductionCandidateRuntimeOperations &operations)
{
    ProductionCandidateRuntimeReadiness readiness;
    memset(&readiness, 0, sizeof(readiness));
    readiness.compiled_identity_available = CompiledIdentityValid();
    readiness.running_board_observation_available =
        operations.read_running_board != 0;
    readiness.filesystem_observation_available =
        operations.read_filesystem_ready != 0;
    readiness.menu_core_observation_available =
        operations.read_menu_core_ready != 0;
    readiness.candidate_boot_observation_validated =
        operations.read_candidate_boot_expected != 0;
    readiness.firmware_tryboot_observation_validated =
        TrybootObservationHardwareGateEnabled() &&
        operations.read_firmware_reports_tryboot != 0;
    readiness.safe_reboot_observation_validated =
        TrybootHardwareGateEnabled() &&
        operations.read_safe_reboot_ready != 0;
    readiness.watchdog_observation_validated =
        UpdateWatchdogHardwareGateEnabled() &&
        operations.read_hardware_watchdog_ready != 0;
    return readiness;
}

bool ProductionCandidateRuntimeReady(
    const ProductionCandidateRuntimeReadiness &readiness)
{
    return readiness.compiled_identity_available &&
           readiness.running_board_observation_available &&
           readiness.candidate_boot_observation_validated &&
           readiness.firmware_tryboot_observation_validated &&
           readiness.filesystem_observation_available &&
           readiness.menu_core_observation_available &&
           readiness.safe_reboot_observation_validated &&
           readiness.watchdog_observation_validated;
}

ProductionCandidateRuntimeHealthSource::
    ProductionCandidateRuntimeHealthSource(
        const ProductionCandidateRuntimeOperations &operations)
    : operations_(operations),
      readiness_(ProductionCandidateRuntimeReadinessForCallbacks(operations)),
      last_status_(ProductionCandidateRuntimeStatus::InvalidArgument)
{
}

#if defined(BMX_UPDATE_HEALTH_TESTING)
ProductionCandidateRuntimeHealthSource::
    ProductionCandidateRuntimeHealthSource(
        const ProductionCandidateRuntimeOperations &operations,
        const ProductionCandidateRuntimeReadiness &test_readiness)
    : operations_(operations), readiness_(test_readiness),
      last_status_(ProductionCandidateRuntimeStatus::InvalidArgument)
{
}
#endif

bool ProductionCandidateRuntimeHealthSource::CollectLocalObservations(
    CandidateRuntimeHealthObservations *observations)
{
    if (observations != 0) memset(observations, 0, sizeof(*observations));
    last_status_ = ProductionCandidateRuntimeStatus::InvalidArgument;
    if (observations == 0 || !RuntimeOperationsComplete(operations_)) {
        return false;
    }
    if (!ProductionCandidateRuntimeReady(readiness_)) {
        last_status_ = ProductionCandidateRuntimeStatus::PlatformNotValidated;
        return false;
    }
    if (!CompiledIdentityValid()) {
        last_status_ = ProductionCandidateRuntimeStatus::CompiledIdentityInvalid;
        return false;
    }

    CandidateRuntimeHealthObservations collected;
    memset(&collected, 0, sizeof(collected));
    collected.running_updater_abi = CompiledUpdaterAbi();
    if (!operations_.read_running_board(operations_.running_board_context,
                                        &collected.running_board) ||
        !operations_.read_candidate_boot_expected(
            operations_.candidate_boot_context,
            &collected.candidate_boot_expected) ||
        !operations_.read_firmware_reports_tryboot(
            operations_.firmware_tryboot_context,
            &collected.firmware_reports_tryboot) ||
        !operations_.read_filesystem_ready(
            operations_.filesystem_context, &collected.filesystem_ready) ||
        !operations_.read_menu_core_ready(
            operations_.menu_core_context, &collected.menu_core_ready) ||
        !operations_.read_safe_reboot_ready(
            operations_.safe_reboot_context, &collected.safe_reboot_ready) ||
        !operations_.read_hardware_watchdog_ready(
            operations_.watchdog_context,
            &collected.hardware_watchdog_ready)) {
        last_status_ = ProductionCandidateRuntimeStatus::ObservationUnavailable;
        return false;
    }
    *observations = collected;
    last_status_ = ProductionCandidateRuntimeStatus::Ok;
    return true;
}

const char *ProductionCandidateRuntimeStatusString(
    ProductionCandidateRuntimeStatus status)
{
    switch (status) {
    case ProductionCandidateRuntimeStatus::Ok: return "ok";
    case ProductionCandidateRuntimeStatus::InvalidArgument:
        return "invalid argument";
    case ProductionCandidateRuntimeStatus::PlatformNotValidated:
        return "candidate runtime platform not validated";
    case ProductionCandidateRuntimeStatus::CompiledIdentityInvalid:
        return "compiled candidate identity invalid";
    case ProductionCandidateRuntimeStatus::ObservationUnavailable:
        return "candidate runtime observation unavailable";
    }
    return "unknown candidate runtime status";
}

}  // namespace update
}  // namespace bmx
