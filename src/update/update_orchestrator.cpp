#include "update/update_orchestrator.h"

#include "update/fat_path_policy.h"
#include "update/sha256.h"
#include "update/signature_envelope.h"
#include "update/url_policy.h"

#include <string.h>

namespace bmx {
namespace update {
namespace {

static const size_t kMinimumOrchestratorBufferBytes = 4096U;

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) combined |= bytes[index];
    return combined != 0U;
}

bool TerminatedWithin(const char *text, size_t capacity)
{
    return text != 0 && capacity != 0U && memchr(text, '\0', capacity) != 0;
}

bool NonEmptyTerminatedWithin(const char *text, size_t capacity)
{
    return TerminatedWithin(text, capacity) && text[0] != '\0';
}

bool EqualTextBounded(const char *left, const char *right, size_t capacity)
{
    if (!TerminatedWithin(left, capacity) ||
        !TerminatedWithin(right, capacity)) return false;
    return strcmp(left, right) == 0;
}

bool AssetBelongsToRelease(const GitHubLatestRelease &release,
                           const GitHubReleaseAsset *candidate,
                           const GitHubReleaseAsset **asset)
{
    if (asset == 0) return false;
    *asset = 0;
    if (release.assets == 0 || release.asset_count == 0U ||
        release.asset_count > kMaximumGitHubReleaseAssets || candidate == 0) {
        return false;
    }
    for (size_t index = 0U; index < release.asset_count; ++index) {
        if (candidate == &release.assets[index]) {
            *asset = &release.assets[index];
            return true;
        }
    }
    return false;
}

GitHubReleaseKind ReleaseKind(ReleaseAcquisitionMode mode)
{
    return mode == ReleaseAcquisitionMode::PreparedDraft
               ? GitHubReleaseKind::PreparedDraft
               : GitHubReleaseKind::PublishedStable;
}

bool AcquisitionModeValid(ReleaseAcquisitionMode mode)
{
    return mode == ReleaseAcquisitionMode::PublishedStable ||
           mode == ReleaseAcquisitionMode::PreparedDraft;
}

bool AssetStringsValid(const GitHubReleaseAsset &asset,
                       ReleaseAcquisitionMode mode)
{
    const char *download_url = GitHubAssetDownloadUrl(asset, ReleaseKind(mode));
    if (!NonEmptyTerminatedWithin(asset.name, sizeof(asset.name)) ||
        download_url == 0 || download_url[0] == '\0' ||
        asset.size == 0U) {
        return false;
    }
    ParsedUpdateUrl parsed;
    return ParseAndAuthorizeUpdateUrl(
               download_url,
               mode == ReleaseAcquisitionMode::PreparedDraft
                   ? UpdateUrlPurpose::AuthenticatedReleaseAsset
                   : UpdateUrlPurpose::ReleaseAsset,
               &parsed) == UrlPolicyStatus::Ok;
}

bool OfferConfigurationAdvisoryValid(const ReleaseOffer &offer)
{
    if (offer.reset_area_count > kMaximumConfigAreas) return false;
    if (offer.configuration_status == OfferConfigurationStatus::Compatible) {
        return offer.reset_area_count == 0U;
    }
    if (offer.configuration_status !=
            OfferConfigurationStatus::ResetConfirmationRequired &&
        offer.configuration_status !=
            OfferConfigurationStatus::BlockedIncompatible) {
        return false;
    }
    if (offer.configuration_status ==
            OfferConfigurationStatus::ResetConfirmationRequired &&
        offer.reset_area_count == 0U) return false;
    for (size_t index = 0U; index < offer.reset_area_count; ++index) {
        if (!IsKnownConfigArea(offer.reset_areas[index])) return false;
        for (size_t prior = 0U; prior < index; ++prior) {
            if (offer.reset_areas[index] == offer.reset_areas[prior]) {
                return false;
            }
        }
    }
    return true;
}

enum class RequestValidation : uint8_t {
    Ok = 0,
    InvalidArgument,
    OfferInvalid,
    IdentityInvalid,
    ConsentInvalid
};

RequestValidation ValidateAuthenticatedRequest(
    const AuthenticatedUpdateRequest &request,
    const ReleaseOffer &offer,
    uint8_t manifest_digest[kSha256DigestBytes])
{
    if (manifest_digest == 0 || request.release == 0 ||
        !IsKnownBoardFamily(request.running_board) ||
        request.transaction_root == 0) {
        return RequestValidation::InvalidArgument;
    }
    const ValidatedReleaseDownload &download = *request.release;
    const ReleaseManifest &manifest = offer.manifest;

    if (!AcquisitionModeValid(download.acquisition_mode) ||
        download.installed_build_info.data == 0 ||
        download.installed_build_info.size == 0U ||
        download.installed_build_info.size > kMaximumBuildInfoBytes ||
        download.github_response.data == 0 ||
        download.github_response.size == 0U ||
        download.github_response.size > kMaximumGitHubReleaseResponseBytes ||
        download.manifest.data == 0 || download.manifest.size == 0U ||
        download.manifest.size > kMaximumReleaseManifestBytes ||
        download.signature.data == 0 || download.signature.size == 0U ||
        download.signature.size > kMaximumSignatureEnvelopeBytes ||
        !Sha256Digest(download.manifest, manifest_digest)) {
        return RequestValidation::OfferInvalid;
    }
    const bool expected_draft = download.acquisition_mode ==
                                ReleaseAcquisitionMode::PreparedDraft;
    if (offer.release_decision != ReleaseDecision::UpdateAvailable ||
        offer.github.draft != expected_draft || offer.github.prerelease ||
        !NonEmptyTerminatedWithin(offer.github.tag_name,
                                  sizeof(offer.github.tag_name)) ||
        !NonEmptyTerminatedWithin(manifest.tag, sizeof(manifest.tag)) ||
        !NonEmptyTerminatedWithin(manifest.version, sizeof(manifest.version)) ||
        !NonEmptyTerminatedWithin(manifest.asset.filename,
                                  sizeof(manifest.asset.filename)) ||
        strcmp(offer.github.tag_name, manifest.tag) != 0 ||
        offer.installed.board != request.running_board ||
        manifest.asset.board != request.running_board ||
        offer.installed.release_sequence == 0U ||
        manifest.release_sequence <= offer.installed.release_sequence ||
        offer.installed.updater_abi == 0U ||
        manifest.minimum_updater_abi == 0U ||
        manifest.maximum_updater_abi < manifest.minimum_updater_abi ||
        offer.installed.updater_abi < manifest.minimum_updater_abi ||
        offer.installed.updater_abi > manifest.maximum_updater_abi ||
        manifest.release_epoch < offer.installed.release_epoch ||
        manifest.asset.download_size == 0U ||
        !BytesNonZero(manifest.asset.sha256, kSha256DigestBytes) ||
        manifest.asset.files == 0 || manifest.asset.file_count == 0U ||
        manifest.asset.file_count > kMaximumManifestFiles ||
        manifest.asset.directory_count > kMaximumManifestDirectories ||
        (manifest.asset.directory_count != 0U &&
         manifest.asset.directories == 0)) {
        return RequestValidation::OfferInvalid;
    }

    const GitHubReleaseAsset *manifest_asset = 0;
    const GitHubReleaseAsset *signature_asset = 0;
    const GitHubReleaseAsset *archive_asset = 0;
    if (!AssetBelongsToRelease(offer.github, offer.assets.manifest,
                               &manifest_asset) ||
        !AssetBelongsToRelease(offer.github, offer.assets.signature,
                               &signature_asset) ||
        !AssetBelongsToRelease(offer.github, offer.assets.board_zip,
                               &archive_asset) ||
        manifest_asset == signature_asset || manifest_asset == archive_asset ||
        signature_asset == archive_asset ||
        !AssetStringsValid(*manifest_asset, download.acquisition_mode) ||
        !AssetStringsValid(*signature_asset, download.acquisition_mode) ||
        !AssetStringsValid(*archive_asset, download.acquisition_mode) ||
        strcmp(manifest_asset->name, "BMX-RELEASE.json") != 0 ||
        strcmp(signature_asset->name, "BMX-RELEASE.sig") != 0 ||
        manifest_asset->size != download.manifest.size ||
        signature_asset->size != download.signature.size ||
        archive_asset->size != manifest.asset.download_size ||
        strcmp(archive_asset->name, manifest.asset.filename) != 0) {
        return RequestValidation::OfferInvalid;
    }
    RequiredGitHubReleaseAssets rebound;
    if (FindRequiredAssetsForKind(
            offer.github, ReleaseKind(download.acquisition_mode), manifest.tag,
            manifest.asset.filename, &rebound) !=
            RequiredGitHubAssetsStatus::Ok ||
        rebound.manifest != manifest_asset ||
        rebound.signature != signature_asset ||
        rebound.board_zip != archive_asset) {
        return RequestValidation::OfferInvalid;
    }

    if (!NonEmptyTerminatedWithin(request.transaction_root,
                                  kInstallerMaximumPathBytes + 1U) ||
        ValidateFatRelativePath(request.transaction_root,
                                kInstallerMaximumPathBytes) !=
            FatPathValidationStatus::Ok ||
        strlen(request.transaction_root) + 1U + strlen("metadata-old") + 1U +
                kMaximumManifestPathBytes >
            kInstallerMaximumPathBytes ||
        !BytesNonZero(request.transaction_id, kTransactionIdBytes) ||
        request.old_boot_generation == 0U ||
        request.new_boot_generation <= request.old_boot_generation) {
        return RequestValidation::IdentityInvalid;
    }
    if (!BytesNonZero(request.consent_sha256, kSha256DigestBytes)) {
        return RequestValidation::ConsentInvalid;
    }
    // BMX-BUILD.json can only provide an advisory view of configuration:
    // users may have replaced the actual files since that build was
    // installed.  Still validate the advisory POD shape fail-closed, but do
    // not bind consent to it.  AuthorizeAndSeal() immediately re-reads the
    // local files and is the sole authority for whether reset is required.
    if (!OfferConfigurationAdvisoryValid(offer)) {
        return RequestValidation::OfferInvalid;
    }
    if (request.reset_required != request.reset_approved) {
        return RequestValidation::ConsentInvalid;
    }
    return RequestValidation::Ok;
}

void BuildBinding(const AuthenticatedUpdateRequest &request,
                  const ReleaseOffer &offer,
                  const uint8_t manifest_digest[kSha256DigestBytes],
                  const SealedUpdateAuthorization &authorization,
                  AuthenticatedUpdateBinding *binding)
{
    memset(binding, 0, sizeof(*binding));
    binding->archive_url = GitHubAssetDownloadUrl(
        *offer.assets.board_zip, ReleaseKind(request.release->acquisition_mode));
    binding->archive_filename = offer.manifest.asset.filename;
    binding->transaction_root = request.transaction_root;
    binding->board = request.running_board;
    binding->source_release_sequence = offer.installed.release_sequence;
    binding->target_release_sequence = offer.manifest.release_sequence;
    binding->old_boot_generation = request.old_boot_generation;
    binding->new_boot_generation = request.new_boot_generation;
    binding->archive_size = offer.manifest.asset.download_size;
    memcpy(binding->transaction_id, request.transaction_id,
           kTransactionIdBytes);
    memcpy(binding->archive_sha256, offer.manifest.asset.sha256,
           kSha256DigestBytes);
    memcpy(binding->manifest_sha256, manifest_digest,
           kSha256DigestBytes);
    memcpy(binding->consent_sha256, authorization.consent_sha256,
           kSha256DigestBytes);
    binding->reset_required = authorization.reset_required;
    binding->reset_approved = authorization.reset_approved;
}

InstallerRequest BuildInstallerRequest(
    const ReleaseOffer &offer,
    const AuthenticatedUpdateBinding &binding,
    SeekableZipSource *archive,
    const PreparedConfigSet *prepared,
    UpdateRecoveryProgress *recovery_progress)
{
    InstallerRequest installer_request;
    memset(&installer_request, 0, sizeof(installer_request));
    installer_request.manifest = &offer.manifest;
    installer_request.downloaded_zip = archive;
    installer_request.transaction_root = binding.transaction_root;
    memcpy(installer_request.identity.transaction_id, binding.transaction_id,
           kTransactionIdBytes);
    installer_request.identity.source_release_sequence =
        binding.source_release_sequence;
    installer_request.identity.source_version = offer.installed.version;
    installer_request.identity.old_boot_generation =
        binding.old_boot_generation;
    installer_request.identity.new_boot_generation =
        binding.new_boot_generation;
    memcpy(installer_request.identity.manifest_sha256,
           binding.manifest_sha256, kSha256DigestBytes);
    memcpy(installer_request.identity.consent_sha256,
           binding.consent_sha256, kSha256DigestBytes);
    installer_request.identity.reset_required = binding.reset_required;
    installer_request.identity.reset_approved = binding.reset_approved;
    installer_request.prepared_configs = prepared;
    installer_request.recovery_progress = recovery_progress;
    return installer_request;
}

size_t ConfigTemplateCount(const ReleaseManifest &manifest)
{
    size_t count = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        if (manifest.asset.files[index].policy ==
            ManifestFilePolicy::ConfigTemplate) ++count;
    }
    return count;
}

bool PreparedSetValid(const PreparedConfigSet *set,
                      const AuthenticatedUpdateBinding &binding,
                      const ReleaseManifest &manifest,
                      bool require_content)
{
    if (set == 0 ||
        !ConstantTimeDigestEqual(set->manifest_sha256,
                                 binding.manifest_sha256) ||
        !ConstantTimeDigestEqual(set->consent_sha256,
                                 binding.consent_sha256) ||
        set->reset_required != binding.reset_required ||
        set->reset_approved != binding.reset_approved) {
        return false;
    }
    const size_t required = ConfigTemplateCount(manifest);
    if (set->entry_count != required ||
        (required != 0U && set->entries == 0)) return false;

    for (size_t entry_index = 0U; entry_index < set->entry_count;
         ++entry_index) {
        const PreparedConfigTemplate &entry = set->entries[entry_index];
        if (!NonEmptyTerminatedWithin(entry.path,
                                      kMaximumManifestPathBytes + 1U) ||
            (require_content && entry.content == 0) ||
            !BytesNonZero(entry.prepared_sha256, kSha256DigestBytes) ||
            (entry.original_existed &&
             !BytesNonZero(entry.original_sha256, kSha256DigestBytes)) ||
            (!entry.original_existed &&
             (entry.original_size != 0U ||
              BytesNonZero(entry.original_sha256, kSha256DigestBytes)))) {
            return false;
        }
        size_t matches = 0U;
        for (size_t file_index = 0U;
             file_index < manifest.asset.file_count; ++file_index) {
            const ManifestFile &file = manifest.asset.files[file_index];
            if (file.policy == ManifestFilePolicy::ConfigTemplate &&
                EqualTextBounded(entry.path, file.path,
                                 kMaximumManifestPathBytes + 1U)) ++matches;
        }
        if (matches != 1U) return false;
        for (size_t prior = 0U; prior < entry_index; ++prior) {
            if (EqualTextBounded(entry.path, set->entries[prior].path,
                                 kMaximumManifestPathBytes + 1U)) return false;
        }
    }
    return true;
}

bool WorkspaceValid(const UpdateOrchestratorWorkspace &workspace,
                    bool start_phase)
{
    if (workspace.release_offer == 0 ||
        workspace.verification_buffer == 0 ||
        workspace.verification_buffer_size <
            kMinimumOrchestratorBufferBytes ||
        workspace.installer.io_buffer == 0 ||
        workspace.installer.io_buffer_size <
            kInstallerMinimumIoBufferBytes) {
        return false;
    }
    if (!start_phase) return workspace.recovery_progress != 0;
    return workspace.installer.zip_entries != 0 &&
           workspace.installer.expected_files != 0 &&
           workspace.installer.zip_workspace != 0;
}

bool WorkspaceFitsManifest(const UpdateOrchestratorWorkspace &workspace,
                           const ReleaseManifest &manifest)
{
    const ManifestAsset &asset = manifest.asset;
    if (asset.file_count > kZipMaximumEntries ||
        asset.directory_count > kZipMaximumEntries - asset.file_count) {
        return false;
    }
    return workspace.installer.zip_entry_capacity >=
               asset.file_count + asset.directory_count &&
           workspace.installer.expected_file_capacity >= asset.file_count &&
           (asset.directory_count == 0U ||
            (workspace.installer.expected_directories != 0 &&
             workspace.installer.expected_directory_capacity >=
                 asset.directory_count));
}

bool RehashStoredArchive(SeekableZipSource *source,
                         const AuthenticatedUpdateBinding &binding,
                         uint8_t *buffer, size_t buffer_size,
                         uint64_t *verified_size,
                         UpdateRecoveryProgress *progress,
                         bool *progress_failed)
{
    if (source == 0 || buffer == 0 || buffer_size == 0U ||
        verified_size == 0 || progress_failed == 0) return false;
    *verified_size = 0U;
    *progress_failed = false;
    uint64_t size = 0U;
    if (!source->GetSize(&size) || size != binding.archive_size) return false;
    Sha256 hash;
    uint64_t offset = 0U;
    while (offset < size) {
        const uint64_t remaining = size - offset;
        const size_t count = remaining < buffer_size
            ? static_cast<size_t>(remaining) : buffer_size;
        if (!source->ReadAt(offset, buffer, count) ||
            !hash.Update(buffer, count)) return false;
        offset += count;
        if (!ReportUpdateRecoveryProgress(
                progress, UpdateRecoveryProgressKind::StoredArchiveHashed,
                offset, size)) {
            *progress_failed = true;
            return false;
        }
    }
    uint8_t digest[kSha256DigestBytes];
    if (!hash.Final(digest) ||
        !ConstantTimeDigestEqual(digest, binding.archive_sha256)) return false;
    *verified_size = size;
    return true;
}

InstallerResult InvalidInstallerResult()
{
    InstallerResult result;
    memset(&result, 0, sizeof(result));
    result.status = InstallerStatus::InvalidArgument;
    result.zip_status = ZipStatus::InvalidArgument;
    result.journal_selection = JournalSelectionStatus::NoJournal;
    result.journal_state = JournalState::Idle;
    return result;
}

UpdateOrchestratorResult InitialResult()
{
    UpdateOrchestratorResult result;
    memset(&result, 0, sizeof(result));
    result.status = UpdateOrchestratorStatus::InvalidArgument;
    result.phase = UpdateOrchestratorPhase::None;
    result.fetch_status = ArchiveFetchStatus::Failed;
    result.storage_status = ArchiveStorageStatus::Failed;
    result.persistence_status = UpdateRequestPersistenceStatus::Failed;
    result.prepared_config_status = PreparedConfigProviderStatus::Unsupported;
    result.release_validation.status =
        AuthenticatedReleaseValidationStatus::InvalidArgument;
    result.release_validation.offer_result.status =
        ReleaseOfferStatus::InvalidArgument;
    result.authorization.status = AuthorizationConsentStatus::InvalidArgument;
    result.authorization.start_decision =
        UpdateStartDecision::NotExplicitUserAction;
    result.authorization.config_status =
        CurrentConfigConsentStatus::InvalidOrBlocked;
    result.readiness_status = InstallReadinessGateStatus::ProbeFailed;
    result.readiness.storage.decision = StorageDecision::InvalidLimits;
    result.health_status = CandidateHealthStatus::JournalUnavailable;
    result.rollback_trigger = UpdateOrchestratorStatus::InvalidArgument;
    result.installer_result = InvalidInstallerResult();
    result.rollback_result = InvalidInstallerResult();
    result.rollback_cleanup_result = InvalidInstallerResult();
    return result;
}

bool StageAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::AlreadyStaged;
}

bool ArmAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::AlreadyArmed;
}

bool HealthMarkAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::AlreadyHealthy;
}

bool CommitAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::AlreadyCommitted;
}

bool RollbackAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::NothingToRollback;
}

bool RolledBackRetirementAccepted(InstallerStatus status)
{
    return status == InstallerStatus::Ok ||
           status == InstallerStatus::AlreadyRetired;
}

UpdateOrchestratorStatus InstallerProgressOr(
    InstallerStatus status, UpdateOrchestratorStatus fallback)
{
    return status == InstallerStatus::RecoveryProgressFailed
        ? UpdateOrchestratorStatus::RecoveryProgressFailed
        : fallback;
}

bool HasTransactionJournal(const InstallerResult &result)
{
    return result.journal_selection == JournalSelectionStatus::SelectedA ||
           result.journal_selection == JournalSelectionStatus::SelectedB ||
           result.journal_selection ==
               JournalSelectionStatus::SelectedEquivalentCopies;
}

bool JournalBoundToTransaction(
    const JournalRecord &record,
    const AuthenticatedUpdateBinding &binding)
{
    if (record.state == JournalState::Idle) return true;
    const bool reset_required =
        (record.flags & kJournalFlagResetRequired) != 0U;
    const bool reset_approved =
        (record.flags & kJournalFlagResetApproved) != 0U;
    return memcmp(record.transaction_id, binding.transaction_id,
                  kTransactionIdBytes) == 0 &&
           record.source_release_sequence ==
               binding.source_release_sequence &&
           record.target_release_sequence ==
               binding.target_release_sequence &&
           record.board == binding.board &&
           ConstantTimeDigestEqual(record.manifest_sha256,
                                   binding.manifest_sha256) &&
           ConstantTimeDigestEqual(record.zip_sha256,
                                   binding.archive_sha256) &&
           ConstantTimeDigestEqual(record.consent_sha256,
                                   binding.consent_sha256) &&
           record.old_boot_generation == binding.old_boot_generation &&
           record.new_boot_generation == binding.new_boot_generation &&
           reset_required == binding.reset_required &&
           reset_approved == binding.reset_approved;
}

bool HealthEvidenceBound(const CandidateHealthEvidence &evidence,
                         const ReleaseManifest &manifest)
{
    return evidence.manifest_board == manifest.asset.board &&
           evidence.target_release_sequence == manifest.release_sequence &&
           evidence.minimum_updater_abi == manifest.minimum_updater_abi &&
           evidence.maximum_updater_abi == manifest.maximum_updater_abi;
}

bool CleanupTransaction(UpdateArchiveStorage *storage,
                        UpdateRequestPersistence *request_persistence,
                        PreparedConfigProvider *prepared_configs,
                        const AuthenticatedUpdateBinding &binding,
                        UpdateRecoveryProgress *recovery_progress,
                        UpdateOrchestratorResult *result)
{
    if (storage == 0 || request_persistence == 0 ||
        prepared_configs == 0 || result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    result->storage_status = storage->Discard(binding, recovery_progress);
    if (result->storage_status != ArchiveStorageStatus::Ok) {
        // Prepared evidence is the only remaining durable key to safe retry;
        // never delete it while the bound archive could not be discarded.
        return false;
    }
    result->prepared_config_status = prepared_configs->Discard(
        binding, recovery_progress);
    if (result->prepared_config_status != PreparedConfigProviderStatus::Ok) {
        // Keep the activation record until all configuration evidence has
        // been removed so an interrupted cleanup remains recoverable.
        return false;
    }
    result->persistence_status =
        request_persistence->DiscardPersisted(binding, recovery_progress);
    return result->persistence_status == UpdateRequestPersistenceStatus::Ok;
}

// Rollback first restores all live files and durably enters IDLE. Keep the
// authenticated request until the installer-owned stage/snapshot/journal
// artifacts have also been retired: otherwise a reset in this gap would lose
// the only signed inventory capable of cleaning the fixed transaction root.
bool CleanupRolledBackTransaction(
    UpdateArchiveStorage *storage,
    UpdateRequestPersistence *request_persistence,
    PreparedConfigProvider *prepared_configs,
    UpdateInstallOperations *installer,
    const InstallerRequest &installer_request,
    const InstallerWorkspace &installer_workspace,
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress,
    UpdateOrchestratorResult *result)
{
    if (storage == 0 || request_persistence == 0 || prepared_configs == 0 ||
        installer == 0 || result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    result->storage_status = storage->Discard(binding, recovery_progress);
    if (result->storage_status != ArchiveStorageStatus::Ok) return false;
    result->prepared_config_status = prepared_configs->Discard(
        binding, recovery_progress);
    if (result->prepared_config_status != PreparedConfigProviderStatus::Ok) {
        return false;
    }
    result->rollback_cleanup_result = installer->RetireRolledBack(
        installer_request, installer_workspace);
    if (!RolledBackRetirementAccepted(
            result->rollback_cleanup_result.status)) {
        return false;
    }
    result->persistence_status =
        request_persistence->DiscardPersisted(binding, recovery_progress);
    return result->persistence_status == UpdateRequestPersistenceStatus::Ok;
}

bool RetainCommittedTransaction(UpdateArchiveStorage *storage,
                                UpdateRequestPersistence *request_persistence,
                                PreparedConfigProvider *prepared_configs,
                                const AuthenticatedUpdateBinding &binding,
                                UpdateRecoveryProgress *recovery_progress,
                                UpdateOrchestratorResult *result)
{
    if (storage == 0 || request_persistence == 0 ||
        prepared_configs == 0 || result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    result->storage_status = storage->Discard(binding, recovery_progress);
    if (result->storage_status != ArchiveStorageStatus::Ok) return false;
    result->prepared_config_status = prepared_configs->Discard(
        binding, recovery_progress);
    if (result->prepared_config_status != PreparedConfigProviderStatus::Ok) {
        return false;
    }
    // Rename activation to an inert committed record last. The four signed
    // raw inputs and installer snapshot remain available for a later explicit
    // retirement; boot recovery cannot see the committed filename.
    result->persistence_status = request_persistence->RetainCommitted(
        binding, recovery_progress);
    return result->persistence_status == UpdateRequestPersistenceStatus::Ok;
}

UpdateOrchestratorStatus CleanupFailureStatus(
    const UpdateOrchestratorResult &result)
{
    // CleanupTransaction runs these owners strictly in this order and stops
    // at the first failure.  Classify that failing owner only: later result
    // fields can still contain the trigger status from work performed before
    // cleanup (for example a canceled final prepared-archive hash).
    if (result.storage_status != ArchiveStorageStatus::Ok) {
        return result.storage_status ==
                       ArchiveStorageStatus::RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::CleanupFailed;
    }
    if (result.prepared_config_status !=
        PreparedConfigProviderStatus::Ok) {
        return result.prepared_config_status ==
                       PreparedConfigProviderStatus::RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::CleanupFailed;
    }
    if (result.persistence_status != UpdateRequestPersistenceStatus::Ok) {
        return result.persistence_status ==
                       UpdateRequestPersistenceStatus::RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::CleanupFailed;
    }
    return UpdateOrchestratorStatus::CleanupFailed;
}

UpdateOrchestratorStatus RolledBackCleanupFailureStatus(
    const UpdateOrchestratorResult &result)
{
    if (result.storage_status != ArchiveStorageStatus::Ok ||
        result.prepared_config_status != PreparedConfigProviderStatus::Ok) {
        return CleanupFailureStatus(result);
    }
    if (!RolledBackRetirementAccepted(
            result.rollback_cleanup_result.status)) {
        return result.rollback_cleanup_result.status ==
                       InstallerStatus::RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::CleanupFailed;
    }
    return CleanupFailureStatus(result);
}

bool DiscardDownloadedRequest(UpdateArchiveStorage *storage,
                              UpdateRequestPersistence *request_persistence,
                              const AuthenticatedUpdateBinding &binding,
                              UpdateRecoveryProgress *recovery_progress,
                              UpdateOrchestratorResult *result)
{
    if (storage == 0 || request_persistence == 0 || result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    result->storage_status = storage->Discard(binding, recovery_progress);
    if (result->storage_status != ArchiveStorageStatus::Ok) return false;
    result->persistence_status =
        request_persistence->DiscardPersisted(binding, recovery_progress);
    return result->persistence_status == UpdateRequestPersistenceStatus::Ok;
}

bool AbortDownloadAndDiscardRequest(
    UpdateArchiveStorage *storage,
    UpdateRequestPersistence *request_persistence,
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress,
    UpdateOrchestratorResult *result)
{
    if (storage == 0 || request_persistence == 0 || result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    storage->Abort();
    result->persistence_status =
        request_persistence->DiscardPersisted(binding, recovery_progress);
    return result->persistence_status == UpdateRequestPersistenceStatus::Ok;
}

bool DeactivatePendingRequest(UpdateRequestPersistence *request_persistence,
                              UpdateRecoveryProgress *recovery_progress,
                              UpdateOrchestratorResult *result)
{
    if (result == 0) return false;
    ScopedMandatoryUpdateRecoveryOperation mandatory(recovery_progress);
    result->persistence_status = request_persistence == 0
        ? UpdateRequestPersistenceStatus::Failed
        : request_persistence->DeactivatePersisted(recovery_progress);
    if (result->persistence_status != UpdateRequestPersistenceStatus::Ok) {
        result->status = result->persistence_status ==
                                 UpdateRequestPersistenceStatus::
                                     RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::RecoveryDeactivationFailed;
        return false;
    }
    return true;
}

InstallerResult MandatoryRollback(
    UpdateInstallOperations *installer, const InstallerRequest &request,
    const InstallerWorkspace &workspace)
{
    if (installer == 0) return InvalidInstallerResult();
    ScopedMandatoryUpdateRecoveryOperation mandatory(
        request.recovery_progress);
    return installer->Rollback(request, workspace);
}

void RequestPreviousFailSafe(UpdateRequestPersistence *request_persistence,
                             UpdateRebootControl *reboot,
                             UpdateOrchestratorStatus trigger,
                             UpdateRecoveryProgress *recovery_progress,
                             UpdateOrchestratorResult *result)
{
    if (result == 0) return;
    result->rollback_trigger = trigger;
    result->phase = UpdateOrchestratorPhase::RequestPreviousReboot;
    // A rejected persisted request is terminal.  Remove the fixed activation
    // record before any reboot so the same invalid request cannot be selected
    // again on the next boot.  Never derive this path from rejected input.
    if (!DeactivatePendingRequest(request_persistence, recovery_progress,
                                  result)) return;
    result->previous_boot_failsafe_requested = true;
    if (reboot == 0 || !reboot->RequestPreviousBootFailSafe()) {
        result->status = UpdateOrchestratorStatus::PreviousRebootFailed;
        return;
    }
    result->status = trigger;
}

}  // namespace

RawAuthenticatedReleaseValidator::RawAuthenticatedReleaseValidator(
    const TrustedReleaseKey *trusted_keys, size_t trusted_key_count,
    VerifyP256SignatureFunction verify_function, void *verify_context,
    const ReleaseOfferStorage &storage)
    : trusted_keys_(trusted_keys), trusted_key_count_(trusted_key_count),
      verify_function_(verify_function), verify_context_(verify_context),
      storage_(storage)
{
}

AuthenticatedReleaseValidationResult
RawAuthenticatedReleaseValidator::Revalidate(
    const ValidatedReleaseDownload &download, BoardFamily running_board,
    ReleaseOffer *fresh_offer)
{
    AuthenticatedReleaseValidationResult result;
    memset(&result, 0, sizeof(result));
    result.status = AuthenticatedReleaseValidationStatus::InvalidArgument;
    result.offer_result.status = ReleaseOfferStatus::InvalidArgument;
    if (fresh_offer == 0 || !AcquisitionModeValid(download.acquisition_mode) ||
        download.installed_build_info.data == 0 ||
        download.installed_build_info.size == 0U ||
        download.github_response.data == 0 ||
        download.github_response.size == 0U || download.manifest.data == 0 ||
        download.manifest.size == 0U || download.signature.data == 0 ||
        download.signature.size == 0U ||
        !IsKnownBoardFamily(running_board) || trusted_keys_ == 0 ||
        trusted_key_count_ == 0U || verify_function_ == 0) {
        return result;
    }
    result.offer_result = BuildReleaseOfferForMode(
        download.installed_build_info, download.github_response,
        download.manifest, download.signature, running_board,
        download.acquisition_mode, trusted_keys_,
        trusted_key_count_, verify_function_, verify_context_, storage_,
        fresh_offer);
    result.status = result.offer_result.status == ReleaseOfferStatus::Ok
        ? AuthenticatedReleaseValidationStatus::Ok
        : AuthenticatedReleaseValidationStatus::AuthenticationRejected;
    return result;
}

ForegroundNetworkAuthorizationConsentGate::
ForegroundNetworkAuthorizationConsentGate(
    ForegroundUpdateAuthorizationSource *foreground_source,
    CurrentConfigConsentSource *config_source)
    : foreground_source_(foreground_source), config_source_(config_source)
{
}

AuthorizationConsentResult
ForegroundNetworkAuthorizationConsentGate::AuthorizeAndSeal(
    const AuthenticatedUpdateRequest &request, const ReleaseOffer &fresh_offer,
    SealedUpdateAuthorization *sealed)
{
    AuthorizationConsentResult result;
    memset(&result, 0, sizeof(result));
    result.status = AuthorizationConsentStatus::InvalidArgument;
    result.start_decision = UpdateStartDecision::NotExplicitUserAction;
    result.config_status = CurrentConfigConsentStatus::InvalidOrBlocked;
    if (sealed == 0 || foreground_source_ == 0 || config_source_ == 0 ||
        request.release == 0 ||
        !IsKnownBoardFamily(request.running_board)) return result;
    memset(sealed, 0, sizeof(*sealed));

    UpdateStartContext current;
    memset(&current, 0, sizeof(current));
    if (!foreground_source_->ConsumeAndReadCurrent(
            request.foreground_authorization_token, &current)) {
        result.status = AuthorizationConsentStatus::NotExplicitUserAction;
        return result;
    }
    result.start_decision = EvaluateUpdateStart(current);
    if (result.start_decision != UpdateStartDecision::Allowed) {
        result.status = result.start_decision ==
                                UpdateStartDecision::NetworkFeatureDisabled
            ? AuthorizationConsentStatus::NetworkFeatureDisabled
            : result.start_decision == UpdateStartDecision::NetworkNotReady
                ? AuthorizationConsentStatus::NetworkNotReady
                : AuthorizationConsentStatus::NotExplicitUserAction;
        return result;
    }

    CurrentConfigConsentEvidence evidence;
    memset(&evidence, 0, sizeof(evidence));
    uint8_t manifest_digest[kSha256DigestBytes];
    if (request.release->manifest.data == 0 ||
        request.release->manifest.size == 0U ||
        request.release->manifest.size > kMaximumReleaseManifestBytes ||
        !Sha256Digest(request.release->manifest, manifest_digest)) {
        result.status = AuthorizationConsentStatus::ConfigRevalidationFailed;
        result.config_status = CurrentConfigConsentStatus::DigestFailed;
        return result;
    }
    result.config_status = config_source_->ReReadAndCompute(
        fresh_offer, request.running_board, manifest_digest, &evidence);
    if (result.config_status != CurrentConfigConsentStatus::Ok) {
        result.status = AuthorizationConsentStatus::ConfigRevalidationFailed;
        return result;
    }
    if (!BytesNonZero(evidence.consent_sha256, kSha256DigestBytes) ||
        !ConstantTimeDigestEqual(evidence.consent_sha256,
                                 request.consent_sha256)) {
        result.status = AuthorizationConsentStatus::ConsentMismatch;
        return result;
    }

    bool reset_required = false;
    if (evidence.configuration_status ==
        OfferConfigurationStatus::Compatible) {
        reset_required = false;
    } else if (evidence.configuration_status ==
               OfferConfigurationStatus::ResetConfirmationRequired) {
        reset_required = true;
    } else {
        result.status = AuthorizationConsentStatus::ConfigBlocked;
        return result;
    }
    if (request.reset_required != reset_required ||
        request.reset_approved != reset_required) {
        result.status = AuthorizationConsentStatus::ResetDecisionMismatch;
        return result;
    }
    memcpy(sealed->consent_sha256, evidence.consent_sha256,
           kSha256DigestBytes);
    sealed->reset_required = reset_required;
    sealed->reset_approved = request.reset_approved;
    result.status = AuthorizationConsentStatus::Ok;
    return result;
}

ProbeInstallReadinessGate::ProbeInstallReadinessGate(
    UpdateFileSystem *file_system,
    const UpdateInstallPlatformReadiness &platform)
    : file_system_(file_system), platform_(platform)
{
}

InstallReadinessGateStatus ProbeInstallReadinessGate::Probe(
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest,
    UpdateInstallReadinessResult *readiness)
{
    if (readiness == 0 || file_system_ == 0 ||
        binding.board != manifest.asset.board ||
        binding.target_release_sequence != manifest.release_sequence) {
        return InstallReadinessGateStatus::ProbeFailed;
    }
    *readiness = ProbeUpdateInstallReadiness(file_system_, &manifest,
                                             platform_);
    return readiness->ready() ? InstallReadinessGateStatus::Ready
                              : InstallReadinessGateStatus::Blocked;
}

DirectUpdateInstallOperations::DirectUpdateInstallOperations(
    UpdateInstaller *installer)
    : installer_(installer)
{
}

InstallerResult DirectUpdateInstallOperations::ReadJournal(
    const char *transaction_root, JournalRecord *record)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->ReadJournal(transaction_root, record);
}

InstallerResult DirectUpdateInstallOperations::Stage(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->Stage(request, workspace);
}

InstallerResult DirectUpdateInstallOperations::ArmCandidate(
    const InstallerRequest &request)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->ArmCandidate(request);
}

InstallerResult DirectUpdateInstallOperations::MarkCandidateHealthy(
    const InstallerRequest &request)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->MarkCandidateHealthy(request);
}

InstallerResult DirectUpdateInstallOperations::Commit(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->Commit(request, workspace);
}

InstallerResult DirectUpdateInstallOperations::Rollback(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->Rollback(request, workspace);
}

InstallerResult DirectUpdateInstallOperations::RetireRolledBack(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->RetireRolledBack(request, workspace);
}

InstallerResult DirectUpdateInstallOperations::RetireCommitted(
    const InstallerRequest &request, const InstallerWorkspace &workspace)
{
    return installer_ == 0 ? InvalidInstallerResult()
                           : installer_->RetireCommitted(request, workspace);
}

UpdateOrchestrator::UpdateOrchestrator(
    AuthenticatedReleaseValidator *release_validator,
    AuthorizationConsentGate *authorization,
    InstallReadinessGate *readiness,
    UpdateArchiveTransport *transport, UpdateArchiveStorage *storage,
    UpdateRequestPersistence *request_persistence,
    PreparedConfigProvider *prepared_configs,
    UpdateInstallOperations *installer, CandidateHealthProbe *health,
    UpdateRebootControl *reboot)
    : release_validator_(release_validator), authorization_(authorization),
      readiness_(readiness), transport_(transport), storage_(storage),
      request_persistence_(request_persistence),
      prepared_configs_(prepared_configs), installer_(installer),
      health_(health), reboot_(reboot)
{
}

UpdateOrchestratorResult UpdateOrchestrator::Start(
    const AuthenticatedUpdateRequest &request,
    const UpdateOrchestratorWorkspace &workspace)
{
    UpdateOrchestratorResult result = InitialResult();
    result.phase = UpdateOrchestratorPhase::Validate;
    if (release_validator_ == 0 || authorization_ == 0 || readiness_ == 0 ||
        transport_ == 0 || storage_ == 0 || request_persistence_ == 0 ||
        prepared_configs_ == 0 || installer_ == 0 || health_ == 0 ||
        reboot_ == 0 ||
        !WorkspaceValid(workspace, true)) {
        return result;
    }

    ReleaseOffer &fresh_offer = *workspace.release_offer;
    memset(&fresh_offer, 0, sizeof(fresh_offer));
    if (request.release == 0) return result;
    result.release_validation = release_validator_->Revalidate(
        *request.release, request.running_board, &fresh_offer);
    if (result.release_validation.status !=
        AuthenticatedReleaseValidationStatus::Ok) {
        result.status = UpdateOrchestratorStatus::AuthenticatedOfferInvalid;
        return result;
    }

    uint8_t manifest_digest[kSha256DigestBytes];
    const RequestValidation validation = ValidateAuthenticatedRequest(
        request, fresh_offer, manifest_digest);
    if (validation != RequestValidation::Ok) {
        result.status = validation == RequestValidation::InvalidArgument
            ? UpdateOrchestratorStatus::InvalidArgument
            : validation == RequestValidation::OfferInvalid
                ? UpdateOrchestratorStatus::AuthenticatedOfferInvalid
                : validation == RequestValidation::IdentityInvalid
                    ? UpdateOrchestratorStatus::IdentityInvalid
                    : UpdateOrchestratorStatus::ConsentInvalid;
        return result;
    }
    if (!reboot_->OneShotRecoverySupported()) {
        result.status = UpdateOrchestratorStatus::PlatformUnsupported;
        return result;
    }
    if (!WorkspaceFitsManifest(workspace, fresh_offer.manifest)) {
        result.status = UpdateOrchestratorStatus::WorkspaceTooSmall;
        return result;
    }

    SealedUpdateAuthorization sealed;
    memset(&sealed, 0, sizeof(sealed));
    result.authorization = authorization_->AuthorizeAndSeal(
        request, fresh_offer, &sealed);
    if (result.authorization.status != AuthorizationConsentStatus::Ok ||
        !BytesNonZero(sealed.consent_sha256, kSha256DigestBytes) ||
        sealed.reset_required != request.reset_required ||
        sealed.reset_approved != request.reset_approved) {
        result.status = UpdateOrchestratorStatus::AuthorizationDenied;
        return result;
    }

    AuthenticatedUpdateBinding binding;
    BuildBinding(request, fresh_offer, manifest_digest, sealed, &binding);
    result.readiness_status = readiness_->Probe(
        binding, fresh_offer.manifest, &result.readiness);
    if (result.readiness_status != InstallReadinessGateStatus::Ready ||
        !result.readiness.ready()) {
        result.status = result.readiness_status ==
                                InstallReadinessGateStatus::ProbeFailed
            ? UpdateOrchestratorStatus::ReadinessProbeFailed
            : UpdateOrchestratorStatus::ReadinessBlocked;
        return result;
    }
    // This is the final cancelable safe point before storage_->Begin creates
    // the transaction archive. A cancel already latched by the foreground UI
    // therefore leaves both storage and request persistence untouched.
    result.phase = UpdateOrchestratorPhase::Download;
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::
                ForegroundDownloadMutationCheckpoint)) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    // No target/injected call is permitted between the complete read-only
    // readiness probe/checkpoint and creation of the transaction download.
    result.storage_status = storage_->Begin(binding);
    if (result.storage_status != ArchiveStorageStatus::Ok) {
        result.status = UpdateOrchestratorStatus::StorageBeginFailed;
        return result;
    }

    result.phase = UpdateOrchestratorPhase::PersistRequest;
    result.persistence_status = request_persistence_->Persist(request);
    if (result.persistence_status != UpdateRequestPersistenceStatus::Ok) {
        const bool cleanup_ok = AbortDownloadAndDiscardRequest(
            storage_, request_persistence_, binding,
            workspace.recovery_progress, &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::RequestPersistenceFailed
            : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }

    result.phase = UpdateOrchestratorPhase::Download;
    HashingBodySink hashing(storage_, binding.archive_size);
    result.fetch_status = transport_->Fetch(
        binding.archive_url, binding.archive_size, &hashing);
    if (result.fetch_status != ArchiveFetchStatus::Ok) {
        const UpdateOrchestratorStatus failure =
            result.fetch_status == ArchiveFetchStatus::Canceled
            ? UpdateOrchestratorStatus::DownloadCanceled
            : UpdateOrchestratorStatus::DownloadFailed;
        result.status = AbortDownloadAndDiscardRequest(
                            storage_, request_persistence_, binding,
                            workspace.recovery_progress, &result)
            ? failure : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }
    uint8_t streamed_digest[kSha256DigestBytes];
    if (!hashing.Finish(streamed_digest) ||
        !ConstantTimeDigestEqual(streamed_digest, binding.archive_sha256)) {
        result.status = AbortDownloadAndDiscardRequest(
                            storage_, request_persistence_, binding,
                            workspace.recovery_progress, &result)
            ? UpdateOrchestratorStatus::DownloadVerificationFailed
            : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }
    result.storage_status = storage_->Finish();
    if (result.storage_status != ArchiveStorageStatus::Ok) {
        result.status = AbortDownloadAndDiscardRequest(
                            storage_, request_persistence_, binding,
                            workspace.recovery_progress, &result)
            ? UpdateOrchestratorStatus::StorageFinishFailed
            : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }

    result.phase = UpdateOrchestratorPhase::VerifyStoredArchive;
    SeekableZipSource *archive = 0;
    result.storage_status = storage_->OpenRead(binding, &archive);
    if (result.storage_status != ArchiveStorageStatus::Ok || archive == 0) {
        result.status = DiscardDownloadedRequest(
                            storage_, request_persistence_, binding,
                            workspace.recovery_progress, &result)
            ? UpdateOrchestratorStatus::StorageOpenFailed
            : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }
    bool archive_hash_progress_failed = false;
    if (!RehashStoredArchive(archive, binding, workspace.verification_buffer,
                             workspace.verification_buffer_size,
                             &result.verified_archive_bytes,
                             workspace.recovery_progress,
                             &archive_hash_progress_failed)) {
        result.storage_status = storage_->CloseRead();
        result.status = DiscardDownloadedRequest(
                            storage_, request_persistence_, binding,
                            workspace.recovery_progress, &result)
            ? (archive_hash_progress_failed
                   ? UpdateOrchestratorStatus::RecoveryProgressFailed
                   : UpdateOrchestratorStatus::StoredArchiveVerificationFailed)
            : UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }

    result.phase = UpdateOrchestratorPhase::PrepareConfiguration;
    const PreparedConfigSet *prepared = 0;
    result.prepared_config_status = prepared_configs_->PrepareForStage(
        binding, fresh_offer.manifest, archive, &prepared,
        workspace.recovery_progress);
    if (result.prepared_config_status != PreparedConfigProviderStatus::Ok) {
        const bool prepare_progress_failed =
            result.prepared_config_status ==
            PreparedConfigProviderStatus::RecoveryProgressFailed;
        result.storage_status = storage_->CloseRead();
        const bool cleanup_ok = CleanupTransaction(
            storage_, request_persistence_, prepared_configs_, binding,
            workspace.recovery_progress,
            &result);
        result.status = cleanup_ok
            ? (prepare_progress_failed
                   ? UpdateOrchestratorStatus::RecoveryProgressFailed
                   : UpdateOrchestratorStatus::PreparedConfigFailed)
            : CleanupFailureStatus(result);
        return result;
    }
    if (!PreparedSetValid(prepared, binding, fresh_offer.manifest, true)) {
        result.storage_status = storage_->CloseRead();
        const bool cleanup_ok = CleanupTransaction(
            storage_, request_persistence_, prepared_configs_, binding,
            workspace.recovery_progress,
            &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::PreparedConfigInvalid
            : CleanupFailureStatus(result);
        return result;
    }

    const InstallerRequest installer_request = BuildInstallerRequest(
        fresh_offer, binding, archive, prepared,
        workspace.recovery_progress);
    result.phase = UpdateOrchestratorPhase::Stage;
    result.installer_result = installer_->Stage(installer_request,
                                                workspace.installer);
    result.storage_status = storage_->CloseRead();
    if (!StageAccepted(result.installer_result.status)) {
        result.status = InstallerProgressOr(
            result.installer_result.status,
            UpdateOrchestratorStatus::InstallerStageFailed);
        if (HasTransactionJournal(result.installer_result) &&
            result.installer_result.journal_state != JournalState::Idle) {
            result.phase = UpdateOrchestratorPhase::Rollback;
            result.rollback_attempted = true;
            result.rollback_result = MandatoryRollback(
                installer_, installer_request, workspace.installer);
            if (!RollbackAccepted(result.rollback_result.status)) {
                result.status = InstallerProgressOr(
                    result.rollback_result.status,
                    UpdateOrchestratorStatus::InstallerRollbackFailed);
                return result;
            }
        }
        if (!CleanupRolledBackTransaction(
                storage_, request_persistence_, prepared_configs_, installer_,
                installer_request, workspace.installer, binding,
                workspace.recovery_progress, &result)) {
            result.status = RolledBackCleanupFailureStatus(result);
        }
        return result;
    }
    if (result.storage_status != ArchiveStorageStatus::Ok) {
        result.phase = UpdateOrchestratorPhase::Rollback;
        result.rollback_attempted = true;
        result.rollback_result = MandatoryRollback(
            installer_, installer_request, workspace.installer);
        if (!RollbackAccepted(result.rollback_result.status)) {
            result.status = InstallerProgressOr(
                result.rollback_result.status,
                UpdateOrchestratorStatus::InstallerRollbackFailed);
            return result;
        }
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            installer_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::StorageCloseFailed
            : RolledBackCleanupFailureStatus(result);
        return result;
    }

    result.phase = UpdateOrchestratorPhase::ArmCandidate;
    result.installer_result = installer_->ArmCandidate(installer_request);
    if (!ArmAccepted(result.installer_result.status)) {
        const UpdateOrchestratorStatus arm_failure = InstallerProgressOr(
            result.installer_result.status,
            UpdateOrchestratorStatus::InstallerArmFailed);
        result.phase = UpdateOrchestratorPhase::Rollback;
        result.rollback_attempted = true;
        result.rollback_result = MandatoryRollback(
            installer_, installer_request, workspace.installer);
        if (!RollbackAccepted(result.rollback_result.status)) {
            result.status = InstallerProgressOr(
                result.rollback_result.status,
                UpdateOrchestratorStatus::InstallerRollbackFailed);
            return result;
        }
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            installer_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.phase = UpdateOrchestratorPhase::RequestPreviousReboot;
        if (!DeactivatePendingRequest(request_persistence_,
                                      workspace.recovery_progress, &result)) {
            return result;
        }
        if (!reboot_->RequestReboot(UpdateRebootTarget::PreviousInstallation,
                                    binding)) {
            result.status = UpdateOrchestratorStatus::PreviousRebootFailed;
            return result;
        }
        result.status = cleanup_ok
            ? arm_failure
            : RolledBackCleanupFailureStatus(result);
        return result;
    }

    result.phase = UpdateOrchestratorPhase::RequestCandidateReboot;
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::ForegroundStageComplete,
            1U, 1U) ||
        !ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::CandidateRebootCheckpoint)) {
        result.phase = UpdateOrchestratorPhase::Rollback;
        result.rollback_attempted = true;
        result.rollback_result = MandatoryRollback(
            installer_, installer_request, workspace.installer);
        if (!RollbackAccepted(result.rollback_result.status)) {
            result.status = InstallerProgressOr(
                result.rollback_result.status,
                UpdateOrchestratorStatus::InstallerRollbackFailed);
            return result;
        }
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            installer_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.phase = UpdateOrchestratorPhase::RequestPreviousReboot;
        if (!DeactivatePendingRequest(request_persistence_,
                                      workspace.recovery_progress, &result)) {
            return result;
        }
        if (!reboot_->RequestReboot(UpdateRebootTarget::PreviousInstallation,
                                    binding)) {
            result.status = UpdateOrchestratorStatus::PreviousRebootFailed;
            return result;
        }
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : RolledBackCleanupFailureStatus(result);
        return result;
    }
    if (!reboot_->RequestReboot(UpdateRebootTarget::OneShotCandidate,
                                binding)) {
        result.phase = UpdateOrchestratorPhase::Rollback;
        result.rollback_attempted = true;
        result.rollback_result = MandatoryRollback(
            installer_, installer_request, workspace.installer);
        if (!RollbackAccepted(result.rollback_result.status)) {
            result.status = InstallerProgressOr(
                result.rollback_result.status,
                UpdateOrchestratorStatus::InstallerRollbackFailed);
            return result;
        }
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            installer_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.phase = UpdateOrchestratorPhase::RequestPreviousReboot;
        if (!DeactivatePendingRequest(request_persistence_,
                                      workspace.recovery_progress, &result)) {
            return result;
        }
        if (!reboot_->RequestReboot(UpdateRebootTarget::PreviousInstallation,
                                    binding)) {
            result.status = UpdateOrchestratorStatus::PreviousRebootFailed;
            return result;
        }
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::CandidateRebootFailed
            : RolledBackCleanupFailureStatus(result);
        return result;
    }
    result.status = UpdateOrchestratorStatus::CandidateRebootRequested;
    return result;
}

UpdateOrchestratorResult UpdateOrchestrator::ResumeAfterBoot(
    const AuthenticatedUpdateRequest &request,
    const UpdateOrchestratorWorkspace &workspace)
{
    UpdateOrchestratorResult result = InitialResult();
    result.phase = UpdateOrchestratorPhase::Validate;
    if (release_validator_ == 0 || storage_ == 0 ||
        request_persistence_ == 0 || prepared_configs_ == 0 ||
        installer_ == 0 || health_ == 0 ||
        !WorkspaceValid(workspace, false)) {
        RequestPreviousFailSafe(request_persistence_, reboot_,
                                UpdateOrchestratorStatus::InvalidArgument,
                                0, &result);
        return result;
    }

    ReleaseOffer &fresh_offer = *workspace.release_offer;
    memset(&fresh_offer, 0, sizeof(fresh_offer));
    if (request.release == 0) {
        RequestPreviousFailSafe(request_persistence_, reboot_,
                                UpdateOrchestratorStatus::InvalidArgument,
                                workspace.recovery_progress, &result);
        return result;
    }
    result.release_validation = release_validator_->Revalidate(
        *request.release, request.running_board, &fresh_offer);
    if (result.release_validation.status !=
        AuthenticatedReleaseValidationStatus::Ok) {
        RequestPreviousFailSafe(
            request_persistence_, reboot_,
            UpdateOrchestratorStatus::AuthenticatedOfferInvalid,
            workspace.recovery_progress, &result);
        return result;
    }

    uint8_t manifest_digest[kSha256DigestBytes];
    const RequestValidation validation = ValidateAuthenticatedRequest(
        request, fresh_offer, manifest_digest);
    if (validation != RequestValidation::Ok) {
        const UpdateOrchestratorStatus failure =
            validation == RequestValidation::InvalidArgument
            ? UpdateOrchestratorStatus::InvalidArgument
            : validation == RequestValidation::OfferInvalid
                ? UpdateOrchestratorStatus::AuthenticatedOfferInvalid
                : validation == RequestValidation::IdentityInvalid
                    ? UpdateOrchestratorStatus::IdentityInvalid
                    : UpdateOrchestratorStatus::ConsentInvalid;
        RequestPreviousFailSafe(request_persistence_, reboot_, failure,
                                workspace.recovery_progress, &result);
        return result;
    }
    SealedUpdateAuthorization persisted;
    memset(&persisted, 0, sizeof(persisted));
    memcpy(persisted.consent_sha256, request.consent_sha256,
           kSha256DigestBytes);
    persisted.reset_required = request.reset_required;
    persisted.reset_approved = request.reset_approved;
    AuthenticatedUpdateBinding binding;
    BuildBinding(request, fresh_offer, manifest_digest, persisted, &binding);

    result.phase = UpdateOrchestratorPhase::InspectJournal;
    JournalRecord journal;
    memset(&journal, 0, sizeof(journal));
    result.installer_result = installer_->ReadJournal(
        binding.transaction_root, &journal);
    const bool no_journal =
        result.installer_result.status == InstallerStatus::WrongState &&
        result.installer_result.journal_selection ==
            JournalSelectionStatus::NoJournal;
    if (no_journal ||
        (result.installer_result.status == InstallerStatus::Ok &&
         journal.state == JournalState::Idle)) {
        const InstallerRequest cleanup_request = BuildInstallerRequest(
            fresh_offer, binding, 0, 0, workspace.recovery_progress);
        result.phase = UpdateOrchestratorPhase::Cleanup;
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            cleanup_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::InterruptedBeforeCandidateCleaned
            : RolledBackCleanupFailureStatus(result);
        return result;
    }
    if (result.installer_result.status != InstallerStatus::Ok ||
        !JournalBoundToTransaction(journal, binding)) {
        RequestPreviousFailSafe(
            request_persistence_, reboot_,
            UpdateOrchestratorStatus::RecoveryJournalInvalid,
            workspace.recovery_progress, &result);
        return result;
    }

    // COMMITTED is a durable point of no return: the candidate is already the
    // active installation and rollback is no longer a valid recovery action.
    // A reset between Commit() and cleanup retries only archive/prepared
    // cleanup, then atomically renames boot activation to an inert committed
    // record. The signed raw inputs, journal and previous config snapshot are
    // retained until a later explicit Update action retires them.
    if (journal.state == JournalState::Committed) {
        result.phase = UpdateOrchestratorPhase::Cleanup;
        const bool cleanup_ok = RetainCommittedTransaction(
            storage_, request_persistence_, prepared_configs_, binding,
            workspace.recovery_progress, &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::UpdateCommitted
            : CleanupFailureStatus(result) ==
                      UpdateOrchestratorStatus::RecoveryProgressFailed
                ? UpdateOrchestratorStatus::RecoveryProgressFailed
                : UpdateOrchestratorStatus::PreviousRetentionFailed;
        return result;
    }

    if (reboot_ == 0 || !reboot_->OneShotRecoverySupported()) {
        RequestPreviousFailSafe(
            request_persistence_, reboot_,
            UpdateOrchestratorStatus::PlatformUnsupported,
            workspace.recovery_progress, &result);
        return result;
    }

    result.phase = UpdateOrchestratorPhase::RestoreConfiguration;
    const PreparedConfigSet *prepared = 0;
    result.prepared_config_status = prepared_configs_->RestoreForResume(
        binding, fresh_offer.manifest, &prepared,
        workspace.recovery_progress);
    if (result.prepared_config_status != PreparedConfigProviderStatus::Ok) {
        if (result.prepared_config_status ==
            PreparedConfigProviderStatus::RecoveryProgressFailed) {
            result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
            return result;
        }
        RequestPreviousFailSafe(
            request_persistence_, reboot_,
            UpdateOrchestratorStatus::PreparedConfigFailed,
            workspace.recovery_progress, &result);
        return result;
    }
    if (!PreparedSetValid(prepared, binding, fresh_offer.manifest, false)) {
        RequestPreviousFailSafe(
            request_persistence_, reboot_,
            UpdateOrchestratorStatus::PreparedConfigInvalid,
            workspace.recovery_progress, &result);
        return result;
    }
    const InstallerRequest installer_request = BuildInstallerRequest(
        fresh_offer, binding, 0, prepared, workspace.recovery_progress);

    if (journal.state == JournalState::Discovered ||
        journal.state == JournalState::Downloaded) {
        result.phase = UpdateOrchestratorPhase::Rollback;
        result.rollback_attempted = true;
        result.rollback_result = MandatoryRollback(
            installer_, installer_request, workspace.installer);
        if (result.rollback_result.status ==
            InstallerStatus::RecoveryProgressFailed) {
            result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
            return result;
        }
        if (!RollbackAccepted(result.rollback_result.status)) {
            result.status = UpdateOrchestratorStatus::InstallerRollbackFailed;
            return result;
        }
        result.phase = UpdateOrchestratorPhase::Cleanup;
        const bool cleanup_ok = CleanupRolledBackTransaction(
            storage_, request_persistence_, prepared_configs_, installer_,
            installer_request, workspace.installer, binding,
            workspace.recovery_progress, &result);
        result.status = cleanup_ok
            ? UpdateOrchestratorStatus::InterruptedBeforeCandidateCleaned
            : RolledBackCleanupFailureStatus(result);
        return result;
    }

    result.phase = UpdateOrchestratorPhase::ProbeHealth;
    CandidateHealthEvidence evidence;
    memset(&evidence, 0, sizeof(evidence));
    const bool evidence_available = health_->Collect(
        binding, fresh_offer.manifest, &evidence);
    result.health_status = evidence_available &&
                           HealthEvidenceBound(evidence,
                                               fresh_offer.manifest)
        ? EvaluateCandidateHealth(evidence)
        : CandidateHealthStatus::JournalUnavailable;
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::CandidateHealthEvaluated,
            static_cast<uint64_t>(result.health_status),
            static_cast<uint64_t>(evidence.probe_status))) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }

    UpdateOrchestratorStatus trigger = UpdateOrchestratorStatus::CandidateUnhealthy;
    if (!evidence_available) {
        trigger = UpdateOrchestratorStatus::HealthProbeFailed;
    } else if (result.health_status == CandidateHealthStatus::Healthy) {
        result.phase = UpdateOrchestratorPhase::MarkHealthy;
        result.installer_result =
            installer_->MarkCandidateHealthy(installer_request);
        if (result.installer_result.status ==
            InstallerStatus::RecoveryProgressFailed) {
            result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
            return result;
        }
        if (HealthMarkAccepted(result.installer_result.status)) {
            result.phase = UpdateOrchestratorPhase::Commit;
            result.installer_result = installer_->Commit(installer_request,
                                                          workspace.installer);
            if (result.installer_result.status ==
                InstallerStatus::RecoveryProgressFailed) {
                result.status =
                    UpdateOrchestratorStatus::RecoveryProgressFailed;
                return result;
            }
            if (CommitAccepted(result.installer_result.status)) {
                result.phase = UpdateOrchestratorPhase::Cleanup;
                if (!RetainCommittedTransaction(
                        storage_, request_persistence_, prepared_configs_,
                        binding, workspace.recovery_progress, &result)) {
                    result.status = CleanupFailureStatus(result) ==
                                            UpdateOrchestratorStatus::
                                                RecoveryProgressFailed
                        ? UpdateOrchestratorStatus::RecoveryProgressFailed
                        : UpdateOrchestratorStatus::PreviousRetentionFailed;
                    return result;
                }
                result.status = UpdateOrchestratorStatus::UpdateCommitted;
                return result;
            }
            trigger = UpdateOrchestratorStatus::InstallerCommitFailed;
        } else {
            trigger =
                UpdateOrchestratorStatus::InstallerHealthTransitionFailed;
        }
    }

    result.phase = UpdateOrchestratorPhase::Rollback;
    result.rollback_trigger = trigger;
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::CandidateRollbackDecision,
            static_cast<uint64_t>(trigger),
            static_cast<uint64_t>(result.installer_result.status))) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    result.rollback_attempted = true;
    result.rollback_result = MandatoryRollback(
        installer_, installer_request, workspace.installer);
    if (result.rollback_result.status ==
        InstallerStatus::RecoveryProgressFailed) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    if (!RollbackAccepted(result.rollback_result.status)) {
        result.status = UpdateOrchestratorStatus::InstallerRollbackFailed;
        return result;
    }
    result.phase = UpdateOrchestratorPhase::Cleanup;
    const bool cleanup_ok = CleanupRolledBackTransaction(
        storage_, request_persistence_, prepared_configs_, installer_,
        installer_request, workspace.installer, binding,
        workspace.recovery_progress, &result);
    if (!cleanup_ok &&
        RolledBackCleanupFailureStatus(result) ==
            UpdateOrchestratorStatus::RecoveryProgressFailed) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    result.phase = UpdateOrchestratorPhase::RequestPreviousReboot;
    if (!DeactivatePendingRequest(request_persistence_,
                                  workspace.recovery_progress, &result)) {
        return result;
    }
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::CandidateRollbackComplete,
            1U, 1U)) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    if (!reboot_->RequestReboot(UpdateRebootTarget::PreviousInstallation,
                                binding)) {
        result.status = UpdateOrchestratorStatus::PreviousRebootFailed;
        return result;
    }
    if (!cleanup_ok) {
        result.status = UpdateOrchestratorStatus::CleanupFailed;
        return result;
    }
    // The safe outcome is primary; rollback_trigger retains why it happened.
    result.status = UpdateOrchestratorStatus::RollbackRebootRequested;
    return result;
}

UpdateOrchestratorResult UpdateOrchestrator::RetireCommitted(
    const AuthenticatedUpdateRequest &request,
    const UpdateOrchestratorWorkspace &workspace)
{
    UpdateOrchestratorResult result = InitialResult();
    result.phase = UpdateOrchestratorPhase::Validate;
    if (release_validator_ == 0 || request_persistence_ == 0 ||
        installer_ == 0 || !WorkspaceValid(workspace, true) ||
        request.release == 0) {
        return result;
    }

    ReleaseOffer &fresh_offer = *workspace.release_offer;
    memset(&fresh_offer, 0, sizeof(fresh_offer));
    result.release_validation = release_validator_->Revalidate(
        *request.release, request.running_board, &fresh_offer);
    if (result.release_validation.status !=
        AuthenticatedReleaseValidationStatus::Ok) {
        result.status = UpdateOrchestratorStatus::AuthenticatedOfferInvalid;
        return result;
    }
    uint8_t manifest_digest[kSha256DigestBytes];
    const RequestValidation validation = ValidateAuthenticatedRequest(
        request, fresh_offer, manifest_digest);
    if (validation != RequestValidation::Ok) {
        result.status = validation == RequestValidation::InvalidArgument
            ? UpdateOrchestratorStatus::InvalidArgument
            : validation == RequestValidation::OfferInvalid
                ? UpdateOrchestratorStatus::AuthenticatedOfferInvalid
                : validation == RequestValidation::IdentityInvalid
                    ? UpdateOrchestratorStatus::IdentityInvalid
                    : UpdateOrchestratorStatus::ConsentInvalid;
        return result;
    }
    SealedUpdateAuthorization retained;
    memset(&retained, 0, sizeof(retained));
    memcpy(retained.consent_sha256, request.consent_sha256,
           kSha256DigestBytes);
    retained.reset_required = request.reset_required;
    retained.reset_approved = request.reset_approved;
    AuthenticatedUpdateBinding binding;
    BuildBinding(request, fresh_offer, manifest_digest, retained, &binding);
    const InstallerRequest installer_request = BuildInstallerRequest(
        fresh_offer, binding, 0, 0, workspace.recovery_progress);

    result.phase = UpdateOrchestratorPhase::RetirePrevious;
    // Retirement deletes the retained previous installation. Honor a
    // foreground cancel while that backup is still completely untouched;
    // once retirement begins, its journaled cleanup remains mandatory.
    if (!ReportUpdateRecoveryProgress(
            workspace.recovery_progress,
            UpdateRecoveryProgressKind::ForegroundRetireMutationCheckpoint)) {
        result.status = UpdateOrchestratorStatus::RecoveryProgressFailed;
        return result;
    }
    ScopedMandatoryUpdateRecoveryOperation mandatory_retirement(
        workspace.recovery_progress);
    result.installer_result = installer_->RetireCommitted(
        installer_request, workspace.installer);
    if (result.installer_result.status != InstallerStatus::Ok &&
        result.installer_result.status != InstallerStatus::AlreadyRetired) {
        result.status = result.installer_result.status ==
                                InstallerStatus::RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::PreviousRetentionFailed;
        return result;
    }
    result.persistence_status =
        request_persistence_->DiscardRetainedCommitted(
            binding, workspace.recovery_progress);
    if (result.persistence_status != UpdateRequestPersistenceStatus::Ok) {
        result.status = result.persistence_status ==
                                UpdateRequestPersistenceStatus::
                                    RecoveryProgressFailed
            ? UpdateOrchestratorStatus::RecoveryProgressFailed
            : UpdateOrchestratorStatus::PreviousRetentionFailed;
        return result;
    }
    result.status = UpdateOrchestratorStatus::PreviousRetired;
    return result;
}

const char *UpdateOrchestratorStatusString(UpdateOrchestratorStatus status)
{
    switch (status) {
    case UpdateOrchestratorStatus::CandidateRebootRequested:
        return "candidate-reboot-requested";
    case UpdateOrchestratorStatus::UpdateCommitted: return "update-committed";
    case UpdateOrchestratorStatus::RollbackRebootRequested:
        return "rollback-reboot-requested";
    case UpdateOrchestratorStatus::InterruptedBeforeCandidateCleaned:
        return "interrupted-before-candidate-cleaned";
    case UpdateOrchestratorStatus::InvalidArgument: return "invalid-argument";
    case UpdateOrchestratorStatus::AuthenticatedOfferInvalid:
        return "authenticated-offer-invalid";
    case UpdateOrchestratorStatus::IdentityInvalid: return "identity-invalid";
    case UpdateOrchestratorStatus::ConsentInvalid: return "consent-invalid";
    case UpdateOrchestratorStatus::AuthorizationDenied:
        return "authorization-denied";
    case UpdateOrchestratorStatus::PlatformUnsupported:
        return "platform-unsupported";
    case UpdateOrchestratorStatus::WorkspaceTooSmall:
        return "workspace-too-small";
    case UpdateOrchestratorStatus::ReadinessBlocked:
        return "readiness-blocked";
    case UpdateOrchestratorStatus::ReadinessProbeFailed:
        return "readiness-probe-failed";
    case UpdateOrchestratorStatus::StorageBeginFailed:
        return "storage-begin-failed";
    case UpdateOrchestratorStatus::RequestPersistenceFailed:
        return "request-persistence-failed";
    case UpdateOrchestratorStatus::DownloadFailed: return "download-failed";
    case UpdateOrchestratorStatus::DownloadCanceled:
        return "download-canceled";
    case UpdateOrchestratorStatus::DownloadVerificationFailed:
        return "download-verification-failed";
    case UpdateOrchestratorStatus::StorageFinishFailed:
        return "storage-finish-failed";
    case UpdateOrchestratorStatus::StorageOpenFailed:
        return "storage-open-failed";
    case UpdateOrchestratorStatus::StoredArchiveVerificationFailed:
        return "stored-archive-verification-failed";
    case UpdateOrchestratorStatus::StorageCloseFailed:
        return "storage-close-failed";
    case UpdateOrchestratorStatus::PreparedConfigFailed:
        return "prepared-config-failed";
    case UpdateOrchestratorStatus::PreparedConfigInvalid:
        return "prepared-config-invalid";
    case UpdateOrchestratorStatus::InstallerStageFailed:
        return "installer-stage-failed";
    case UpdateOrchestratorStatus::InstallerArmFailed:
        return "installer-arm-failed";
    case UpdateOrchestratorStatus::CandidateRebootFailed:
        return "candidate-reboot-failed";
    case UpdateOrchestratorStatus::HealthProbeFailed:
        return "health-probe-failed";
    case UpdateOrchestratorStatus::CandidateUnhealthy:
        return "candidate-unhealthy";
    case UpdateOrchestratorStatus::InstallerHealthTransitionFailed:
        return "installer-health-transition-failed";
    case UpdateOrchestratorStatus::InstallerCommitFailed:
        return "installer-commit-failed";
    case UpdateOrchestratorStatus::InstallerRollbackFailed:
        return "installer-rollback-failed";
    case UpdateOrchestratorStatus::RecoveryJournalInvalid:
        return "recovery-journal-invalid";
    case UpdateOrchestratorStatus::RecoveryDeactivationFailed:
        return "recovery-deactivation-failed";
    case UpdateOrchestratorStatus::PreviousRebootFailed:
        return "previous-reboot-failed";
    case UpdateOrchestratorStatus::RecoveryProgressFailed:
        return "recovery-progress-failed";
    case UpdateOrchestratorStatus::PreviousRetentionFailed:
        return "previous-retention-failed";
    case UpdateOrchestratorStatus::PreviousRetired:
        return "previous-retired";
    case UpdateOrchestratorStatus::CleanupFailed: return "cleanup-failed";
    }
    return "unknown-update-orchestrator-status";
}

const char *UpdateOrchestratorPhaseString(UpdateOrchestratorPhase phase)
{
    switch (phase) {
    case UpdateOrchestratorPhase::None: return "none";
    case UpdateOrchestratorPhase::Validate: return "validate";
    case UpdateOrchestratorPhase::InspectJournal: return "inspect-journal";
    case UpdateOrchestratorPhase::PersistRequest: return "persist-request";
    case UpdateOrchestratorPhase::Download: return "download";
    case UpdateOrchestratorPhase::VerifyStoredArchive:
        return "verify-stored-archive";
    case UpdateOrchestratorPhase::PrepareConfiguration:
        return "prepare-configuration";
    case UpdateOrchestratorPhase::Stage: return "stage";
    case UpdateOrchestratorPhase::ArmCandidate: return "arm-candidate";
    case UpdateOrchestratorPhase::RequestCandidateReboot:
        return "request-candidate-reboot";
    case UpdateOrchestratorPhase::RestoreConfiguration:
        return "restore-configuration";
    case UpdateOrchestratorPhase::ProbeHealth: return "probe-health";
    case UpdateOrchestratorPhase::MarkHealthy: return "mark-healthy";
    case UpdateOrchestratorPhase::Commit: return "commit";
    case UpdateOrchestratorPhase::Rollback: return "rollback";
    case UpdateOrchestratorPhase::RequestPreviousReboot:
        return "request-previous-reboot";
    case UpdateOrchestratorPhase::Cleanup: return "cleanup";
    case UpdateOrchestratorPhase::RetirePrevious: return "retire-previous";
    }
    return "unknown-update-orchestrator-phase";
}

const char *AuthorizationConsentStatusString(
    AuthorizationConsentStatus status)
{
    switch (status) {
    case AuthorizationConsentStatus::Ok: return "ok";
    case AuthorizationConsentStatus::InvalidArgument:
        return "invalid-argument";
    case AuthorizationConsentStatus::NotExplicitUserAction:
        return "not-explicit-user-action";
    case AuthorizationConsentStatus::NetworkFeatureDisabled:
        return "network-feature-disabled";
    case AuthorizationConsentStatus::NetworkNotReady:
        return "network-not-ready";
    case AuthorizationConsentStatus::ConfigRevalidationFailed:
        return "config-revalidation-failed";
    case AuthorizationConsentStatus::ConfigBlocked:
        return "config-blocked";
    case AuthorizationConsentStatus::ConsentMismatch:
        return "consent-mismatch";
    case AuthorizationConsentStatus::ResetDecisionMismatch:
        return "reset-decision-mismatch";
    }
    return "unknown-authorization-consent-status";
}

const char *UpdateStartDecisionString(UpdateStartDecision decision)
{
    switch (decision) {
    case UpdateStartDecision::Allowed: return "allowed";
    case UpdateStartDecision::NotExplicitUserAction:
        return "not-explicit-user-action";
    case UpdateStartDecision::NetworkFeatureDisabled:
        return "network-feature-disabled";
    case UpdateStartDecision::NetworkNotReady: return "network-not-ready";
    }
    return "unknown-update-start-decision";
}

const char *CurrentConfigConsentStatusString(
    CurrentConfigConsentStatus status)
{
    switch (status) {
    case CurrentConfigConsentStatus::Ok: return "ok";
    case CurrentConfigConsentStatus::ReadFailed: return "read-failed";
    case CurrentConfigConsentStatus::InvalidOrBlocked:
        return "invalid-or-blocked";
    case CurrentConfigConsentStatus::DigestFailed: return "digest-failed";
    }
    return "unknown-current-config-consent-status";
}

}  // namespace update
}  // namespace bmx
