#include "update/release_offer.h"

#include <string.h>

namespace bmx {
namespace update {

namespace {

ReleaseOfferResult MakeResult(ReleaseOfferStatus status) {
    ReleaseOfferResult result;
    memset(&result, 0, sizeof(result));
    result.status = status;
    result.build_info_status = BuildInfoStatus::InvalidArgument;
    result.github_status = GitHubReleaseParseStatus::InvalidArgument;
    result.assets_status = RequiredGitHubAssetsStatus::InvalidArgument;
    result.manifest_status = ManifestParseStatus::InvalidArgument;
    result.trust_status = ManifestTrustStatus::InvalidArgument;
    result.release_decision = ReleaseDecision::InvalidCandidateMetadata;
    return result;
}

bool StorageIsValid(const ReleaseOfferStorage &storage) {
    return storage.installed_tokens != 0 &&
           storage.installed_token_capacity != 0U &&
           storage.github_tokens != 0 &&
           storage.github_token_capacity != 0U &&
           storage.github_assets != 0 &&
           storage.github_asset_capacity != 0U &&
           storage.manifest_tokens != 0 &&
           storage.manifest_token_capacity != 0U &&
           storage.manifest_files != 0 &&
           storage.manifest_file_capacity != 0U &&
           storage.manifest_directories != 0 &&
           storage.manifest_directory_capacity != 0U;
}

bool SchemaAccepts(const ManifestConfigSchema &schema, uint32_t version) {
    for (size_t i = 0U; i < schema.accepted_version_count; ++i) {
        if (schema.accepted_versions[i] == version) return true;
    }
    return false;
}

const InstalledSchemaVersion *FindInstalledSchema(
    const InstalledBuildInfo &installed, ConfigArea area) {
    for (size_t i = 0U; i < installed.schema_count; ++i) {
        if (installed.schemas[i].area == area) return &installed.schemas[i];
    }
    return 0;
}

const ManifestMigration *FindMigration(const ReleaseManifest &manifest,
                                       ConfigArea area,
                                       uint32_t from_version,
                                       uint32_t to_version) {
    for (size_t i = 0U; i < manifest.migration_count; ++i) {
        const ManifestMigration &migration = manifest.migrations[i];
        if (migration.area == area && migration.from_version == from_version &&
            migration.to_version == to_version) {
            return &migration;
        }
    }
    return 0;
}

OfferConfigurationStatus ClassifySchemas(ReleaseOffer *offer) {
    bool blocked = false;
    offer->reset_area_count = 0U;
    for (size_t i = 0U; i < offer->manifest.schema_count; ++i) {
        const ManifestConfigSchema &target = offer->manifest.schemas[i];
        const InstalledSchemaVersion *source =
            FindInstalledSchema(offer->installed, target.area);
        if (source == 0 || source->version > target.target_version) {
            blocked = true;
            continue;
        }
        if (SchemaAccepts(target, source->version)) continue;
        const ManifestMigration *migration = FindMigration(
            offer->manifest, target.area, source->version,
            target.target_version);
        if (migration == 0) {
            blocked = true;
            continue;
        }
        if (!migration->lossy) continue;
        if (offer->reset_area_count >= kMaximumConfigAreas) {
            blocked = true;
            continue;
        }
        offer->reset_areas[offer->reset_area_count++] = target.area;
    }
    if (blocked) return OfferConfigurationStatus::BlockedIncompatible;
    return offer->reset_area_count == 0U
               ? OfferConfigurationStatus::Compatible
               : OfferConfigurationStatus::ResetConfirmationRequired;
}

}  // namespace

ReleaseOfferResult BuildReleaseOffer(
    ByteView installed_build_info,
    ByteView github_latest_response,
    ByteView manifest_bytes,
    ByteView signature_envelope,
    BoardFamily running_board,
    const TrustedReleaseKey *trusted_keys,
    size_t trusted_key_count,
    VerifyP256SignatureFunction verify_function,
    void *verify_context,
    const ReleaseOfferStorage &storage,
    ReleaseOffer *offer) {
    return BuildReleaseOfferForMode(
        installed_build_info, github_latest_response, manifest_bytes,
        signature_envelope, running_board,
        ReleaseAcquisitionMode::PublishedStable, trusted_keys,
        trusted_key_count, verify_function, verify_context, storage, offer);
}

ReleaseOfferResult BuildReleaseOfferForMode(
    ByteView installed_build_info, ByteView github_latest_response,
    ByteView manifest_bytes, ByteView signature_envelope,
    BoardFamily running_board, ReleaseAcquisitionMode acquisition_mode,
    const TrustedReleaseKey *trusted_keys, size_t trusted_key_count,
    VerifyP256SignatureFunction verify_function, void *verify_context,
    const ReleaseOfferStorage &storage, ReleaseOffer *offer) {
    ReleaseOfferResult result = MakeResult(ReleaseOfferStatus::InvalidArgument);
    if (offer == 0 || installed_build_info.data == 0 ||
        github_latest_response.data == 0 || manifest_bytes.data == 0 ||
        signature_envelope.data == 0 || !IsKnownBoardFamily(running_board) ||
        (acquisition_mode != ReleaseAcquisitionMode::PublishedStable &&
         acquisition_mode != ReleaseAcquisitionMode::PreparedDraft) ||
        trusted_keys == 0 || trusted_key_count == 0U || verify_function == 0 ||
        !StorageIsValid(storage)) {
        return result;
    }
    memset(offer, 0, sizeof(*offer));

    JsonParseResult json_result;
    result.build_info_status = ParseBuildInfo(
        installed_build_info, storage.installed_tokens,
        storage.installed_token_capacity, &offer->installed, &json_result);
    if (result.build_info_status != BuildInfoStatus::Ok ||
        offer->installed.board != running_board) {
        result.status = ReleaseOfferStatus::InstalledMetadataInvalid;
        return result;
    }

    const GitHubReleaseParseStorage github_storage = {
        storage.github_tokens, storage.github_token_capacity,
        storage.github_assets, storage.github_asset_capacity};
    const GitHubReleaseKind release_kind =
        acquisition_mode == ReleaseAcquisitionMode::PreparedDraft
            ? GitHubReleaseKind::PreparedDraft
            : GitHubReleaseKind::PublishedStable;
    result.github_status = ParseGitHubRelease(
        github_latest_response, github_storage, release_kind, &offer->github,
        &json_result);
    if (result.github_status != GitHubReleaseParseStatus::Ok) {
        result.status = ReleaseOfferStatus::GitHubResponseInvalid;
        return result;
    }

    GitHubReleaseMetadataAssets metadata;
    result.assets_status = FindReleaseMetadataAssetsForKind(
        offer->github, release_kind, &metadata);
    if (result.assets_status != RequiredGitHubAssetsStatus::Ok) {
        result.status = ReleaseOfferStatus::MetadataAssetsInvalid;
        return result;
    }
    if (metadata.manifest->size != manifest_bytes.size ||
        metadata.signature->size != signature_envelope.size) {
        result.status = ReleaseOfferStatus::MetadataSizeMismatch;
        return result;
    }

    const ManifestParseStorage manifest_storage = {
        storage.manifest_tokens, storage.manifest_token_capacity,
        storage.manifest_files, storage.manifest_file_capacity,
        storage.manifest_directories, storage.manifest_directory_capacity};
    result.manifest_status = ParseReleaseManifest(
        manifest_bytes, running_board, manifest_storage, &offer->manifest,
        &json_result);
    if (result.manifest_status != ManifestParseStatus::Ok) {
        result.status = ReleaseOfferStatus::ManifestInvalid;
        return result;
    }

    const ManifestTrustResult trust = VerifyManifestTrust(
        manifest_bytes, offer->manifest, signature_envelope, trusted_keys,
        trusted_key_count, verify_function, verify_context);
    result.trust_status = trust.status;
    if (trust.status != ManifestTrustStatus::Trusted) {
        result.status = ReleaseOfferStatus::ManifestUntrusted;
        return result;
    }

    result.assets_status = FindRequiredAssetsForKind(
        offer->github, release_kind, offer->manifest.tag,
        offer->manifest.asset.filename, &offer->assets);
    if (result.assets_status != RequiredGitHubAssetsStatus::Ok) {
        result.status = ReleaseOfferStatus::ReleaseAssetsInvalid;
        return result;
    }
    if (offer->assets.manifest != metadata.manifest ||
        offer->assets.signature != metadata.signature ||
        offer->assets.board_zip->size != offer->manifest.asset.download_size) {
        result.status = ReleaseOfferStatus::ZipMetadataMismatch;
        return result;
    }

    InstalledRelease installed;
    installed.has_update_metadata = true;
    installed.release_sequence = offer->installed.release_sequence;
    installed.board = offer->installed.board;
    installed.updater_abi = offer->installed.updater_abi;
    ReleaseCandidate candidate;
    candidate.source = ReleaseSource::GitHubLatestKdreBmx;
    candidate.channel = ReleaseChannel::Stable;
    // A prepared draft is eligible only through the separately signed local
    // ticket and authenticated acquisition path.  The ordinary policy still
    // receives the literal API flag and therefore rejects every draft.
    candidate.api_reports_draft =
        acquisition_mode == ReleaseAcquisitionMode::PublishedStable
            ? offer->github.draft : false;
    candidate.api_reports_prerelease = offer->github.prerelease;
    candidate.release_sequence = offer->manifest.release_sequence;
    candidate.board = offer->manifest.asset.board;
    candidate.minimum_updater_abi = offer->manifest.minimum_updater_abi;
    candidate.maximum_updater_abi = offer->manifest.maximum_updater_abi;
    offer->release_decision = EvaluateReleaseCandidate(installed, candidate);
    result.release_decision = offer->release_decision;
    if (offer->release_decision != ReleaseDecision::UpdateAvailable) {
        result.status = ReleaseOfferStatus::ReleaseRejected;
        return result;
    }
    if (offer->manifest.release_epoch < offer->installed.release_epoch) {
        result.status = ReleaseOfferStatus::ReleaseEpochRegressed;
        return result;
    }
    offer->configuration_status = ClassifySchemas(offer);
    // The schema versions in BMX-BUILD.json describe the release defaults,
    // not necessarily the files that are currently present on the boot
    // volume.  Users may have copied or edited configuration manually.  Keep
    // this classification as advisory discovery information only; the
    // foreground installer re-reads and classifies the actual local files
    // immediately before it consumes consent or writes anything.
    result.status = ReleaseOfferStatus::Ok;
    return result;
}

const char *ReleaseOfferStatusString(ReleaseOfferStatus status) {
    switch (status) {
    case ReleaseOfferStatus::Ok: return "ok";
    case ReleaseOfferStatus::InvalidArgument: return "invalid argument";
    case ReleaseOfferStatus::InstalledMetadataInvalid:
        return "installed BMX metadata invalid or wrong board";
    case ReleaseOfferStatus::GitHubResponseInvalid:
        return "GitHub latest-release response invalid";
    case ReleaseOfferStatus::MetadataAssetsInvalid:
        return "release metadata assets invalid";
    case ReleaseOfferStatus::MetadataSizeMismatch:
        return "release metadata size differs from GitHub";
    case ReleaseOfferStatus::ManifestInvalid: return "release manifest invalid";
    case ReleaseOfferStatus::ManifestUntrusted:
        return "release manifest signature untrusted";
    case ReleaseOfferStatus::ReleaseAssetsInvalid:
        return "signed release assets invalid";
    case ReleaseOfferStatus::ZipMetadataMismatch:
        return "board ZIP metadata mismatch";
    case ReleaseOfferStatus::ReleaseRejected:
        return "release is not an eligible upgrade";
    case ReleaseOfferStatus::ReleaseEpochRegressed:
        return "release timestamp regressed";
    case ReleaseOfferStatus::OnlineSourceUnsupported:
        return "installed release has no signed online source inventory";
    case ReleaseOfferStatus::ConfigurationBlocked:
        return "configuration is not safely compatible";
    }
    return "unknown release offer error";
}

}  // namespace update
}  // namespace bmx
