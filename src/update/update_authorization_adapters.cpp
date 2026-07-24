#include "update/update_authorization_adapters.h"

#include "update/consent_digest_input.h"
#include "update/sha256.h"

#include <string.h>

namespace bmx {
namespace update {

namespace {

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) combined |= bytes[index];
    return combined != 0U;
}

bool TokensEqual(uint64_t left, uint64_t right)
{
    uint64_t difference = left ^ right;
    difference |= difference >> 32U;
    difference |= difference >> 16U;
    difference |= difference >> 8U;
    return (difference & UINT64_C(0xff)) == 0U;
}

bool PlanIsInstallable(const ConfigMigrationPlan &plan)
{
    if (plan.area_count != kConfigMigrationAreaCount ||
        plan.blocked_count != 0U) {
        return false;
    }
    size_t compatible = 0U;
    size_t migrations = 0U;
    size_t resets = 0U;
    for (size_t index = 0U; index < plan.area_count; ++index) {
        const ConfigClassification classification =
            plan.areas[index].classification;
        if (classification == ConfigClassification::Compatible) {
            ++compatible;
        } else if (classification == ConfigClassification::LosslessMigration) {
            ++migrations;
        } else if (classification == ConfigClassification::ResetRequired) {
            ++resets;
        } else {
            return false;
        }
    }
    if (compatible != plan.compatible_count ||
        migrations != plan.migration_count || resets != plan.reset_count ||
        compatible + migrations + resets != plan.area_count) {
        return false;
    }
    if (resets != 0U) {
        return plan.decision == ConfigPlanDecision::ResetConfirmationRequired;
    }
    if (migrations != 0U) {
        return plan.decision == ConfigPlanDecision::LosslessMigration;
    }
    return plan.decision == ConfigPlanDecision::Compatible;
}

const ConfigAreaSnapshot *FindSnapshotArea(const ConfigSnapshot &snapshot,
                                           ConfigArea area)
{
    const ConfigAreaSnapshot *found = 0;
    if (snapshot.areas == 0 ||
        snapshot.area_count != kConfigMigrationAreaCount) {
        return 0;
    }
    for (size_t index = 0U; index < snapshot.area_count; ++index) {
        if (snapshot.areas[index].area != area) continue;
        if (found != 0) return 0;
        found = &snapshot.areas[index];
    }
    return found;
}

const ConfigAreaAssessment *FindPlanArea(const ConfigMigrationPlan &plan,
                                         ConfigArea area)
{
    const ConfigAreaAssessment *found = 0;
    if (plan.area_count != kConfigMigrationAreaCount) return 0;
    for (size_t index = 0U; index < plan.area_count; ++index) {
        if (plan.areas[index].area != area) continue;
        if (found != 0) return 0;
        found = &plan.areas[index];
    }
    return found;
}

bool SameAssessment(const ConfigAreaAssessment &left,
                    const ConfigAreaAssessment &right,
                    bool compare_content)
{
    return left.area == right.area && left.detection == right.detection &&
        left.source_version == right.source_version &&
        left.target_version == right.target_version &&
        left.classification == right.classification &&
        strcmp(left.migration_id, right.migration_id) == 0 &&
        (!compare_content ||
         memcmp(left.source_content_sha256, right.source_content_sha256,
                kSha256DigestBytes) == 0);
}

bool SamePlanShape(const ConfigMigrationPlan &left,
                   const ConfigMigrationPlan &right)
{
    return left.area_count == right.area_count &&
        left.decision == right.decision &&
        left.compatible_count == right.compatible_count &&
        left.migration_count == right.migration_count &&
        left.reset_count == right.reset_count &&
        left.blocked_count == right.blocked_count;
}

enum class UpdateStateSnapshotStatus {
    Ok = 0,
    Invalid,
    JournalPresent
};

UpdateStateSnapshotStatus HashBuildInfo(const ConfigSnapshot &snapshot,
                                        bool require_journals_absent,
                                        uint8_t digest[kSha256DigestBytes])
{
    const ConfigAreaSnapshot *area =
        FindSnapshotArea(snapshot, ConfigArea::UpdateState);
    if (area == 0 || area->files == 0 || area->file_count == 0U ||
        area->file_count > 3U || digest == 0) {
        return UpdateStateSnapshotStatus::Invalid;
    }
    const ConfigFileView *build = 0;
    bool journal_a = false;
    bool journal_b = false;
    for (size_t index = 0U; index < area->file_count; ++index) {
        const ConfigFileView &file = area->files[index];
        if (file.path == 0 ||
            (file.content.data == 0 && file.content.size != 0U)) {
            return UpdateStateSnapshotStatus::Invalid;
        }
        if (strcmp(file.path, "BMX-BUILD.json") == 0) {
            if (build != 0) return UpdateStateSnapshotStatus::Invalid;
            build = &file;
        } else if (strcmp(file.path,
                          ".bmx-update/transaction/journal.a") == 0) {
            if (journal_a) return UpdateStateSnapshotStatus::Invalid;
            journal_a = true;
        } else if (strcmp(file.path,
                          ".bmx-update/transaction/journal.b") == 0) {
            if (journal_b) return UpdateStateSnapshotStatus::Invalid;
            journal_b = true;
        } else {
            return UpdateStateSnapshotStatus::Invalid;
        }
    }
    if (build == 0) return UpdateStateSnapshotStatus::Invalid;
    if (require_journals_absent && (journal_a || journal_b)) {
        return UpdateStateSnapshotStatus::JournalPresent;
    }
    return Sha256Digest(build->content, digest)
        ? UpdateStateSnapshotStatus::Ok
        : UpdateStateSnapshotStatus::Invalid;
}

}  // namespace

RetainedUpdateStateConsentStatus CaptureRetainedUpdateStateConsentEvidence(
    const ConfigSnapshot &snapshot, const ConfigMigrationPlan &plan,
    RetainedUpdateStateConsentEvidence *evidence)
{
    if (evidence == 0 || !PlanIsInstallable(plan)) {
        return RetainedUpdateStateConsentStatus::InvalidInput;
    }
    memset(evidence, 0, sizeof(*evidence));
    if (HashBuildInfo(snapshot, false, evidence->build_info_sha256) !=
        UpdateStateSnapshotStatus::Ok) {
        return RetainedUpdateStateConsentStatus::UnexpectedUpdateState;
    }
    evidence->plan = plan;
    return RetainedUpdateStateConsentStatus::Ok;
}

RetainedUpdateStateConsentStatus ValidateRetainedUpdateStateConsentTransition(
    const RetainedUpdateStateConsentEvidence &before,
    const ConfigSnapshot &after_snapshot,
    const ConfigMigrationPlan &after_plan)
{
    if (!PlanIsInstallable(before.plan) || !PlanIsInstallable(after_plan) ||
        !SamePlanShape(before.plan, after_plan)) {
        return RetainedUpdateStateConsentStatus::ConfigurationChanged;
    }
    for (size_t value = static_cast<size_t>(ConfigArea::Machines);
         value <= static_cast<size_t>(ConfigArea::UpdateState); ++value) {
        const ConfigArea area = static_cast<ConfigArea>(value);
        const ConfigAreaAssessment *left = FindPlanArea(before.plan, area);
        const ConfigAreaAssessment *right = FindPlanArea(after_plan, area);
        if (left == 0 || right == 0 ||
            !SameAssessment(*left, *right, area != ConfigArea::UpdateState)) {
            return RetainedUpdateStateConsentStatus::ConfigurationChanged;
        }
    }
    uint8_t build_info_sha256[kSha256DigestBytes];
    if (HashBuildInfo(after_snapshot, true, build_info_sha256) !=
        UpdateStateSnapshotStatus::Ok) {
        return RetainedUpdateStateConsentStatus::UnexpectedUpdateState;
    }
    if (memcmp(before.build_info_sha256, build_info_sha256,
               sizeof(build_info_sha256)) != 0) {
        return RetainedUpdateStateConsentStatus::ConfigurationChanged;
    }
    return RetainedUpdateStateConsentStatus::Ok;
}

const char *RetainedUpdateStateConsentStatusString(
    RetainedUpdateStateConsentStatus status)
{
    switch (status) {
    case RetainedUpdateStateConsentStatus::Ok: return "ok";
    case RetainedUpdateStateConsentStatus::InvalidInput:
        return "invalid-input";
    case RetainedUpdateStateConsentStatus::UnexpectedUpdateState:
        return "unexpected-update-state";
    case RetainedUpdateStateConsentStatus::ConfigurationChanged:
        return "configuration-changed";
    }
    return "unknown-retained-update-state-consent-status";
}

ExplicitUpdateMenuAuthorizationController::
ExplicitUpdateMenuAuthorizationController(
    OneShotForegroundUpdateAuthorizationSource *source)
    : source_(source)
{
}

bool ExplicitUpdateMenuAuthorizationController::IssueForConfirmedMenuAction(
    uint64_t *token)
{
    return source_ != 0 && source_->Issue(token);
}

void ExplicitUpdateMenuAuthorizationController::Revoke()
{
    if (source_ != 0) source_->RevokePending();
}

OneShotForegroundUpdateAuthorizationSource::
OneShotForegroundUpdateAuthorizationSource(
    AuthorizationTokenEntropySource *entropy,
    AuthorizationMonotonicClock *clock,
    UpdateNetworkStateSource *network,
    uint64_t lifetime_milliseconds)
    : entropy_(entropy), clock_(clock), network_(network),
      lifetime_milliseconds_(lifetime_milliseconds), pending_token_(0U),
      last_token_(0U), issued_at_milliseconds_(0U), pending_(false)
{
}

void OneShotForegroundUpdateAuthorizationSource::Lock()
{
    while (lock_.test_and_set(std::memory_order_acquire)) {
    }
}

void OneShotForegroundUpdateAuthorizationSource::Unlock()
{
    lock_.clear(std::memory_order_release);
}

bool OneShotForegroundUpdateAuthorizationSource::Issue(uint64_t *token)
{
    if (token == 0) return false;
    *token = 0U;
    Lock();
    if (entropy_ == 0 || clock_ == 0 || network_ == 0 ||
        lifetime_milliseconds_ == 0U ||
        lifetime_milliseconds_ >
            kMaximumForegroundAuthorizationLifetimeMilliseconds) {
        Unlock();
        return false;
    }

    uint64_t now = 0U;
    uint64_t candidate = 0U;
    bool generated = clock_->NowMilliseconds(&now);
    if (generated && pending_) {
        const bool still_valid = now >= issued_at_milliseconds_ &&
            now - issued_at_milliseconds_ < lifetime_milliseconds_;
        if (still_valid) {
            Unlock();
            return false;
        }
        pending_token_ = 0U;
        issued_at_milliseconds_ = 0U;
        pending_ = false;
    }
    for (unsigned attempt = 0U; generated && attempt < 4U; ++attempt) {
        candidate = 0U;
        if (!entropy_->Fill(reinterpret_cast<uint8_t *>(&candidate),
                            sizeof(candidate))) {
            generated = false;
            break;
        }
        if (candidate != 0U && !TokensEqual(candidate, last_token_)) break;
        candidate = 0U;
    }
    if (!generated || candidate == 0U) {
        Unlock();
        return false;
    }

    pending_token_ = candidate;
    last_token_ = candidate;
    issued_at_milliseconds_ = now;
    pending_ = true;
    *token = candidate;
    Unlock();
    return true;
}

void OneShotForegroundUpdateAuthorizationSource::RevokePending()
{
    Lock();
    pending_token_ = 0U;
    issued_at_milliseconds_ = 0U;
    pending_ = false;
    Unlock();
}

bool OneShotForegroundUpdateAuthorizationSource::ConsumeAndReadCurrent(
    uint64_t foreground_authorization_token, UpdateStartContext *current)
{
    if (current == 0) return false;
    memset(current, 0, sizeof(*current));
    if (foreground_authorization_token == 0U) return false;

    Lock();
    if (!pending_ ||
        !TokensEqual(foreground_authorization_token, pending_token_)) {
        Unlock();
        return false;
    }

    uint64_t now = 0U;
    const bool clock_ok = clock_ != 0 && clock_->NowMilliseconds(&now);
    const bool time_valid = clock_ok && now >= issued_at_milliseconds_ &&
        now - issued_at_milliseconds_ < lifetime_milliseconds_;

    // Consume before consulting target state. A failed/disabled network read
    // must not leave a reusable authorization behind.
    pending_token_ = 0U;
    issued_at_milliseconds_ = 0U;
    pending_ = false;
    if (!time_valid) {
        Unlock();
        return false;
    }

    bool feature_enabled = false;
    bool ready = false;
    const bool network_ok = network_ != 0 &&
        network_->Read(&feature_enabled, &ready);
    if (network_ok) {
        current->invocation = UpdateInvocation::ConfirmedUpdateMenuAction;
        current->network_feature_enabled = feature_enabled;
        current->network_ready = ready;
    }
    Unlock();
    return network_ok;
}

FatFsCurrentConfigConsentSource::FatFsCurrentConfigConsentSource(
    const char *volume)
    : volume_(), snapshot_()
{
    if (volume == 0) return;
    const size_t length = strlen(volume);
    if (length == 0U || length >= sizeof(volume_)) return;
    memcpy(volume_, volume, length + 1U);
}

CurrentConfigConsentStatus FatFsCurrentConfigConsentSource::ReReadAndCompute(
    const ReleaseOffer &fresh_offer, BoardFamily running_board,
    const uint8_t authenticated_manifest_sha256[kSha256DigestBytes],
    CurrentConfigConsentEvidence *evidence)
{
    if (evidence == 0) return CurrentConfigConsentStatus::InvalidOrBlocked;
    memset(evidence, 0, sizeof(*evidence));
    const ReleaseManifest &manifest = fresh_offer.manifest;
    if (volume_[0] == '\0' || !IsKnownBoardFamily(running_board) ||
        fresh_offer.release_decision != ReleaseDecision::UpdateAvailable ||
        fresh_offer.installed.board != running_board ||
        manifest.asset.board != running_board ||
        manifest.release_sequence == 0U ||
        manifest.schema_count != kConfigMigrationAreaCount ||
        manifest.migration_count > kMaximumDeclaredConfigMigrations ||
        !BytesNonZero(authenticated_manifest_sha256, kSha256DigestBytes)) {
        return CurrentConfigConsentStatus::InvalidOrBlocked;
    }

    const FatFsConfigSnapshotStatus loaded = snapshot_.Load(volume_);
    if (loaded != FatFsConfigSnapshotStatus::Ok) {
        return CurrentConfigConsentStatus::ReadFailed;
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
        migrations[index].from_version =
            manifest.migrations[index].from_version;
        migrations[index].to_version = manifest.migrations[index].to_version;
        migrations[index].lossy = manifest.migrations[index].lossy;
    }

    ConfigMigrationPlan plan;
    const ConfigAssessmentStatus assessed = AssessConfigSnapshot(
        snapshot_.snapshot(), requirements, manifest.schema_count, migrations,
        manifest.migration_count, &plan);
    if (assessed == ConfigAssessmentStatus::HashFailed) {
        return CurrentConfigConsentStatus::DigestFailed;
    }
    if (assessed != ConfigAssessmentStatus::Ok || !PlanIsInstallable(plan)) {
        return CurrentConfigConsentStatus::InvalidOrBlocked;
    }

    ConsentConfigItem items[kConfigMigrationAreaCount];
    for (size_t index = 0U; index < plan.area_count; ++index) {
        const ConfigAreaAssessment &area = plan.areas[index];
        items[index].area = area.area;
        items[index].classification = area.classification;
        items[index].source_schema_version = area.source_version;
        items[index].target_schema_version = area.target_version;
        memcpy(items[index].source_content_sha256,
               area.source_content_sha256, kSha256DigestBytes);
    }
    ConsentDigestInput input;
    input.board = running_board;
    input.target_release_sequence = manifest.release_sequence;
    memcpy(input.manifest_sha256, authenticated_manifest_sha256,
           kSha256DigestBytes);
    input.items = items;
    input.item_count = plan.area_count;
    uint8_t encoded[kMaximumConsentEncodedBytes];
    size_t encoded_size = 0U;
    if (SerializeConsentDigestInput(
            input, MutableByteView(encoded, sizeof(encoded)), &encoded_size) !=
            ConsentInputStatus::Valid ||
        !Sha256Digest(ByteView(encoded, encoded_size),
                      evidence->consent_sha256) ||
        !BytesNonZero(evidence->consent_sha256, kSha256DigestBytes)) {
        memset(evidence, 0, sizeof(*evidence));
        return CurrentConfigConsentStatus::DigestFailed;
    }
    evidence->configuration_status = plan.reset_count == 0U
        ? OfferConfigurationStatus::Compatible
        : OfferConfigurationStatus::ResetConfirmationRequired;
    return CurrentConfigConsentStatus::Ok;
}

}  // namespace update
}  // namespace bmx
