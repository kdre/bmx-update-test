#ifndef BMX_UPDATE_CONFIG_MIGRATION_H
#define BMX_UPDATE_CONFIG_MIGRATION_H

#include "update/config_schema.h"
#include "update/consent_digest_input.h"
#include "update/update_types.h"

namespace bmx {
namespace update {

// The migration engine is deliberately independent of a filesystem.  The
// caller reads a stable snapshot, passes bounded views here, then persists the
// fully validated output through the update transaction layer.
static const size_t kConfigMigrationAreaCount = 6U;
static const size_t kMaximumConfigFilesPerArea = 16U;
static const size_t kMaximumConfigPathBytes = 127U;
static const size_t kMaximumConfigFileBytes = 512U * 1024U;
static const size_t kMaximumConfigAreaBytes = 2U * 1024U * 1024U;
static const size_t kMaximumDeclaredConfigMigrations = 64U;
static const size_t kMaximumConfigMigrationIdBytes = 64U;
// Covers six reset areas with uint32 schema versions and the complete bounded
// signed description for each area.  The C menu bridge uses the same bound.
static const size_t kMaximumConfigWarningBytes = 2048U;

struct ManifestLossyChange;

struct ConfigFileView {
    // Relative boot-partition path, using '/'.  Only the fixed paths/families
    // belonging to the enclosing area are accepted.
    const char *path;
    ByteView content;
};

struct ConfigAreaSnapshot {
    ConfigArea area;
    const ConfigFileView *files;
    size_t file_count;
};

struct ConfigSnapshot {
    // A full snapshot contains every area exactly once.  An absent optional
    // area is represented by an area with zero files, never by omitting it.
    const ConfigAreaSnapshot *areas;
    size_t area_count;
};

struct ConfigSchemaRequirement {
    ConfigArea area;
    uint32_t target_version;
    const uint32_t *accepted_versions;
    size_t accepted_version_count;
};

struct DeclaredConfigMigration {
    const char *id;
    ConfigArea area;
    uint32_t from_version;
    uint32_t to_version;
    bool lossy;
};

enum class ConfigMigrationRegistryStatus : uint8_t {
    Valid = 0,
    InvalidInput,
    DuplicateDeclaration,
    UnknownMigration,
    DeclarationMismatch,
    SchemaMismatch
};

// Every declaration from the signed manifest must match an exact compiled-in
// registry entry.  The manifest selects code; it never supplies code or a
// generic transformation language.
ConfigMigrationRegistryStatus ValidateConfigMigrationDeclarations(
    const ConfigSchemaRequirement *requirements,
    size_t requirement_count,
    const DeclaredConfigMigration *migrations,
    size_t migration_count);

enum class ConfigDetectionDetail : uint8_t {
    Valid = 0,
    Missing,
    UnknownFormat,
    Corrupt,
    LimitExceeded
};

struct ConfigAreaAssessment {
    ConfigArea area;
    ConfigDetectionDetail detection;
    uint32_t source_version;
    uint32_t target_version;
    ConfigClassification classification;
    char migration_id[kMaximumConfigMigrationIdBytes + 1U];
    // SHA-256 over path, length and exact bytes of every file in this area.
    // For config.txt/cmdline.txt this intentionally covers the complete file,
    // so any concurrent edit invalidates a previous UI consent.
    uint8_t source_content_sha256[kSha256DigestBytes];
};

struct ConfigMigrationPlan {
    ConfigAreaAssessment areas[kConfigMigrationAreaCount];
    size_t area_count;
    ConfigPlanDecision decision;
    size_t compatible_count;
    size_t migration_count;
    size_t reset_count;
    size_t blocked_count;
};

enum class ConfigAssessmentStatus : uint8_t {
    Ok = 0,
    InvalidInput,
    RegistryRejected,
    SnapshotChangedOrAmbiguous,
    HashFailed
};

ConfigAssessmentStatus AssessConfigSnapshot(
    const ConfigSnapshot &snapshot,
    const ConfigSchemaRequirement *requirements,
    size_t requirement_count,
    const DeclaredConfigMigration *migrations,
    size_t migration_count,
    ConfigMigrationPlan *plan);

// Generates a warning without ever copying configuration values into it.
// Every reset area must have exactly one matching, display-safe description
// from the authenticated manifest.  The complete signed description is shown
// together with fixed area names and schema numbers.  Returns false when no
// reset is required, the descriptions are inconsistent, or the buffer is too
// small.
bool FormatConfigResetWarning(const ConfigMigrationPlan &plan,
                              const ManifestLossyChange *lossy_changes,
                              size_t lossy_change_count,
                              char *output,
                              size_t output_size);

enum class ConfigConsentStatus : uint8_t {
    Ok = 0,
    NoConfigChange,
    InvalidInput,
    OutputTooSmall
};

// Builds the existing canonical ConsentDigestInput for only the areas that a
// migration/reset will actually modify.  The returned input points at the
// caller-owned items array.
ConfigConsentStatus BuildConfigConsentDigestInput(
    const ConfigMigrationPlan &plan,
    BoardFamily board,
    uint64_t target_release_sequence,
    const uint8_t manifest_sha256[kSha256DigestBytes],
    ConsentConfigItem *items,
    size_t item_capacity,
    ConsentDigestInput *input);

struct ConfigOutputFile {
    const char *path;
    MutableByteView content;
    size_t written;
};

struct ConfigChangeRequest {
    ConfigArea area;
    const char *migration_id;
    uint32_t source_version;
    uint32_t target_version;
    bool reset_consent;
    const ConfigAreaSnapshot *source;
    // Required only by reset/lossy registry entries.  Defaults must themselves
    // parse as the requested target schema before any output is produced.
    const ConfigAreaSnapshot *defaults;
    ConfigOutputFile *output_files;
    size_t output_file_count;
};

enum class ConfigChangeStatus : uint8_t {
    Ok = 0,
    InvalidInput,
    UnknownMigration,
    MigrationMismatch,
    SourceRejected,
    DefaultsRequired,
    DefaultsRejected,
    ResetConsentRequired,
    OutputCountMismatch,
    OutputTooSmall,
    AliasedOutput,
    TransformFailed,
    SemanticRevalidationFailed
};

// Applies one exact compiled migration to caller-provided copies and performs
// a complete target-schema parse afterwards.  On any failure every `written`
// field is reset to zero; source/default buffers are never modified.
ConfigChangeStatus ApplyConfigChange(const ConfigChangeRequest &request);

const char *ConfigMigrationRegistryStatusString(
    ConfigMigrationRegistryStatus status);
const char *ConfigAssessmentStatusString(ConfigAssessmentStatus status);
const char *ConfigChangeStatusString(ConfigChangeStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CONFIG_MIGRATION_H
