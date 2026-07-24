#ifndef BMX_UPDATE_CONFIG_SCHEMA_H
#define BMX_UPDATE_CONFIG_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

namespace bmx {
namespace update {

static const size_t kMaximumConfigAreas = 16U;
static const size_t kMaximumSchemaTransitionsPerArea = 16U;

enum class ConfigArea : uint8_t {
    Unknown = 0,
    Machines = 1,
    ConfigManagedBlock = 2,
    CmdlineManagedKeys = 3,
    Network = 4,
    Settings = 5,
    UpdateState = 6
};

bool IsKnownConfigArea(ConfigArea area);

enum class ConfigObservationStatus : uint8_t {
    Present = 0,
    Missing,
    UnknownFormat,
    Corrupt
};

struct ConfigObservation {
    ConfigArea area;
    ConfigObservationStatus status;
    uint32_t schema_version;
};

enum class SchemaTransitionKind : uint8_t {
    Lossless = 0,
    ResetOrLossy = 1
};

struct SchemaTransition {
    uint32_t transition_id;
    uint32_t from_version;
    uint32_t to_version;
    SchemaTransitionKind kind;
};

struct ConfigSchemaTarget {
    ConfigArea area;
    bool required;
    uint32_t target_version;
    uint32_t compatible_minimum_version;
    uint32_t compatible_maximum_version;
    const SchemaTransition *transitions;
    size_t transition_count;
};

enum class ConfigClassification : uint8_t {
    Compatible = 0,
    LosslessMigration,
    ResetRequired,
    UnknownOrCorrupt,
    NewerThanTarget,
    InvalidRule
};

struct ConfigClassificationResult {
    ConfigClassification classification;
    ConfigArea area;
    uint32_t source_version;
    uint32_t target_version;
    uint32_t transition_id;
};

ConfigClassificationResult ClassifyConfig(const ConfigObservation &observation,
                                          const ConfigSchemaTarget &target);

enum class ConfigPlanDecision : uint8_t {
    Compatible = 0,
    LosslessMigration,
    ResetConfirmationRequired,
    BlockedUnknownOrCorrupt,
    BlockedNewerThanTarget,
    InvalidInput
};

struct ConfigPlanResult {
    ConfigPlanDecision decision;
    size_t compatible_count;
    size_t migration_count;
    size_t reset_count;
    size_t blocked_count;
};

// Observations and targets may be in any order, but every area must occur exactly
// once in each array. No configuration content is modified by this function.
ConfigPlanResult ClassifyConfigPlan(const ConfigObservation *observations,
                                    size_t observation_count,
                                    const ConfigSchemaTarget *targets,
                                    size_t target_count);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CONFIG_SCHEMA_H
