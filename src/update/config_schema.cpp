#include "config_schema.h"

namespace bmx {
namespace update {

namespace {

bool IsKnownObservationStatus(ConfigObservationStatus status)
{
    return status == ConfigObservationStatus::Present ||
           status == ConfigObservationStatus::Missing ||
           status == ConfigObservationStatus::UnknownFormat ||
           status == ConfigObservationStatus::Corrupt;
}

bool IsKnownTransitionKind(SchemaTransitionKind kind)
{
    return kind == SchemaTransitionKind::Lossless ||
           kind == SchemaTransitionKind::ResetOrLossy;
}

bool TargetIsValid(const ConfigSchemaTarget &target)
{
    if (!IsKnownConfigArea(target.area) || target.target_version == 0U ||
        target.compatible_minimum_version == 0U ||
        target.compatible_maximum_version == 0U ||
        target.compatible_minimum_version > target.compatible_maximum_version ||
        target.target_version < target.compatible_minimum_version ||
        target.target_version > target.compatible_maximum_version ||
        target.transition_count > kMaximumSchemaTransitionsPerArea ||
        (target.transition_count != 0U && target.transitions == 0)) {
        return false;
    }

    for (size_t i = 0U; i < target.transition_count; ++i) {
        const SchemaTransition &transition = target.transitions[i];
        if (transition.transition_id == 0U || transition.from_version == 0U ||
            transition.to_version != target.target_version ||
            transition.from_version >= transition.to_version ||
            (transition.from_version >= target.compatible_minimum_version &&
             transition.from_version <= target.compatible_maximum_version) ||
            !IsKnownTransitionKind(transition.kind)) {
            return false;
        }
        for (size_t j = 0U; j < i; ++j) {
            if (target.transitions[j].transition_id == transition.transition_id ||
                target.transitions[j].from_version == transition.from_version) {
                return false;
            }
        }
    }
    return true;
}

ConfigClassificationResult MakeClassification(ConfigClassification classification,
                                              ConfigArea area,
                                              uint32_t source,
                                              uint32_t target,
                                              uint32_t transition)
{
    ConfigClassificationResult result;
    result.classification = classification;
    result.area = area;
    result.source_version = source;
    result.target_version = target;
    result.transition_id = transition;
    return result;
}

ConfigPlanResult InvalidPlanResult()
{
    ConfigPlanResult result;
    result.decision = ConfigPlanDecision::InvalidInput;
    result.compatible_count = 0U;
    result.migration_count = 0U;
    result.reset_count = 0U;
    result.blocked_count = 0U;
    return result;
}

}  // namespace

bool IsKnownConfigArea(ConfigArea area)
{
    return area == ConfigArea::Machines || area == ConfigArea::ConfigManagedBlock ||
           area == ConfigArea::CmdlineManagedKeys || area == ConfigArea::Network ||
           area == ConfigArea::Settings || area == ConfigArea::UpdateState;
}

ConfigClassificationResult ClassifyConfig(const ConfigObservation &observation,
                                          const ConfigSchemaTarget &target)
{
    if (!TargetIsValid(target) || !IsKnownConfigArea(observation.area) ||
        observation.area != target.area || !IsKnownObservationStatus(observation.status) ||
        (observation.status == ConfigObservationStatus::Present &&
         observation.schema_version == 0U) ||
        (observation.status != ConfigObservationStatus::Present &&
         observation.schema_version != 0U)) {
        return MakeClassification(ConfigClassification::InvalidRule, observation.area,
                                  observation.schema_version, target.target_version, 0U);
    }

    if (observation.status == ConfigObservationStatus::Missing) {
        return MakeClassification(target.required
                                      ? ConfigClassification::UnknownOrCorrupt
                                      : ConfigClassification::Compatible,
                                  observation.area, 0U, target.target_version, 0U);
    }
    if (observation.status == ConfigObservationStatus::UnknownFormat ||
        observation.status == ConfigObservationStatus::Corrupt) {
        return MakeClassification(ConfigClassification::UnknownOrCorrupt, observation.area,
                                  0U, target.target_version, 0U);
    }
    if (observation.schema_version > target.target_version) {
        return MakeClassification(ConfigClassification::NewerThanTarget, observation.area,
                                  observation.schema_version, target.target_version, 0U);
    }
    if (observation.schema_version >= target.compatible_minimum_version &&
        observation.schema_version <= target.compatible_maximum_version) {
        return MakeClassification(ConfigClassification::Compatible, observation.area,
                                  observation.schema_version, target.target_version, 0U);
    }

    for (size_t i = 0U; i < target.transition_count; ++i) {
        const SchemaTransition &transition = target.transitions[i];
        if (transition.from_version == observation.schema_version) {
            return MakeClassification(
                transition.kind == SchemaTransitionKind::Lossless
                    ? ConfigClassification::LosslessMigration
                    : ConfigClassification::ResetRequired,
                observation.area, observation.schema_version, target.target_version,
                transition.transition_id);
        }
    }
    return MakeClassification(ConfigClassification::UnknownOrCorrupt, observation.area,
                              observation.schema_version, target.target_version, 0U);
}

ConfigPlanResult ClassifyConfigPlan(const ConfigObservation *observations,
                                    size_t observation_count,
                                    const ConfigSchemaTarget *targets,
                                    size_t target_count)
{
    if (observations == 0 || targets == 0 || observation_count == 0U ||
        observation_count != target_count || observation_count > kMaximumConfigAreas) {
        return InvalidPlanResult();
    }

    for (size_t i = 0U; i < observation_count; ++i) {
        if (!IsKnownConfigArea(observations[i].area) ||
            !IsKnownConfigArea(targets[i].area)) {
            return InvalidPlanResult();
        }
        for (size_t j = 0U; j < i; ++j) {
            if (observations[j].area == observations[i].area ||
                targets[j].area == targets[i].area) {
                return InvalidPlanResult();
            }
        }
    }

    ConfigPlanResult result;
    result.decision = ConfigPlanDecision::Compatible;
    result.compatible_count = 0U;
    result.migration_count = 0U;
    result.reset_count = 0U;
    result.blocked_count = 0U;

    for (size_t i = 0U; i < target_count; ++i) {
        const ConfigObservation *observation = 0;
        for (size_t j = 0U; j < observation_count; ++j) {
            if (observations[j].area == targets[i].area) {
                observation = &observations[j];
                break;
            }
        }
        if (observation == 0) {
            return InvalidPlanResult();
        }

        const ConfigClassificationResult classification =
            ClassifyConfig(*observation, targets[i]);
        switch (classification.classification) {
        case ConfigClassification::Compatible:
            ++result.compatible_count;
            break;
        case ConfigClassification::LosslessMigration:
            ++result.migration_count;
            if (result.decision == ConfigPlanDecision::Compatible) {
                result.decision = ConfigPlanDecision::LosslessMigration;
            }
            break;
        case ConfigClassification::ResetRequired:
            ++result.reset_count;
            if (result.decision != ConfigPlanDecision::BlockedUnknownOrCorrupt &&
                result.decision != ConfigPlanDecision::BlockedNewerThanTarget) {
                result.decision = ConfigPlanDecision::ResetConfirmationRequired;
            }
            break;
        case ConfigClassification::UnknownOrCorrupt:
            ++result.blocked_count;
            if (result.decision != ConfigPlanDecision::BlockedNewerThanTarget) {
                result.decision = ConfigPlanDecision::BlockedUnknownOrCorrupt;
            }
            break;
        case ConfigClassification::NewerThanTarget:
            ++result.blocked_count;
            result.decision = ConfigPlanDecision::BlockedNewerThanTarget;
            break;
        case ConfigClassification::InvalidRule:
        default:
            return InvalidPlanResult();
        }
    }
    return result;
}

}  // namespace update
}  // namespace bmx
