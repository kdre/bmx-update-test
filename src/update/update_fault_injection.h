#ifndef BMX_UPDATE_UPDATE_FAULT_INJECTION_H
#define BMX_UPDATE_UPDATE_FAULT_INJECTION_H

#include "update_hardware_test_mode.h"

#include <stdint.h>

// Fault injection is intentionally a compile-time-only hardware-test aid.
// A release/non-target build must not be able to enable the target backend.
#if defined(BMX_UPDATE_FAULT_INJECTION) && BMX_UPDATE_FAULT_INJECTION != 1
#error "BMX_UPDATE_FAULT_INJECTION must be exactly 1 when defined"
#endif

#if defined(BMX_UPDATE_FAULT_INJECTION) && \
    !defined(BMX_UPDATE_HARDWARE_TEST_MODE)
#error "BMX update fault injection requires hardware-test mode"
#endif

#if defined(BMX_UPDATE_FAULT_INJECTION_TESTING) && \
    defined(BMX_UPDATE_FAULT_INJECTION)
#error "host fault-injection testing and the target backend are exclusive"
#endif

#if !defined(BMX_UPDATE_FAULT_INJECTION) && \
    (defined(BMX_UPDATE_FAULT_POINT_ID) || \
     defined(BMX_UPDATE_FAULT_OCCURRENCE))
#error "fault point selection requires BMX_UPDATE_FAULT_INJECTION=1"
#endif

#if defined(BMX_UPDATE_FAULT_INJECTION)
#if !defined(BMX_UPDATE_FAULT_POINT_ID)
#error "BMX_UPDATE_FAULT_POINT_ID is required for fault injection"
#endif
#if !defined(BMX_UPDATE_FAULT_OCCURRENCE)
#error "BMX_UPDATE_FAULT_OCCURRENCE is required for fault injection"
#endif
#if BMX_UPDATE_FAULT_OCCURRENCE < 1 || BMX_UPDATE_FAULT_OCCURRENCE > 1000000
#error "BMX_UPDATE_FAULT_OCCURRENCE must be in [1, 1000000]"
#endif
#if BMX_UPDATE_FAULT_POINT_ID != 100 && \
    BMX_UPDATE_FAULT_POINT_ID != 101 && \
    BMX_UPDATE_FAULT_POINT_ID != 102 && \
    BMX_UPDATE_FAULT_POINT_ID != 103 && \
    BMX_UPDATE_FAULT_POINT_ID != 104 && \
    BMX_UPDATE_FAULT_POINT_ID != 105 && \
    BMX_UPDATE_FAULT_POINT_ID != 200 && \
    BMX_UPDATE_FAULT_POINT_ID != 201 && \
    BMX_UPDATE_FAULT_POINT_ID != 210 && \
    BMX_UPDATE_FAULT_POINT_ID != 211 && \
    BMX_UPDATE_FAULT_POINT_ID != 220 && \
    BMX_UPDATE_FAULT_POINT_ID != 221 && \
    BMX_UPDATE_FAULT_POINT_ID != 230 && \
    BMX_UPDATE_FAULT_POINT_ID != 231 && \
    BMX_UPDATE_FAULT_POINT_ID != 240 && \
    BMX_UPDATE_FAULT_POINT_ID != 241 && \
    BMX_UPDATE_FAULT_POINT_ID != 250 && \
    BMX_UPDATE_FAULT_POINT_ID != 251 && \
    BMX_UPDATE_FAULT_POINT_ID != 260 && \
    BMX_UPDATE_FAULT_POINT_ID != 261 && \
    BMX_UPDATE_FAULT_POINT_ID != 270 && \
    BMX_UPDATE_FAULT_POINT_ID != 271 && \
    BMX_UPDATE_FAULT_POINT_ID != 300 && \
    BMX_UPDATE_FAULT_POINT_ID != 301 && \
    BMX_UPDATE_FAULT_POINT_ID != 302 && \
    BMX_UPDATE_FAULT_POINT_ID != 303 && \
    BMX_UPDATE_FAULT_POINT_ID != 304 && \
    BMX_UPDATE_FAULT_POINT_ID != 305 && \
    BMX_UPDATE_FAULT_POINT_ID != 400 && \
    BMX_UPDATE_FAULT_POINT_ID != 401 && \
    BMX_UPDATE_FAULT_POINT_ID != 410 && \
    BMX_UPDATE_FAULT_POINT_ID != 411 && \
    BMX_UPDATE_FAULT_POINT_ID != 412 && \
    BMX_UPDATE_FAULT_POINT_ID != 413 && \
    BMX_UPDATE_FAULT_POINT_ID != 420 && \
    BMX_UPDATE_FAULT_POINT_ID != 421 && \
    BMX_UPDATE_FAULT_POINT_ID != 422 && \
    BMX_UPDATE_FAULT_POINT_ID != 430 && \
    BMX_UPDATE_FAULT_POINT_ID != 431 && \
    BMX_UPDATE_FAULT_POINT_ID != 432 && \
    BMX_UPDATE_FAULT_POINT_ID != 500 && \
    BMX_UPDATE_FAULT_POINT_ID != 501 && \
    BMX_UPDATE_FAULT_POINT_ID != 510 && \
    BMX_UPDATE_FAULT_POINT_ID != 511 && \
    BMX_UPDATE_FAULT_POINT_ID != 520 && \
    BMX_UPDATE_FAULT_POINT_ID != 521 && \
    BMX_UPDATE_FAULT_POINT_ID != 522 && \
    BMX_UPDATE_FAULT_POINT_ID != 523 && \
    BMX_UPDATE_FAULT_POINT_ID != 530 && \
    BMX_UPDATE_FAULT_POINT_ID != 531 && \
    BMX_UPDATE_FAULT_POINT_ID != 600 && \
    BMX_UPDATE_FAULT_POINT_ID != 601 && \
    BMX_UPDATE_FAULT_POINT_ID != 610 && \
    BMX_UPDATE_FAULT_POINT_ID != 611 && \
    BMX_UPDATE_FAULT_POINT_ID != 612 && \
    BMX_UPDATE_FAULT_POINT_ID != 700 && \
    BMX_UPDATE_FAULT_POINT_ID != 701 && \
    BMX_UPDATE_FAULT_POINT_ID != 702 && \
    BMX_UPDATE_FAULT_POINT_ID != 703 && \
    BMX_UPDATE_FAULT_POINT_ID != 704 && \
    BMX_UPDATE_FAULT_POINT_ID != 705
#error "BMX_UPDATE_FAULT_POINT_ID is not a known stable checkpoint"
#endif
#endif

namespace bmx {
namespace update {

// These numeric IDs are a hardware-test protocol. Keep existing IDs and
// names stable so relay scripts and archived test reports remain reproducible.
enum class UpdateFaultPoint : uint16_t {
    JournalBeforeTemporaryFileSync = 100,
    JournalAfterTemporaryFileSync = 101,
    JournalBeforePublish = 102,
    JournalAfterPublish = 103,
    JournalAfterDirectorySync = 104,
    JournalAfterValidatedReadback = 105,

    FatBeforeFreshFileCreate = 200,
    FatAfterFreshFileCreate = 201,
    FatBeforeFileSync = 210,
    FatAfterFileSync = 211,
    FatBeforeFileRemove = 220,
    FatAfterFileRemove = 221,
    FatBeforeDirectoryCreate = 230,
    FatAfterDirectoryCreate = 231,
    FatBeforeDirectoryRemove = 240,
    FatAfterDirectoryRemove = 241,
    FatBeforeReplaceDestinationRemove = 250,
    FatAfterReplaceDestinationRemove = 251,
    FatBeforeRename = 260,
    FatAfterRename = 261,
    FatBeforeDirectorySync = 270,
    FatAfterDirectorySync = 271,

    SelectorBeforeTemporaryFileSync = 300,
    SelectorAfterTemporaryFileSync = 301,
    SelectorBeforePublish = 302,
    SelectorAfterPublish = 303,
    SelectorAfterDirectorySync = 304,
    SelectorAfterValidatedReadback = 305,

    TrybootBeforeShutdownPrepare = 400,
    TrybootAfterShutdownPrepare = 401,
    TrybootBeforeFlagSet = 410,
    TrybootAfterFlagSet = 411,
    TrybootAfterFlagReadback = 412,
    TrybootAfterFirmwareNotify = 413,
    TrybootBeforeArm = 420,
    TrybootAfterArm = 421,
    TrybootBeforeCandidateReboot = 422,
    TrybootBeforeClear = 430,
    TrybootAfterClear = 431,
    TrybootBeforePreviousReboot = 432,

    CommitBeforeCommittingJournal = 500,
    CommitAfterCommittingJournal = 501,
    CommitBeforeMetadataPublish = 510,
    CommitAfterMetadataPublish = 511,
    CommitBeforeSelectorPublish = 520,
    CommitAfterSelectorPublish = 521,
    CommitBeforeSelectorJournal = 522,
    CommitAfterSelectorJournal = 523,
    CommitBeforeFinalJournal = 530,
    CommitAfterFinalJournal = 531,

    RequestBeforeActivationStatePublish = 600,
    RequestAfterActivationStatePublish = 601,
    RequestBeforeCommitRetentionRename = 610,
    RequestAfterCommitRetentionRename = 611,
    RequestAfterCommitRetentionDirectorySync = 612,

    ContentPlanBeforeFileSync = 700,
    ContentPlanAfterFileSync = 701,
    ContentPlanBeforePublish = 702,
    ContentPlanAfterPublish = 703,
    ContentPlanAfterDirectorySync = 704,
    ContentPlanAfterValidatedReadback = 705
};

inline const char *UpdateFaultPointName(UpdateFaultPoint point)
{
    switch (point) {
    case UpdateFaultPoint::JournalBeforeTemporaryFileSync:
        return "journal.before-temporary-file-sync";
    case UpdateFaultPoint::JournalAfterTemporaryFileSync:
        return "journal.after-temporary-file-sync";
    case UpdateFaultPoint::JournalBeforePublish:
        return "journal.before-publish";
    case UpdateFaultPoint::JournalAfterPublish:
        return "journal.after-publish";
    case UpdateFaultPoint::JournalAfterDirectorySync:
        return "journal.after-directory-sync";
    case UpdateFaultPoint::JournalAfterValidatedReadback:
        return "journal.after-validated-readback";
    case UpdateFaultPoint::FatBeforeFreshFileCreate:
        return "fat.before-fresh-file-create";
    case UpdateFaultPoint::FatAfterFreshFileCreate:
        return "fat.after-fresh-file-create";
    case UpdateFaultPoint::FatBeforeFileSync:
        return "fat.before-file-sync";
    case UpdateFaultPoint::FatAfterFileSync:
        return "fat.after-file-sync";
    case UpdateFaultPoint::FatBeforeFileRemove:
        return "fat.before-file-remove";
    case UpdateFaultPoint::FatAfterFileRemove:
        return "fat.after-file-remove";
    case UpdateFaultPoint::FatBeforeDirectoryCreate:
        return "fat.before-directory-create";
    case UpdateFaultPoint::FatAfterDirectoryCreate:
        return "fat.after-directory-create";
    case UpdateFaultPoint::FatBeforeDirectoryRemove:
        return "fat.before-directory-remove";
    case UpdateFaultPoint::FatAfterDirectoryRemove:
        return "fat.after-directory-remove";
    case UpdateFaultPoint::FatBeforeReplaceDestinationRemove:
        return "fat.before-replace-destination-remove";
    case UpdateFaultPoint::FatAfterReplaceDestinationRemove:
        return "fat.after-replace-destination-remove";
    case UpdateFaultPoint::FatBeforeRename:
        return "fat.before-rename";
    case UpdateFaultPoint::FatAfterRename:
        return "fat.after-rename";
    case UpdateFaultPoint::FatBeforeDirectorySync:
        return "fat.before-directory-sync";
    case UpdateFaultPoint::FatAfterDirectorySync:
        return "fat.after-directory-sync";
    case UpdateFaultPoint::SelectorBeforeTemporaryFileSync:
        return "selector.before-temporary-file-sync";
    case UpdateFaultPoint::SelectorAfterTemporaryFileSync:
        return "selector.after-temporary-file-sync";
    case UpdateFaultPoint::SelectorBeforePublish:
        return "selector.before-publish";
    case UpdateFaultPoint::SelectorAfterPublish:
        return "selector.after-publish";
    case UpdateFaultPoint::SelectorAfterDirectorySync:
        return "selector.after-directory-sync";
    case UpdateFaultPoint::SelectorAfterValidatedReadback:
        return "selector.after-validated-readback";
    case UpdateFaultPoint::TrybootBeforeShutdownPrepare:
        return "tryboot.before-shutdown-prepare";
    case UpdateFaultPoint::TrybootAfterShutdownPrepare:
        return "tryboot.after-shutdown-prepare";
    case UpdateFaultPoint::TrybootBeforeFlagSet:
        return "tryboot.before-flag-set";
    case UpdateFaultPoint::TrybootAfterFlagSet:
        return "tryboot.after-flag-set";
    case UpdateFaultPoint::TrybootAfterFlagReadback:
        return "tryboot.after-flag-readback";
    case UpdateFaultPoint::TrybootAfterFirmwareNotify:
        return "tryboot.after-firmware-notify";
    case UpdateFaultPoint::TrybootBeforeArm:
        return "tryboot.before-arm";
    case UpdateFaultPoint::TrybootAfterArm:
        return "tryboot.after-arm";
    case UpdateFaultPoint::TrybootBeforeCandidateReboot:
        return "tryboot.before-candidate-reboot";
    case UpdateFaultPoint::TrybootBeforeClear:
        return "tryboot.before-clear";
    case UpdateFaultPoint::TrybootAfterClear:
        return "tryboot.after-clear";
    case UpdateFaultPoint::TrybootBeforePreviousReboot:
        return "tryboot.before-previous-reboot";
    case UpdateFaultPoint::CommitBeforeCommittingJournal:
        return "commit.before-committing-journal";
    case UpdateFaultPoint::CommitAfterCommittingJournal:
        return "commit.after-committing-journal";
    case UpdateFaultPoint::CommitBeforeMetadataPublish:
        return "commit.before-metadata-publish";
    case UpdateFaultPoint::CommitAfterMetadataPublish:
        return "commit.after-metadata-publish";
    case UpdateFaultPoint::CommitBeforeSelectorPublish:
        return "commit.before-selector-publish";
    case UpdateFaultPoint::CommitAfterSelectorPublish:
        return "commit.after-selector-publish";
    case UpdateFaultPoint::CommitBeforeSelectorJournal:
        return "commit.before-selector-journal";
    case UpdateFaultPoint::CommitAfterSelectorJournal:
        return "commit.after-selector-journal";
    case UpdateFaultPoint::CommitBeforeFinalJournal:
        return "commit.before-final-journal";
    case UpdateFaultPoint::CommitAfterFinalJournal:
        return "commit.after-final-journal";
    case UpdateFaultPoint::RequestBeforeActivationStatePublish:
        return "request.before-activation-state-publish";
    case UpdateFaultPoint::RequestAfterActivationStatePublish:
        return "request.after-activation-state-publish";
    case UpdateFaultPoint::RequestBeforeCommitRetentionRename:
        return "request.before-commit-retention-rename";
    case UpdateFaultPoint::RequestAfterCommitRetentionRename:
        return "request.after-commit-retention-rename";
    case UpdateFaultPoint::RequestAfterCommitRetentionDirectorySync:
        return "request.after-commit-retention-directory-sync";
    case UpdateFaultPoint::ContentPlanBeforeFileSync:
        return "content-plan.before-file-sync";
    case UpdateFaultPoint::ContentPlanAfterFileSync:
        return "content-plan.after-file-sync";
    case UpdateFaultPoint::ContentPlanBeforePublish:
        return "content-plan.before-publish";
    case UpdateFaultPoint::ContentPlanAfterPublish:
        return "content-plan.after-publish";
    case UpdateFaultPoint::ContentPlanAfterDirectorySync:
        return "content-plan.after-directory-sync";
    case UpdateFaultPoint::ContentPlanAfterValidatedReadback:
        return "content-plan.after-validated-readback";
    }
    return 0;
}

inline bool IsKnownUpdateFaultPoint(UpdateFaultPoint point)
{
    return UpdateFaultPointName(point) != 0;
}

// Emits the exact compile-time selection when an explicit update action is
// entered. Production and ordinary debug builds implement this as a no-op.
void LogUpdateFaultInjectionConfiguration();

// Emits one early marker per instrumented boot as soon as the target logger is
// ready.  This lets an external relay arm a candidate/recovery checkpoint
// before local recovery begins; it performs no update or network operation.
void LogUpdateFaultInjectionBootConfiguration();

#if defined(BMX_UPDATE_FAULT_INJECTION_TESTING)
struct UpdateFaultInjectionTestEvent {
    UpdateFaultPoint point;
    uint32_t occurrence;
    bool selected;
};

typedef void (*UpdateFaultInjectionTestObserver)(
    void *context, const UpdateFaultInjectionTestEvent &event);

bool ConfigureUpdateFaultInjectionForTest(
    UpdateFaultPoint selected_point, uint32_t selected_occurrence,
    UpdateFaultInjectionTestObserver observer, void *context);
void ResetUpdateFaultInjectionForTest();
bool UpdateFaultInjectionTriggeredForTest();
uint32_t UpdateFaultPointOccurrenceForTest(UpdateFaultPoint point);
#endif

#if defined(BMX_UPDATE_FAULT_INJECTION) || \
    defined(BMX_UPDATE_FAULT_INJECTION_TESTING)
void UpdateFaultCheckpoint(UpdateFaultPoint point);
#define BMX_UPDATE_FAULT_CHECKPOINT(point) \
    ::bmx::update::UpdateFaultCheckpoint(point)
#else
// Do not emit a call or evaluate the argument in production builds.
#define BMX_UPDATE_FAULT_CHECKPOINT(point) \
    do { (void) sizeof(point); } while (0)
#endif

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_FAULT_INJECTION_H
