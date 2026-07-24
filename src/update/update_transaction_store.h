#ifndef BMX_UPDATE_UPDATE_TRANSACTION_STORE_H
#define BMX_UPDATE_UPDATE_TRANSACTION_STORE_H

#include "update/update_filesystem.h"
#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

static const size_t kPersistedUpdateRequestStateBytes = 288U;
extern const char kUpdateTransactionRoot[];
// Relative fixed activation record. Its presence is only a cheap boot-time
// precheck; Load() remains the sole authority for validity and contents.
extern const char kUpdateTransactionActivationPath[];
extern const char kUpdateTransactionCommittedPath[];
extern const char kUpdateTransactionRetiringPath[];

struct PersistedUpdateRequestBuffers {
    uint8_t *installed_build_info;
    size_t installed_build_info_capacity;
    uint8_t *github_response;
    size_t github_response_capacity;
    uint8_t *manifest;
    size_t manifest_capacity;
    uint8_t *signature;
    size_t signature_capacity;
};

enum class UpdateTransactionStoreStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    InvalidIdentity,
    DurabilityUnsupported,
    NotFound,
    Conflict,
    WorkspaceTooSmall,
    FileSystemError,
    Corrupt,
    HashMismatch,
    RecoveryProgressFailed
};

// Persists only the already-downloaded small authentication inputs and the
// sealed local transaction identity. It never stores a foreground token and
// never performs network I/O. A loaded request must still pass the raw
// AuthenticatedReleaseValidator before ResumeAfterBoot may use it.
class UpdateTransactionRequestStore : public UpdateRequestPersistence {
public:
    explicit UpdateTransactionRequestStore(UpdateFileSystem *file_system);

    UpdateTransactionStoreStatus Save(
        const AuthenticatedUpdateRequest &request);

    UpdateTransactionStoreStatus Load(
        const char *transaction_root,
        BoardFamily expected_board,
        const PersistedUpdateRequestBuffers &buffers,
        ValidatedReleaseDownload *release,
        AuthenticatedUpdateRequest *request,
        UpdateRecoveryProgress *recovery_progress = 0);

    // Loads the same authenticated raw inputs from the inert post-commit
    // record. Its filename is never considered boot activation.
    UpdateTransactionStoreStatus LoadCommitted(
        const char *transaction_root,
        BoardFamily expected_board,
        const PersistedUpdateRequestBuffers &buffers,
        ValidatedReleaseDownload *release,
        AuthenticatedUpdateRequest *request,
        UpdateRecoveryProgress *recovery_progress = 0);

    bool HasCommitted(const char *transaction_root) const;
    bool HasRetiringCommitted(const char *transaction_root) const;

    // Idempotently removes and syncs only the fixed activation record.  Raw
    // payloads and journal/config evidence remain inert for diagnosis.  This
    // method accepts no untrusted path and is safe before a binding exists.
    UpdateTransactionStoreStatus Deactivate(
        UpdateRecoveryProgress *recovery_progress = 0);

    // Idempotently removes only the five fixed files below the validated
    // transaction root. The directory itself is retained for journal/config
    // cleanup by their owning components.
    UpdateTransactionStoreStatus Discard(
        const char *transaction_root,
        UpdateRecoveryProgress *recovery_progress = 0);

    UpdateTransactionStoreStatus DiscardCommitted(
        const char *transaction_root,
        UpdateRecoveryProgress *recovery_progress = 0);

    UpdateRequestPersistenceStatus Persist(
        const AuthenticatedUpdateRequest &request);
    UpdateRequestPersistenceStatus DiscardPersisted(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0);
    UpdateRequestPersistenceStatus DeactivatePersisted(
        UpdateRecoveryProgress *recovery_progress = 0);
    UpdateRequestPersistenceStatus RetainCommitted(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0);
    UpdateRequestPersistenceStatus DiscardRetainedCommitted(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0);

private:
    UpdateTransactionRequestStore(const UpdateTransactionRequestStore &);
    UpdateTransactionRequestStore &operator=(
        const UpdateTransactionRequestStore &);

    UpdateFileSystem *file_system_;
    uint8_t io_buffer_[4096U];

    UpdateTransactionStoreStatus LoadNamed(
        const char *transaction_root,
        const char *state_name,
        BoardFamily expected_board,
        const PersistedUpdateRequestBuffers &buffers,
        ValidatedReleaseDownload *release,
        AuthenticatedUpdateRequest *request,
        UpdateRecoveryProgress *recovery_progress);
    UpdateTransactionStoreStatus DiscardNamed(
        const char *transaction_root,
        const char *state_name,
        UpdateRecoveryProgress *recovery_progress);
};

const char *UpdateTransactionStoreStatusString(
    UpdateTransactionStoreStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_TRANSACTION_STORE_H
