#ifndef BMX_UPDATE_UPDATE_INSTALLER_H
#define BMX_UPDATE_UPDATE_INSTALLER_H

#include "update/release_manifest.h"
#include "update/storage_preflight.h"
#include "update/update_filesystem.h"
#include "update/update_journal.h"
#include "update/update_recovery_progress.h"
#include "update/zip_reader.h"

namespace bmx {
namespace update {

static const size_t kInstallerMaximumPathBytes = 512U;
static const size_t kInstallerMinimumIoBufferBytes = 4096U;

struct InstallerWorkspace {
    ZipEntry *zip_entries;
    size_t zip_entry_capacity;
    ZipExpectedFile *expected_files;
    size_t expected_file_capacity;
    const char **expected_directories;
    size_t expected_directory_capacity;
    ZipWorkspace *zip_workspace;
    uint8_t *io_buffer;
    size_t io_buffer_size;
};

struct InstallerIdentity {
    uint8_t transaction_id[kTransactionIdBytes];
    uint64_t source_release_sequence;
    // Authenticated installed version from the same raw-revalidated offer as
    // `manifest`. It is used only to select the exact signed source inventory
    // when an inert committed transaction is explicitly retired.
    const char *source_version;
    uint64_t old_boot_generation;
    uint64_t new_boot_generation;
    uint8_t manifest_sha256[kSha256DigestBytes];
    uint8_t consent_sha256[kSha256DigestBytes];
    bool reset_required;
    bool reset_approved;
};

// ConfigTemplate payloads in the release ZIP are signed defaults, not a
// license to overwrite local configuration. The migration layer must provide
// exactly one prepared result per ConfigTemplate. It binds that result to the
// current local source bytes, manifest, consent digest, and reset decision.
// `content` must remain immutable for the duration of Stage().
struct PreparedConfigTemplate {
    const char *path;
    SeekableZipSource *content;
    bool original_existed;
    uint64_t original_size;
    uint8_t original_sha256[kSha256DigestBytes];
    uint64_t prepared_size;
    uint8_t prepared_sha256[kSha256DigestBytes];
};

struct PreparedConfigSet {
    const PreparedConfigTemplate *entries;
    size_t entry_count;
    uint8_t manifest_sha256[kSha256DigestBytes];
    uint8_t consent_sha256[kSha256DigestBytes];
    bool reset_required;
    bool reset_approved;
};

struct InstallerRequest {
    const ReleaseManifest *manifest;
    // Required by Stage(), ignored by later local-only operations. Stage()
    // hashes and validates this seekable, already-downloaded archive again.
    SeekableZipSource *downloaded_zip;
    const char *transaction_root;
    InstallerIdentity identity;
    const PreparedConfigSet *prepared_configs;
    // Non-null only for the synchronous post-boot path.  Inner loops report
    // only after successful bounded I/O or durable journal progress.
    UpdateRecoveryProgress *recovery_progress;
};

struct CandidateContext {
    const char *transaction_root;
    const char *staging_root;
    // Authenticated asset retained by the caller for the complete operation.
    // Candidate backends use it to prove that a selector names exactly one
    // signed stable kernel for this board/release; they must never infer a
    // candidate by scanning writable filesystem state.
    const ManifestAsset *asset;
    BoardFamily board;
    uint64_t source_release_sequence;
    uint64_t target_release_sequence;
    uint64_t old_boot_generation;
    uint64_t new_boot_generation;
    uint8_t transaction_id[kTransactionIdBytes];
};

// Every method must be idempotent: the installer can call it again after a
// reset whose exact boundary is unknown. Supported() is checked before any
// active boot selection is requested. Production must return false until the
// board-specific tryboot implementation has passed its hardware gate.
class CandidateBackend {
public:
    virtual ~CandidateBackend() {}
    virtual bool Supported() const = 0;
    virtual bool ArmCandidate(const CandidateContext &context) = 0;
    virtual bool CommitCandidate(const CandidateContext &context) = 0;
    virtual bool DisarmCandidate(const CandidateContext &context) = 0;
};

// Numeric values are persisted in UpdateLocalLog v1 rollback diagnostics.
// Append only; never renumber or reuse an existing value.
enum class InstallerStatus : uint8_t {
    Ok = 0,
    AlreadyStaged = 1,
    AlreadyArmed = 2,
    AlreadyHealthy = 3,
    AlreadyCommitted = 4,
    AlreadyRetired = 5,
    NothingToRollback = 6,
    InvalidArgument = 7,
    InvalidPath = 8,
    InvalidManifest = 9,
    RetentionInventoryMissing = 10,
    RetentionConflict = 11,
    InvalidIdentity = 12,
    WorkspaceTooSmall = 13,
    ArchiveIo = 14,
    ArchiveHashMismatch = 15,
    ArchiveInvalid = 16,
    InventoryMismatch = 17,
    StorageInsufficient = 18,
    PreparedConfigRequired = 19,
    PreparedConfigInvalid = 20,
    ConfigChangedSinceConsent = 21,
    FileSystemDurabilityUnsupported = 22,
    FileSystemError = 23,
    UnexpectedNodeType = 24,
    KernelCollision = 25,
    PreserveChanged = 26,
    FileHashMismatch = 27,
    JournalCorrupt = 28,
    JournalConflict = 29,
    JournalCodecError = 30,
    JournalTransitionDenied = 31,
    WrongState = 32,
    CandidateBackendUnsupported = 33,
    CandidateBackendError = 34,
    RollbackEvidenceMissing = 35,
    RecoveryProgressFailed = 36
};

struct InstallerResult {
    InstallerStatus status;
    ZipStatus zip_status;
    StoragePreflightResult storage;
    JournalSelectionStatus journal_selection;
    JournalState journal_state;
    uint32_t completed_steps;
    uint32_t total_steps;
};

class UpdateInstaller {
public:
    UpdateInstaller(UpdateFileSystem *file_system,
                    CandidateBackend *candidate_backend);

    // Validates the complete archive before writing the first journal. It then
    // snapshots only ManagedReplace/ConfigTemplate files, extracts into a
    // fresh transaction staging tree, and activates all non-metadata files.
    // It does so only when the filesystem explicitly advertises every
    // required crash guarantee. Preserve entries that exist are untouched.
    InstallerResult Stage(const InstallerRequest &request,
                          const InstallerWorkspace &workspace);

    InstallerResult ArmCandidate(const InstallerRequest &request);
    InstallerResult MarkCandidateHealthy(const InstallerRequest &request);
    // Metadata is swapped only after health, then the injected selector is
    // committed. Old metadata remains in the transaction rollback area.
    InstallerResult Commit(const InstallerRequest &request,
                           const InstallerWorkspace &workspace);

    // Purely local and idempotent. It restores managed/config snapshots,
    // metadata rollback copies, removes only transaction-owned kernel or
    // newly-added preserve files, and never traverses unknown filesystem data.
    InstallerResult Rollback(const InstallerRequest &request,
                             const InstallerWorkspace &workspace);

    // Removes the inert installer-owned artifacts of a transaction whose
    // journal has reached IDLE after rollback. The authenticated request is
    // still retained by the caller while this runs, so cleanup remains bound
    // to the exact signed manifest. Journals are removed last and retries are
    // idempotent.
    InstallerResult RetireRolledBack(const InstallerRequest &request,
                                     const InstallerWorkspace &workspace);

    // Explicitly retires the rollback evidence of an authenticated committed
    // transaction so the fixed root can be reused by a later update. It never
    // traverses the filesystem and removes only manifest-derived paths below
    // transaction_root. Unknown content prevents directory removal.
    InstallerResult RetireCommitted(const InstallerRequest &request,
                                    const InstallerWorkspace &workspace);

    InstallerResult ReadJournal(const char *transaction_root,
                                JournalRecord *record);

    static bool ComputeStepCounts(const ManifestAsset &asset,
                                  uint32_t *stage_steps,
                                  uint32_t *total_steps);

private:
    UpdateInstaller(const UpdateInstaller &);
    UpdateInstaller &operator=(const UpdateInstaller &);

    UpdateFileSystem *file_system_;
    CandidateBackend *candidate_backend_;
};

const char *InstallerStatusString(InstallerStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_INSTALLER_H
