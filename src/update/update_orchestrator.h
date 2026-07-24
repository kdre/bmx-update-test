#ifndef BMX_UPDATE_UPDATE_ORCHESTRATOR_H
#define BMX_UPDATE_UPDATE_ORCHESTRATOR_H

#include "update/body_sinks.h"
#include "update/github_release_client.h"
#include "update/update_health.h"
#include "update/update_install_readiness.h"
#include "update/update_installer.h"
#include "update/update_recovery_progress.h"

namespace bmx {
namespace update {

enum class AuthenticatedReleaseValidationStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    AuthenticationRejected
};

struct AuthenticatedReleaseValidationResult {
    AuthenticatedReleaseValidationStatus status;
    ReleaseOfferResult offer_result;
};

// A ValidatedReleaseDownload contains public POD fields and is therefore not
// itself an unforgeable capability.  The orchestrator accepts a release only
// after this injected boundary produces a fresh ReleaseOffer from the raw
// installed/GitHub/manifest/signature bytes.
class AuthenticatedReleaseValidator {
public:
    virtual ~AuthenticatedReleaseValidator() {}
    // Implementations must derive fresh_offer exclusively from the immutable
    // raw byte views in download and must not consume download.offer.  The
    // caller may use that non-authoritative cached member as output scratch.
    virtual AuthenticatedReleaseValidationResult Revalidate(
        const ValidatedReleaseDownload &download,
        BoardFamily running_board,
        ReleaseOffer *fresh_offer) = 0;
};

// Concrete raw revalidator used by production integration.  Its parser
// storage and trusted-key inputs must remain alive and exclusively owned for
// every synchronous call.  The same instance/storage is not reentrant; raw
// buffers must not be mutated concurrently.
class RawAuthenticatedReleaseValidator : public AuthenticatedReleaseValidator {
public:
    RawAuthenticatedReleaseValidator(
        const TrustedReleaseKey *trusted_keys,
        size_t trusted_key_count,
        VerifyP256SignatureFunction verify_function,
        void *verify_context,
        const ReleaseOfferStorage &storage);

    AuthenticatedReleaseValidationResult Revalidate(
        const ValidatedReleaseDownload &download,
        BoardFamily running_board,
        ReleaseOffer *fresh_offer);

private:
    const TrustedReleaseKey *trusted_keys_;
    size_t trusted_key_count_;
    VerifyP256SignatureFunction verify_function_;
    void *verify_context_;
    ReleaseOfferStorage storage_;
};

// Every downstream operation receives the same immutable binding.  It is
// derived only from a freshly raw-revalidated ReleaseOffer, current sealed
// foreground/config consent, and the validated transaction identity.
// Implementations must not substitute a URL, board, release sequence,
// transaction, or digest.
struct AuthenticatedUpdateBinding {
    const char *archive_url;
    const char *archive_filename;
    const char *transaction_root;
    BoardFamily board;
    uint64_t source_release_sequence;
    uint64_t target_release_sequence;
    uint64_t old_boot_generation;
    uint64_t new_boot_generation;
    uint64_t archive_size;
    uint8_t transaction_id[kTransactionIdBytes];
    uint8_t archive_sha256[kSha256DigestBytes];
    uint8_t manifest_sha256[kSha256DigestBytes];
    uint8_t consent_sha256[kSha256DigestBytes];
    bool reset_required;
    bool reset_approved;
};

// Input to both phases.  `release` must be the successful output of
// CheckLatestRelease(), not a separately parsed or caller-created manifest.
// The raw installed/GitHub/manifest/signature buffers must remain immutable
// and alive for the complete call.  The injected raw validator separately
// owns caller-provided ReleaseOfferStorage with the same lifetime.
struct AuthenticatedUpdateRequest {
    const ValidatedReleaseDownload *release;
    BoardFamily running_board;
    const char *transaction_root;
    uint8_t transaction_id[kTransactionIdBytes];
    uint64_t old_boot_generation;
    uint64_t new_boot_generation;
    uint8_t consent_sha256[kSha256DigestBytes];
    bool reset_required;
    bool reset_approved;
    // Opaque, one-use handle issued by the foreground Update-menu controller.
    // A production authorization source owns and consumes it; the numeric
    // value is never trusted by the orchestrator itself.
    uint64_t foreground_authorization_token;
};

enum class UpdateRequestPersistenceStatus : uint8_t {
    Ok = 0,
    Failed,
    RecoveryProgressFailed
};

// Persists the raw, already-authenticated request inputs and the sealed local
// transaction identity for a network-free ResumeAfterBoot.  Persist must
// write any activation record last.  DiscardPersisted must be idempotent and
// remove that activation record first, leaving partial payload bytes inert.
// DeactivatePersisted is the binding-independent recovery escape hatch: it
// removes only the fixed activation record before a previous-boot fail-safe.
// It must be idempotent and must never derive a path from rejected input.
class UpdateRequestPersistence {
public:
    virtual ~UpdateRequestPersistence() {}
    virtual UpdateRequestPersistenceStatus Persist(
        const AuthenticatedUpdateRequest &request) = 0;
    virtual UpdateRequestPersistenceStatus DiscardPersisted(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
    virtual UpdateRequestPersistenceStatus DeactivatePersisted(
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
    // A successful commit removes boot activation but retains the signed raw
    // request and rollback snapshot until the next explicitly confirmed
    // Update action. Platforms must opt in; the base implementation fails
    // closed.
    virtual UpdateRequestPersistenceStatus RetainCommitted(
        const AuthenticatedUpdateBinding &,
        UpdateRecoveryProgress * = 0) {
        return UpdateRequestPersistenceStatus::Failed;
    }
    virtual UpdateRequestPersistenceStatus DiscardRetainedCommitted(
        const AuthenticatedUpdateBinding &,
        UpdateRecoveryProgress * = 0) {
        return UpdateRequestPersistenceStatus::Failed;
    }
};

class ForegroundUpdateAuthorizationSource {
public:
    virtual ~ForegroundUpdateAuthorizationSource() {}
    // Atomically consumes an outstanding one-use Update-menu authorization
    // and re-reads current network-feature/ready state into `current`.  It
    // must reject forged, expired, replayed, boot-time, and background tokens.
    virtual bool ConsumeAndReadCurrent(
        uint64_t foreground_authorization_token,
        UpdateStartContext *current) = 0;
};

enum class CurrentConfigConsentStatus : uint8_t {
    Ok = 0,
    ReadFailed,
    InvalidOrBlocked,
    DigestFailed
};

struct CurrentConfigConsentEvidence {
    uint8_t consent_sha256[kSha256DigestBytes];
    OfferConfigurationStatus configuration_status;
};

// A target implementation must re-read the current configuration during this
// call, assess it against the freshly authenticated manifest, and compute the
// exact consent digest using authenticated_manifest_sha256 (the digest of the
// same raw manifest bytes that produced fresh_offer). Cached menu assessment
// alone is insufficient.
class CurrentConfigConsentSource {
public:
    virtual ~CurrentConfigConsentSource() {}
    virtual CurrentConfigConsentStatus ReReadAndCompute(
        const ReleaseOffer &fresh_offer,
        BoardFamily running_board,
        const uint8_t authenticated_manifest_sha256[kSha256DigestBytes],
        CurrentConfigConsentEvidence *evidence) = 0;
};

enum class AuthorizationConsentStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    NotExplicitUserAction,
    NetworkFeatureDisabled,
    NetworkNotReady,
    ConfigRevalidationFailed,
    ConfigBlocked,
    ConsentMismatch,
    ResetDecisionMismatch
};

struct SealedUpdateAuthorization {
    uint8_t consent_sha256[kSha256DigestBytes];
    bool reset_required;
    bool reset_approved;
};

struct AuthorizationConsentResult {
    AuthorizationConsentStatus status;
    UpdateStartDecision start_decision;
    CurrentConfigConsentStatus config_status;
};

class AuthorizationConsentGate {
public:
    virtual ~AuthorizationConsentGate() {}
    virtual AuthorizationConsentResult AuthorizeAndSeal(
        const AuthenticatedUpdateRequest &request,
        const ReleaseOffer &fresh_offer,
        SealedUpdateAuthorization *sealed) = 0;
};

// Concrete foreground/network policy.  Config provenance is delegated only to
// a source whose contract requires an immediate local re-read.
class ForegroundNetworkAuthorizationConsentGate
    : public AuthorizationConsentGate {
public:
    explicit ForegroundNetworkAuthorizationConsentGate(
        ForegroundUpdateAuthorizationSource *foreground_source,
        CurrentConfigConsentSource *config_source);
    AuthorizationConsentResult AuthorizeAndSeal(
        const AuthenticatedUpdateRequest &request,
        const ReleaseOffer &fresh_offer,
        SealedUpdateAuthorization *sealed);

private:
    ForegroundUpdateAuthorizationSource *foreground_source_;
    CurrentConfigConsentSource *config_source_;
};

enum class ArchiveFetchStatus : uint8_t {
    Ok = 0,
    Failed,
    Canceled
};

// The transport owns network/TLS/redirect policy.  The URL is the exact
// GitHub board-ZIP URL already bound into the authenticated offer.  `sink`
// must receive the response body only and no more than maximum_body_bytes.
class UpdateArchiveTransport {
public:
    virtual ~UpdateArchiveTransport() {}
    virtual ArchiveFetchStatus Fetch(const char *authenticated_url,
                                     uint64_t maximum_body_bytes,
                                     HttpBodySink *sink) = 0;
};

enum class ArchiveStorageStatus : uint8_t {
    Ok = 0,
    Failed,
    NotFound,
    Busy,
    RecoveryProgressFailed
};

// A transaction-scoped durable download.  Begin must create a fresh .part
// object, Finish must sync/publish it, and OpenRead must return the exact
// object selected by the full binding.  The orchestrator independently hashes
// both the streamed bytes and the reopened SeekableZipSource.  Abort applies
// only before Finish; Discard removes a completed transaction download.
class UpdateArchiveStorage : public HttpBodySink {
public:
    virtual ~UpdateArchiveStorage() {}
    virtual ArchiveStorageStatus Begin(
        const AuthenticatedUpdateBinding &binding) = 0;
    virtual ArchiveStorageStatus Finish() = 0;
    virtual void Abort() = 0;
    virtual ArchiveStorageStatus OpenRead(
        const AuthenticatedUpdateBinding &binding,
        SeekableZipSource **source) = 0;
    virtual ArchiveStorageStatus CloseRead() = 0;
    virtual ArchiveStorageStatus Discard(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
};

enum class InstallReadinessGateStatus : uint8_t {
    Ready = 0,
    Blocked,
    ProbeFailed
};

class InstallReadinessGate {
public:
    virtual ~InstallReadinessGate() {}
    virtual InstallReadinessGateStatus Probe(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        UpdateInstallReadinessResult *readiness) = 0;
};

// Concrete read-only adapter.  It delegates to ProbeUpdateInstallReadiness,
// including free-space, local inventory, durability and all platform gates.
class ProbeInstallReadinessGate : public InstallReadinessGate {
public:
    ProbeInstallReadinessGate(
        UpdateFileSystem *file_system,
        const UpdateInstallPlatformReadiness &platform);
    InstallReadinessGateStatus Probe(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        UpdateInstallReadinessResult *readiness);

private:
    UpdateFileSystem *file_system_;
    UpdateInstallPlatformReadiness platform_;
};

enum class PreparedConfigProviderStatus : uint8_t {
    Ok = 0,
    InvalidBinding,
    SourceChanged,
    IoError,
    Unsupported,
    RecoveryProgressFailed
};

// PrepareForStage must build and durably record exactly one prepared entry
// for every ConfigTemplate.  The result is bound to the manifest digest,
// consent digest, and reset decision and must remain alive through Stage().
// RestoreForResume reconstructs the same metadata after reboot; entry content
// may be null then because Commit/Rollback use only the persisted evidence.
class PreparedConfigProvider {
public:
    virtual ~PreparedConfigProvider() {}
    virtual PreparedConfigProviderStatus PrepareForStage(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        SeekableZipSource *authenticated_archive,
        const PreparedConfigSet **prepared,
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
    virtual PreparedConfigProviderStatus RestoreForResume(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        const PreparedConfigSet **prepared,
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
    virtual PreparedConfigProviderStatus Discard(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0) = 0;
};

// This narrow adapter makes the persistent state sequence host-testable while
// the production implementation still calls UpdateInstaller directly.
class UpdateInstallOperations {
public:
    virtual ~UpdateInstallOperations() {}
    virtual InstallerResult ReadJournal(const char *transaction_root,
                                        JournalRecord *record) = 0;
    virtual InstallerResult Stage(const InstallerRequest &request,
                                  const InstallerWorkspace &workspace) = 0;
    virtual InstallerResult ArmCandidate(const InstallerRequest &request) = 0;
    virtual InstallerResult MarkCandidateHealthy(
        const InstallerRequest &request) = 0;
    virtual InstallerResult Commit(const InstallerRequest &request,
                                   const InstallerWorkspace &workspace) = 0;
    virtual InstallerResult Rollback(const InstallerRequest &request,
                                     const InstallerWorkspace &workspace) = 0;
    virtual InstallerResult RetireRolledBack(
        const InstallerRequest &,
        const InstallerWorkspace &) {
        InstallerResult result = {};
        result.status = InstallerStatus::InvalidArgument;
        return result;
    }
    virtual InstallerResult RetireCommitted(
        const InstallerRequest &,
        const InstallerWorkspace &) {
        InstallerResult result = {};
        result.status = InstallerStatus::InvalidArgument;
        return result;
    }
};

class DirectUpdateInstallOperations : public UpdateInstallOperations {
public:
    explicit DirectUpdateInstallOperations(UpdateInstaller *installer);
    InstallerResult ReadJournal(const char *transaction_root,
                                JournalRecord *record);
    InstallerResult Stage(const InstallerRequest &request,
                          const InstallerWorkspace &workspace);
    InstallerResult ArmCandidate(const InstallerRequest &request);
    InstallerResult MarkCandidateHealthy(const InstallerRequest &request);
    InstallerResult Commit(const InstallerRequest &request,
                           const InstallerWorkspace &workspace);
    InstallerResult Rollback(const InstallerRequest &request,
                             const InstallerWorkspace &workspace);
    InstallerResult RetireRolledBack(const InstallerRequest &request,
                                     const InstallerWorkspace &workspace);
    InstallerResult RetireCommitted(const InstallerRequest &request,
                                    const InstallerWorkspace &workspace);

private:
    UpdateInstaller *installer_;
};

class CandidateHealthProbe {
public:
    virtual ~CandidateHealthProbe() {}
    // The orchestrator passes the same freshly re-authenticated manifest used
    // to construct binding. Production probes must collect only local,
    // network-free runtime evidence and bind it to both values.
    virtual bool Collect(const AuthenticatedUpdateBinding &binding,
                         const ReleaseManifest &manifest,
                         CandidateHealthEvidence *evidence) = 0;
};

enum class UpdateRebootTarget : uint8_t {
    OneShotCandidate = 0,
    PreviousInstallation
};

class UpdateRebootControl {
public:
    virtual ~UpdateRebootControl() {}
    // Must remain false until one-shot tryboot and old-install recovery have
    // both passed the target hardware matrix.
    virtual bool OneShotRecoverySupported() const = 0;
    virtual bool RequestReboot(UpdateRebootTarget target,
                               const AuthenticatedUpdateBinding &binding) = 0;
    // Must select/request the known previous installation without consuming
    // any caller-provided release, transaction, path, or digest.  Resume uses
    // this when those inputs cannot be authenticated or restored.
    virtual bool RequestPreviousBootFailSafe() = 0;
};

struct UpdateOrchestratorWorkspace {
    InstallerWorkspace installer;
    // Mandatory caller-owned scratch for raw release revalidation.  A
    // ReleaseOffer is about 27 KiB on the supported target ABIs and must not
    // be placed in Start()/ResumeAfterBoot() stack frames.  The scratch is
    // synchronously overwritten and need not retain its contents afterward.
    // It may alias ValidatedReleaseDownload::offer: a conforming validator
    // derives the output only from the immutable raw byte views, never from
    // that freely copyable cached offer.
    ReleaseOffer *release_offer;
    // Used for the independent post-download size/SHA-256 readback.  It may
    // alias installer.io_buffer and must be at least 4096 bytes.
    uint8_t *verification_buffer;
    size_t verification_buffer_size;
    // Mandatory for ResumeAfterBoot().  Start() may bind the same synchronous
    // callback to a foreground progress/cancel controller.  Production boot
    // recovery binds it to the boot-lifetime candidate-watchdog owner.  No
    // timer/background reporter is used in either path.
    UpdateRecoveryProgress *recovery_progress;
};

enum class UpdateOrchestratorPhase : uint8_t {
    None = 0,
    Validate,
    InspectJournal,
    PersistRequest,
    Download,
    VerifyStoredArchive,
    PrepareConfiguration,
    Stage,
    ArmCandidate,
    RequestCandidateReboot,
    RestoreConfiguration,
    ProbeHealth,
    MarkHealthy,
    Commit,
    Rollback,
    RequestPreviousReboot,
    Cleanup,
    RetirePrevious
};

// Numeric values are persisted in UpdateLocalLog v1 rollback diagnostics.
// Append only; never renumber or reuse an existing value.
enum class UpdateOrchestratorStatus : uint8_t {
    CandidateRebootRequested = 0,
    UpdateCommitted = 1,
    RollbackRebootRequested = 2,
    InterruptedBeforeCandidateCleaned = 3,
    InvalidArgument = 4,
    AuthenticatedOfferInvalid = 5,
    IdentityInvalid = 6,
    ConsentInvalid = 7,
    AuthorizationDenied = 8,
    PlatformUnsupported = 9,
    WorkspaceTooSmall = 10,
    ReadinessBlocked = 11,
    ReadinessProbeFailed = 12,
    StorageBeginFailed = 13,
    RequestPersistenceFailed = 14,
    DownloadFailed = 15,
    DownloadCanceled = 16,
    DownloadVerificationFailed = 17,
    StorageFinishFailed = 18,
    StorageOpenFailed = 19,
    StoredArchiveVerificationFailed = 20,
    StorageCloseFailed = 21,
    PreparedConfigFailed = 22,
    PreparedConfigInvalid = 23,
    InstallerStageFailed = 24,
    InstallerArmFailed = 25,
    CandidateRebootFailed = 26,
    HealthProbeFailed = 27,
    CandidateUnhealthy = 28,
    InstallerHealthTransitionFailed = 29,
    InstallerCommitFailed = 30,
    InstallerRollbackFailed = 31,
    RecoveryJournalInvalid = 32,
    RecoveryDeactivationFailed = 33,
    PreviousRebootFailed = 34,
    RecoveryProgressFailed = 35,
    PreviousRetentionFailed = 36,
    PreviousRetired = 37,
    CleanupFailed = 38
};

struct UpdateOrchestratorResult {
    UpdateOrchestratorStatus status;
    UpdateOrchestratorPhase phase;
    ArchiveFetchStatus fetch_status;
    ArchiveStorageStatus storage_status;
    UpdateRequestPersistenceStatus persistence_status;
    PreparedConfigProviderStatus prepared_config_status;
    AuthenticatedReleaseValidationResult release_validation;
    AuthorizationConsentResult authorization;
    InstallReadinessGateStatus readiness_status;
    UpdateInstallReadinessResult readiness;
    CandidateHealthStatus health_status;
    // When status is RollbackRebootRequested, this retains the condition that
    // triggered the safe rollback (health, health transition, or commit).
    UpdateOrchestratorStatus rollback_trigger;
    InstallerResult installer_result;
    InstallerResult rollback_result;
    InstallerResult rollback_cleanup_result;
    uint64_t verified_archive_bytes;
    bool rollback_attempted;
    bool previous_boot_failsafe_requested;
};

class UpdateOrchestrator {
public:
    UpdateOrchestrator(AuthenticatedReleaseValidator *release_validator,
                       AuthorizationConsentGate *authorization,
                       InstallReadinessGate *readiness,
                       UpdateArchiveTransport *transport,
                       UpdateArchiveStorage *storage,
                       UpdateRequestPersistence *request_persistence,
                       PreparedConfigProvider *prepared_configs,
                       UpdateInstallOperations *installer,
                       CandidateHealthProbe *health,
                       UpdateRebootControl *reboot);

    // Explicit foreground phase: download, independently owned archive and
    // content integrity passes, UpdateInstaller::Stage/ArmCandidate, and
    // candidate reboot.
    UpdateOrchestratorResult Start(
        const AuthenticatedUpdateRequest &request,
        const UpdateOrchestratorWorkspace &workspace);

    // Post-boot phase.  A healthy candidate is marked and committed.  Every
    // negative/indeterminate health result is fail-closed into installer
    // rollback and a reboot request for the previous installation.
    UpdateOrchestratorResult ResumeAfterBoot(
        const AuthenticatedUpdateRequest &request,
        const UpdateOrchestratorWorkspace &workspace);

    // Re-authenticates and retires an inert COMMITTED request loaded from the
    // fixed transaction store. This has no network dependency and is called
    // only as part of a later explicit Update-menu action.
    UpdateOrchestratorResult RetireCommitted(
        const AuthenticatedUpdateRequest &request,
        const UpdateOrchestratorWorkspace &workspace);

private:
    UpdateOrchestrator(const UpdateOrchestrator &);
    UpdateOrchestrator &operator=(const UpdateOrchestrator &);

    AuthenticatedReleaseValidator *release_validator_;
    AuthorizationConsentGate *authorization_;
    InstallReadinessGate *readiness_;
    UpdateArchiveTransport *transport_;
    UpdateArchiveStorage *storage_;
    UpdateRequestPersistence *request_persistence_;
    PreparedConfigProvider *prepared_configs_;
    UpdateInstallOperations *installer_;
    CandidateHealthProbe *health_;
    UpdateRebootControl *reboot_;
};

const char *UpdateOrchestratorStatusString(UpdateOrchestratorStatus status);
const char *UpdateOrchestratorPhaseString(UpdateOrchestratorPhase phase);
const char *AuthorizationConsentStatusString(
    AuthorizationConsentStatus status);
const char *UpdateStartDecisionString(UpdateStartDecision decision);
const char *CurrentConfigConsentStatusString(
    CurrentConfigConsentStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_ORCHESTRATOR_H
