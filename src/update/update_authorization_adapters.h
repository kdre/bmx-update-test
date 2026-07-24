#ifndef BMX_UPDATE_UPDATE_AUTHORIZATION_ADAPTERS_H
#define BMX_UPDATE_UPDATE_AUTHORIZATION_ADAPTERS_H

#include "update/fatfs_config_snapshot.h"
#include "update/update_orchestrator.h"

#include <atomic>

namespace bmx {
namespace update {

static const uint64_t kDefaultForegroundAuthorizationLifetimeMilliseconds =
    UINT64_C(60000);
static const uint64_t kMaximumForegroundAuthorizationLifetimeMilliseconds =
    UINT64_C(5) * 60U * 1000U;

// Evidence captured after the user's confirmed configuration has been
// re-read, but before an inert previous transaction is retired.  Retirement
// is allowed to remove only the two fixed internal journals.  It must never
// silently rebind consent across a change to BMX-BUILD.json or user-owned
// configuration.
struct RetainedUpdateStateConsentEvidence {
    ConfigMigrationPlan plan;
    uint8_t build_info_sha256[kSha256DigestBytes];
};

enum class RetainedUpdateStateConsentStatus : uint8_t {
    Ok = 0,
    InvalidInput,
    UnexpectedUpdateState,
    ConfigurationChanged
};

RetainedUpdateStateConsentStatus CaptureRetainedUpdateStateConsentEvidence(
    const ConfigSnapshot &snapshot,
    const ConfigMigrationPlan &plan,
    RetainedUpdateStateConsentEvidence *evidence);

// Accepts the post-retirement plan only when every assessment is unchanged
// except for UpdateState's aggregate content hash, BMX-BUILD.json itself is
// byte-identical, and both internal journal files are now absent.
RetainedUpdateStateConsentStatus ValidateRetainedUpdateStateConsentTransition(
    const RetainedUpdateStateConsentEvidence &before,
    const ConfigSnapshot &after_snapshot,
    const ConfigMigrationPlan &after_plan);

const char *RetainedUpdateStateConsentStatusString(
    RetainedUpdateStateConsentStatus status);

class AuthorizationTokenEntropySource {
public:
    virtual ~AuthorizationTokenEntropySource() {}
    // Must return cryptographically unpredictable bytes in production.
    virtual bool Fill(uint8_t *output, size_t size) = 0;
};

class AuthorizationMonotonicClock {
public:
    virtual ~AuthorizationMonotonicClock() {}
    virtual bool NowMilliseconds(uint64_t *milliseconds) = 0;
};

class UpdateNetworkStateSource {
public:
    virtual ~UpdateNetworkStateSource() {}
    // Reads both values from the already configured network subsystem. This
    // method must never enable, initialize or reconfigure networking.
    virtual bool Read(bool *feature_enabled, bool *ready) = 0;
};

class OneShotForegroundUpdateAuthorizationSource;

// This controller is deliberately an instance capability. There is no global
// issuer, constructor hook, timer hook or network callback that can create an
// authorization. The explicit Update-menu/service controller must own and call
// this object only for the user's confirmed foreground action.
class ExplicitUpdateMenuAuthorizationController {
public:
    explicit ExplicitUpdateMenuAuthorizationController(
        OneShotForegroundUpdateAuthorizationSource *source);

    bool IssueForConfirmedMenuAction(uint64_t *token);
    void Revoke();

private:
    ExplicitUpdateMenuAuthorizationController(
        const ExplicitUpdateMenuAuthorizationController &);
    ExplicitUpdateMenuAuthorizationController &operator=(
        const ExplicitUpdateMenuAuthorizationController &);

    OneShotForegroundUpdateAuthorizationSource *source_;
};

// Holds at most one unpredictable, short-lived authorization. Correct
// consumption clears it before the current network state is read, so replay or
// re-entrancy cannot authorize a second transaction. A forged token does not
// revoke the legitimate pending action; an expired or clock-regressed token
// does. Issuance is private and available only through the explicit controller.
class OneShotForegroundUpdateAuthorizationSource
    : public ForegroundUpdateAuthorizationSource {
public:
    OneShotForegroundUpdateAuthorizationSource(
        AuthorizationTokenEntropySource *entropy,
        AuthorizationMonotonicClock *clock,
        UpdateNetworkStateSource *network,
        uint64_t lifetime_milliseconds =
            kDefaultForegroundAuthorizationLifetimeMilliseconds);

    bool ConsumeAndReadCurrent(uint64_t foreground_authorization_token,
                               UpdateStartContext *current);

private:
    friend class ExplicitUpdateMenuAuthorizationController;

    bool Issue(uint64_t *token);
    void RevokePending();
    void Lock();
    void Unlock();

    OneShotForegroundUpdateAuthorizationSource(
        const OneShotForegroundUpdateAuthorizationSource &);
    OneShotForegroundUpdateAuthorizationSource &operator=(
        const OneShotForegroundUpdateAuthorizationSource &);

    AuthorizationTokenEntropySource *entropy_;
    AuthorizationMonotonicClock *clock_;
    UpdateNetworkStateSource *network_;
    uint64_t lifetime_milliseconds_;
    uint64_t pending_token_;
    uint64_t last_token_;
    uint64_t issued_at_milliseconds_;
    bool pending_;
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
};

// Re-loads a bounded FatFsConfigSnapshot for every call, assesses it against
// the freshly authenticated offer's exact schema/migration declarations, and
// computes the same all-area consent digest used by explicit discovery. It is
// read-only and owns no cached authorization decision.
class FatFsCurrentConfigConsentSource : public CurrentConfigConsentSource {
public:
    explicit FatFsCurrentConfigConsentSource(const char *volume = "SYS:");

    CurrentConfigConsentStatus ReReadAndCompute(
        const ReleaseOffer &fresh_offer,
        BoardFamily running_board,
        const uint8_t authenticated_manifest_sha256[kSha256DigestBytes],
        CurrentConfigConsentEvidence *evidence);

private:
    FatFsCurrentConfigConsentSource(const FatFsCurrentConfigConsentSource &);
    FatFsCurrentConfigConsentSource &operator=(
        const FatFsCurrentConfigConsentSource &);

    char volume_[13U];
    FatFsConfigSnapshot snapshot_;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_AUTHORIZATION_ADAPTERS_H
