#ifndef BMX_UPDATE_FATFS_PREPARED_CONFIG_H
#define BMX_UPDATE_FATFS_PREPARED_CONFIG_H

#include "update/fatfs_config_snapshot.h"
#include "update/fatfs_update_archive.h"
#include "update/fatfs_update_filesystem.h"
#include "update/selector_candidate_backend.h"
#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

// The boot-v1 manifest currently has ten fixed ConfigTemplate paths.  Keep a
// little headroom for a future authenticated profile while retaining a hard
// bound on RAM, evidence size and cleanup scope.
static const size_t kFatFsPreparedConfigMaximumTemplates = 16U;
static const size_t kFatFsPreparedConfigEvidenceBytes = 5536U;

enum class PreparedConfigRepresentabilityStatus : uint8_t {
    Ok = 0,
    InvalidInput,
    UnsupportedTemplatePath,
    RequiredTemplateMissing,
    ChangedAreaSourceMissing,
    ChangedSourceNotTemplate,
    SharedCmdlineNetworkTransform
};

struct PreparedConfigRepresentabilityResult {
    PreparedConfigRepresentabilityStatus status;
    ConfigArea area;
    char path[kMaximumConfigPathBytes + 1U];

    bool representable() const {
        return status == PreparedConfigRepresentabilityStatus::Ok;
    }
};

// Pure, read-only preflight over an authenticated manifest and the exact local
// classification snapshot.  It mirrors all path-level transformation limits
// of FatFsPreparedConfigProvider without reading the ZIP or writing storage.
PreparedConfigRepresentabilityResult CheckPreparedConfigRepresentability(
    const ConfigMigrationPlan &plan,
    const ConfigSnapshot &snapshot,
    const ReleaseManifest &manifest);

// Produces a bounded, value-free reason suitable for the menu.  Local config
// bytes and user-selected setting filenames are never copied to the output.
bool FormatPreparedConfigRepresentabilityFailure(
    const PreparedConfigRepresentabilityResult &result,
    char *output,
    size_t output_size);

const char *PreparedConfigRepresentabilityStatusString(
    PreparedConfigRepresentabilityStatus status);

// Concrete, synchronous PreparedConfigProvider for the FatFs boot volume.
// It never writes an active configuration path.  Prepared bytes and their
// evidence are published below
//   <transaction_root>/prepared-<complete-binding-sha256>/
// and are therefore scoped to the exact authenticated transaction, manifest,
// consent digest and reset decision.
//
// The caller-owned InstallerWorkspace is reused only during
// PrepareForStage().  It may subsequently be reused by UpdateInstaller after
// that call returns.  The provider and filesystem are single-caller and must
// remain alive through Stage()/Resume cleanup.
class FatFsPreparedConfigProvider : public PreparedConfigProvider {
public:
    FatFsPreparedConfigProvider(FatFsUpdateFileSystem *file_system,
                                const InstallerWorkspace &workspace,
                                const char *volume = "SYS:");
    ~FatFsPreparedConfigProvider();

    PreparedConfigProviderStatus PrepareForStage(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        SeekableZipSource *authenticated_archive,
        const PreparedConfigSet **prepared,
        UpdateRecoveryProgress *recovery_progress = 0) override;
    PreparedConfigProviderStatus RestoreForResume(
        const AuthenticatedUpdateBinding &binding,
        const ReleaseManifest &manifest,
        const PreparedConfigSet **prepared,
        UpdateRecoveryProgress *recovery_progress = 0) override;
    PreparedConfigProviderStatus Discard(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0) override;

    FatFsConfigSnapshotStatus last_snapshot_status() const {
        return last_snapshot_status_;
    }
    ConfigAssessmentStatus last_assessment_status() const {
        return last_assessment_status_;
    }
    ConfigChangeStatus last_change_status() const {
        return last_change_status_;
    }
    KernelSelectorStatus last_selector_status() const {
        return last_selector_status_;
    }
    ZipStatus last_zip_status() const { return last_zip_status_; }
    const PreparedConfigRepresentabilityResult &last_representability() const {
        return last_representability_;
    }

private:
    class PreparedFileSource : public SeekableZipSource {
    public:
        PreparedFileSource();
        void Configure(UpdateFileSystem *file_system, const char *path,
                       uint64_t expected_size);
        void Reset();
        bool GetSize(uint64_t *size) override;
        bool ReadAt(uint64_t offset, uint8_t *destination,
                    size_t size) override;

    private:
        UpdateFileSystem *file_system_;
        char path_[kFatFsUpdateFileSystemRelativePathBytes];
        uint64_t expected_size_;
        bool configured_;
    };

    FatFsPreparedConfigProvider(const FatFsPreparedConfigProvider &);
    FatFsPreparedConfigProvider &operator=(
        const FatFsPreparedConfigProvider &);

    void ResetPublishedSet();

    UpdateFileSystem *file_system_;
    InstallerWorkspace workspace_;
    char volume_[20U];
    bool configured_;
    bool active_;
    uint8_t active_binding_sha256_[kSha256DigestBytes];
    char active_root_[kFatFsUpdateFileSystemRelativePathBytes];
    char entry_paths_[kFatFsPreparedConfigMaximumTemplates]
                     [kMaximumManifestPathBytes + 1U];
    PreparedFileSource sources_[kFatFsPreparedConfigMaximumTemplates];
    PreparedConfigTemplate entries_[kFatFsPreparedConfigMaximumTemplates];
    PreparedConfigSet set_;
    FatFsConfigSnapshot snapshot_;
    FatFsConfigSnapshotStatus last_snapshot_status_;
    ConfigAssessmentStatus last_assessment_status_;
    ConfigChangeStatus last_change_status_;
    KernelSelectorStatus last_selector_status_;
    ZipStatus last_zip_status_;
    PreparedConfigRepresentabilityResult last_representability_;
};

const char *PreparedConfigProviderStatusString(
    PreparedConfigProviderStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_FATFS_PREPARED_CONFIG_H
