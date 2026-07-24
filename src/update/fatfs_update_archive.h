#ifndef BMX_UPDATE_FATFS_UPDATE_ARCHIVE_H
#define BMX_UPDATE_FATFS_UPDATE_ARCHIVE_H

#include "update/fatfs_update_storage.h"
#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

// The final and temporary archive names contain a SHA-256 fingerprint of the
// complete authenticated binding.  A different transaction, release, URL,
// archive hash, manifest, consent decision, or boot generation therefore
// resolves to a different object even after a reboot.
struct FatFsUpdateArchivePaths {
    char part_path[kFatFsUpdatePathBytes];
    char final_path[kFatFsUpdatePathBytes];
    uint8_t binding_sha256[kSha256DigestBytes];
};

FatFsStorageStatus BuildFatFsUpdateArchivePaths(
    const char *volume,
    const AuthenticatedUpdateBinding &binding,
    FatFsUpdateArchivePaths *paths);

// Synchronous, single-caller FatFs implementation of UpdateArchiveStorage.
// It deliberately provides no readiness claim: target code must keep online
// writes gated until the separate filesystem and hardware recovery contract
// has passed.  Abort and Discard touch only paths derived from the supplied
// authenticated binding and are safe to repeat for already-absent files.
class FatFsUpdateArchiveStorage : public UpdateArchiveStorage {
public:
    explicit FatFsUpdateArchiveStorage(const char *volume = "SYS:");
    ~FatFsUpdateArchiveStorage();

    ArchiveStorageStatus Begin(
        const AuthenticatedUpdateBinding &binding) override;
    bool Write(const uint8_t *data, size_t size) override;
    ArchiveStorageStatus Finish() override;
    void Abort() override;
    ArchiveStorageStatus OpenRead(
        const AuthenticatedUpdateBinding &binding,
        SeekableZipSource **source) override;
    ArchiveStorageStatus CloseRead() override;
    ArchiveStorageStatus Discard(
        const AuthenticatedUpdateBinding &binding,
        UpdateRecoveryProgress *recovery_progress = 0) override;

    bool configured() const { return configured_; }
    FatFsStorageStatus last_fatfs_status() const {
        return last_fatfs_status_;
    }

private:
    enum class State : uint8_t {
        Idle = 0,
        Writing,
        Completed,
        Reading,
        CleanupPending
    };

    FatFsUpdateArchiveStorage(const FatFsUpdateArchiveStorage &);
    FatFsUpdateArchiveStorage &operator=(const FatFsUpdateArchiveStorage &);

    bool BindingMatches(const FatFsUpdateArchivePaths &paths) const;
    void Remember(const FatFsUpdateArchivePaths &paths);
    void ClearRemembered();
    bool CleanupRemembered(bool remove_final,
                           UpdateRecoveryProgress *recovery_progress = 0,
                           bool *progress_failed = 0);

    char volume_[20U];
    FatFsDownloadSink download_;
    FatFsZipSource source_;
    FatFsUpdateArchivePaths active_paths_;
    State state_;
    bool configured_;
    bool have_active_paths_;
    bool failed_finish_may_have_final_;
    FatFsStorageStatus last_fatfs_status_;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_FATFS_UPDATE_ARCHIVE_H
