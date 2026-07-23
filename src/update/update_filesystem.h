#ifndef BMX_UPDATE_UPDATE_FILESYSTEM_H
#define BMX_UPDATE_UPDATE_FILESYSTEM_H

#include "update/update_types.h"

namespace bmx {
namespace update {

// The installer deliberately knows nothing about FatFs, POSIX, or Circle.
// Implementations must keep all paths below the update volume root and must
// provide the durability guarantees documented on each operation.
enum class UpdateNodeType : uint8_t {
    Missing = 0,
    RegularFile,
    Directory,
    Other
};

struct UpdateFileStat {
    UpdateNodeType type;
    uint64_t size;
};

// These are capabilities, not assumptions. In particular, stock FatFs does
// not by itself prove any of the crash guarantees below. A platform adapter
// must return true only after its block layer, media flush behavior, and
// power-cut recovery model have been established for the target hardware.
struct UpdateDurabilityCapabilities {
    bool durable_file_sync;
    bool crash_safe_fresh_rename;
    bool crash_safe_replace_with_backup;
    bool durable_directory_updates;
    // Some FAT namespace updates are not individually atomic. This may be
    // true only when the complete journal/snapshot/selector recovery protocol
    // has passed the documented power-cut matrix and makes interrupted fresh
    // publishes and replace-with-backup operations deterministically
    // recoverable. It is an alternative safety contract, not an assertion
    // that FatFs rename itself became atomic.
    bool power_loss_recovery_validated;
};

class UpdateReadFile {
public:
    virtual ~UpdateReadFile() {}
    virtual bool GetSize(uint64_t *size) = 0;
    // A successful call fills the complete requested range.
    virtual bool ReadAt(uint64_t offset, uint8_t *destination, size_t size) = 0;
    virtual bool Close() = 0;
};

class UpdateWriteFile {
public:
    virtual ~UpdateWriteFile() {}
    virtual bool Write(ByteView bytes) = 0;
    // Sync must make all previously written file data durable.
    virtual bool Sync() = 0;
    virtual bool Close() = 0;
};

class UpdateFileSystem {
public:
    virtual ~UpdateFileSystem() {}

    // Missing is a successful Stat result, not an I/O error.
    virtual bool Stat(const char *path, UpdateFileStat *result) = 0;
    virtual bool OpenRead(const char *path, UpdateReadFile **file) = 0;
    // Fails if path already exists. The filesystem retains ownership of the
    // returned handle and may reuse it after Close.
    virtual bool CreateFileFresh(const char *path, UpdateWriteFile **file) = 0;
    // Idempotent for an existing directory, fail-closed for another node type.
    virtual bool CreateDirectory(const char *path) = 0;
    // Removing a missing path succeeds. RemoveDirectory only removes empties.
    virtual bool RemoveFile(const char *path) = 0;
    virtual bool RemoveDirectory(const char *path) = 0;
    // Rename performs the requested namespace operation. Crash behavior is
    // *not* implied by this method; it is declared separately through
    // GetDurabilityCapabilities. If replace_existing is false, an existing
    // target must fail during ordinary execution.
    virtual bool Rename(const char *source,
                        const char *destination,
                        bool replace_existing) = 0;
    // Request a metadata barrier for the containing directory/volume. This is
    // useful only when durable_directory_updates is truthfully advertised.
    virtual bool SyncContainingDirectory(const char *path) = 0;
    // Read-only, non-recursive namespace check used before retirement removes
    // its last authenticated journal. `only_expected` is true only when every
    // direct child name of `path` matches one of the supplied FAT names. The
    // default is fail-closed so an adapter cannot silently ignore unknown
    // transaction content.
    virtual bool DirectoryContainsOnly(
        const char *path, const char *const *expected_names,
        size_t expected_name_count, bool *only_expected)
    {
        (void) path;
        (void) expected_names;
        (void) expected_name_count;
        if (only_expected != 0) *only_expected = false;
        return false;
    }
    virtual bool GetFreeSpace(uint64_t *bytes) = 0;
    // Total mounted volume capacity. Legacy host adapters inherit a
    // conservative free-space fallback; production FatFs reports exact
    // geometry so updater-capable boot partitions below 512 MiB are blocked.
    virtual bool GetVolumeSize(uint64_t *bytes)
    {
        return GetFreeSpace(bytes);
    }
    // Reports the allocation unit of the mounted update volume.  The default
    // is fail-closed so adapters which predate cluster-aware accounting cannot
    // silently authorize an online install.
    virtual bool GetAllocationUnit(uint64_t *bytes)
    {
        if (bytes != 0) *bytes = 0U;
        return false;
    }
    virtual bool GetDurabilityCapabilities(
        UpdateDurabilityCapabilities *capabilities) = 0;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_FILESYSTEM_H
