#ifndef BMX_UPDATE_FATFS_UPDATE_STORAGE_H
#define BMX_UPDATE_FATFS_UPDATE_STORAGE_H

#include "http_response_parser.h"
#include "sha256.h"
#include "zip_reader.h"

#if defined(RASPI_COMPILE) || defined(BMX_UPDATE_USE_FATFS)
#include <ff.h>
#define BMX_UPDATE_HAS_FATFS 1
#else
#define BMX_UPDATE_HAS_FATFS 0
#endif

namespace bmx {
namespace update {

// Includes the volume prefix, separators and terminating NUL.  ZIP member
// names are capped separately at kZipMaximumPathBytes.
static const size_t kFatFsUpdatePathBytes = 512U;
static const size_t kFatFsVerifyBufferBytes = 8192U;

enum class FatFsStorageStatus : uint8_t {
    Ok = 0,
    BackendUnavailable,
    InvalidArgument,
    InvalidPath,
    PathTooLong,
    NotOpen,
    Busy,
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    SeekFailed,
    SyncFailed,
    CloseFailed,
    StatFailed,
    MkdirFailed,
    RemoveFailed,
    RenameFailed,
    SizeMismatch,
    LimitExceeded,
    HashFailed,
    HashMismatch,
    VerifyAfterWriteFailed
};

struct FatFsPathInfo {
    bool exists;
    bool is_directory;
    uint64_t size;
};

// Absolute update paths use an explicit FatFs volume (for example SYS:/) and
// relative paths use forward slashes only.  Both reject dot components,
// backslashes, controls and non-ASCII bytes.
FatFsStorageStatus ValidateFatFsAbsolutePath(const char *path);
FatFsStorageStatus ValidateFatFsRelativePath(const char *path);

FatFsStorageStatus FatFsStatPath(const char *path, FatFsPathInfo *info);
FatFsStorageStatus FatFsRemoveFileIfPresent(const char *path);

class FatFsDownloadSink : public HttpBodySink {
public:
    FatFsDownloadSink();
    ~FatFsDownloadSink();

    // part_path must end in .part.  Starting a new explicit download removes
    // only that stale .part file; it never replaces an existing final file.
    FatFsStorageStatus Start(
        const char *part_path, const char *final_path, uint64_t expected_size,
        const uint8_t expected_sha256[kSha256DigestBytes]);
    bool Write(const uint8_t *data, size_t size);

    // Syncs and closes, checks the streaming digest, then reopens and hashes
    // the complete file before the no-replace rename.  The caller still needs
    // the dual journal: FAT rename is not treated as power-loss transactional.
    FatFsStorageStatus Finish();
    void Abort(bool remove_part);

    FatFsStorageStatus last_status() const { return last_status_; }
    uint64_t bytes_written() const { return bytes_written_; }
    bool committed() const { return committed_; }

private:
    FatFsDownloadSink(const FatFsDownloadSink &);
    FatFsDownloadSink &operator=(const FatFsDownloadSink &);

#if BMX_UPDATE_HAS_FATFS
    FIL file_;
#endif
    bool open_;
    bool committed_;
    uint64_t expected_size_;
    uint64_t bytes_written_;
    uint8_t expected_sha256_[kSha256DigestBytes];
    Sha256 streaming_sha256_;
    char part_path_[kFatFsUpdatePathBytes];
    char final_path_[kFatFsUpdatePathBytes];
    uint8_t verify_buffer_[kFatFsVerifyBufferBytes];
    FatFsStorageStatus last_status_;
};

class FatFsZipSource : public SeekableZipSource {
public:
    FatFsZipSource();
    ~FatFsZipSource();

    FatFsStorageStatus Open(const char *path);
    FatFsStorageStatus Close();
    bool GetSize(uint64_t *size);
    bool ReadAt(uint64_t offset, uint8_t *destination, size_t size);
    FatFsStorageStatus last_status() const { return last_status_; }

private:
    FatFsZipSource(const FatFsZipSource &);
    FatFsZipSource &operator=(const FatFsZipSource &);

#if BMX_UPDATE_HAS_FATFS
    FIL file_;
#endif
    bool open_;
    uint64_t size_;
    FatFsStorageStatus last_status_;
};

class Sha256ZipHashSink : public ZipHashSink {
public:
    Sha256ZipHashSink();
    bool BeginFile(const char *validated_path, uint64_t size);
    bool Update(ByteView bytes);
    bool FinishFile(uint8_t digest[kSha256DigestBytes]);
    void AbortFile();

private:
    Sha256 sha256_;
    uint64_t expected_size_;
    uint64_t received_size_;
    bool active_;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_FATFS_UPDATE_STORAGE_H
