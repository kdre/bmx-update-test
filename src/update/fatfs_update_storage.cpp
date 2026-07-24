#include "fatfs_update_storage.h"

#include "fat_path_policy.h"

#include <string.h>

namespace bmx {
namespace update {

namespace {

static_assert(kZipMaximumPathBytes == kFatReleasePathMaximumBytes,
              "storage and ZIP release path limits must remain identical");

unsigned char AsciiLower(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') {
        return static_cast<unsigned char>(value + ('a' - 'A'));
    }
    return value;
}

bool BoundedStringLength(const char *text, size_t maximum_with_nul,
                         size_t *length)
{
    if (text == 0 || length == 0 || maximum_with_nul == 0U) return false;
    size_t index = 0U;
    while (index < maximum_with_nul && text[index] != 0) ++index;
    if (index == maximum_with_nul) return false;
    *length = index;
    return true;
}

FatFsStorageStatus MapPathStatus(FatPathValidationStatus status)
{
    switch (status) {
    case FatPathValidationStatus::Ok:
        return FatFsStorageStatus::Ok;
    case FatPathValidationStatus::InvalidArgument:
        return FatFsStorageStatus::InvalidArgument;
    case FatPathValidationStatus::PathTooLong:
        return FatFsStorageStatus::PathTooLong;
    case FatPathValidationStatus::InvalidPath:
        return FatFsStorageStatus::InvalidPath;
    }
    return FatFsStorageStatus::InvalidPath;
}

bool CopyPath(const char *source, char *destination, size_t capacity)
{
    if (source == 0 || destination == 0 || capacity == 0U) return false;
    const size_t size = strlen(source);
    if (size >= capacity) return false;
    memcpy(destination, source, size + 1U);
    return true;
}

bool EndsWith(const char *text, const char *suffix)
{
    if (text == 0 || suffix == 0) return false;
    const size_t text_size = strlen(text);
    const size_t suffix_size = strlen(suffix);
    return text_size >= suffix_size &&
           memcmp(text + text_size - suffix_size, suffix, suffix_size) == 0;
}

bool SameVolume(const char *left, const char *right)
{
    size_t index = 0U;
    while (left[index] != ':' && right[index] != ':') {
        if (left[index] == 0 || right[index] == 0 ||
            AsciiLower(static_cast<unsigned char>(left[index])) !=
                AsciiLower(static_cast<unsigned char>(right[index]))) {
            return false;
        }
        ++index;
    }
    return left[index] == ':' && right[index] == ':';
}

#if BMX_UPDATE_HAS_FATFS

static const size_t kMaximumFatFsIoBytes =
    static_cast<size_t>(static_cast<UINT>(-1));

bool IsMissing(FRESULT result)
{
    return result == FR_NO_FILE || result == FR_NO_PATH;
}

FatFsStorageStatus CloseFile(FIL *file)
{
    return f_close(file) == FR_OK ? FatFsStorageStatus::Ok
                                  : FatFsStorageStatus::CloseFailed;
}

FatFsStorageStatus StatValidated(const char *path, FatFsPathInfo *info)
{
    FILINFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    const FRESULT result = f_stat(path, &file_info);
    if (IsMissing(result)) {
        info->exists = false;
        info->is_directory = false;
        info->size = 0U;
        return FatFsStorageStatus::Ok;
    }
    if (result != FR_OK) return FatFsStorageStatus::StatFailed;
    info->exists = true;
    info->is_directory = (file_info.fattrib & AM_DIR) != 0U;
    info->size = info->is_directory ? 0U
                                    : static_cast<uint64_t>(file_info.fsize);
    return FatFsStorageStatus::Ok;
}

FatFsStorageStatus EnsureOneDirectory(const char *path)
{
    const FRESULT result = f_mkdir(path);
    if (result != FR_OK && result != FR_EXIST) {
        return FatFsStorageStatus::MkdirFailed;
    }
    FatFsPathInfo info;
    const FatFsStorageStatus status = StatValidated(path, &info);
    if (status != FatFsStorageStatus::Ok) return status;
    if (!info.exists) return FatFsStorageStatus::MkdirFailed;
    if (!info.is_directory) return FatFsStorageStatus::NotDirectory;
    return FatFsStorageStatus::Ok;
}

FatFsStorageStatus EnsureParentDirectories(const char *path)
{
    char working[kFatFsUpdatePathBytes];
    if (!CopyPath(path, working, sizeof(working))) {
        return FatFsStorageStatus::PathTooLong;
    }
    char *volume = strchr(working, ':');
    if (volume == 0 || volume[1] != '/') {
        return FatFsStorageStatus::InvalidPath;
    }
    for (char *cursor = volume + 2; *cursor != 0; ++cursor) {
        if (*cursor != '/') continue;
        *cursor = 0;
        const FatFsStorageStatus status = EnsureOneDirectory(working);
        *cursor = '/';
        if (status != FatFsStorageStatus::Ok) return status;
    }
    return FatFsStorageStatus::Ok;
}

FatFsStorageStatus WriteAll(FIL *file, const uint8_t *data, size_t size)
{
    while (size != 0U) {
        const size_t limited = size > kMaximumFatFsIoBytes
                                   ? kMaximumFatFsIoBytes
                                   : size;
        UINT written = 0U;
        const FRESULT result =
            f_write(file, data, static_cast<UINT>(limited), &written);
        if (result != FR_OK || written != limited) {
            return FatFsStorageStatus::WriteFailed;
        }
        data += limited;
        size -= limited;
    }
    return FatFsStorageStatus::Ok;
}

FatFsStorageStatus ReadExact(FIL *file, uint8_t *data, size_t size)
{
    while (size != 0U) {
        const size_t limited = size > kMaximumFatFsIoBytes
                                   ? kMaximumFatFsIoBytes
                                   : size;
        UINT received = 0U;
        const FRESULT result =
            f_read(file, data, static_cast<UINT>(limited), &received);
        if (result != FR_OK || received != limited) {
            return FatFsStorageStatus::ReadFailed;
        }
        data += limited;
        size -= limited;
    }
    return FatFsStorageStatus::Ok;
}

FatFsStorageStatus HashFile(const char *path, uint64_t maximum_bytes,
                            uint8_t *scratch, size_t scratch_size,
                            uint64_t *size_out,
                            uint8_t digest[kSha256DigestBytes])
{
    if (scratch == 0 || scratch_size == 0U || digest == 0) {
        return FatFsStorageStatus::InvalidArgument;
    }
    FatFsPathInfo before;
    FatFsStorageStatus status = StatValidated(path, &before);
    if (status != FatFsStorageStatus::Ok) return status;
    if (!before.exists) return FatFsStorageStatus::NotFound;
    if (before.is_directory) return FatFsStorageStatus::IsDirectory;
    if (before.size > maximum_bytes) return FatFsStorageStatus::LimitExceeded;

    FIL file;
    memset(&file, 0, sizeof(file));
    if (f_open(&file, path, FA_READ | FA_OPEN_EXISTING) != FR_OK) {
        return FatFsStorageStatus::OpenFailed;
    }
    Sha256 sha256;
    uint64_t remaining = before.size;
    while (remaining != 0U) {
        size_t request = scratch_size;
        if (request > kMaximumFatFsIoBytes) request = kMaximumFatFsIoBytes;
        if (static_cast<uint64_t>(request) > remaining) {
            request = static_cast<size_t>(remaining);
        }
        UINT received = 0U;
        const FRESULT read_result =
            f_read(&file, scratch, static_cast<UINT>(request), &received);
        if (read_result != FR_OK || received != request) {
            (void)f_close(&file);
            return FatFsStorageStatus::ReadFailed;
        }
        if (!sha256.Update(scratch, request)) {
            (void)f_close(&file);
            return FatFsStorageStatus::HashFailed;
        }
        remaining -= request;
    }
    uint8_t extra = 0U;
    UINT extra_size = 0U;
    if (f_read(&file, &extra, 1U, &extra_size) != FR_OK || extra_size != 0U) {
        (void)f_close(&file);
        return FatFsStorageStatus::SizeMismatch;
    }
    status = CloseFile(&file);
    if (status != FatFsStorageStatus::Ok) return status;
    if (!sha256.Final(digest)) return FatFsStorageStatus::HashFailed;

    FatFsPathInfo after;
    status = StatValidated(path, &after);
    if (status != FatFsStorageStatus::Ok) return status;
    if (!after.exists || after.is_directory || after.size != before.size) {
        return FatFsStorageStatus::SizeMismatch;
    }
    if (size_out != 0) *size_out = before.size;
    return FatFsStorageStatus::Ok;
}

#endif  // BMX_UPDATE_HAS_FATFS

}  // namespace

FatFsStorageStatus ValidateFatFsAbsolutePath(const char *path)
{
    if (path == 0 || path[0] == 0) return FatFsStorageStatus::InvalidArgument;
    size_t length = 0U;
    if (!BoundedStringLength(path, kFatFsUpdatePathBytes, &length)) {
        return FatFsStorageStatus::PathTooLong;
    }
    size_t colon = 0U;
    while (colon < length && path[colon] != ':') {
        const unsigned char value = static_cast<unsigned char>(path[colon]);
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_')) {
            return FatFsStorageStatus::InvalidPath;
        }
        ++colon;
    }
    if (colon == 0U || colon > 15U || colon + 1U >= length ||
        path[colon] != ':' || path[colon + 1U] != '/') {
        return FatFsStorageStatus::InvalidPath;
    }
    if (colon + 2U == length) return FatFsStorageStatus::Ok;
    return MapPathStatus(ValidateFatRelativePathBytes(
        reinterpret_cast<const uint8_t *>(path + colon + 2U),
        length - colon - 2U, kFatFsUpdatePathBytes - 1U));
}

FatFsStorageStatus ValidateFatFsRelativePath(const char *path)
{
    if (path == 0 || path[0] == 0) return FatFsStorageStatus::InvalidArgument;
    return MapPathStatus(
        ValidateFatRelativePath(path, kFatReleasePathMaximumBytes));
}

FatFsStorageStatus FatFsStatPath(const char *path, FatFsPathInfo *info)
{
    if (info == 0) return FatFsStorageStatus::InvalidArgument;
    info->exists = false;
    info->is_directory = false;
    info->size = 0U;
    const FatFsStorageStatus validation = ValidateFatFsAbsolutePath(path);
    if (validation != FatFsStorageStatus::Ok) return validation;
#if BMX_UPDATE_HAS_FATFS
    return StatValidated(path, info);
#else
    return FatFsStorageStatus::BackendUnavailable;
#endif
}

FatFsStorageStatus FatFsRemoveFileIfPresent(const char *path)
{
    FatFsPathInfo info;
    FatFsStorageStatus status = FatFsStatPath(path, &info);
    if (status != FatFsStorageStatus::Ok || !info.exists) return status;
    if (info.is_directory) return FatFsStorageStatus::IsDirectory;
#if BMX_UPDATE_HAS_FATFS
    return f_unlink(path) == FR_OK ? FatFsStorageStatus::Ok
                                   : FatFsStorageStatus::RemoveFailed;
#else
    return FatFsStorageStatus::BackendUnavailable;
#endif
}

FatFsDownloadSink::FatFsDownloadSink()
    : open_(false), committed_(false), expected_size_(0U), bytes_written_(0U),
      expected_sha256_(), streaming_sha256_(), part_path_(), final_path_(),
      verify_buffer_(), last_status_(FatFsStorageStatus::NotOpen)
{
#if BMX_UPDATE_HAS_FATFS
    memset(&file_, 0, sizeof(file_));
#endif
}

FatFsDownloadSink::~FatFsDownloadSink()
{
    Abort(false);
}

FatFsStorageStatus FatFsDownloadSink::Start(
    const char *part_path, const char *final_path, uint64_t expected_size,
    const uint8_t expected_sha256[kSha256DigestBytes])
{
    if (open_) return last_status_ = FatFsStorageStatus::Busy;
    if (expected_sha256 == 0) {
        return last_status_ = FatFsStorageStatus::InvalidArgument;
    }
    FatFsStorageStatus status = ValidateFatFsAbsolutePath(part_path);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    status = ValidateFatFsAbsolutePath(final_path);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    if (!EndsWith(part_path, ".part") || strcmp(part_path, final_path) == 0 ||
        !SameVolume(part_path, final_path) ||
        !CopyPath(part_path, part_path_, sizeof(part_path_)) ||
        !CopyPath(final_path, final_path_, sizeof(final_path_))) {
        return last_status_ = FatFsStorageStatus::InvalidPath;
    }
#if BMX_UPDATE_HAS_FATFS
    FatFsPathInfo final_info;
    status = FatFsStatPath(final_path_, &final_info);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    if (final_info.exists) return last_status_ = FatFsStorageStatus::AlreadyExists;
    status = FatFsRemoveFileIfPresent(part_path_);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    status = EnsureParentDirectories(part_path_);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    memset(&file_, 0, sizeof(file_));
    if (f_open(&file_, part_path_, FA_WRITE | FA_CREATE_NEW) != FR_OK) {
        return last_status_ = FatFsStorageStatus::OpenFailed;
    }
    open_ = true;
    committed_ = false;
    expected_size_ = expected_size;
    bytes_written_ = 0U;
    memcpy(expected_sha256_, expected_sha256, sizeof(expected_sha256_));
    streaming_sha256_.Reset();
    return last_status_ = FatFsStorageStatus::Ok;
#else
    (void)expected_size;
    return last_status_ = FatFsStorageStatus::BackendUnavailable;
#endif
}

bool FatFsDownloadSink::Write(const uint8_t *data, size_t size)
{
    if (!open_) {
        last_status_ = FatFsStorageStatus::NotOpen;
        return false;
    }
    if ((data == 0 && size != 0U) ||
        static_cast<uint64_t>(size) > expected_size_ - bytes_written_) {
        last_status_ = data == 0 ? FatFsStorageStatus::InvalidArgument
                                 : FatFsStorageStatus::LimitExceeded;
        return false;
    }
#if BMX_UPDATE_HAS_FATFS
    FatFsStorageStatus status = WriteAll(&file_, data, size);
    if (status != FatFsStorageStatus::Ok) {
        last_status_ = status;
        return false;
    }
    if (!streaming_sha256_.Update(data, size)) {
        last_status_ = FatFsStorageStatus::HashFailed;
        return false;
    }
    bytes_written_ += size;
    last_status_ = FatFsStorageStatus::Ok;
    return true;
#else
    (void)data;
    (void)size;
    last_status_ = FatFsStorageStatus::BackendUnavailable;
    return false;
#endif
}

FatFsStorageStatus FatFsDownloadSink::Finish()
{
    if (!open_) return last_status_ = FatFsStorageStatus::NotOpen;
#if BMX_UPDATE_HAS_FATFS
    if (bytes_written_ != expected_size_) {
        (void)f_close(&file_);
        open_ = false;
        return last_status_ = FatFsStorageStatus::SizeMismatch;
    }
    uint8_t streaming_digest[kSha256DigestBytes];
    if (!streaming_sha256_.Final(streaming_digest)) {
        (void)f_close(&file_);
        open_ = false;
        return last_status_ = FatFsStorageStatus::HashFailed;
    }
    FatFsStorageStatus status = FatFsStorageStatus::Ok;
    if (f_sync(&file_) != FR_OK) status = FatFsStorageStatus::SyncFailed;
    const FatFsStorageStatus close_status = CloseFile(&file_);
    open_ = false;
    if (status == FatFsStorageStatus::Ok) status = close_status;
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    if (!ConstantTimeDigestEqual(streaming_digest, expected_sha256_)) {
        return last_status_ = FatFsStorageStatus::HashMismatch;
    }

    uint8_t disk_digest[kSha256DigestBytes];
    uint64_t disk_size = 0U;
    status = HashFile(part_path_, expected_size_, verify_buffer_,
                      sizeof(verify_buffer_), &disk_size, disk_digest);
    if (status != FatFsStorageStatus::Ok || disk_size != expected_size_ ||
        !ConstantTimeDigestEqual(disk_digest, expected_sha256_) ||
        !ConstantTimeDigestEqual(disk_digest, streaming_digest)) {
        return last_status_ = status == FatFsStorageStatus::Ok
                                  ? FatFsStorageStatus::VerifyAfterWriteFailed
                                  : status;
    }
    FatFsPathInfo final_info;
    status = FatFsStatPath(final_path_, &final_info);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    if (final_info.exists) return last_status_ = FatFsStorageStatus::AlreadyExists;
    if (f_rename(part_path_, final_path_) != FR_OK) {
        return last_status_ = FatFsStorageStatus::RenameFailed;
    }
    uint8_t final_digest[kSha256DigestBytes];
    uint64_t final_size = 0U;
    status = HashFile(final_path_, expected_size_, verify_buffer_,
                      sizeof(verify_buffer_), &final_size, final_digest);
    if (status != FatFsStorageStatus::Ok || final_size != expected_size_ ||
        !ConstantTimeDigestEqual(final_digest, expected_sha256_)) {
        return last_status_ = FatFsStorageStatus::VerifyAfterWriteFailed;
    }
    committed_ = true;
    return last_status_ = FatFsStorageStatus::Ok;
#else
    return last_status_ = FatFsStorageStatus::BackendUnavailable;
#endif
}

void FatFsDownloadSink::Abort(bool remove_part)
{
#if BMX_UPDATE_HAS_FATFS
    if (open_) {
        (void)f_close(&file_);
        open_ = false;
    }
    if (remove_part && part_path_[0] != 0) {
        (void)FatFsRemoveFileIfPresent(part_path_);
    }
#else
    (void)remove_part;
#endif
}

FatFsZipSource::FatFsZipSource()
    : open_(false), size_(0U), last_status_(FatFsStorageStatus::NotOpen)
{
#if BMX_UPDATE_HAS_FATFS
    memset(&file_, 0, sizeof(file_));
#endif
}

FatFsZipSource::~FatFsZipSource()
{
    (void)Close();
}

FatFsStorageStatus FatFsZipSource::Open(const char *path)
{
    if (open_) return last_status_ = FatFsStorageStatus::Busy;
    FatFsStorageStatus status = ValidateFatFsAbsolutePath(path);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
#if BMX_UPDATE_HAS_FATFS
    FatFsPathInfo info;
    status = FatFsStatPath(path, &info);
    if (status != FatFsStorageStatus::Ok) return last_status_ = status;
    if (!info.exists) return last_status_ = FatFsStorageStatus::NotFound;
    if (info.is_directory) return last_status_ = FatFsStorageStatus::IsDirectory;
    memset(&file_, 0, sizeof(file_));
    if (f_open(&file_, path, FA_READ | FA_OPEN_EXISTING) != FR_OK) {
        return last_status_ = FatFsStorageStatus::OpenFailed;
    }
    size_ = info.size;
    if (static_cast<uint64_t>(f_size(&file_)) != size_) {
        (void)f_close(&file_);
        return last_status_ = FatFsStorageStatus::SizeMismatch;
    }
    open_ = true;
    return last_status_ = FatFsStorageStatus::Ok;
#else
    return last_status_ = FatFsStorageStatus::BackendUnavailable;
#endif
}

FatFsStorageStatus FatFsZipSource::Close()
{
    if (!open_) return FatFsStorageStatus::Ok;
#if BMX_UPDATE_HAS_FATFS
    open_ = false;
    return last_status_ = CloseFile(&file_);
#else
    open_ = false;
    return last_status_ = FatFsStorageStatus::BackendUnavailable;
#endif
}

bool FatFsZipSource::GetSize(uint64_t *size)
{
    if (!open_ || size == 0) {
        last_status_ = !open_ ? FatFsStorageStatus::NotOpen
                              : FatFsStorageStatus::InvalidArgument;
        return false;
    }
#if BMX_UPDATE_HAS_FATFS
    if (static_cast<uint64_t>(f_size(&file_)) != size_) {
        last_status_ = FatFsStorageStatus::SizeMismatch;
        return false;
    }
    *size = size_;
    last_status_ = FatFsStorageStatus::Ok;
    return true;
#else
    last_status_ = FatFsStorageStatus::BackendUnavailable;
    return false;
#endif
}

bool FatFsZipSource::ReadAt(uint64_t offset, uint8_t *destination, size_t size)
{
    if (!open_ || (destination == 0 && size != 0U) || offset > size_ ||
        static_cast<uint64_t>(size) > size_ - offset) {
        last_status_ = !open_ ? FatFsStorageStatus::NotOpen
                              : FatFsStorageStatus::InvalidArgument;
        return false;
    }
#if BMX_UPDATE_HAS_FATFS
    const FSIZE_t fat_offset = static_cast<FSIZE_t>(offset);
    if (static_cast<uint64_t>(fat_offset) != offset ||
        f_lseek(&file_, fat_offset) != FR_OK ||
        static_cast<uint64_t>(f_tell(&file_)) != offset) {
        last_status_ = FatFsStorageStatus::SeekFailed;
        return false;
    }
    const FatFsStorageStatus status = ReadExact(&file_, destination, size);
    last_status_ = status;
    return status == FatFsStorageStatus::Ok;
#else
    (void)destination;
    (void)size;
    last_status_ = FatFsStorageStatus::BackendUnavailable;
    return false;
#endif
}

Sha256ZipHashSink::Sha256ZipHashSink()
    : sha256_(), expected_size_(0U), received_size_(0U), active_(false)
{
}

bool Sha256ZipHashSink::BeginFile(const char *validated_path, uint64_t size)
{
    if (active_ || ValidateFatFsRelativePath(validated_path) !=
                       FatFsStorageStatus::Ok) {
        return false;
    }
    sha256_.Reset();
    expected_size_ = size;
    received_size_ = 0U;
    active_ = true;
    return true;
}

bool Sha256ZipHashSink::Update(ByteView bytes)
{
    if (!active_ || (bytes.data == 0 && bytes.size != 0U) ||
        static_cast<uint64_t>(bytes.size) > expected_size_ - received_size_ ||
        !sha256_.Update(bytes.data, bytes.size)) {
        return false;
    }
    received_size_ += bytes.size;
    return true;
}

bool Sha256ZipHashSink::FinishFile(uint8_t digest[kSha256DigestBytes])
{
    if (!active_ || digest == 0 || received_size_ != expected_size_) {
        return false;
    }
    active_ = false;
    return sha256_.Final(digest);
}

void Sha256ZipHashSink::AbortFile()
{
    active_ = false;
    expected_size_ = 0U;
    received_size_ = 0U;
    sha256_.Reset();
}

}  // namespace update
}  // namespace bmx
