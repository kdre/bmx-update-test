#ifndef BMX_UPDATE_ZIP_READER_H
#define BMX_UPDATE_ZIP_READER_H

#include "update_types.h"

namespace bmx {
namespace update {

// bmx-zip32-v1 deliberately caps all metadata so the device parser can be
// allocation-free. Callers provide one ZipEntry slot per central entry.
static const size_t kZipMaximumEntries = 2048U;
static const size_t kZipMaximumPathBytes = 240U;
static const size_t kZipInputBufferBytes = 8192U;
static const size_t kZipInflateDictionaryBytes = 32768U;
static const size_t kZipInflateStateWords = 1056U;

// Roughly 49 KiB, intentionally caller-owned so the raw-Deflate dictionary is
// never placed on Circle's default 32 KiB task stack. One reader operation may
// use a workspace at a time.
struct ZipWorkspace {
    uint8_t input[kZipInputBufferBytes];
    uint8_t dictionary[kZipInflateDictionaryBytes];
    uint64_t inflate_state[kZipInflateStateWords];
};

struct ZipLimits {
    uint64_t maximum_archive_bytes;
    size_t maximum_entries;
    size_t maximum_path_bytes;
    uint64_t maximum_file_bytes;
    uint64_t maximum_installed_bytes;
    uint32_t maximum_compression_ratio;

    ZipLimits();
};

enum class ZipCompression : uint8_t {
    Store = 0,
    Deflate = 8
};

struct ZipEntry {
    // Directories are stored without their ZIP trailing slash. Every path is
    // validated before becoming observable through this structure.
    char path[kZipMaximumPathBytes + 1U];
    bool is_directory;
    ZipCompression compression;
    uint16_t flags;
    uint32_t crc32;
    uint64_t compressed_size;
    uint64_t size;
    uint64_t local_header_offset;
    uint64_t data_offset;
    uint32_t external_attributes;
    uint8_t creator_system;
};

struct ZipInventory {
    const ZipEntry *entries;
    size_t entry_count;
    size_t file_count;
    size_t directory_count;
    uint64_t archive_size;
    uint64_t installed_size;
    uint64_t central_directory_offset;
    uint64_t central_directory_size;
};

struct ZipExpectedFile {
    const char *path;
    uint64_t size;
    ZipCompression compression;
    // NULL skips SHA-256 comparison for this file. If any digest is supplied,
    // the operation requires a ZipHashSink.
    const uint8_t *sha256;
};

struct ZipExpectedInventory {
    const ZipExpectedFile *files;
    size_t file_count;
    const char *const *directories;
    size_t directory_count;
};

// Implement this over a seekable file, block device, or host byte vector.
// ReadAt must either fill the complete requested range or return false.
class SeekableZipSource {
public:
    virtual ~SeekableZipSource();
    virtual bool GetSize(uint64_t *size) = 0;
    virtual bool ReadAt(uint64_t offset, uint8_t *destination, size_t size) = 0;
};

// Injected SHA-256 implementation. The reader owns neither the object nor any
// returned digest. One instance is reused sequentially, never concurrently.
class ZipHashSink {
public:
    virtual ~ZipHashSink();
    virtual bool BeginFile(const char *validated_path, uint64_t size) = 0;
    virtual bool Update(ByteView bytes) = 0;
    virtual bool FinishFile(uint8_t digest[kSha256DigestBytes]) = 0;
    virtual void AbortFile() = 0;
};

// The ZIP reader never opens filesystem paths. It passes only paths accepted
// by bmx-zip32-v1 to this sink. A production sink should write into a fresh
// transaction staging area and make CommitEntry atomic.
class ZipExtractSink {
public:
    virtual ~ZipExtractSink();
    virtual bool BeginEntry(const ZipEntry &entry) = 0;
    virtual bool Write(ByteView bytes) = 0;
    virtual bool CommitEntry(const ZipEntry &entry) = 0;
    virtual void AbortEntry(const ZipEntry &entry) = 0;
};

enum class ZipStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    NotOpen,
    SourceIo,
    ArchiveSizeInvalid,
    EndRecordInvalid,
    ArchiveCommentForbidden,
    MultiDiskForbidden,
    Zip64Forbidden,
    EntryCountInvalid,
    StorageTooSmall,
    CentralDirectoryInvalid,
    UnsupportedVersion,
    UnsupportedFlags,
    UnsupportedCompression,
    ExtraFieldForbidden,
    MemberCommentForbidden,
    SpecialFileForbidden,
    DirectoryMetadataInvalid,
    PathInvalid,
    PathTooLong,
    PathEncodingInvalid,
    NonAsciiPathUnsupported,
    DuplicatePath,
    FatCaseCollision,
    FileUsedAsDirectory,
    MemberSizeInvalid,
    CompressionRatioInvalid,
    OffsetInvalid,
    LocalHeaderMismatch,
    InstalledSizeInvalid,
    ExpectedInventoryInvalid,
    InventoryMismatch,
    EntryNotFound,
    HashSinkRequired,
    HashSinkError,
    HashMismatch,
    SinkError,
    WorkspaceRequired,
    CrcMismatch,
    UncompressedSizeMismatch,
    DeflateInvalid
};

class ZipReader {
public:
    ZipReader();

    void SetWorkspace(ZipWorkspace *workspace);

    // Open validates every EOCD, central, local, metadata, path, ordering, and
    // limit invariant, but does not yet inflate payloads. entries must remain
    // alive until this reader is destroyed or Open is called again.
    ZipStatus Open(SeekableZipSource *source,
                   ZipEntry *entries,
                   size_t entry_capacity,
                   const ZipLimits &limits = ZipLimits());

    const ZipInventory &inventory() const;

    // Checks an exact (order-independent) manifest inventory, inflates every
    // file, and verifies its declared CRC-32, size, and optional SHA-256.
    ZipStatus ValidateContents(const ZipExpectedInventory &expected,
                               ZipHashSink *hash_sink = 0);

    // Binds an exact inventory without inflating every member. This is safe
    // only after the caller has authenticated the complete archive bytes
    // against the signed asset hash. Extracted files still verify CRC, size,
    // and SHA-256 while being written.
    ZipStatus BindAuthenticatedInventory(
        const ZipExpectedInventory &expected);

    // Extraction is normally two-pass: requested payloads are fully validated
    // before BeginEntry is called, then validated again while writing. A
    // successful ValidateContents call on this reader may satisfy the first
    // pass for the exact same inventory. The writing pass always verifies CRC,
    // size, and every supplied SHA-256 before CommitEntry. The source must
    // remain immutable for the duration of the operation.
    ZipStatus ExtractOne(const char *path,
                         const ZipExpectedInventory &expected,
                         ZipExtractSink *sink,
                         ZipHashSink *hash_sink = 0);
    ZipStatus ExtractAll(const ZipExpectedInventory &expected,
                         ZipExtractSink *sink,
                         ZipHashSink *hash_sink = 0);

private:
    ZipReader(const ZipReader &);
    ZipReader &operator=(const ZipReader &);

    ZipStatus VerifyExpectedInventory(const ZipExpectedInventory &expected,
                                      bool *requires_hash) const;
    ZipStatus StreamFile(const ZipEntry &entry,
                         const ZipExpectedFile *expected,
                         ZipHashSink *hash_sink,
                         ZipExtractSink *extract_sink);
    const ZipExpectedFile *FindExpectedFile(
        const ZipExpectedInventory &expected,
        const char *path) const;
    bool ComputeExpectedInventoryBinding(
        const ZipExpectedInventory &expected,
        uint8_t digest[kSha256DigestBytes]) const;
    bool ValidatedContentsMatch(
        const ZipExpectedInventory &expected) const;
    void ClearValidatedContents();

    SeekableZipSource *source_;
    ZipEntry *entries_;
    ZipInventory inventory_;
    ZipLimits limits_;
    ZipWorkspace *workspace_;
    bool open_;
    uint8_t validated_inventory_binding_[kSha256DigestBytes];
    bool validated_contents_;
};

const char *ZipStatusString(ZipStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_ZIP_READER_H
