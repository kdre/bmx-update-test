#include "update/fatfs_prepared_config.h"

#include "update/consent_digest_input.h"
#include "update/fat_path_policy.h"
#include "update/fatfs_update_storage.h"
#include "update/generated/update_path_policy_v1.h"
#include "update/selector_candidate_backend.h"
#include "update/sha256.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {

namespace {

namespace path_policy = generated_path_policy_v1;

static_assert(path_policy::kMachineKernelBaseCount == 2U,
              "prepared config requires pi4 and pi5 kernel bases");

static const size_t kEvidenceHeaderBytes = 128U;
static const size_t kEvidenceRecordBytes = 336U;
static const size_t kEvidencePayloadBytes =
    kEvidenceHeaderBytes +
    kFatFsPreparedConfigMaximumTemplates * kEvidenceRecordBytes;
static const size_t kEvidenceDigestOffset = kEvidencePayloadBytes;
static const size_t kMinimumPreparedIoBytes = 4096U;
static const size_t kMaximumPreparedIoChunkBytes = 8192U;
static const uint64_t kArchiveHashProgressIntervalBytes =
    UINT64_C(256) * UINT64_C(1024);
static const uint64_t kMaximumPreparedAggregateBytes =
    UINT64_C(8) * 1024U * 1024U;
static const uint8_t kEvidenceMagic[16U] = {
    'B', 'M', 'X', '-', 'P', 'R', 'E', 'P', '-', 'C', 'F', 'G', '-',
    'V', '1', 0U};

static_assert(kFatFsPreparedConfigEvidenceBytes ==
                  kEvidencePayloadBytes + kSha256DigestBytes,
              "prepared-config evidence size drifted");
static_assert(kMaximumManifestPathBytes + 1U == 241U,
              "evidence path field assumes manifest path bound");

bool BytesNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0 || size == 0U) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) {
        combined = static_cast<uint8_t>(combined | bytes[index]);
    }
    return combined != 0U;
}

bool BoundedLength(const char *text, size_t maximum, size_t *length)
{
    if (text == 0 || length == 0) return false;
    for (size_t index = 0U; index <= maximum; ++index) {
        if (text[index] == '\0') {
            *length = index;
            return true;
        }
    }
    return false;
}

bool FatTextEqual(const char *left, const char *right)
{
    if (left == 0 || right == 0) return false;
    for (size_t index = 0U;; ++index) {
        uint8_t a = static_cast<uint8_t>(left[index]);
        uint8_t b = static_cast<uint8_t>(right[index]);
        if (a >= 'A' && a <= 'Z') a = static_cast<uint8_t>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + ('a' - 'A'));
        if (a != b) return false;
        if (a == 0U) return true;
    }
}

void EncodeU32(uint32_t value, uint8_t output[4U])
{
    output[0] = static_cast<uint8_t>(value >> 24U);
    output[1] = static_cast<uint8_t>(value >> 16U);
    output[2] = static_cast<uint8_t>(value >> 8U);
    output[3] = static_cast<uint8_t>(value);
}

void EncodeU64(uint64_t value, uint8_t output[8U])
{
    for (unsigned index = 0U; index < 8U; ++index) {
        output[7U - index] =
            static_cast<uint8_t>(value >> (index * 8U));
    }
}

uint32_t DecodeU32(const uint8_t input[4U])
{
    return (static_cast<uint32_t>(input[0]) << 24U) |
           (static_cast<uint32_t>(input[1]) << 16U) |
           (static_cast<uint32_t>(input[2]) << 8U) |
           static_cast<uint32_t>(input[3]);
}

uint64_t DecodeU64(const uint8_t input[8U])
{
    uint64_t value = 0U;
    for (unsigned index = 0U; index < 8U; ++index) {
        value = (value << 8U) | input[index];
    }
    return value;
}

void HexDigest(const uint8_t digest[kSha256DigestBytes], char output[65U])
{
    static const char alphabet[] = "0123456789abcdef";
    for (size_t index = 0U; index < kSha256DigestBytes; ++index) {
        output[index * 2U] = alphabet[digest[index] >> 4U];
        output[index * 2U + 1U] = alphabet[digest[index] & 0x0fU];
    }
    output[64U] = '\0';
}

class OwnedBuffer {
public:
    OwnedBuffer() : bytes_(0), size_(0U), capacity_(0U) {}
    ~OwnedBuffer() { Reset(); }

    bool Allocate(size_t capacity)
    {
        Reset();
        if (capacity > kMaximumConfigFileBytes) return false;
        bytes_ = new uint8_t[capacity == 0U ? 1U : capacity];
        if (bytes_ == 0) return false;
        capacity_ = capacity;
        size_ = 0U;
        return true;
    }

    bool Assign(const uint8_t *bytes, size_t size)
    {
        if ((bytes == 0 && size != 0U) || size > capacity_) return false;
        if (size != 0U) memcpy(bytes_, bytes, size);
        size_ = size;
        return true;
    }

    void Reset()
    {
        delete[] bytes_;
        bytes_ = 0;
        size_ = 0U;
        capacity_ = 0U;
    }

    uint8_t *data() { return bytes_; }
    const uint8_t *data() const { return bytes_; }
    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }
    void set_size(size_t size) { size_ = size; }

private:
    OwnedBuffer(const OwnedBuffer &);
    OwnedBuffer &operator=(const OwnedBuffer &);

    uint8_t *bytes_;
    size_t size_;
    size_t capacity_;
};

struct TemplateWork {
    const ManifestFile *manifest_file;
    bool original_existed;
    uint64_t original_size;
    uint8_t original_sha256[kSha256DigestBytes];
    OwnedBuffer signed_default;
    OwnedBuffer current;
    OwnedBuffer prepared;

    TemplateWork()
        : manifest_file(0), original_existed(false), original_size(0U),
          original_sha256(), signed_default(), current(), prepared()
    {
        memset(original_sha256, 0, sizeof(original_sha256));
    }
};

struct PreparedPaths {
    char root[kFatFsUpdateFileSystemRelativePathBytes];
    uint8_t binding_sha256[kSha256DigestBytes];
};

bool JoinPath(const char *left, const char *right, char *output,
              size_t output_size)
{
    if (left == 0 || right == 0 || output == 0 || output_size == 0U) {
        return false;
    }
    const int written = snprintf(output, output_size, "%s/%s", left, right);
    return written > 0 && static_cast<size_t>(written) < output_size &&
           ValidateFatRelativePath(output,
                                   kFatFsUpdateFileSystemRelativePathBytes - 1U) ==
               FatPathValidationStatus::Ok;
}

bool ItemPath(const PreparedPaths &paths, size_t index, bool temporary,
              char output[kFatFsUpdateFileSystemRelativePathBytes])
{
    if (index >= kFatFsPreparedConfigMaximumTemplates) return false;
    char name[32U];
    const int written = snprintf(name, sizeof(name),
                                 temporary ? "item-%02u.bin.part"
                                           : "item-%02u.bin",
                                 static_cast<unsigned>(index));
    return written > 0 && static_cast<size_t>(written) < sizeof(name) &&
           JoinPath(paths.root, name, output,
                    kFatFsUpdateFileSystemRelativePathBytes);
}

bool EvidencePath(const PreparedPaths &paths, bool temporary,
                  char output[kFatFsUpdateFileSystemRelativePathBytes])
{
    return JoinPath(paths.root,
                    temporary ? "evidence.bin.part" : "evidence.bin", output,
                    kFatFsUpdateFileSystemRelativePathBytes);
}

bool BuildPreparedPaths(const char *volume,
                        const AuthenticatedUpdateBinding &binding,
                        PreparedPaths *paths)
{
    if (paths == 0) return false;
    memset(paths, 0, sizeof(*paths));
    FatFsUpdateArchivePaths archive_paths;
    if (BuildFatFsUpdateArchivePaths(volume, binding, &archive_paths) !=
        FatFsStorageStatus::Ok) {
        return false;
    }
    char digest[65U];
    HexDigest(archive_paths.binding_sha256, digest);
    char leaf[80U];
    const int leaf_size = snprintf(leaf, sizeof(leaf), "prepared-%s", digest);
    if (leaf_size <= 0 || static_cast<size_t>(leaf_size) >= sizeof(leaf) ||
        !JoinPath(binding.transaction_root, leaf, paths->root,
                  sizeof(paths->root))) {
        return false;
    }
    memcpy(paths->binding_sha256, archive_paths.binding_sha256,
           kSha256DigestBytes);
    return true;
}

bool IsCompressionValid(ManifestCompression compression)
{
    return compression == ManifestCompression::Store ||
           compression == ManifestCompression::Deflate;
}

bool IsPolicyValid(ManifestFilePolicy policy)
{
    return policy == ManifestFilePolicy::Kernel ||
           policy == ManifestFilePolicy::ManagedReplace ||
           policy == ManifestFilePolicy::ConfigTemplate ||
           policy == ManifestFilePolicy::Preserve ||
           policy == ManifestFilePolicy::Metadata;
}

bool IsKnownConfigTemplatePath(const char *path)
{
    static const char *const paths[] = {
        "config.txt",
        "cmdline.txt",
        "machines.txt",
        "machines.ini",
        "machines.defaults.ini",
        "bmx-active-kernel.txt",
        "bmx-tryboot-kernel.txt",
        "bmx-machine.txt",
        "tryboot.txt",
        "autoboot.txt"};
    if (path == 0) return false;
    for (size_t index = 0U; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        if (strcmp(path, paths[index]) == 0) return true;
    }
    return false;
}

bool IsSettingsPath(const char *path)
{
    if (path == 0) return false;
    const size_t length = strlen(path);
    static const char prefix[] = "settings";
    static const char suffix[] = ".txt";
    if (length < sizeof(prefix) - 1U + sizeof(suffix) - 1U ||
        memcmp(path, prefix, sizeof(prefix) - 1U) != 0 ||
        memcmp(path + length - (sizeof(suffix) - 1U), suffix,
               sizeof(suffix) - 1U) != 0) {
        return false;
    }
    for (size_t index = sizeof(prefix) - 1U;
         index < length - (sizeof(suffix) - 1U); ++index) {
        const char value = path[index];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-' ||
              value == '_')) {
            return false;
        }
    }
    return true;
}

bool PathBelongsToArea(ConfigArea area, const char *path)
{
    if (path == 0) return false;
    switch (area) {
    case ConfigArea::Machines:
        return strcmp(path, "machines.ini") == 0 ||
               strcmp(path, "machines.defaults.ini") == 0 ||
               strcmp(path, "machines.local.ini") == 0;
    case ConfigArea::ConfigManagedBlock:
        return strcmp(path, "config.txt") == 0;
    case ConfigArea::CmdlineManagedKeys:
    case ConfigArea::Network:
        return strcmp(path, "cmdline.txt") == 0;
    case ConfigArea::Settings:
        return IsSettingsPath(path);
    case ConfigArea::UpdateState:
        return strcmp(path, "BMX-BUILD.json") == 0 ||
               strcmp(path, ".bmx-update/transaction/journal.a") == 0 ||
               strcmp(path, ".bmx-update/transaction/journal.b") == 0;
    case ConfigArea::Unknown:
        break;
    }
    return false;
}

ConfigArea TemplateArea(const char *path)
{
    if (PathBelongsToArea(ConfigArea::Machines, path)) {
        return ConfigArea::Machines;
    }
    if (PathBelongsToArea(ConfigArea::ConfigManagedBlock, path)) {
        return ConfigArea::ConfigManagedBlock;
    }
    if (PathBelongsToArea(ConfigArea::CmdlineManagedKeys, path)) {
        // CmdlineManagedKeys and Network intentionally share this file.  The
        // caller handles the ambiguity before applying either transform.
        return ConfigArea::CmdlineManagedKeys;
    }
    if (PathBelongsToArea(ConfigArea::Settings, path)) {
        return ConfigArea::Settings;
    }
    if (PathBelongsToArea(ConfigArea::UpdateState, path)) {
        return ConfigArea::UpdateState;
    }
    return ConfigArea::Unknown;
}

bool IsPath(const ManifestFile *file, const char *path)
{
    return file != 0 && path != 0 && strcmp(file->path, path) == 0;
}

const char *BoardKernel(BoardFamily board)
{
    switch (board) {
    case BoardFamily::Pi4Pi400:
        return path_policy::kMachineKernelBases[0U];
    case BoardFamily::Pi5Pi500:
        return path_policy::kMachineKernelBases[1U];
    case BoardFamily::Unknown: break;
    }
    return 0;
}

struct TextLine {
    const uint8_t *data;
    size_t size;
    size_t number;
};

bool LineEquals(const TextLine &line, const char *text)
{
    const size_t size = strlen(text);
    return line.size == size &&
           (size == 0U || memcmp(line.data, text, size) == 0);
}

bool TrimmedStartsWith(const TextLine &line, const char *prefix)
{
    size_t begin = 0U;
    while (begin < line.size &&
           (line.data[begin] == ' ' || line.data[begin] == '\t')) {
        ++begin;
    }
    const size_t prefix_size = strlen(prefix);
    return line.size - begin >= prefix_size &&
           memcmp(line.data + begin, prefix, prefix_size) == 0;
}

// Validates the same boot-v1 fallback/include profile enforced by the release
// tooling, while permitting arbitrary user comments/options outside the
// managed block.  Kernel/include directives with leading whitespace still
// count and are therefore rejected unless they are the single canonical pair.
bool ValidateSelectorConfigProfile(ByteView content, BoardFamily board,
                                   bool candidate)
{
    const char *kernel = BoardKernel(board);
    if (kernel == 0 || content.data == 0 || content.size == 0U ||
        content.size > kMaximumConfigFileBytes ||
        content.data[content.size - 1U] != '\n') {
        return false;
    }
    char fallback[64U];
    const int fallback_size = snprintf(fallback, sizeof(fallback),
                                       "kernel=%s.c64", kernel);
    const char *include = candidate
        ? "include bmx-tryboot-kernel.txt"
        : "include bmx-active-kernel.txt";
    if (fallback_size <= 0 ||
        static_cast<size_t>(fallback_size) >= sizeof(fallback)) {
        return false;
    }

    size_t line_begin = 0U;
    size_t line_number = 0U;
    size_t begin_line = SIZE_MAX;
    size_t end_line = SIZE_MAX;
    size_t kernel_line = SIZE_MAX;
    size_t include_line = SIZE_MAX;
    size_t begin_count = 0U;
    size_t end_count = 0U;
    size_t kernel_count = 0U;
    size_t include_count = 0U;
    for (size_t index = 0U; index < content.size; ++index) {
        const uint8_t value = content.data[index];
        if (value == '\r' || value == 0U ||
            (value != '\n' && value != '\t' &&
             (value < 0x20U || value > 0x7eU))) {
            return false;
        }
        if (value != '\n') continue;
        TextLine line = {content.data + line_begin, index - line_begin,
                         line_number++};
        if (LineEquals(line, "# BEGIN BMX MANAGED")) {
            ++begin_count;
            begin_line = line.number;
        }
        if (LineEquals(line, "# END BMX MANAGED")) {
            ++end_count;
            end_line = line.number;
        }
        if (TrimmedStartsWith(line, "kernel=")) {
            ++kernel_count;
            kernel_line = line.number;
            if (!LineEquals(line, fallback)) return false;
        }
        if (TrimmedStartsWith(line, "include ")) {
            ++include_count;
            include_line = line.number;
            if (!LineEquals(line, include)) return false;
        }
        line_begin = index + 1U;
    }
    return line_begin == content.size && begin_count == 1U &&
           end_count == 1U && kernel_count == 1U && include_count == 1U &&
           begin_line < kernel_line && kernel_line < include_line &&
           include_line < end_line;
}

bool ParseMachineMarker(ByteView content, const char *expected_machine)
{
    if (content.data == 0 || expected_machine == 0) return false;
    const size_t machine_size = strlen(expected_machine);
    return machine_size != 0U && content.size == machine_size + 1U &&
           memcmp(content.data, expected_machine, machine_size) == 0 &&
           content.data[machine_size] == '\n';
}

bool BuildTrybootConfig(ByteView active, OwnedBuffer *tryboot)
{
    static const char active_include[] =
        "include bmx-active-kernel.txt\n";
    static const char tryboot_include[] =
        "include bmx-tryboot-kernel.txt\n";
    if (tryboot == 0 || active.data == 0 || active.size == 0U) return false;
    const size_t active_size = sizeof(active_include) - 1U;
    const size_t tryboot_size = sizeof(tryboot_include) - 1U;
    size_t match = SIZE_MAX;
    size_t matches = 0U;
    if (active.size >= active_size) {
        for (size_t index = 0U; index <= active.size - active_size; ++index) {
            if (memcmp(active.data + index, active_include,
                       active_size) == 0) {
                match = index;
                ++matches;
            }
        }
    }
    if (matches != 1U || tryboot_size < active_size ||
        active.size > SIZE_MAX - (tryboot_size - active_size)) {
        return false;
    }
    const size_t output_size =
        active.size + (tryboot_size - active_size);
    if (output_size > tryboot->capacity()) return false;
    if (match != 0U) memcpy(tryboot->data(), active.data, match);
    memcpy(tryboot->data() + match, tryboot_include, tryboot_size);
    const size_t suffix = match + active_size;
    if (suffix < active.size) {
        memcpy(tryboot->data() + match + tryboot_size,
               active.data + suffix, active.size - suffix);
    }
    tryboot->set_size(output_size);
    return true;
}

bool RenderTargetSelector(BoardFamily board, const char *machine,
                          uint64_t release_sequence, OwnedBuffer *output,
                          ParsedKernelSelector *parsed)
{
    const char *kernel = BoardKernel(board);
    if (kernel == 0 || machine == 0 || output == 0 || parsed == 0) {
        return false;
    }
    char selector[kMaximumKernelSelectorBytes];
    if (release_sequence == 0U) return false;
    const int written = snprintf(
        selector, sizeof(selector),
        "# BMX-KERNEL-SELECTOR-V2\nkernel=%s.%s\n", kernel, machine);
    if (written <= 0 || static_cast<size_t>(written) >= sizeof(selector) ||
        !output->Assign(reinterpret_cast<const uint8_t *>(selector),
                        static_cast<size_t>(written))) {
        return false;
    }
    return ParseKernelSelector(ByteView(output->data(), output->size()), board,
                               parsed) == KernelSelectorStatus::Ok;
}

bool ValidateManifestBinding(const AuthenticatedUpdateBinding &binding,
                             const ReleaseManifest &manifest,
                             size_t *template_count)
{
    if (template_count == 0) return false;
    *template_count = 0U;
    const ManifestAsset &asset = manifest.asset;
    size_t filename_size = 0U;
    if (!IsKnownBoardFamily(binding.board) || asset.board != binding.board ||
        manifest.release_sequence != binding.target_release_sequence ||
        asset.download_size != binding.archive_size ||
        !ConstantTimeDigestEqual(asset.sha256, binding.archive_sha256) ||
        !BoundedLength(asset.filename, sizeof(asset.filename) - 1U,
                       &filename_size) ||
        filename_size == 0U || binding.archive_filename == 0 ||
        strcmp(asset.filename, binding.archive_filename) != 0 ||
        asset.file_count == 0U || asset.file_count > kMaximumManifestFiles ||
        asset.files == 0 ||
        asset.directory_count > kMaximumManifestDirectories ||
        (asset.directory_count != 0U && asset.directories == 0) ||
        manifest.schema_count != kConfigMigrationAreaCount ||
        manifest.migration_count > kMaximumDeclaredConfigMigrations) {
        return false;
    }

    uint64_t installed_size = 0U;
    uint64_t template_bytes = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        size_t path_size = 0U;
        if (!BoundedLength(file.path, kMaximumManifestPathBytes, &path_size) ||
            path_size == 0U ||
            ValidateFatRelativePath(file.path, kMaximumManifestPathBytes) !=
                FatPathValidationStatus::Ok ||
            !IsPolicyValid(file.policy) ||
            !IsCompressionValid(file.compression) ||
            !BytesNonZero(file.sha256, kSha256DigestBytes) ||
            file.size > UINT64_MAX - installed_size) {
            return false;
        }
        installed_size += file.size;
        for (size_t prior = 0U; prior < index; ++prior) {
            if (FatTextEqual(file.path, asset.files[prior].path)) return false;
        }
        if (file.policy == ManifestFilePolicy::ConfigTemplate) {
            if (*template_count >= kFatFsPreparedConfigMaximumTemplates ||
                !IsKnownConfigTemplatePath(file.path) ||
                file.size > kMaximumConfigFileBytes ||
                file.size > UINT64_MAX - template_bytes) {
                return false;
            }
            template_bytes += file.size;
            ++*template_count;
        }
    }
    if (installed_size != asset.installed_size ||
        template_bytes > kMaximumPreparedAggregateBytes) {
        return false;
    }
    for (size_t index = 0U; index < asset.directory_count; ++index) {
        const char *path = asset.directories[index].path;
        size_t ignored = 0U;
        if (!BoundedLength(path, kMaximumManifestPathBytes, &ignored) ||
            ignored == 0U ||
            ValidateFatRelativePath(path, kMaximumManifestPathBytes) !=
                FatPathValidationStatus::Ok) {
            return false;
        }
        for (size_t prior = 0U; prior < index; ++prior) {
            if (FatTextEqual(path, asset.directories[prior].path)) return false;
        }
        for (size_t file = 0U; file < asset.file_count; ++file) {
            if (FatTextEqual(path, asset.files[file].path)) return false;
        }
    }
    return true;
}

const ConfigAreaSnapshot *FindArea(const ConfigSnapshot &snapshot,
                                   ConfigArea area)
{
    for (size_t index = 0U; index < snapshot.area_count; ++index) {
        if (snapshot.areas[index].area == area) return &snapshot.areas[index];
    }
    return 0;
}

const ConfigAreaAssessment *FindAssessment(const ConfigMigrationPlan &plan,
                                           ConfigArea area)
{
    for (size_t index = 0U; index < plan.area_count; ++index) {
        if (plan.areas[index].area == area) return &plan.areas[index];
    }
    return 0;
}

PreparedConfigProviderStatus AssessAndBindConfig(
    const char *volume, const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest, FatFsConfigSnapshot *snapshot,
    ConfigMigrationPlan *plan, FatFsConfigSnapshotStatus *snapshot_status,
    ConfigAssessmentStatus *assessment_status)
{
    if (snapshot == 0 || plan == 0 || snapshot_status == 0 ||
        assessment_status == 0) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    *snapshot_status = snapshot->Load(volume);
    if (*snapshot_status != FatFsConfigSnapshotStatus::Ok) {
        return PreparedConfigProviderStatus::IoError;
    }

    ConfigSchemaRequirement requirements[kConfigMigrationAreaCount];
    for (size_t index = 0U; index < manifest.schema_count; ++index) {
        requirements[index].area = manifest.schemas[index].area;
        requirements[index].target_version =
            manifest.schemas[index].target_version;
        requirements[index].accepted_versions =
            manifest.schemas[index].accepted_versions;
        requirements[index].accepted_version_count =
            manifest.schemas[index].accepted_version_count;
    }
    DeclaredConfigMigration migrations[kMaximumDeclaredConfigMigrations];
    for (size_t index = 0U; index < manifest.migration_count; ++index) {
        migrations[index].id = manifest.migrations[index].id;
        migrations[index].area = manifest.migrations[index].area;
        migrations[index].from_version =
            manifest.migrations[index].from_version;
        migrations[index].to_version = manifest.migrations[index].to_version;
        migrations[index].lossy = manifest.migrations[index].lossy;
    }
    *assessment_status = AssessConfigSnapshot(
        snapshot->snapshot(), requirements, manifest.schema_count, migrations,
        manifest.migration_count, plan);
    if (*assessment_status != ConfigAssessmentStatus::Ok ||
        plan->area_count != kConfigMigrationAreaCount ||
        plan->blocked_count != 0U ||
        plan->decision == ConfigPlanDecision::BlockedUnknownOrCorrupt ||
        plan->decision == ConfigPlanDecision::BlockedNewerThanTarget ||
        plan->decision == ConfigPlanDecision::InvalidInput) {
        return PreparedConfigProviderStatus::SourceChanged;
    }

    ConsentConfigItem items[kConfigMigrationAreaCount];
    for (size_t index = 0U; index < plan->area_count; ++index) {
        const ConfigAreaAssessment &area = plan->areas[index];
        if (area.classification != ConfigClassification::Compatible &&
            area.classification != ConfigClassification::LosslessMigration &&
            area.classification != ConfigClassification::ResetRequired) {
            return PreparedConfigProviderStatus::SourceChanged;
        }
        items[index].area = area.area;
        items[index].classification = area.classification;
        items[index].source_schema_version = area.source_version;
        items[index].target_schema_version = area.target_version;
        memcpy(items[index].source_content_sha256,
               area.source_content_sha256, kSha256DigestBytes);
    }
    ConsentDigestInput input;
    input.board = binding.board;
    input.target_release_sequence = binding.target_release_sequence;
    memcpy(input.manifest_sha256, binding.manifest_sha256,
           kSha256DigestBytes);
    input.items = items;
    input.item_count = plan->area_count;
    uint8_t encoded[kMaximumConsentEncodedBytes];
    size_t encoded_size = 0U;
    uint8_t digest[kSha256DigestBytes];
    if (SerializeConsentDigestInput(
            input, MutableByteView(encoded, sizeof(encoded)), &encoded_size) !=
            ConsentInputStatus::Valid ||
        !Sha256Digest(ByteView(encoded, encoded_size), digest)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    if (!ConstantTimeDigestEqual(digest, binding.consent_sha256)) {
        return PreparedConfigProviderStatus::SourceChanged;
    }
    const bool reset_required = plan->reset_count != 0U;
    if (binding.reset_required != reset_required ||
        binding.reset_approved != reset_required) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    return PreparedConfigProviderStatus::Ok;
}

enum class ReadCurrentStatus : uint8_t {
    Ok = 0,
    Unsupported,
    IoError
};

ReadCurrentStatus ReadCurrentFile(UpdateFileSystem *file_system,
                                  const char *path, OwnedBuffer *buffer,
                                  bool *existed, uint64_t *size,
                                  uint8_t digest[kSha256DigestBytes])
{
    if (file_system == 0 || path == 0 || buffer == 0 || existed == 0 ||
        size == 0 || digest == 0) {
        return ReadCurrentStatus::IoError;
    }
    *existed = false;
    *size = 0U;
    memset(digest, 0, kSha256DigestBytes);
    UpdateFileStat before;
    if (!file_system->Stat(path, &before)) return ReadCurrentStatus::IoError;
    if (before.type == UpdateNodeType::Missing) {
        return buffer->Allocate(0U) ? ReadCurrentStatus::Ok
                                    : ReadCurrentStatus::IoError;
    }
    if (before.type != UpdateNodeType::RegularFile ||
        before.size > kMaximumConfigFileBytes || before.size > SIZE_MAX) {
        return ReadCurrentStatus::Unsupported;
    }
    if (!buffer->Allocate(static_cast<size_t>(before.size))) {
        return ReadCurrentStatus::IoError;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) {
        return ReadCurrentStatus::IoError;
    }
    uint64_t opened_size = 0U;
    bool ok = file->GetSize(&opened_size) && opened_size == before.size;
    uint64_t offset = 0U;
    while (ok && offset < before.size) {
        const uint64_t remaining = before.size - offset;
        const size_t count = remaining < kMinimumPreparedIoBytes
                                 ? static_cast<size_t>(remaining)
                                 : kMinimumPreparedIoBytes;
        ok = file->ReadAt(offset, buffer->data() + offset, count);
        offset += count;
    }
    const bool closed = file->Close();
    UpdateFileStat after;
    ok = ok && closed && file_system->Stat(path, &after) &&
         after.type == UpdateNodeType::RegularFile &&
         after.size == before.size;
    if (!ok || !buffer->Assign(buffer->data(), static_cast<size_t>(before.size)) ||
        !Sha256Digest(ByteView(buffer->data(), buffer->size()), digest)) {
        return ReadCurrentStatus::IoError;
    }
    *existed = true;
    *size = before.size;
    return ReadCurrentStatus::Ok;
}

bool FileMatches(UpdateFileSystem *file_system, const char *path,
                 uint64_t expected_size,
                 const uint8_t expected_sha256[kSha256DigestBytes],
                 uint8_t *scratch, size_t scratch_size,
                 UpdateRecoveryProgress *recovery_progress,
                 bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0 || path == 0 || expected_sha256 == 0 ||
        scratch == 0 || scratch_size < kMinimumPreparedIoBytes) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint64_t opened_size = 0U;
    bool ok = file->GetSize(&opened_size) && opened_size == expected_size;
    Sha256 hash;
    uint64_t offset = 0U;
    while (ok && offset < expected_size) {
        const uint64_t remaining = expected_size - offset;
        const size_t bounded_scratch =
            scratch_size < kMaximumPreparedIoChunkBytes
                ? scratch_size : kMaximumPreparedIoChunkBytes;
        const size_t count = remaining < bounded_scratch
                                 ? static_cast<size_t>(remaining)
                                 : bounded_scratch;
        ok = file->ReadAt(offset, scratch, count) &&
             hash.Update(scratch, count);
        offset += count;
        if (ok && !ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::PreparedFileVerified,
                offset, expected_size)) {
            if (progress_failed != 0) *progress_failed = true;
            ok = false;
        }
    }
    uint8_t digest[kSha256DigestBytes];
    ok = ok && hash.Final(digest) &&
         ConstantTimeDigestEqual(digest, expected_sha256);
    const bool closed = file->Close();
    UpdateFileStat after;
    return ok && closed && file_system->Stat(path, &after) &&
           after.type == UpdateNodeType::RegularFile &&
           after.size == expected_size;
}

bool ReadWholeFile(UpdateFileSystem *file_system, const char *path,
                   uint8_t *output, size_t expected_size,
                   UpdateRecoveryProgress *recovery_progress,
                   bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0 || path == 0 || output == 0) return false;
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint64_t size = 0U;
    bool ok = file->GetSize(&size) && size == expected_size;
    size_t offset = 0U;
    while (ok && offset < expected_size) {
        const size_t remaining = expected_size - offset;
        const size_t count = remaining < kMinimumPreparedIoBytes
                                 ? remaining : kMinimumPreparedIoBytes;
        ok = file->ReadAt(offset, output + offset, count);
        offset += count;
        if (ok && !ReportUpdateRecoveryProgress(
                recovery_progress,
                UpdateRecoveryProgressKind::PreparedEvidenceRead,
                offset, expected_size)) {
            if (progress_failed != 0) *progress_failed = true;
            ok = false;
        }
    }
    const bool closed = file->Close();
    return ok && closed;
}

bool HashArchive(SeekableZipSource *source, uint64_t expected_size,
                 const uint8_t expected_sha256[kSha256DigestBytes],
                 uint8_t *scratch, size_t scratch_size,
                 UpdateRecoveryProgress *recovery_progress,
                 UpdateRecoveryProgressKind progress_kind,
                 bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (source == 0 || expected_sha256 == 0 || scratch == 0 ||
        scratch_size < kMinimumPreparedIoBytes) {
        return false;
    }
    uint64_t size = 0U;
    if (!source->GetSize(&size) || size != expected_size) return false;
    if (!ReportUpdateRecoveryProgress(recovery_progress, progress_kind, 0U,
                                      size)) {
        if (progress_failed != 0) *progress_failed = true;
        return false;
    }
    Sha256 hash;
    uint64_t offset = 0U;
    uint64_t last_progress = 0U;
    while (offset < size) {
        const uint64_t remaining = size - offset;
        const size_t bounded_scratch =
            scratch_size < kMaximumPreparedIoChunkBytes
                ? scratch_size : kMaximumPreparedIoChunkBytes;
        const uint64_t since_progress = offset - last_progress;
        const uint64_t until_progress =
            kArchiveHashProgressIntervalBytes - since_progress;
        uint64_t bounded_count = remaining;
        if (bounded_count > bounded_scratch) {
            bounded_count = bounded_scratch;
        }
        if (bounded_count > until_progress) bounded_count = until_progress;
        const size_t count = static_cast<size_t>(bounded_count);
        if (!source->ReadAt(offset, scratch, count) ||
            !hash.Update(scratch, count)) {
            return false;
        }
        offset += count;
        const bool report_due = offset == size ||
            offset - last_progress >= kArchiveHashProgressIntervalBytes;
        if (report_due &&
            !ReportUpdateRecoveryProgress(recovery_progress, progress_kind,
                                          offset, size)) {
            if (progress_failed != 0) *progress_failed = true;
            return false;
        }
        if (report_due) last_progress = offset;
    }
    uint8_t digest[kSha256DigestBytes];
    return hash.Final(digest) &&
           ConstantTimeDigestEqual(digest, expected_sha256);
}

class TemplateExtractSink : public ZipExtractSink {
public:
    TemplateExtractSink(TemplateWork *templates, size_t template_count)
        : templates_(templates), template_count_(template_count),
          active_(false), active_directory_(false), active_template_(SIZE_MAX),
          expected_size_(0U), received_size_(0U)
    {
    }

    bool BeginEntry(const ZipEntry &entry) override
    {
        if (active_) return false;
        active_ = true;
        active_directory_ = entry.is_directory;
        active_template_ = SIZE_MAX;
        expected_size_ = entry.size;
        received_size_ = 0U;
        if (!entry.is_directory) {
            for (size_t index = 0U; index < template_count_; ++index) {
                if (templates_[index].manifest_file != 0 &&
                    strcmp(templates_[index].manifest_file->path,
                           entry.path) == 0) {
                    active_template_ = index;
                    break;
                }
            }
        }
        return true;
    }

    bool Write(ByteView bytes) override
    {
        if (!active_ || active_directory_ ||
            (bytes.data == 0 && bytes.size != 0U) ||
            bytes.size > expected_size_ - received_size_) {
            return false;
        }
        if (active_template_ != SIZE_MAX) {
            OwnedBuffer &target = templates_[active_template_].signed_default;
            if (received_size_ > target.capacity() ||
                bytes.size > target.capacity() -
                                 static_cast<size_t>(received_size_)) {
                return false;
            }
            if (bytes.size != 0U) {
                memcpy(target.data() + static_cast<size_t>(received_size_),
                       bytes.data, bytes.size);
            }
        }
        received_size_ += bytes.size;
        return true;
    }

    bool CommitEntry(const ZipEntry &entry) override
    {
        if (!active_ || entry.is_directory != active_directory_ ||
            received_size_ != expected_size_) {
            return false;
        }
        if (active_template_ != SIZE_MAX) {
            templates_[active_template_].signed_default.set_size(
                static_cast<size_t>(received_size_));
        }
        Clear();
        return true;
    }

    void AbortEntry(const ZipEntry &) override { Clear(); }

private:
    void Clear()
    {
        active_ = false;
        active_directory_ = false;
        active_template_ = SIZE_MAX;
        expected_size_ = 0U;
        received_size_ = 0U;
    }

    TemplateWork *templates_;
    size_t template_count_;
    bool active_;
    bool active_directory_;
    size_t active_template_;
    uint64_t expected_size_;
    uint64_t received_size_;
};

bool PrepareExpectedInventory(const ReleaseManifest &manifest,
                              const InstallerWorkspace &workspace,
                              ZipExpectedInventory *expected,
                              ZipLimits *limits)
{
    if (expected == 0 || limits == 0 || workspace.zip_entries == 0 ||
        workspace.expected_files == 0 || workspace.zip_workspace == 0 ||
        workspace.io_buffer == 0 ||
        workspace.io_buffer_size < kMinimumPreparedIoBytes ||
        workspace.zip_entry_capacity < manifest.asset.file_count +
                                           manifest.asset.directory_count ||
        workspace.expected_file_capacity < manifest.asset.file_count ||
        (manifest.asset.directory_count != 0U &&
         (workspace.expected_directories == 0 ||
          workspace.expected_directory_capacity <
              manifest.asset.directory_count))) {
        return false;
    }
    uint64_t maximum_file_size = 1U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        const ManifestFile &file = manifest.asset.files[index];
        workspace.expected_files[index].path = file.path;
        workspace.expected_files[index].size = file.size;
        workspace.expected_files[index].compression =
            file.compression == ManifestCompression::Store
                ? ZipCompression::Store
                : ZipCompression::Deflate;
        workspace.expected_files[index].sha256 = file.sha256;
        if (file.size > maximum_file_size) maximum_file_size = file.size;
    }
    for (size_t index = 0U; index < manifest.asset.directory_count; ++index) {
        workspace.expected_directories[index] =
            manifest.asset.directories[index].path;
    }
    expected->files = workspace.expected_files;
    expected->file_count = manifest.asset.file_count;
    expected->directories = workspace.expected_directories;
    expected->directory_count = manifest.asset.directory_count;
    limits->maximum_archive_bytes = manifest.asset.download_size;
    limits->maximum_entries = manifest.asset.file_count +
                              manifest.asset.directory_count;
    limits->maximum_path_bytes = kMaximumManifestPathBytes;
    limits->maximum_file_bytes = maximum_file_size;
    limits->maximum_installed_bytes =
        manifest.asset.installed_size == 0U ? 1U
                                            : manifest.asset.installed_size;
    limits->maximum_compression_ratio = 200U;
    return true;
}

PreparedConfigProviderStatus ExtractSignedDefaults(
    const AuthenticatedUpdateBinding &binding, const ReleaseManifest &manifest,
    SeekableZipSource *archive, const InstallerWorkspace &workspace,
    TemplateWork *templates, size_t template_count, ZipStatus *zip_status,
    UpdateRecoveryProgress *recovery_progress)
{
    if (archive == 0 || templates == 0 || zip_status == 0) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    for (size_t index = 0U; index < template_count; ++index) {
        if (templates[index].manifest_file == 0 ||
            templates[index].manifest_file->size > SIZE_MAX ||
            !templates[index].signed_default.Allocate(
                static_cast<size_t>(templates[index].manifest_file->size))) {
            return PreparedConfigProviderStatus::IoError;
        }
    }
    bool progress_failed = false;
    if (!HashArchive(archive, binding.archive_size, binding.archive_sha256,
                     workspace.io_buffer, workspace.io_buffer_size,
                     recovery_progress,
                     UpdateRecoveryProgressKind::PreparedArchiveInitialHashed,
                     &progress_failed)) {
        return progress_failed
            ? PreparedConfigProviderStatus::RecoveryProgressFailed
            : PreparedConfigProviderStatus::SourceChanged;
    }
    ZipExpectedInventory expected;
    ZipLimits limits;
    if (!PrepareExpectedInventory(manifest, workspace, &expected, &limits)) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    ZipReader reader;
    reader.SetWorkspace(workspace.zip_workspace);
    *zip_status = reader.Open(archive, workspace.zip_entries,
                              workspace.zip_entry_capacity, limits);
    if (*zip_status != ZipStatus::Ok ||
        reader.inventory().archive_size != binding.archive_size ||
        reader.inventory().file_count != manifest.asset.file_count ||
        reader.inventory().directory_count !=
            manifest.asset.directory_count ||
        reader.inventory().installed_size != manifest.asset.installed_size) {
        return PreparedConfigProviderStatus::SourceChanged;
    }
    TemplateExtractSink sink(templates, template_count);
    Sha256ZipHashSink hash_sink;
    // The exact archive bytes are authenticated immediately before opening
    // the ZIP. Only ConfigTemplate members are inputs to configuration
    // preparation; walking every kernel, firmware and media member here adds
    // no additional binding beyond that whole-archive digest. ExtractOne
    // still validates the exact signed inventory and verifies each selected
    // member's CRC, size and SHA-256 before committing it to the in-memory
    // template sink. PrepareForStage performs the second whole-archive binding
    // check after the prepared evidence and local configuration have both
    // been revalidated.
    for (size_t index = 0U; index < template_count; ++index) {
        *zip_status = reader.ExtractOne(
            templates[index].manifest_file->path, expected, &sink, &hash_sink);
        if (*zip_status != ZipStatus::Ok) {
            return PreparedConfigProviderStatus::SourceChanged;
        }
    }
    for (size_t index = 0U; index < template_count; ++index) {
        if (templates[index].signed_default.size() !=
            templates[index].manifest_file->size) {
            return PreparedConfigProviderStatus::SourceChanged;
        }
    }
    return PreparedConfigProviderStatus::Ok;
}

size_t FindTemplate(const TemplateWork *templates, size_t template_count,
                    const char *path)
{
    if (templates == 0 || path == 0) return SIZE_MAX;
    for (size_t index = 0U; index < template_count; ++index) {
        if (templates[index].manifest_file != 0 &&
            strcmp(templates[index].manifest_file->path, path) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

bool ClassificationChanged(const ConfigAreaAssessment *assessment)
{
    return assessment != 0 &&
           (assessment->classification ==
                ConfigClassification::LosslessMigration ||
            assessment->classification == ConfigClassification::ResetRequired);
}

PreparedConfigProviderStatus ReadCurrentTemplates(
    UpdateFileSystem *file_system, const ConfigMigrationPlan &plan,
    TemplateWork *templates, size_t template_count)
{
    if (file_system == 0 || templates == 0) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    for (size_t index = 0U; index < template_count; ++index) {
        TemplateWork &work = templates[index];
        const ReadCurrentStatus read = ReadCurrentFile(
            file_system, work.manifest_file->path, &work.current,
            &work.original_existed, &work.original_size,
            work.original_sha256);
        if (read == ReadCurrentStatus::IoError) {
            return PreparedConfigProviderStatus::IoError;
        }
        if (read == ReadCurrentStatus::Unsupported) {
            return PreparedConfigProviderStatus::Unsupported;
        }

        const ConfigArea area = TemplateArea(work.manifest_file->path);
        const bool generated_boot_template =
            IsPath(work.manifest_file, "bmx-active-kernel.txt") ||
            IsPath(work.manifest_file, "bmx-tryboot-kernel.txt") ||
            IsPath(work.manifest_file, "bmx-machine.txt") ||
            IsPath(work.manifest_file, "tryboot.txt");
        size_t capacity = work.signed_default.size();
        if (area != ConfigArea::Unknown || generated_boot_template) {
            capacity = kMaximumConfigFileBytes;
        }
        if (work.original_existed && work.current.size() > capacity) {
            capacity = work.current.size();
        }
        if (!work.prepared.Allocate(capacity)) {
            return PreparedConfigProviderStatus::IoError;
        }

        // Schema-owned compatible paths retain their current bytes.  The
        // active selector is also retained here and is subsequently parsed
        // against the authenticated source binding.  machines.txt is opaque
        // user configuration: preserve it byte-for-byte when present instead
        // of replacing it with a target-release default.
        bool preserve_current = false;
        if (area == ConfigArea::CmdlineManagedKeys) {
            const ConfigAreaAssessment *cmdline =
                FindAssessment(plan, ConfigArea::CmdlineManagedKeys);
            const ConfigAreaAssessment *network =
                FindAssessment(plan, ConfigArea::Network);
            preserve_current = cmdline != 0 && network != 0 &&
                               !ClassificationChanged(cmdline) &&
                               !ClassificationChanged(network) &&
                               work.original_existed;
        } else if (area != ConfigArea::Unknown) {
            const ConfigAreaAssessment *assessment = FindAssessment(plan, area);
            preserve_current = assessment != 0 &&
                               assessment->classification ==
                                   ConfigClassification::Compatible &&
                               work.original_existed;
        } else if ((IsPath(work.manifest_file, "machines.txt") ||
                    IsPath(work.manifest_file,
                           "bmx-active-kernel.txt")) &&
                   work.original_existed) {
            preserve_current = true;
        }
        const uint8_t *source = preserve_current
                                    ? work.current.data()
                                    : work.signed_default.data();
        const size_t source_size = preserve_current
                                       ? work.current.size()
                                       : work.signed_default.size();
        if (!work.prepared.Assign(source, source_size)) {
            return PreparedConfigProviderStatus::IoError;
        }
    }
    return PreparedConfigProviderStatus::Ok;
}

PreparedConfigProviderStatus ApplyAreaChange(
    ConfigArea area, const ConfigMigrationPlan &plan,
    const ConfigSnapshot &snapshot, TemplateWork *templates,
    size_t template_count, ConfigChangeStatus *change_status)
{
    const ConfigAreaAssessment *assessment = FindAssessment(plan, area);
    if (!ClassificationChanged(assessment)) {
        return PreparedConfigProviderStatus::Ok;
    }
    const ConfigAreaSnapshot *source = FindArea(snapshot, area);
    if (source == 0 || source->file_count == 0U ||
        source->file_count > kMaximumConfigFilesPerArea) {
        return PreparedConfigProviderStatus::Unsupported;
    }

    // A transform is representable only if every source file it may need to
    // change is a ConfigTemplate.  This deliberately rejects settings,
    // update-state journals and machines.local.ini instead of silently
    // producing a semantically mixed area.
    for (size_t index = 0U; index < source->file_count; ++index) {
        if (FindTemplate(templates, template_count, source->files[index].path) ==
            SIZE_MAX) {
            return PreparedConfigProviderStatus::Unsupported;
        }
    }

    ConfigFileView default_views[kMaximumConfigFilesPerArea];
    size_t default_count = 0U;
    if (assessment->classification == ConfigClassification::ResetRequired) {
        for (size_t index = 0U; index < template_count; ++index) {
            const char *path = templates[index].manifest_file->path;
            if (!PathBelongsToArea(area, path)) continue;
            if (default_count >= kMaximumConfigFilesPerArea) {
                return PreparedConfigProviderStatus::Unsupported;
            }
            default_views[default_count].path = path;
            default_views[default_count].content = ByteView(
                templates[index].signed_default.data(),
                templates[index].signed_default.size());
            ++default_count;
        }
        if (default_count == 0U) {
            return PreparedConfigProviderStatus::Unsupported;
        }
    }
    const ConfigAreaSnapshot defaults = {area, default_views, default_count};
    const ConfigAreaSnapshot *expected =
        assessment->classification == ConfigClassification::ResetRequired
            ? &defaults
            : source;
    if (expected->file_count == 0U ||
        expected->file_count > kMaximumConfigFilesPerArea) {
        return PreparedConfigProviderStatus::Unsupported;
    }

    ConfigOutputFile outputs[kMaximumConfigFilesPerArea];
    size_t output_template[kMaximumConfigFilesPerArea];
    for (size_t index = 0U; index < expected->file_count; ++index) {
        const size_t found =
            FindTemplate(templates, template_count, expected->files[index].path);
        if (found == SIZE_MAX) {
            return PreparedConfigProviderStatus::Unsupported;
        }
        output_template[index] = found;
        outputs[index].path = expected->files[index].path;
        outputs[index].content = MutableByteView(
            templates[found].prepared.data(),
            templates[found].prepared.capacity());
        outputs[index].written = 0U;
    }
    ConfigChangeRequest request;
    request.area = area;
    request.migration_id = assessment->migration_id;
    request.source_version = assessment->source_version;
    request.target_version = assessment->target_version;
    request.reset_consent =
        assessment->classification == ConfigClassification::ResetRequired;
    request.source = source;
    request.defaults = request.reset_consent ? &defaults : 0;
    request.output_files = outputs;
    request.output_file_count = expected->file_count;
    *change_status = ApplyConfigChange(request);
    if (*change_status != ConfigChangeStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    for (size_t index = 0U; index < expected->file_count; ++index) {
        templates[output_template[index]].prepared.set_size(
            outputs[index].written);
    }
    return PreparedConfigProviderStatus::Ok;
}

PreparedConfigProviderStatus ApplyRepresentableChanges(
    const ConfigMigrationPlan &plan, const ConfigSnapshot &snapshot,
    TemplateWork *templates, size_t template_count,
    ConfigChangeStatus *change_status)
{
    const bool cmdline_changed = ClassificationChanged(
        FindAssessment(plan, ConfigArea::CmdlineManagedKeys));
    const bool network_changed =
        ClassificationChanged(FindAssessment(plan, ConfigArea::Network));
    if (cmdline_changed && network_changed) {
        // Both transforms rewrite cmdline.txt from the same original.  There
        // is no compiled composition contract, so applying either order would
        // be ambiguous and could erase the first result.
        return PreparedConfigProviderStatus::Unsupported;
    }
    static const ConfigArea order[] = {
        ConfigArea::Machines,
        ConfigArea::ConfigManagedBlock,
        ConfigArea::CmdlineManagedKeys,
        ConfigArea::Network,
        ConfigArea::Settings,
        ConfigArea::UpdateState};
    for (size_t index = 0U; index < sizeof(order) / sizeof(order[0]); ++index) {
        const PreparedConfigProviderStatus status = ApplyAreaChange(
            order[index], plan, snapshot, templates, template_count,
            change_status);
        if (status != PreparedConfigProviderStatus::Ok) return status;
    }
    return PreparedConfigProviderStatus::Ok;
}

KernelSelectorStatus ParseSelectorForSequence(
    const OwnedBuffer &bytes, BoardFamily board, uint64_t release_sequence,
    ParsedKernelSelector *selector)
{
    if (release_sequence == 0U) {
        return KernelSelectorStatus::SequenceMismatch;
    }
    KernelSelectorStatus status = ParseKernelSelector(
        ByteView(bytes.data(), bytes.size()), board, selector);
    return status;
}

PreparedConfigProviderStatus PrepareBootTemplates(
    const AuthenticatedUpdateBinding &binding, const ReleaseManifest &manifest,
    TemplateWork *templates, size_t template_count,
    KernelSelectorStatus *selector_status)
{
    if (templates == 0 || selector_status == 0) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    *selector_status = KernelSelectorStatus::InvalidArgument;
    if (FindTemplate(templates, template_count, "autoboot.txt") != SIZE_MAX) {
        // No compiled autoboot grammar/ownership contract exists yet.  It is
        // boot-critical, so an authenticated release cannot make it a
        // ConfigTemplate until that contract is implemented.
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }

    const size_t config_index =
        FindTemplate(templates, template_count, "config.txt");
    const size_t tryboot_index =
        FindTemplate(templates, template_count, "tryboot.txt");
    const size_t active_index =
        FindTemplate(templates, template_count, "bmx-active-kernel.txt");
    const size_t candidate_index =
        FindTemplate(templates, template_count, "bmx-tryboot-kernel.txt");
    const size_t machine_index =
        FindTemplate(templates, template_count, "bmx-machine.txt");
    if (config_index == SIZE_MAX || tryboot_index == SIZE_MAX ||
        active_index == SIZE_MAX || candidate_index == SIZE_MAX) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }

    TemplateWork &config = templates[config_index];
    TemplateWork &tryboot = templates[tryboot_index];
    TemplateWork &active = templates[active_index];
    TemplateWork &candidate = templates[candidate_index];

    // The signed manual-install profile is the immutable target-release C64
    // baseline.  Binding it here prevents the online path from accepting a
    // release whose defaults disagree with release-tooling semantics.
    ParsedKernelSelector signed_active;
    ParsedKernelSelector signed_candidate;
    *selector_status = ParseSelectorForSequence(
        active.signed_default, binding.board,
        binding.target_release_sequence, &signed_active);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    *selector_status = ValidateKernelSelectorAgainstAsset(
        signed_active, manifest.asset, binding.target_release_sequence);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    *selector_status = ParseSelectorForSequence(
        candidate.signed_default, binding.board,
        binding.target_release_sequence, &signed_candidate);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    *selector_status = ValidateKernelSelectorAgainstAsset(
        signed_candidate, manifest.asset, binding.target_release_sequence);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    if (strcmp(signed_active.machine, "c64") != 0 ||
        strcmp(signed_candidate.machine, "c64") != 0 ||
        active.signed_default.size() != candidate.signed_default.size() ||
        memcmp(active.signed_default.data(), candidate.signed_default.data(),
               active.signed_default.size()) != 0 ||
        !ValidateSelectorConfigProfile(
            ByteView(config.signed_default.data(),
                     config.signed_default.size()),
            binding.board, false) ||
        !ValidateSelectorConfigProfile(
            ByteView(tryboot.signed_default.data(),
                     tryboot.signed_default.size()),
            binding.board, true)) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }
    OwnedBuffer derived_signed_tryboot;
    if (!derived_signed_tryboot.Allocate(kMaximumConfigFileBytes) ||
        !BuildTrybootConfig(
            ByteView(config.signed_default.data(),
                     config.signed_default.size()),
            &derived_signed_tryboot) ||
        derived_signed_tryboot.size() != tryboot.signed_default.size() ||
        memcmp(derived_signed_tryboot.data(), tryboot.signed_default.data(),
               derived_signed_tryboot.size()) != 0) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }
    if (machine_index != SIZE_MAX &&
        !ParseMachineMarker(
            ByteView(templates[machine_index].signed_default.data(),
                     templates[machine_index].signed_default.size()),
            "c64")) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }

    // Selectors carry only board/machine identity. Parse the freshly read
    // stable paths and preserve the active selection exactly. The dormant
    // selector may name another machine after an in-menu machine switch.
    if (!active.original_existed || !candidate.original_existed ||
        !config.original_existed) {
        *selector_status = KernelSelectorStatus::InvalidFormat;
        return PreparedConfigProviderStatus::SourceChanged;
    }
    ParsedKernelSelector current_active;
    ParsedKernelSelector current_candidate;
    *selector_status = ParseSelectorForSequence(
        active.current, binding.board, binding.source_release_sequence,
        &current_active);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::SourceChanged;
    }
    *selector_status = ParseSelectorForSequence(
        candidate.current, binding.board, binding.source_release_sequence,
        &current_candidate);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::SourceChanged;
    }
    if (!ValidateSelectorConfigProfile(
            ByteView(config.current.data(), config.current.size()),
            binding.board, false) ||
        (tryboot.original_existed &&
         !ValidateSelectorConfigProfile(
             ByteView(tryboot.current.data(), tryboot.current.size()),
             binding.board, true)) ||
        (machine_index != SIZE_MAX &&
         templates[machine_index].original_existed &&
         !ParseMachineMarker(
             ByteView(templates[machine_index].current.data(),
                      templates[machine_index].current.size()),
             current_active.machine))) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::SourceChanged;
    }

    if (!ValidateSelectorConfigProfile(
            ByteView(config.prepared.data(), config.prepared.size()),
            binding.board, false) ||
        !active.prepared.Assign(active.current.data(), active.current.size())) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }
    ParsedKernelSelector target_candidate;
    if (!RenderTargetSelector(binding.board, current_active.machine,
                              binding.target_release_sequence,
                              &candidate.prepared, &target_candidate)) {
        *selector_status = KernelSelectorStatus::InvalidFormat;
        return PreparedConfigProviderStatus::Unsupported;
    }
    *selector_status = ValidateKernelSelectorAgainstAsset(
        target_candidate, manifest.asset, binding.target_release_sequence);
    if (*selector_status != KernelSelectorStatus::Ok) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    if (!BuildTrybootConfig(
            ByteView(config.prepared.data(), config.prepared.size()),
            &tryboot.prepared) ||
        !ValidateSelectorConfigProfile(
            ByteView(tryboot.prepared.data(), tryboot.prepared.size()),
            binding.board, true)) {
        *selector_status = KernelSelectorStatus::ManifestMismatch;
        return PreparedConfigProviderStatus::Unsupported;
    }
    if (machine_index != SIZE_MAX) {
        char marker[17U];
        const int written = snprintf(marker, sizeof(marker), "%s\n",
                                     current_active.machine);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(marker) ||
            !templates[machine_index].prepared.Assign(
                reinterpret_cast<const uint8_t *>(marker),
                static_cast<size_t>(written))) {
            *selector_status = KernelSelectorStatus::ManifestMismatch;
            return PreparedConfigProviderStatus::Unsupported;
        }
    }
    *selector_status = KernelSelectorStatus::Ok;
    return PreparedConfigProviderStatus::Ok;
}

bool EnsureDirectoryTree(UpdateFileSystem *file_system, const char *path)
{
    if (file_system == 0 || path == 0 ||
        ValidateFatRelativePath(path,
                                kFatFsUpdateFileSystemRelativePathBytes - 1U) !=
            FatPathValidationStatus::Ok) {
        return false;
    }
    char current[kFatFsUpdateFileSystemRelativePathBytes];
    const size_t length = strlen(path);
    if (length >= sizeof(current)) return false;
    memcpy(current, path, length + 1U);
    for (size_t index = 0U; index <= length; ++index) {
        if (current[index] != '/' && current[index] != '\0') continue;
        const char saved = current[index];
        current[index] = '\0';
        if (!file_system->CreateDirectory(current)) return false;
        current[index] = saved;
    }
    return true;
}

bool CleanupPreparedPaths(UpdateFileSystem *file_system,
                          const PreparedPaths &paths,
                          UpdateRecoveryProgress *recovery_progress,
                          bool *progress_failed)
{
    if (progress_failed != 0) *progress_failed = false;
    if (file_system == 0) return false;
    bool ok = true;
    char path[kFatFsUpdateFileSystemRelativePathBytes];
    if (EvidencePath(paths, true, path)) {
        if (!file_system->RemoveFile(path)) ok = false;
        else if (!ReportUpdateRecoveryProgress(
                     recovery_progress,
                     UpdateRecoveryProgressKind::PreparedCleanup)) {
            if (progress_failed != 0) *progress_failed = true;
            return false;
        }
    } else {
        ok = false;
    }
    if (EvidencePath(paths, false, path)) {
        if (!file_system->RemoveFile(path)) ok = false;
        else if (!ReportUpdateRecoveryProgress(
                     recovery_progress,
                     UpdateRecoveryProgressKind::PreparedCleanup)) {
            if (progress_failed != 0) *progress_failed = true;
            return false;
        }
    } else {
        ok = false;
    }
    for (size_t index = 0U; index < kFatFsPreparedConfigMaximumTemplates;
         ++index) {
        if (ItemPath(paths, index, true, path)) {
            if (!file_system->RemoveFile(path)) ok = false;
            else if (!ReportUpdateRecoveryProgress(
                         recovery_progress,
                         UpdateRecoveryProgressKind::PreparedCleanup)) {
                if (progress_failed != 0) *progress_failed = true;
                return false;
            }
        } else {
            ok = false;
        }
        if (ItemPath(paths, index, false, path)) {
            if (!file_system->RemoveFile(path)) ok = false;
            else if (!ReportUpdateRecoveryProgress(
                         recovery_progress,
                         UpdateRecoveryProgressKind::PreparedCleanup)) {
                if (progress_failed != 0) *progress_failed = true;
                return false;
            }
        } else {
            ok = false;
        }
    }
    if (!file_system->RemoveDirectory(paths.root)) ok = false;
    else if (!ReportUpdateRecoveryProgress(
                 recovery_progress,
                 UpdateRecoveryProgressKind::PreparedCleanup)) {
        if (progress_failed != 0) *progress_failed = true;
        return false;
    }
    return ok;
}

bool WriteFreshVerified(UpdateFileSystem *file_system, const char *temporary,
                        const char *final_path, ByteView content,
                        const uint8_t expected_sha256[kSha256DigestBytes],
                        uint8_t *scratch, size_t scratch_size)
{
    if (file_system == 0 || temporary == 0 || final_path == 0 ||
        expected_sha256 == 0 || (content.data == 0 && content.size != 0U) ||
        !file_system->RemoveFile(temporary)) {
        return false;
    }
    UpdateFileStat final_stat;
    if (!file_system->Stat(final_path, &final_stat) ||
        final_stat.type != UpdateNodeType::Missing) {
        return false;
    }
    UpdateWriteFile *file = 0;
    if (!file_system->CreateFileFresh(temporary, &file) || file == 0) {
        return false;
    }
    const bool wrote = file->Write(content);
    const bool synced = wrote && file->Sync();
    const bool closed = file->Close();
    bool ok = wrote && synced && closed &&
              file_system->Rename(temporary, final_path, false) &&
              file_system->SyncContainingDirectory(final_path) &&
              FileMatches(file_system, final_path, content.size,
                          expected_sha256, scratch, scratch_size, 0, 0);
    if (!ok) {
        (void)file_system->RemoveFile(temporary);
        (void)file_system->RemoveFile(final_path);
    }
    return ok;
}

const ManifestFile *NthTemplate(const ReleaseManifest &manifest, size_t wanted)
{
    size_t current = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        const ManifestFile &file = manifest.asset.files[index];
        if (file.policy != ManifestFilePolicy::ConfigTemplate) continue;
        if (current == wanted) return &file;
        ++current;
    }
    return 0;
}

bool ZeroRange(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) {
        combined = static_cast<uint8_t>(combined | bytes[index]);
    }
    return combined == 0U;
}

bool EncodeEvidence(
    const PreparedPaths &paths, const AuthenticatedUpdateBinding &binding,
    const TemplateWork *templates, size_t template_count,
    const uint8_t prepared_sha256
        [kFatFsPreparedConfigMaximumTemplates][kSha256DigestBytes],
    uint8_t output[kFatFsPreparedConfigEvidenceBytes])
{
    if (templates == 0 || output == 0 ||
        template_count > kFatFsPreparedConfigMaximumTemplates) {
        return false;
    }
    memset(output, 0, kFatFsPreparedConfigEvidenceBytes);
    memcpy(output, kEvidenceMagic, sizeof(kEvidenceMagic));
    EncodeU32(1U, output + 16U);
    EncodeU32(static_cast<uint32_t>(template_count), output + 20U);
    memcpy(output + 24U, paths.binding_sha256, kSha256DigestBytes);
    memcpy(output + 56U, binding.manifest_sha256, kSha256DigestBytes);
    memcpy(output + 88U, binding.consent_sha256, kSha256DigestBytes);
    output[120U] = binding.reset_required ? 1U : 0U;
    output[121U] = binding.reset_approved ? 1U : 0U;

    for (size_t index = 0U; index < template_count; ++index) {
        const TemplateWork &work = templates[index];
        const size_t offset = kEvidenceHeaderBytes +
                              index * kEvidenceRecordBytes;
        size_t path_size = 0U;
        if (work.manifest_file == 0 ||
            !BoundedLength(work.manifest_file->path,
                           kMaximumManifestPathBytes, &path_size) ||
            path_size == 0U ||
            work.original_size > kMaximumConfigFileBytes ||
            work.prepared.size() > kMaximumConfigFileBytes ||
            !BytesNonZero(prepared_sha256[index], kSha256DigestBytes) ||
            (work.original_existed &&
             !BytesNonZero(work.original_sha256, kSha256DigestBytes)) ||
            (!work.original_existed &&
             (work.original_size != 0U ||
              BytesNonZero(work.original_sha256, kSha256DigestBytes)))) {
            return false;
        }
        memcpy(output + offset, work.manifest_file->path, path_size + 1U);
        output[offset + 241U] = work.original_existed ? 1U : 0U;
        EncodeU64(work.original_size, output + offset + 248U);
        memcpy(output + offset + 256U, work.original_sha256,
               kSha256DigestBytes);
        EncodeU64(work.prepared.size(), output + offset + 288U);
        memcpy(output + offset + 296U, prepared_sha256[index],
               kSha256DigestBytes);
    }
    return Sha256Digest(ByteView(output, kEvidencePayloadBytes),
                        output + kEvidenceDigestOffset);
}

bool ParseEvidence(const uint8_t input[kFatFsPreparedConfigEvidenceBytes],
                   const PreparedPaths &paths,
                   const AuthenticatedUpdateBinding &binding,
                   const ReleaseManifest &manifest, size_t template_count,
                   PreparedConfigTemplate *entries)
{
    if (input == 0 || entries == 0 ||
        template_count > kFatFsPreparedConfigMaximumTemplates ||
        memcmp(input, kEvidenceMagic, sizeof(kEvidenceMagic)) != 0 ||
        DecodeU32(input + 16U) != 1U ||
        DecodeU32(input + 20U) != template_count ||
        !ConstantTimeDigestEqual(input + 24U, paths.binding_sha256) ||
        !ConstantTimeDigestEqual(input + 56U, binding.manifest_sha256) ||
        !ConstantTimeDigestEqual(input + 88U, binding.consent_sha256) ||
        input[120U] != (binding.reset_required ? 1U : 0U) ||
        input[121U] != (binding.reset_approved ? 1U : 0U) ||
        !ZeroRange(input + 122U, 6U)) {
        return false;
    }
    uint8_t evidence_digest[kSha256DigestBytes];
    if (!Sha256Digest(ByteView(input, kEvidencePayloadBytes),
                      evidence_digest) ||
        !ConstantTimeDigestEqual(evidence_digest,
                                 input + kEvidenceDigestOffset)) {
        return false;
    }
    for (size_t index = 0U;
         index < kFatFsPreparedConfigMaximumTemplates; ++index) {
        const size_t offset = kEvidenceHeaderBytes +
                              index * kEvidenceRecordBytes;
        if (index >= template_count) {
            if (!ZeroRange(input + offset, kEvidenceRecordBytes)) return false;
            continue;
        }
        const ManifestFile *manifest_file = NthTemplate(manifest, index);
        if (manifest_file == 0 ||
            !ZeroRange(input + offset + 242U, 6U) ||
            !ZeroRange(input + offset + 328U, 8U) ||
            input[offset + 241U] > 1U) {
            return false;
        }
        size_t path_size = 0U;
        if (!BoundedLength(
                reinterpret_cast<const char *>(input + offset),
                kMaximumManifestPathBytes, &path_size) ||
            path_size == 0U ||
            !ZeroRange(input + offset + path_size + 1U,
                       241U - path_size - 1U) ||
            strcmp(reinterpret_cast<const char *>(input + offset),
                   manifest_file->path) != 0 ||
            ValidateFatRelativePath(
                reinterpret_cast<const char *>(input + offset),
                kMaximumManifestPathBytes) != FatPathValidationStatus::Ok) {
            return false;
        }
        PreparedConfigTemplate &entry = entries[index];
        memset(&entry, 0, sizeof(entry));
        // The provider replaces this pointer with its own bounded path copy.
        entry.path = manifest_file->path;
        entry.content = 0;
        entry.original_existed = input[offset + 241U] != 0U;
        entry.original_size = DecodeU64(input + offset + 248U);
        memcpy(entry.original_sha256, input + offset + 256U,
               kSha256DigestBytes);
        entry.prepared_size = DecodeU64(input + offset + 288U);
        memcpy(entry.prepared_sha256, input + offset + 296U,
               kSha256DigestBytes);
        if (entry.original_size > kMaximumConfigFileBytes ||
            entry.prepared_size > kMaximumConfigFileBytes ||
            !BytesNonZero(entry.prepared_sha256, kSha256DigestBytes) ||
            (entry.original_existed &&
             !BytesNonZero(entry.original_sha256, kSha256DigestBytes)) ||
            (!entry.original_existed &&
             (entry.original_size != 0U ||
              BytesNonZero(entry.original_sha256, kSha256DigestBytes)))) {
            return false;
        }
    }
    return true;
}

PreparedConfigProviderStatus VerifyCurrentEvidence(
    UpdateFileSystem *file_system, const TemplateWork *templates,
    size_t template_count)
{
    for (size_t index = 0U; index < template_count; ++index) {
        OwnedBuffer current;
        bool existed = false;
        uint64_t size = 0U;
        uint8_t digest[kSha256DigestBytes];
        const ReadCurrentStatus read = ReadCurrentFile(
            file_system, templates[index].manifest_file->path, &current,
            &existed, &size, digest);
        if (read == ReadCurrentStatus::IoError) {
            return PreparedConfigProviderStatus::IoError;
        }
        if (read == ReadCurrentStatus::Unsupported ||
            existed != templates[index].original_existed ||
            size != templates[index].original_size ||
            (existed && !ConstantTimeDigestEqual(
                            digest, templates[index].original_sha256))) {
            return PreparedConfigProviderStatus::SourceChanged;
        }
    }
    return PreparedConfigProviderStatus::Ok;
}

}  // namespace

PreparedConfigRepresentabilityResult CheckPreparedConfigRepresentability(
    const ConfigMigrationPlan &plan, const ConfigSnapshot &snapshot,
    const ReleaseManifest &manifest)
{
    PreparedConfigRepresentabilityResult result;
    memset(&result, 0, sizeof(result));
    result.status = PreparedConfigRepresentabilityStatus::InvalidInput;
    result.area = ConfigArea::Unknown;

    if (plan.area_count != kConfigMigrationAreaCount ||
        snapshot.areas == 0 ||
        snapshot.area_count != kConfigMigrationAreaCount ||
        manifest.asset.files == 0 || manifest.asset.file_count == 0U ||
        manifest.asset.file_count > kMaximumManifestFiles) {
        return result;
    }

    bool plan_areas[kConfigMigrationAreaCount + 1U] = {
        false, false, false, false, false, false, false};
    size_t reset_count = 0U;
    for (size_t index = 0U; index < plan.area_count; ++index) {
        const ConfigAreaAssessment &assessment = plan.areas[index];
        const size_t area_index = static_cast<size_t>(assessment.area);
        if (!IsKnownConfigArea(assessment.area) ||
            area_index > kConfigMigrationAreaCount || plan_areas[area_index] ||
            (assessment.classification != ConfigClassification::Compatible &&
             assessment.classification !=
                 ConfigClassification::LosslessMigration &&
             assessment.classification !=
                 ConfigClassification::ResetRequired)) {
            return result;
        }
        plan_areas[area_index] = true;
        if (assessment.classification == ConfigClassification::ResetRequired) {
            ++reset_count;
        }
    }
    if (reset_count != plan.reset_count) return result;

    bool snapshot_areas[kConfigMigrationAreaCount + 1U] = {
        false, false, false, false, false, false, false};
    for (size_t index = 0U; index < snapshot.area_count; ++index) {
        const ConfigAreaSnapshot &area = snapshot.areas[index];
        const size_t area_index = static_cast<size_t>(area.area);
        if (!IsKnownConfigArea(area.area) ||
            area_index > kConfigMigrationAreaCount ||
            snapshot_areas[area_index] ||
            area.file_count > kMaximumConfigFilesPerArea ||
            (area.file_count != 0U && area.files == 0)) {
            return result;
        }
        snapshot_areas[area_index] = true;
        for (size_t file = 0U; file < area.file_count; ++file) {
            size_t path_size = 0U;
            if (!BoundedLength(area.files[file].path,
                               kMaximumConfigPathBytes, &path_size) ||
                path_size == 0U ||
                !PathBelongsToArea(area.area, area.files[file].path)) {
                return result;
            }
        }
    }

    size_t template_count = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        const ManifestFile &file = manifest.asset.files[index];
        if (file.policy != ManifestFilePolicy::ConfigTemplate) continue;
        ++template_count;
        size_t path_size = 0U;
        if (template_count > kFatFsPreparedConfigMaximumTemplates ||
            !BoundedLength(file.path, kMaximumManifestPathBytes, &path_size) ||
            path_size == 0U ||
            ValidateFatRelativePath(file.path, kMaximumManifestPathBytes) !=
                FatPathValidationStatus::Ok) {
            return result;
        }
        if (!IsKnownConfigTemplatePath(file.path) ||
            strcmp(file.path, "autoboot.txt") == 0) {
            result.status =
                PreparedConfigRepresentabilityStatus::UnsupportedTemplatePath;
            if (path_size <= kMaximumConfigPathBytes) {
                memcpy(result.path, file.path, path_size + 1U);
            }
            return result;
        }
        for (size_t prior = 0U; prior < index; ++prior) {
            if (manifest.asset.files[prior].policy ==
                    ManifestFilePolicy::ConfigTemplate &&
                FatTextEqual(file.path, manifest.asset.files[prior].path)) {
                return result;
            }
        }
    }

    static const char *const required_templates[] = {
        "config.txt", "bmx-active-kernel.txt", "bmx-tryboot-kernel.txt",
        "tryboot.txt"};
    for (size_t required = 0U;
         required < sizeof(required_templates) / sizeof(required_templates[0]);
         ++required) {
        bool found = false;
        for (size_t file = 0U; file < manifest.asset.file_count; ++file) {
            if (manifest.asset.files[file].policy ==
                    ManifestFilePolicy::ConfigTemplate &&
                strcmp(manifest.asset.files[file].path,
                       required_templates[required]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.status =
                PreparedConfigRepresentabilityStatus::RequiredTemplateMissing;
            memcpy(result.path, required_templates[required],
                   strlen(required_templates[required]) + 1U);
            return result;
        }
    }

    const ConfigAreaAssessment *cmdline =
        FindAssessment(plan, ConfigArea::CmdlineManagedKeys);
    const ConfigAreaAssessment *network =
        FindAssessment(plan, ConfigArea::Network);
    if (ClassificationChanged(cmdline) && ClassificationChanged(network)) {
        result.status = PreparedConfigRepresentabilityStatus::
            SharedCmdlineNetworkTransform;
        result.area = ConfigArea::CmdlineManagedKeys;
        memcpy(result.path, "cmdline.txt", sizeof("cmdline.txt"));
        return result;
    }

    for (size_t index = 0U; index < plan.area_count; ++index) {
        const ConfigAreaAssessment &assessment = plan.areas[index];
        if (!ClassificationChanged(&assessment)) continue;
        const ConfigAreaSnapshot *source = FindArea(snapshot, assessment.area);
        if (source == 0 || source->file_count == 0U) {
            result.status = PreparedConfigRepresentabilityStatus::
                ChangedAreaSourceMissing;
            result.area = assessment.area;
            return result;
        }
        for (size_t source_index = 0U;
             source_index < source->file_count; ++source_index) {
            const char *source_path = source->files[source_index].path;
            bool represented = false;
            for (size_t file = 0U; file < manifest.asset.file_count; ++file) {
                if (manifest.asset.files[file].policy ==
                        ManifestFilePolicy::ConfigTemplate &&
                    strcmp(manifest.asset.files[file].path, source_path) == 0) {
                    represented = true;
                    break;
                }
            }
            if (!represented) {
                result.status = PreparedConfigRepresentabilityStatus::
                    ChangedSourceNotTemplate;
                result.area = assessment.area;
                const size_t source_size = strlen(source_path);
                if (source_size <= kMaximumConfigPathBytes) {
                    memcpy(result.path, source_path, source_size + 1U);
                }
                return result;
            }
        }
    }

    result.status = PreparedConfigRepresentabilityStatus::Ok;
    return result;
}

namespace {

const char *RepresentabilityAreaName(ConfigArea area)
{
    switch (area) {
    case ConfigArea::Machines: return "machines";
    case ConfigArea::ConfigManagedBlock: return "config.txt managed block";
    case ConfigArea::CmdlineManagedKeys: return "cmdline machine/video keys";
    case ConfigArea::Network: return "network keys";
    case ConfigArea::Settings: return "settings";
    case ConfigArea::UpdateState: return "update state";
    case ConfigArea::Unknown: break;
    }
    return "configuration";
}

}  // namespace

bool FormatPreparedConfigRepresentabilityFailure(
    const PreparedConfigRepresentabilityResult &result, char *output,
    size_t output_size)
{
    if (output == 0 || output_size == 0U || result.representable()) {
        if (output != 0 && output_size != 0U) output[0] = '\0';
        return false;
    }
    output[0] = '\0';
    size_t path_size = 0U;
    const char *safe_path = "unknown";
    if (BoundedLength(result.path, kMaximumConfigPathBytes, &path_size) &&
        path_size != 0U &&
        ValidateFatRelativePath(result.path, kMaximumConfigPathBytes) ==
            FatPathValidationStatus::Ok) {
        safe_path = result.path;
    }
    int written = -1;
    switch (result.status) {
    case PreparedConfigRepresentabilityStatus::InvalidInput:
        written = snprintf(output, output_size,
                           "configuration representability input is invalid");
        break;
    case PreparedConfigRepresentabilityStatus::UnsupportedTemplatePath:
        written = snprintf(output, output_size,
                           "signed ConfigTemplate path is unsupported: %s",
                           safe_path);
        break;
    case PreparedConfigRepresentabilityStatus::RequiredTemplateMissing:
        written = snprintf(output, output_size,
                           "signed release lacks required ConfigTemplate: %s",
                           safe_path);
        break;
    case PreparedConfigRepresentabilityStatus::ChangedAreaSourceMissing:
        written = snprintf(
            output, output_size,
            "%s migration has no representable local source (values hidden)",
            RepresentabilityAreaName(result.area));
        break;
    case PreparedConfigRepresentabilityStatus::ChangedSourceNotTemplate:
        written = snprintf(
            output, output_size,
            "signed ConfigTemplate coverage is incomplete for %s (values hidden)",
            RepresentabilityAreaName(result.area));
        break;
    case PreparedConfigRepresentabilityStatus::SharedCmdlineNetworkTransform:
        written = snprintf(
            output, output_size,
            "cmdline machine/video and network migrations cannot be composed safely");
        break;
    case PreparedConfigRepresentabilityStatus::Ok:
        return false;
    }
    if (written < 0 || static_cast<size_t>(written) >= output_size) {
        output[0] = '\0';
        return false;
    }
    return true;
}

const char *PreparedConfigRepresentabilityStatusString(
    PreparedConfigRepresentabilityStatus status)
{
    switch (status) {
    case PreparedConfigRepresentabilityStatus::Ok: return "ok";
    case PreparedConfigRepresentabilityStatus::InvalidInput:
        return "invalid representability input";
    case PreparedConfigRepresentabilityStatus::UnsupportedTemplatePath:
        return "unsupported ConfigTemplate path";
    case PreparedConfigRepresentabilityStatus::RequiredTemplateMissing:
        return "required ConfigTemplate missing";
    case PreparedConfigRepresentabilityStatus::ChangedAreaSourceMissing:
        return "changed configuration source missing";
    case PreparedConfigRepresentabilityStatus::ChangedSourceNotTemplate:
        return "changed configuration is not a ConfigTemplate";
    case PreparedConfigRepresentabilityStatus::SharedCmdlineNetworkTransform:
        return "cmdline and network transforms conflict";
    }
    return "unknown representability status";
}

FatFsPreparedConfigProvider::PreparedFileSource::PreparedFileSource()
    : file_system_(0), path_(), expected_size_(0U), configured_(false)
{
}

void FatFsPreparedConfigProvider::PreparedFileSource::Configure(
    UpdateFileSystem *file_system, const char *path, uint64_t expected_size)
{
    Reset();
    size_t path_size = 0U;
    if (file_system == 0 ||
        !BoundedLength(path, sizeof(path_) - 1U, &path_size) ||
        path_size == 0U ||
        ValidateFatRelativePath(path, sizeof(path_) - 1U) !=
            FatPathValidationStatus::Ok) {
        return;
    }
    file_system_ = file_system;
    memcpy(path_, path, path_size + 1U);
    expected_size_ = expected_size;
    configured_ = true;
}

void FatFsPreparedConfigProvider::PreparedFileSource::Reset()
{
    file_system_ = 0;
    memset(path_, 0, sizeof(path_));
    expected_size_ = 0U;
    configured_ = false;
}

bool FatFsPreparedConfigProvider::PreparedFileSource::GetSize(uint64_t *size)
{
    if (!configured_ || size == 0) return false;
    UpdateFileStat stat;
    if (!file_system_->Stat(path_, &stat) ||
        stat.type != UpdateNodeType::RegularFile ||
        stat.size != expected_size_) {
        return false;
    }
    *size = expected_size_;
    return true;
}

bool FatFsPreparedConfigProvider::PreparedFileSource::ReadAt(
    uint64_t offset, uint8_t *destination, size_t size)
{
    if (!configured_ || (destination == 0 && size != 0U) ||
        offset > expected_size_ || size > expected_size_ - offset) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system_->OpenRead(path_, &file) || file == 0) return false;
    uint64_t actual_size = 0U;
    bool ok = file->GetSize(&actual_size) && actual_size == expected_size_ &&
              file->ReadAt(offset, destination, size);
    const bool closed = file->Close();
    UpdateFileStat after;
    return ok && closed && file_system_->Stat(path_, &after) &&
           after.type == UpdateNodeType::RegularFile &&
           after.size == expected_size_;
}

FatFsPreparedConfigProvider::FatFsPreparedConfigProvider(
    FatFsUpdateFileSystem *file_system, const InstallerWorkspace &workspace,
    const char *volume)
    : file_system_(file_system), workspace_(workspace), volume_(),
      configured_(false), active_(false), active_binding_sha256_(),
      active_root_(), entry_paths_(), sources_(), entries_(), set_(),
      snapshot_(),
      last_snapshot_status_(FatFsConfigSnapshotStatus::InvalidArgument),
      last_assessment_status_(ConfigAssessmentStatus::InvalidInput),
      last_change_status_(ConfigChangeStatus::InvalidInput),
      last_selector_status_(KernelSelectorStatus::InvalidArgument),
      last_zip_status_(ZipStatus::InvalidArgument),
      last_representability_()
{
    memset(&last_representability_, 0, sizeof(last_representability_));
    last_representability_.status =
        PreparedConfigRepresentabilityStatus::InvalidInput;
    last_representability_.area = ConfigArea::Unknown;
    size_t volume_size = 0U;
    if (file_system_ != 0 && BoundedLength(volume, 17U, &volume_size) &&
        volume_size >= 2U) {
        if (volume[volume_size - 1U] == '/') --volume_size;
        if (volume_size >= 2U && volume[volume_size - 1U] == ':' &&
            volume_size + 1U < sizeof(volume_)) {
            bool valid = true;
            for (size_t index = 0U; index + 1U < volume_size; ++index) {
                const char value = volume[index];
                if (!((value >= 'A' && value <= 'Z') ||
                      (value >= 'a' && value <= 'z') ||
                      (value >= '0' && value <= '9') || value == '_')) {
                    valid = false;
                }
            }
            if (valid) {
                memcpy(volume_, volume, volume_size);
                volume_[volume_size] = '\0';
                char expected_root[20U];
                const int written = snprintf(expected_root,
                                             sizeof(expected_root), "%s/",
                                             volume_);
                configured_ = file_system->configured() && written > 0 &&
                              static_cast<size_t>(written) <
                                  sizeof(expected_root) &&
                              strcmp(file_system->volume_root(),
                                     expected_root) == 0;
            }
        }
    }
    ResetPublishedSet();
}

FatFsPreparedConfigProvider::~FatFsPreparedConfigProvider()
{
    ResetPublishedSet();
}

void FatFsPreparedConfigProvider::ResetPublishedSet()
{
    for (size_t index = 0U;
         index < kFatFsPreparedConfigMaximumTemplates; ++index) {
        sources_[index].Reset();
        memset(&entries_[index], 0, sizeof(entries_[index]));
        memset(entry_paths_[index], 0, sizeof(entry_paths_[index]));
    }
    memset(&set_, 0, sizeof(set_));
}

PreparedConfigProviderStatus FatFsPreparedConfigProvider::PrepareForStage(
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest, SeekableZipSource *authenticated_archive,
    const PreparedConfigSet **prepared,
    UpdateRecoveryProgress *recovery_progress)
{
    if (prepared != 0) *prepared = 0;
    last_snapshot_status_ = FatFsConfigSnapshotStatus::InvalidArgument;
    last_assessment_status_ = ConfigAssessmentStatus::InvalidInput;
    last_change_status_ = ConfigChangeStatus::InvalidInput;
    last_selector_status_ = KernelSelectorStatus::InvalidArgument;
    last_zip_status_ = ZipStatus::InvalidArgument;
    memset(&last_representability_, 0, sizeof(last_representability_));
    last_representability_.status =
        PreparedConfigRepresentabilityStatus::InvalidInput;
    last_representability_.area = ConfigArea::Unknown;
    if (!configured_ || prepared == 0 || authenticated_archive == 0 ||
        active_) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    if (workspace_.io_buffer == 0 ||
        workspace_.io_buffer_size < kMinimumPreparedIoBytes) {
        return PreparedConfigProviderStatus::Unsupported;
    }

    PreparedPaths paths;
    size_t template_count = 0U;
    if (!BuildPreparedPaths(volume_, binding, &paths) ||
        !ValidateManifestBinding(binding, manifest, &template_count)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    TemplateWork templates[kFatFsPreparedConfigMaximumTemplates];
    size_t template_index = 0U;
    for (size_t index = 0U; index < manifest.asset.file_count; ++index) {
        if (manifest.asset.files[index].policy ==
            ManifestFilePolicy::ConfigTemplate) {
            templates[template_index++].manifest_file =
                &manifest.asset.files[index];
        }
    }
    if (template_index != template_count) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }

    ConfigMigrationPlan plan;
    PreparedConfigProviderStatus status = AssessAndBindConfig(
        volume_, binding, manifest, &snapshot_, &plan,
        &last_snapshot_status_, &last_assessment_status_);
    if (status != PreparedConfigProviderStatus::Ok) return status;

    last_representability_ = CheckPreparedConfigRepresentability(
        plan, snapshot_.snapshot(), manifest);
    if (!last_representability_.representable()) {
        return PreparedConfigProviderStatus::Unsupported;
    }

    status = ExtractSignedDefaults(
        binding, manifest, authenticated_archive, workspace_, templates,
        template_count, &last_zip_status_, recovery_progress);
    if (status != PreparedConfigProviderStatus::Ok) return status;
    status = ReadCurrentTemplates(file_system_, plan, templates,
                                  template_count);
    if (status != PreparedConfigProviderStatus::Ok) return status;
    status = ApplyRepresentableChanges(
        plan, snapshot_.snapshot(), templates, template_count,
        &last_change_status_);
    if (status != PreparedConfigProviderStatus::Ok) return status;
    status = PrepareBootTemplates(binding, manifest, templates,
                                  template_count, &last_selector_status_);
    if (status != PreparedConfigProviderStatus::Ok) return status;

    uint8_t prepared_sha256[kFatFsPreparedConfigMaximumTemplates]
                           [kSha256DigestBytes];
    memset(prepared_sha256, 0, sizeof(prepared_sha256));
    for (size_t index = 0U; index < template_count; ++index) {
        if (!Sha256Digest(ByteView(templates[index].prepared.data(),
                                   templates[index].prepared.size()),
                          prepared_sha256[index]) ||
            !BytesNonZero(prepared_sha256[index], kSha256DigestBytes)) {
            return PreparedConfigProviderStatus::IoError;
        }
    }

    // Do not remove a previously recoverable record until every source and
    // transformation has been validated.  From here on failures clean only
    // this exact binding-derived tree.
    if (!CleanupPreparedPaths(file_system_, paths, 0, 0) ||
        !EnsureDirectoryTree(file_system_, paths.root)) {
        return PreparedConfigProviderStatus::IoError;
    }
    for (size_t index = 0U; index < template_count; ++index) {
        char temporary[kFatFsUpdateFileSystemRelativePathBytes];
        char final_path[kFatFsUpdateFileSystemRelativePathBytes];
        if (!ItemPath(paths, index, true, temporary) ||
            !ItemPath(paths, index, false, final_path) ||
            !WriteFreshVerified(
                file_system_, temporary, final_path,
                ByteView(templates[index].prepared.data(),
                         templates[index].prepared.size()),
                prepared_sha256[index], workspace_.io_buffer,
                workspace_.io_buffer_size)) {
            (void)CleanupPreparedPaths(file_system_, paths, 0, 0);
            return PreparedConfigProviderStatus::IoError;
        }
    }

    // Re-read consent and every original ConfigTemplate after the relatively
    // long ZIP/extract/write work.  Evidence is published only if the source
    // still matches exactly.
    ConfigMigrationPlan final_plan;
    status = AssessAndBindConfig(volume_, binding, manifest, &snapshot_,
                                 &final_plan, &last_snapshot_status_,
                                 &last_assessment_status_);
    if (status == PreparedConfigProviderStatus::Ok) {
        status = VerifyCurrentEvidence(file_system_, templates,
                                       template_count);
    }
    if (status != PreparedConfigProviderStatus::Ok) {
        (void)CleanupPreparedPaths(file_system_, paths, 0, 0);
        return status;
    }

    uint8_t evidence[kFatFsPreparedConfigEvidenceBytes];
    uint8_t evidence_file_sha256[kSha256DigestBytes];
    char evidence_temporary[kFatFsUpdateFileSystemRelativePathBytes];
    char evidence_final[kFatFsUpdateFileSystemRelativePathBytes];
    if (!EncodeEvidence(paths, binding, templates, template_count,
                        prepared_sha256, evidence) ||
        !Sha256Digest(ByteView(evidence, sizeof(evidence)),
                      evidence_file_sha256) ||
        !EvidencePath(paths, true, evidence_temporary) ||
        !EvidencePath(paths, false, evidence_final) ||
        !WriteFreshVerified(file_system_, evidence_temporary, evidence_final,
                            ByteView(evidence, sizeof(evidence)),
                            evidence_file_sha256, workspace_.io_buffer,
                            workspace_.io_buffer_size)) {
        (void)CleanupPreparedPaths(file_system_, paths, 0, 0);
        return PreparedConfigProviderStatus::IoError;
    }

    // The evidence write itself can take long enough for removable-media
    // configuration to change.  Repeat both source bindings after its verified
    // publication; a mismatch removes the whole prepared tree before return.
    ConfigMigrationPlan post_evidence_plan;
    status = AssessAndBindConfig(volume_, binding, manifest, &snapshot_,
                                 &post_evidence_plan, &last_snapshot_status_,
                                 &last_assessment_status_);
    if (status == PreparedConfigProviderStatus::Ok) {
        status = VerifyCurrentEvidence(file_system_, templates,
                                       template_count);
    }
    bool archive_progress_failed = false;
    if (status == PreparedConfigProviderStatus::Ok &&
        !HashArchive(authenticated_archive, binding.archive_size,
                     binding.archive_sha256, workspace_.io_buffer,
                     workspace_.io_buffer_size, recovery_progress,
                     UpdateRecoveryProgressKind::PreparedArchiveFinalHashed,
                     &archive_progress_failed)) {
        status = archive_progress_failed
            ? PreparedConfigProviderStatus::RecoveryProgressFailed
            : PreparedConfigProviderStatus::SourceChanged;
    }
    if (status != PreparedConfigProviderStatus::Ok) {
        (void)CleanupPreparedPaths(file_system_, paths, 0, 0);
        return status;
    }

    ResetPublishedSet();
    for (size_t index = 0U; index < template_count; ++index) {
        const char *manifest_path = templates[index].manifest_file->path;
        memcpy(entry_paths_[index], manifest_path, strlen(manifest_path) + 1U);
        entries_[index].path = entry_paths_[index];
        entries_[index].original_existed = templates[index].original_existed;
        entries_[index].original_size = templates[index].original_size;
        memcpy(entries_[index].original_sha256,
               templates[index].original_sha256, kSha256DigestBytes);
        entries_[index].prepared_size = templates[index].prepared.size();
        memcpy(entries_[index].prepared_sha256, prepared_sha256[index],
               kSha256DigestBytes);
        char item[kFatFsUpdateFileSystemRelativePathBytes];
        if (!ItemPath(paths, index, false, item)) {
            (void)CleanupPreparedPaths(file_system_, paths, 0, 0);
            ResetPublishedSet();
            return PreparedConfigProviderStatus::IoError;
        }
        sources_[index].Configure(file_system_, item,
                                  entries_[index].prepared_size);
        entries_[index].content = &sources_[index];
    }
    set_.entries = entries_;
    set_.entry_count = template_count;
    memcpy(set_.manifest_sha256, binding.manifest_sha256,
           kSha256DigestBytes);
    memcpy(set_.consent_sha256, binding.consent_sha256,
           kSha256DigestBytes);
    set_.reset_required = binding.reset_required;
    set_.reset_approved = binding.reset_approved;
    memcpy(active_binding_sha256_, paths.binding_sha256, kSha256DigestBytes);
    memcpy(active_root_, paths.root, strlen(paths.root) + 1U);
    active_ = true;
    *prepared = &set_;
    return PreparedConfigProviderStatus::Ok;
}

PreparedConfigProviderStatus FatFsPreparedConfigProvider::RestoreForResume(
    const AuthenticatedUpdateBinding &binding,
    const ReleaseManifest &manifest, const PreparedConfigSet **prepared,
    UpdateRecoveryProgress *recovery_progress)
{
    if (prepared != 0) *prepared = 0;
    if (!configured_ || prepared == 0 || active_) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    if (workspace_.io_buffer == 0 ||
        workspace_.io_buffer_size < kMinimumPreparedIoBytes) {
        return PreparedConfigProviderStatus::Unsupported;
    }
    PreparedPaths paths;
    size_t template_count = 0U;
    if (!BuildPreparedPaths(volume_, binding, &paths) ||
        !ValidateManifestBinding(binding, manifest, &template_count)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    char evidence_path[kFatFsUpdateFileSystemRelativePathBytes];
    if (!EvidencePath(paths, false, evidence_path)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    uint8_t evidence[kFatFsPreparedConfigEvidenceBytes];
    bool progress_failed = false;
    if (!ReadWholeFile(file_system_, evidence_path, evidence,
                       sizeof(evidence), recovery_progress,
                       &progress_failed)) {
        return progress_failed
            ? PreparedConfigProviderStatus::RecoveryProgressFailed
            : PreparedConfigProviderStatus::IoError;
    }
    ResetPublishedSet();
    if (!ParseEvidence(evidence, paths, binding, manifest, template_count,
                       entries_)) {
        ResetPublishedSet();
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    for (size_t index = 0U; index < template_count; ++index) {
        const ManifestFile *manifest_file = NthTemplate(manifest, index);
        if (manifest_file == 0) {
            ResetPublishedSet();
            return PreparedConfigProviderStatus::InvalidBinding;
        }
        memcpy(entry_paths_[index], manifest_file->path,
               strlen(manifest_file->path) + 1U);
        entries_[index].path = entry_paths_[index];
        entries_[index].content = 0;
        char item[kFatFsUpdateFileSystemRelativePathBytes];
        if (!ItemPath(paths, index, false, item) ||
            !FileMatches(file_system_, item, entries_[index].prepared_size,
                         entries_[index].prepared_sha256,
                         workspace_.io_buffer, workspace_.io_buffer_size,
                         recovery_progress, &progress_failed)) {
            ResetPublishedSet();
            return progress_failed
                ? PreparedConfigProviderStatus::RecoveryProgressFailed
                : PreparedConfigProviderStatus::SourceChanged;
        }
    }
    set_.entries = entries_;
    set_.entry_count = template_count;
    memcpy(set_.manifest_sha256, binding.manifest_sha256,
           kSha256DigestBytes);
    memcpy(set_.consent_sha256, binding.consent_sha256,
           kSha256DigestBytes);
    set_.reset_required = binding.reset_required;
    set_.reset_approved = binding.reset_approved;
    memcpy(active_binding_sha256_, paths.binding_sha256, kSha256DigestBytes);
    memcpy(active_root_, paths.root, strlen(paths.root) + 1U);
    active_ = true;
    *prepared = &set_;
    return PreparedConfigProviderStatus::Ok;
}

PreparedConfigProviderStatus FatFsPreparedConfigProvider::Discard(
    const AuthenticatedUpdateBinding &binding,
    UpdateRecoveryProgress *recovery_progress)
{
    if (!configured_) return PreparedConfigProviderStatus::InvalidBinding;
    PreparedPaths paths;
    if (!BuildPreparedPaths(volume_, binding, &paths)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    if (active_ &&
        (!ConstantTimeDigestEqual(active_binding_sha256_,
                                  paths.binding_sha256) ||
         strcmp(active_root_, paths.root) != 0)) {
        return PreparedConfigProviderStatus::InvalidBinding;
    }
    bool progress_failed = false;
    if (!CleanupPreparedPaths(file_system_, paths, recovery_progress,
                              &progress_failed)) {
        return progress_failed
            ? PreparedConfigProviderStatus::RecoveryProgressFailed
            : PreparedConfigProviderStatus::IoError;
    }
    ResetPublishedSet();
    memset(active_binding_sha256_, 0, sizeof(active_binding_sha256_));
    memset(active_root_, 0, sizeof(active_root_));
    active_ = false;
    return PreparedConfigProviderStatus::Ok;
}

const char *PreparedConfigProviderStatusString(
    PreparedConfigProviderStatus status)
{
    switch (status) {
    case PreparedConfigProviderStatus::Ok: return "ok";
    case PreparedConfigProviderStatus::InvalidBinding:
        return "invalid prepared-config binding";
    case PreparedConfigProviderStatus::SourceChanged:
        return "configuration or archive source changed";
    case PreparedConfigProviderStatus::IoError:
        return "prepared-config I/O failed";
    case PreparedConfigProviderStatus::Unsupported:
        return "configuration transformation unsupported";
    case PreparedConfigProviderStatus::RecoveryProgressFailed:
        return "recovery progress failed";
    }
    return "unknown prepared-config error";
}

}  // namespace update
}  // namespace bmx
