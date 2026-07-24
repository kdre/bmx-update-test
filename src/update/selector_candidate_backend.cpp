#include "update/selector_candidate_backend.h"

#include "update/tryboot_control.h"
#include "update/generated/update_path_policy_v1.h"
#include "update/sha256.h"
#include "update/update_fault_injection.h"
#include "update/update_hardware_test_mode.h"

#include <stdio.h>
#include <string.h>

namespace bmx {
namespace update {

namespace {

namespace path_policy = generated_path_policy_v1;

static_assert(path_policy::kMachineKernelBaseCount == 2U,
              "selector backend requires pi4 and pi5 kernel bases");

bool IsMachine(const char *machine)
{
    if (machine == 0) return false;
    for (size_t index = 0U;
         index < path_policy::kRequiredKernelMachineCount; ++index) {
        if (strcmp(machine, path_policy::kMachineKernelMachines[index]) == 0) {
            return true;
        }
    }
    return false;
}

const char *KernelBase(BoardFamily board)
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

bool SafeSelectorPath(const char *path)
{
    if (path == 0) return false;
    const size_t size = strlen(path);
    if (size == 0U || size >= kInstallerMaximumPathBytes || path[0] == '/' ||
        path[size - 1U] == '/') return false;
    size_t component = 0U;
    for (size_t index = 0U; index <= size; ++index) {
        if (index != size && path[index] != '/') {
            const unsigned char value =
                static_cast<unsigned char>(path[index]);
            if (value < 0x21U || value > 0x7eU || value == '\\' ||
                value == ':') return false;
            continue;
        }
        const size_t component_size = index - component;
        if (component_size == 0U ||
            (component_size == 1U && path[component] == '.') ||
            (component_size == 2U && path[component] == '.' &&
             path[component + 1U] == '.')) return false;
        component = index + 1U;
    }
    return true;
}

bool ReadSmallFile(UpdateFileSystem *file_system, const char *path,
                   uint8_t *bytes, size_t capacity, size_t *size)
{
    if (file_system == 0 || path == 0 || bytes == 0 || size == 0) {
        return false;
    }
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile || stat.size == 0U ||
        stat.size > capacity) return false;
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    const size_t amount = static_cast<size_t>(stat.size);
    const bool read = file->ReadAt(0U, bytes, amount);
    const bool closed = file->Close();
    if (!read || !closed) return false;
    *size = amount;
    return true;
}

bool AddSuffix(const char *path, const char *suffix, char *output,
               size_t output_size)
{
    if (path == 0 || suffix == 0 || output == 0 || output_size == 0U) {
        return false;
    }
    const int written = snprintf(output, output_size, "%s%s", path, suffix);
    return written > 0 && static_cast<size_t>(written) < output_size;
}

bool JoinPath(const char *left, const char *right, char *output,
              size_t output_size)
{
    if (left == 0 || right == 0 || output == 0 || output_size == 0U) {
        return false;
    }
    const int written = snprintf(output, output_size, "%s/%s", left, right);
    return written > 0 && static_cast<size_t>(written) < output_size;
}

bool VerifyFileDigest(UpdateFileSystem *file_system, const char *path,
                      const ManifestFile &expected)
{
    UpdateFileStat stat;
    if (!file_system->Stat(path, &stat) ||
        stat.type != UpdateNodeType::RegularFile || stat.size != expected.size) {
        return false;
    }
    UpdateReadFile *file = 0;
    if (!file_system->OpenRead(path, &file) || file == 0) return false;
    uint8_t buffer[4096U];
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < stat.size) {
        const size_t amount = static_cast<size_t>(
            stat.size - offset > sizeof(buffer) ? sizeof(buffer)
                                                : stat.size - offset);
        if (!file->ReadAt(offset, buffer, amount) ||
            !hash.Update(buffer, amount)) {
            ok = false;
            break;
        }
        offset += amount;
    }
    uint8_t digest[kSha256DigestBytes];
    ok = file->Close() && ok && hash.Final(digest) &&
         ConstantTimeDigestEqual(digest, expected.sha256);
    return ok;
}

bool CopyAndVerify(UpdateFileSystem *file_system, const char *source,
                   const char *target, const ManifestFile &expected)
{
    UpdateFileStat source_stat;
    if (!file_system->Stat(source, &source_stat) ||
        source_stat.type != UpdateNodeType::RegularFile ||
        source_stat.size != expected.size || !file_system->RemoveFile(target)) {
        return false;
    }
    UpdateReadFile *input = 0;
    UpdateWriteFile *output = 0;
    if (!file_system->OpenRead(source, &input) || input == 0 ||
        !file_system->CreateFileFresh(target, &output) || output == 0) {
        if (input != 0) input->Close();
        return false;
    }
    uint8_t buffer[4096U];
    Sha256 hash;
    uint64_t offset = 0U;
    bool ok = true;
    while (offset < source_stat.size) {
        const size_t amount = static_cast<size_t>(
            source_stat.size - offset > sizeof(buffer) ? sizeof(buffer)
                                                       : source_stat.size - offset);
        if (!input->ReadAt(offset, buffer, amount) ||
            !output->Write(ByteView(buffer, amount)) ||
            !hash.Update(buffer, amount)) {
            ok = false;
            break;
        }
        offset += amount;
    }
    uint8_t digest[kSha256DigestBytes];
    ok = input->Close() && ok && hash.Final(digest) &&
         ConstantTimeDigestEqual(digest, expected.sha256) && output->Sync() &&
         output->Close() && file_system->SyncContainingDirectory(target);
    if (!ok) {
        output->Close();
        file_system->RemoveFile(target);
    }
    return ok;
}

}  // namespace

SelectorCandidatePlatformReadiness
ProductionSelectorCandidatePlatformReadiness()
{
    SelectorCandidatePlatformReadiness readiness;
    memset(&readiness, 0, sizeof(readiness));
    readiness.one_shot_boot_validated = TrybootHardwareGateEnabled();
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_SELECTOR)
    readiness.fallback_kernel_validated = true;
    readiness.selector_replace_validated = true;
#endif
    return readiness;
}

KernelSelectorStatus ParseKernelSelector(ByteView bytes, BoardFamily board,
                                         ParsedKernelSelector *selector)
{
    if (selector == 0 || (bytes.data == 0 && bytes.size != 0U) ||
        bytes.size == 0U || bytes.size >= kMaximumKernelSelectorBytes) {
        return KernelSelectorStatus::InvalidArgument;
    }
    const char *base = KernelBase(board);
    if (base == 0) return KernelSelectorStatus::BoardMismatch;
    static const char header[] = "# BMX-KERNEL-SELECTOR-V2\n";
    static const char directive[] = "kernel=";
    const size_t header_size = sizeof(header) - 1U;
    const size_t directive_size = sizeof(directive) - 1U;
    const size_t base_size = strlen(base);
    if (bytes.size < header_size + directive_size + base_size + 2U ||
        memcmp(bytes.data, header, header_size) != 0 ||
        memcmp(bytes.data + header_size, directive, directive_size) != 0 ||
        bytes.data[bytes.size - 1U] != '\n') {
        return KernelSelectorStatus::InvalidFormat;
    }
    for (size_t index = header_size; index + 1U < bytes.size; ++index) {
        const uint8_t value = bytes.data[index];
        if (value < 0x21U || value > 0x7eU || value == '\\' ||
            value == ':' || value == '/') {
            return KernelSelectorStatus::InvalidFormat;
        }
    }
    const size_t path_size = bytes.size - header_size - directive_size - 1U;
    if (path_size == 0U || path_size >= sizeof(selector->kernel_path)) {
        return KernelSelectorStatus::InvalidFormat;
    }
    memcpy(selector->kernel_path,
           bytes.data + header_size + directive_size, path_size);
    selector->kernel_path[path_size] = '\0';
    if (strncmp(selector->kernel_path, base, base_size) != 0 ||
        selector->kernel_path[base_size] != '.') {
        return KernelSelectorStatus::BoardMismatch;
    }
    const char *suffix = selector->kernel_path + base_size + 1U;
    static const char candidate_suffix[] = ".bmx-next";
    size_t suffix_size = strlen(suffix);
    const size_t candidate_size = sizeof(candidate_suffix) - 1U;
    selector->candidate = suffix_size > candidate_size &&
        strcmp(suffix + suffix_size - candidate_size, candidate_suffix) == 0;
    const size_t machine_size = selector->candidate
        ? suffix_size - candidate_size : suffix_size;
    if (machine_size == 0U || machine_size >= sizeof(selector->machine) ||
        memchr(suffix, '.', machine_size) != 0) {
        return KernelSelectorStatus::InvalidFormat;
    }
    memcpy(selector->machine, suffix, machine_size);
    selector->machine[machine_size] = '\0';
    if (!IsMachine(selector->machine)) {
        return KernelSelectorStatus::InvalidFormat;
    }
    const int stable_size = snprintf(
        selector->manifest_kernel_path, sizeof(selector->manifest_kernel_path),
        "%s.%s", base, selector->machine);
    if (stable_size <= 0 ||
        static_cast<size_t>(stable_size) >= sizeof(selector->manifest_kernel_path)) {
        return KernelSelectorStatus::InvalidFormat;
    }
    return KernelSelectorStatus::Ok;
}

KernelSelectorStatus ValidateKernelSelectorAgainstAsset(
    const ParsedKernelSelector &selector, const ManifestAsset &asset,
    uint64_t expected_release_sequence)
{
    if (!IsKnownBoardFamily(asset.board) || expected_release_sequence == 0U) {
        return KernelSelectorStatus::InvalidArgument;
    }
    size_t matches = 0U;
    for (size_t index = 0U; index < asset.file_count; ++index) {
        const ManifestFile &file = asset.files[index];
        if (file.policy == ManifestFilePolicy::Kernel &&
            strcmp(file.path, selector.manifest_kernel_path) == 0) {
            ++matches;
        }
    }
    return matches == 1U ? KernelSelectorStatus::Ok
                         : KernelSelectorStatus::ManifestMismatch;
}

SelectorCandidateBackend::SelectorCandidateBackend(
    UpdateFileSystem *file_system,
    const SelectorCandidatePlatformReadiness &platform,
    const char *active_selector, const char *candidate_selector)
    : file_system_(file_system), platform_(platform),
      active_selector_(active_selector), candidate_selector_(candidate_selector),
      last_status_(KernelSelectorStatus::InvalidArgument)
{
    memset(io_buffer_, 0, sizeof(io_buffer_));
}

bool SelectorCandidateBackend::PathsValid() const
{
    return SafeSelectorPath(active_selector_) &&
           SafeSelectorPath(candidate_selector_) &&
           strcmp(active_selector_, candidate_selector_) != 0;
}

bool SelectorCandidateBackend::Supported() const
{
    if (file_system_ == 0 || !PathsValid() ||
        !platform_.one_shot_boot_validated ||
        !platform_.fallback_kernel_validated ||
        !platform_.selector_replace_validated) return false;
    UpdateDurabilityCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    return file_system_->GetDurabilityCapabilities(&capabilities) &&
           capabilities.durable_file_sync &&
           (capabilities.crash_safe_fresh_rename ||
            capabilities.power_loss_recovery_validated) &&
           (capabilities.crash_safe_replace_with_backup ||
            capabilities.power_loss_recovery_validated) &&
           capabilities.durable_directory_updates;
}

bool SelectorCandidateBackend::ReadAndValidate(
    const char *path, const CandidateContext &context,
    uint64_t expected_sequence, ParsedKernelSelector *selector)
{
    if (context.asset == 0 || context.asset->board != context.board ||
        selector == 0) {
        last_status_ = KernelSelectorStatus::InvalidArgument;
        return false;
    }
    size_t size = 0U;
    if (!ReadSmallFile(file_system_, path, io_buffer_, sizeof(io_buffer_),
                       &size)) {
        last_status_ = KernelSelectorStatus::FileSystemError;
        return false;
    }
    last_status_ = ParseKernelSelector(ByteView(io_buffer_, size),
                                       context.board, selector);
    if (last_status_ != KernelSelectorStatus::Ok) return false;
    // The target manifest intentionally contains only target files. The
    // source selector is bound by the installed build identity and its local
    // health verification; the candidate must additionally occur exactly
    // once in the freshly authenticated target asset.
    last_status_ = expected_sequence == context.target_release_sequence
        ? ValidateKernelSelectorAgainstAsset(*selector, *context.asset,
                                             expected_sequence)
        : KernelSelectorStatus::Ok;
    return last_status_ == KernelSelectorStatus::Ok;
}

bool SelectorCandidateBackend::ArmCandidate(const CandidateContext &context)
{
    if (!Supported()) {
        last_status_ = KernelSelectorStatus::PlatformGateClosed;
        return false;
    }
    ParsedKernelSelector active;
    if (!ReadAndValidate(active_selector_, context,
                         context.source_release_sequence, &active) ||
        active.candidate) {
        return false;
    }
    char candidate_path[kMaximumKernelSelectorBytes];
    bool temporary = false;
    if (!PrepareCandidateKernel(context, active, candidate_path,
                                sizeof(candidate_path), &temporary) ||
        !PublishSelector(candidate_selector_, candidate_path)) {
        if (temporary) file_system_->RemoveFile(candidate_path);
        last_status_ = KernelSelectorStatus::FileSystemError;
        return false;
    }
    ParsedKernelSelector candidate;
    if (!ReadAndValidate(candidate_selector_, context,
                         context.target_release_sequence, &candidate) ||
        strcmp(active.machine, candidate.machine) != 0) return false;
    last_status_ = KernelSelectorStatus::Ok;
    return true;
}

bool SelectorCandidateBackend::SelectorsEqual(const char *left,
                                               const char *right,
                                               bool *equal)
{
    if (equal == 0) return false;
    uint8_t left_bytes[kMaximumKernelSelectorBytes];
    uint8_t right_bytes[kMaximumKernelSelectorBytes];
    size_t left_size = 0U;
    size_t right_size = 0U;
    if (!ReadSmallFile(file_system_, left, left_bytes, sizeof(left_bytes),
                       &left_size) ||
        !ReadSmallFile(file_system_, right, right_bytes, sizeof(right_bytes),
                       &right_size)) return false;
    *equal = left_size == right_size &&
             memcmp(left_bytes, right_bytes, left_size) == 0;
    return true;
}

bool SelectorCandidateBackend::ReplaceActiveFromCandidate()
{
    bool equal = false;
    if (SelectorsEqual(active_selector_, candidate_selector_, &equal) && equal) {
        return true;
    }
    uint8_t candidate[kMaximumKernelSelectorBytes];
    size_t candidate_size = 0U;
    if (!ReadSmallFile(file_system_, candidate_selector_, candidate,
                       sizeof(candidate), &candidate_size)) return false;
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (!AddSuffix(active_selector_, ".next", temporary, sizeof(temporary)) ||
        !file_system_->RemoveFile(temporary)) return false;
    UpdateWriteFile *file = 0;
    if (!file_system_->CreateFileFresh(temporary, &file) || file == 0) {
        return false;
    }
    const bool wrote = file->Write(ByteView(candidate, candidate_size));
    bool synced = false;
    if (wrote) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::SelectorBeforeTemporaryFileSync);
        synced = file->Sync();
        if (synced) {
            BMX_UPDATE_FAULT_CHECKPOINT(
                UpdateFaultPoint::SelectorAfterTemporaryFileSync);
        }
    }
    const bool closed = file->Close();
    bool published = false;
    if (wrote && synced && closed) {
        BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::SelectorBeforePublish);
        published = file_system_->Rename(temporary, active_selector_, true);
        if (published) {
            BMX_UPDATE_FAULT_CHECKPOINT(UpdateFaultPoint::SelectorAfterPublish);
        }
    }
    const bool directory_synced = published &&
        file_system_->SyncContainingDirectory(active_selector_);
    if (directory_synced) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::SelectorAfterDirectorySync);
    }
    if (!wrote || !synced || !closed || !published || !directory_synced) {
        file_system_->RemoveFile(temporary);
        return false;
    }
    const bool validated =
        SelectorsEqual(active_selector_, candidate_selector_, &equal) && equal;
    if (validated) {
        BMX_UPDATE_FAULT_CHECKPOINT(
            UpdateFaultPoint::SelectorAfterValidatedReadback);
    }
    return validated;
}

bool SelectorCandidateBackend::PublishSelector(const char *path,
                                                const char *kernel_path)
{
    if (!SafeSelectorPath(path) || !SafeSelectorPath(kernel_path) ||
        strchr(kernel_path, '/') != 0) return false;
    char content[kMaximumKernelSelectorBytes];
    const int content_size = snprintf(
        content, sizeof(content),
        "# BMX-KERNEL-SELECTOR-V2\nkernel=%s\n", kernel_path);
    char temporary[kInstallerMaximumPathBytes + 1U];
    if (content_size <= 0 ||
        static_cast<size_t>(content_size) >= sizeof(content) ||
        !AddSuffix(path, ".next", temporary, sizeof(temporary)) ||
        !file_system_->RemoveFile(temporary)) return false;
    UpdateWriteFile *file = 0;
    if (!file_system_->CreateFileFresh(temporary, &file) || file == 0) {
        return false;
    }
    const bool wrote = file->Write(ByteView(
        reinterpret_cast<const uint8_t *>(content),
        static_cast<size_t>(content_size)));
    const bool synced = wrote && file->Sync();
    const bool closed = file->Close();
    const bool published = wrote && synced && closed &&
        file_system_->Rename(temporary, path, true) &&
        file_system_->SyncContainingDirectory(path);
    if (!published) file_system_->RemoveFile(temporary);
    return published;
}

bool SelectorCandidateBackend::PrepareCandidateKernel(
    const CandidateContext &context, const ParsedKernelSelector &active,
    char *candidate_path, size_t capacity, bool *temporary)
{
    if (context.asset == 0 || context.staging_root == 0 ||
        candidate_path == 0 || temporary == 0 || active.candidate) return false;
    const ManifestFile *kernel = 0;
    for (size_t index = 0U; index < context.asset->file_count; ++index) {
        const ManifestFile &file = context.asset->files[index];
        if (file.policy == ManifestFilePolicy::Kernel &&
            strcmp(file.path, active.manifest_kernel_path) == 0) {
            if (kernel != 0) return false;
            kernel = &file;
        }
    }
    if (kernel == 0) return false;
    char staged[kInstallerMaximumPathBytes + 1U];
    if (!JoinPath(context.staging_root, kernel->path, staged, sizeof(staged))) {
        return false;
    }
    UpdateFileStat staged_stat;
    if (!file_system_->Stat(staged, &staged_stat)) return false;
    if (staged_stat.type == UpdateNodeType::Missing) {
        if (!VerifyFileDigest(file_system_, kernel->path, *kernel) ||
            strlen(kernel->path) >= capacity) return false;
        memcpy(candidate_path, kernel->path, strlen(kernel->path) + 1U);
        *temporary = false;
        return true;
    }
    if (staged_stat.type != UpdateNodeType::RegularFile ||
        !AddSuffix(kernel->path, ".bmx-next", candidate_path, capacity) ||
        !CopyAndVerify(file_system_, staged, candidate_path, *kernel)) {
        return false;
    }
    *temporary = true;
    return true;
}

bool SelectorCandidateBackend::RemoveCandidateKernel(
    const ParsedKernelSelector &selector)
{
    return !selector.candidate ||
        (file_system_->RemoveFile(selector.kernel_path) &&
         file_system_->SyncContainingDirectory(selector.kernel_path));
}

bool SelectorCandidateBackend::CommitCandidate(
    const CandidateContext &context)
{
    if (!Supported()) {
        last_status_ = KernelSelectorStatus::PlatformGateClosed;
        return false;
    }
    ParsedKernelSelector candidate;
    if (!ReadAndValidate(candidate_selector_, context,
                         context.target_release_sequence, &candidate)) {
        return false;
    }
    if (!PublishSelector(active_selector_, candidate.manifest_kernel_path) ||
        !PublishSelector(candidate_selector_, candidate.manifest_kernel_path) ||
        !RemoveCandidateKernel(candidate)) {
        last_status_ = KernelSelectorStatus::FileSystemError;
        return false;
    }
    ParsedKernelSelector committed;
    if (!ReadAndValidate(active_selector_, context,
                         context.target_release_sequence, &committed) ||
        committed.candidate ||
        strcmp(committed.kernel_path, candidate.manifest_kernel_path) != 0) {
        if (last_status_ == KernelSelectorStatus::Ok) {
            last_status_ = KernelSelectorStatus::FileSystemError;
        }
        return false;
    }
    last_status_ = KernelSelectorStatus::Ok;
    return true;
}

bool SelectorCandidateBackend::DisarmCandidate(
    const CandidateContext &context)
{
    if (!Supported()) {
        last_status_ = KernelSelectorStatus::PlatformGateClosed;
        return false;
    }
    // The firmware tryboot flag is one-shot and is controlled by the reboot
    // adapter. The installer restores the snapshotted selector after this
    // call. Here we only prove that the rollback context still refers to a
    // signed source or candidate selector; no guessed filesystem state is
    // activated.
    ParsedKernelSelector active;
    if (!ReadAndValidate(active_selector_, context,
                         context.source_release_sequence, &active) ||
        active.candidate) return false;
    ParsedKernelSelector candidate;
    size_t ignored = 0U;
    if (ReadSmallFile(file_system_, candidate_selector_, io_buffer_,
                      sizeof(io_buffer_), &ignored) &&
        ParseKernelSelector(ByteView(io_buffer_, ignored), context.board,
                            &candidate) == KernelSelectorStatus::Ok &&
        !RemoveCandidateKernel(candidate)) return false;
    if (!PublishSelector(candidate_selector_, active.kernel_path)) return false;
    last_status_ = KernelSelectorStatus::Ok;
    return true;
}

const char *KernelSelectorStatusString(KernelSelectorStatus status)
{
    switch (status) {
    case KernelSelectorStatus::Ok: return "ok";
    case KernelSelectorStatus::InvalidArgument: return "invalid argument";
    case KernelSelectorStatus::InvalidFormat: return "invalid selector format";
    case KernelSelectorStatus::BoardMismatch: return "selector board mismatch";
    case KernelSelectorStatus::SequenceMismatch:
        return "selector release sequence mismatch";
    case KernelSelectorStatus::ManifestMismatch:
        return "selector is not bound to the signed manifest";
    case KernelSelectorStatus::FileSystemError: return "selector filesystem error";
    case KernelSelectorStatus::DurabilityUnsupported:
        return "selector durability unsupported";
    case KernelSelectorStatus::PlatformGateClosed:
        return "selector hardware validation gate closed";
    }
    return "unknown selector error";
}

}  // namespace update
}  // namespace bmx
