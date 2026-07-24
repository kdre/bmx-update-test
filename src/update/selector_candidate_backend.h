#ifndef BMX_UPDATE_SELECTOR_CANDIDATE_BACKEND_H
#define BMX_UPDATE_SELECTOR_CANDIDATE_BACKEND_H

#include "update/update_installer.h"

namespace bmx {
namespace update {

static const size_t kMaximumKernelSelectorBytes = 128U;

struct SelectorCandidatePlatformReadiness {
    // These are evidence gates, not user/build preferences. Production may
    // set them only after the documented board and power-cut matrices pass.
    bool one_shot_boot_validated;
    bool fallback_kernel_validated;
    bool selector_replace_validated;
};

// Production evidence gates. They remain false unless the corresponding
// Pi4/Pi400/Pi5/Pi500 firmware/selector matrix has been completed at build
// time; constructing the backend never enables them.
SelectorCandidatePlatformReadiness
ProductionSelectorCandidatePlatformReadiness();

enum class KernelSelectorStatus : uint8_t {
    Ok = 0,
    InvalidArgument,
    InvalidFormat,
    BoardMismatch,
    SequenceMismatch,
    ManifestMismatch,
    FileSystemError,
    DurabilityUnsupported,
    PlatformGateClosed
};

struct ParsedKernelSelector {
    char kernel_path[kMaximumKernelSelectorBytes];
    char manifest_kernel_path[kMaximumKernelSelectorBytes];
    char machine[16U];
    bool candidate;
};

// Strictly parses exactly this two-line selector:
//   # BMX-KERNEL-SELECTOR-V2\n
//   kernel=kernel7l.img.<machine>[.bmx-next]\n
// The temporary suffix is accepted only for an internal tryboot candidate.
KernelSelectorStatus ParseKernelSelector(ByteView bytes, BoardFamily board,
                                         ParsedKernelSelector *selector);

// Verifies that a parsed selector maps to exactly one signed stable kernel in
// the authenticated board asset.
KernelSelectorStatus ValidateKernelSelectorAgainstAsset(
    const ParsedKernelSelector &selector, const ManifestAsset &asset,
    uint64_t expected_release_sequence);

class SelectorCandidateBackend : public CandidateBackend {
public:
    SelectorCandidateBackend(
        UpdateFileSystem *file_system,
        const SelectorCandidatePlatformReadiness &platform,
        const char *active_selector = "bmx-active-kernel.txt",
        const char *candidate_selector = "bmx-tryboot-kernel.txt");

    bool Supported() const;
    bool ArmCandidate(const CandidateContext &context);
    bool CommitCandidate(const CandidateContext &context);
    bool DisarmCandidate(const CandidateContext &context);

    KernelSelectorStatus last_status() const { return last_status_; }

private:
    bool ReadAndValidate(const char *path, const CandidateContext &context,
                         uint64_t expected_sequence,
                         ParsedKernelSelector *selector);
    bool SelectorsEqual(const char *left, const char *right, bool *equal);
    bool ReplaceActiveFromCandidate();
    bool PublishSelector(const char *path, const char *kernel_path);
    bool PrepareCandidateKernel(const CandidateContext &context,
                                const ParsedKernelSelector &active,
                                char *candidate_path, size_t capacity,
                                bool *temporary);
    bool RemoveCandidateKernel(const ParsedKernelSelector &selector);
    bool PathsValid() const;

    SelectorCandidateBackend(const SelectorCandidateBackend &);
    SelectorCandidateBackend &operator=(const SelectorCandidateBackend &);

    UpdateFileSystem *file_system_;
    SelectorCandidatePlatformReadiness platform_;
    const char *active_selector_;
    const char *candidate_selector_;
    KernelSelectorStatus last_status_;
    uint8_t io_buffer_[kMaximumKernelSelectorBytes];
};

const char *KernelSelectorStatusString(KernelSelectorStatus status);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_SELECTOR_CANDIDATE_BACKEND_H
