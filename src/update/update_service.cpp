#include "update/update_service.h"

#include "network/network_manager.h"
#include "update/build_info.h"
#include "update/candidate_health_adapters.h"
#include "update/candidate_health_probe.h"
#include "update/circle_secure_stream.h"
#include "update/circle_update_archive_transport.h"
#include "update/circle_update_authorization_adapters.h"
#include "update/config_migration.h"
#include "update/consent_digest_input.h"
#include "update/draft_test_ticket.h"
#include "update/fatfs_config_snapshot.h"
#include "update/fatfs_prepared_config.h"
#include "update/fatfs_update_archive.h"
#include "update/fatfs_update_filesystem.h"
#include "update/github_release_client.h"
#include "update/github_draft_client.h"
#include "update/github_repository_policy.h"
#include "update/menu_update_progress_bridge.h"
#include "update/sha256.h"
#include "update/selector_candidate_backend.h"
#include "update/trust_store.h"
#include "update/tryboot_control.h"
#include "update/tryboot_reboot_control.h"
#include "update/update_authorization_adapters.h"
#include "update/update_fault_injection.h"
#include "update/update_hardware_test_mode.h"
#include "update/update_install_readiness.h"
#include "update/update_local_log.h"
#include "update/update_orchestrator.h"
#include "update/update_recovery_executor.h"
#include "update/update_transaction_store.h"
#include "update/update_watchdog.h"

#include <ff.h>

#if defined(RASPI_COMPILE)
#include <circle/logger.h>
#include <circle/startup.h>
#include <circle/timer.h>
#endif

#include <stdio.h>
#include <string.h>

extern "C" {
#include "ui.h"
}

namespace bmx {
namespace update {

namespace {

static const char kInstalledBuildPath[] = "SYS:/BMX-BUILD.json";
static const char kDraftTestTicketPath[] = "SYS:/BMX-DRAFT-TEST.json";
static const char kDraftTestSignaturePath[] = "SYS:/BMX-DRAFT-TEST.sig";

struct ServiceState {
    bool allocated;
    bool offer_valid;
    uint8_t *installed_bytes;
    size_t installed_size;
    uint8_t *github_bytes;
    uint8_t *manifest_bytes;
    uint8_t *signature_bytes;
    JsonToken *installed_tokens;
    JsonToken *github_tokens;
    JsonToken *manifest_tokens;
    GitHubReleaseAsset *github_assets;
    ManifestFile *manifest_files;
    ManifestDirectory *manifest_directories;
    ZipEntry *zip_entries;
    ZipExpectedFile *expected_files;
    const char **expected_directories;
    ZipWorkspace *zip_workspace;
    uint8_t *installer_io_buffer;
    uint8_t *verification_buffer;
    HttpsGetWorkspace *https_workspace;
    ValidatedReleaseDownload download;
    FatFsConfigSnapshot config_snapshot;
    ConfigMigrationPlan config_plan;
    uint8_t config_consent_sha256[kSha256DigestBytes];
    bool config_consent_valid;
    DraftTestTicket draft_ticket;
    GitHubDeviceAuthorization device_authorization;
    bool device_authorization_pending;
    uint64_t device_authorization_deadline_epoch;
    uint64_t device_authorization_next_poll_epoch;
    char access_token[kMaximumGitHubAccessTokenBytes + 1U];
};

ServiceState g_state;
bool g_recovery_attempted;
CandidateUpdateWatchdog *g_candidate_boot_watchdog;
bool g_candidate_boot_guard_attempted;
bool g_candidate_boot_observed;
bool g_candidate_boot_watchdog_armed;
CandidateUpdateWatchdogStartResult g_candidate_boot_watchdog_start_result =
    CandidateUpdateWatchdogStartResult::Failed;
bool g_early_previous_boot_failsafe_attempted;
bool g_candidate_boot_progress_failed;
UpdateLocalLogWorkspace *g_update_local_log_workspace;

static const char kUpdateLogSource[] = "bmx-update";

bool EnsureUpdateLocalLogWorkspace() {
    if (g_update_local_log_workspace != 0) return true;
    g_update_local_log_workspace = new UpdateLocalLogWorkspace;
    return g_update_local_log_workspace != 0;
}

// Heap-only because FatFsUpdateFileSystem owns file handles and a 4 KiB
// verification buffer. Logging remains best effort and is never consulted by
// an update or recovery decision.
class LocalLogComposition {
public:
    LocalLogComposition(UpdateLocalLogScope scope,
                        UpdateRecoveryProgress *delegate)
        : file_system_("SYS:"),
          log_(&file_system_, g_update_local_log_workspace),
          progress_(&log_, scope, delegate) {
    }

    UpdateLocalLog *log() { return &log_; }
    UpdateRecoveryProgress *progress() { return &progress_; }

private:
    LocalLogComposition(const LocalLogComposition &);
    LocalLogComposition &operator=(const LocalLogComposition &);

    FatFsUpdateFileSystem file_system_;
    UpdateLocalLog log_;
    LoggingUpdateRecoveryProgress progress_;
};

LocalLogComposition *CreateLocalLog(
    UpdateLocalLogScope scope, UpdateRecoveryProgress *delegate = 0) {
    return EnsureUpdateLocalLogWorkspace()
        ? new LocalLogComposition(scope, delegate) : 0;
}

class LocalLogOwner {
public:
    LocalLogOwner() : composition_(0) {}
    ~LocalLogOwner() { delete composition_; }

    void Start(UpdateLocalLogScope scope,
               UpdateRecoveryProgress *delegate = 0) {
        if (composition_ == 0) composition_ = CreateLocalLog(scope, delegate);
    }
    UpdateLocalLog *log() {
        return composition_ == 0 ? 0 : composition_->log();
    }
    UpdateRecoveryProgress *progress(UpdateRecoveryProgress *fallback = 0) {
        return composition_ == 0 ? fallback : composition_->progress();
    }

private:
    LocalLogOwner(const LocalLogOwner &);
    LocalLogOwner &operator=(const LocalLogOwner &);
    LocalLogComposition *composition_;
};

void RecordLocal(UpdateLocalLogScope scope, UpdateLocalLogCode code,
                 uint64_t completed = 0U, uint64_t total = 0U) {
    LocalLogComposition *local = CreateLocalLog(scope);
    if (local == 0) return;
    local->log()->Record(scope, code, completed, total);
    delete local;
}

void Message(char *output, unsigned output_size, const char *format,
             const char *detail = 0) {
    if (output == 0 || output_size == 0U) return;
    if (detail != 0) {
        snprintf(output, output_size, format, detail);
    } else {
        snprintf(output, output_size, "%s", format);
    }
    output[output_size - 1U] = '\0';
}

void SecureZero(void *memory, size_t size) {
    volatile uint8_t *bytes = static_cast<volatile uint8_t *>(memory);
    while (size-- != 0U) *bytes++ = 0U;
}

void ClearDraftAuthorization() {
    SecureZero(g_state.access_token, sizeof(g_state.access_token));
    SecureZero(&g_state.device_authorization,
               sizeof(g_state.device_authorization));
    g_state.device_authorization_pending = false;
    g_state.device_authorization_deadline_epoch = 0U;
    g_state.device_authorization_next_poll_epoch = 0U;
}

class DraftAuthorizationCleanup {
public:
    ~DraftAuthorizationCleanup() { ClearDraftAuthorization(); }
};

uint64_t CurrentUniversalEpoch() {
#if defined(RASPI_COMPILE)
    return CTimer::Get() == 0 ? 0U : CTimer::Get()->GetUniversalTime();
#else
    return 0U;
#endif
}

BoardFamily RunningBoard() {
#if RASPPI == 4
    return BoardFamily::Pi4Pi400;
#elif RASPPI == 5
    return BoardFamily::Pi5Pi500;
#else
    return BoardFamily::Unknown;
#endif
}

InstallerWorkspace ServiceInstallerWorkspace() {
    InstallerWorkspace workspace;
    memset(&workspace, 0, sizeof(workspace));
    workspace.zip_entries = g_state.zip_entries;
    workspace.zip_entry_capacity = kZipMaximumEntries;
    workspace.expected_files = g_state.expected_files;
    workspace.expected_file_capacity = kMaximumManifestFiles;
    workspace.expected_directories = g_state.expected_directories;
    workspace.expected_directory_capacity = kMaximumManifestDirectories;
    workspace.zip_workspace = g_state.zip_workspace;
    workspace.io_buffer = g_state.installer_io_buffer;
    workspace.io_buffer_size = kZipInputBufferBytes;
    return workspace;
}

UpdateOrchestratorWorkspace ServiceOrchestratorWorkspace() {
    UpdateOrchestratorWorkspace workspace;
    memset(&workspace, 0, sizeof(workspace));
    workspace.installer = ServiceInstallerWorkspace();
    // Revalidation derives this output only from the immutable raw ByteViews,
    // so the cached offer embedded in the download is valid aliasing scratch.
    // Keeping it in ServiceState removes a roughly 27 KiB target stack frame.
    workspace.release_offer = &g_state.download.offer;
    workspace.verification_buffer = g_state.verification_buffer;
    workspace.verification_buffer_size = kZipInputBufferBytes;
    return workspace;
}

bool ReadRunningBoardObservation(void *, BoardFamily *board) {
    if (board == 0) return false;
    *board = RunningBoard();
    return IsKnownBoardFamily(*board);
}

bool ReadFileSystemReadyObservation(void *context, bool *ready) {
    if (ready != 0) *ready = false;
    if (context == 0 || ready == 0) return false;
    uint64_t free_bytes = 0U;
    if (!static_cast<UpdateFileSystem *>(context)->GetFreeSpace(&free_bytes)) {
        return false;
    }
    *ready = true;
    return true;
}

bool ReadBooleanObservation(void *context, bool *value) {
    if (value != 0) *value = false;
    if (context == 0 || value == 0) return false;
    *value = *static_cast<const bool *>(context);
    return true;
}

bool ReadSafeRebootObservation(void *context, bool *ready) {
    if (!ReadBooleanObservation(context, ready)) return false;
    *ready = *ready && TrybootHardwareGateEnabled();
    return true;
}

ProductionCandidateRuntimeOperations BuildRuntimeOperations(
    UpdateFileSystem *file_system,
    SelectorCandidateBootObservation *selector_observation,
    CandidateUpdateWatchdog *watchdog,
    bool *menu_core_ready,
    bool *safe_reboot_ready) {
    ProductionCandidateRuntimeOperations operations =
        EmptyProductionCandidateRuntimeOperations();
    operations.read_running_board = ReadRunningBoardObservation;
    operations.candidate_boot_context = selector_observation;
    operations.read_candidate_boot_expected =
        SelectorCandidateBootObservation::ReadCallback;
    operations.read_firmware_reports_tryboot =
        ReadFirmwareTrybootObservation;
    operations.filesystem_context = file_system;
    operations.read_filesystem_ready = ReadFileSystemReadyObservation;
    operations.menu_core_context = menu_core_ready;
    operations.read_menu_core_ready = ReadBooleanObservation;
    operations.safe_reboot_context = safe_reboot_ready;
    operations.read_safe_reboot_ready = ReadSafeRebootObservation;
    operations.watchdog_context = watchdog;
    operations.read_hardware_watchdog_ready =
        ReadCandidateWatchdogObservation;
    return operations;
}

bool BytesNonZero(const uint8_t *bytes, size_t size) {
    if (bytes == 0 || size == 0U) return false;
    uint8_t combined = 0U;
    for (size_t index = 0U; index < size; ++index) {
        combined = static_cast<uint8_t>(combined | bytes[index]);
    }
    return combined != 0U;
}

bool GenerateTransactionId(AuthorizationTokenEntropySource *entropy,
                           uint8_t output[kTransactionIdBytes]) {
    if (entropy == 0 || output == 0) return false;
    for (unsigned attempt = 0U; attempt < 4U; ++attempt) {
        memset(output, 0, kTransactionIdBytes);
        if (!entropy->Fill(output, kTransactionIdBytes)) return false;
        if (BytesNonZero(output, kTransactionIdBytes)) return true;
    }
    memset(output, 0, kTransactionIdBytes);
    return false;
}

bool ReadCachedCandidateBoot(void *context) {
    return context != 0 && *static_cast<const bool *>(context);
}

void LogRecoveryMessage(const char *message) {
#if defined(RASPI_COMPILE)
    CLogger::Get()->Write(kUpdateLogSource, LogNotice, "%s", message);
#else
    (void) message;
#endif
}

void RequestMinimalPreviousBootFailSafe(const char *reason) {
#if defined(RASPI_COMPILE)
    CLogger::Get()->Write(kUpdateLogSource, LogError,
                          "candidate recovery failed: %s; requesting previous boot",
                          reason == 0 ? "unknown" : reason);
#else
    (void) reason;
#endif
    TrybootUpdateRebootControl reboot(ProductionTrybootRebootOperations());
    if (!reboot.RequestPreviousBootFailSafe()) {
#if defined(RASPI_COMPILE)
        CLogger::Get()->Write(kUpdateLogSource, LogError,
                              "previous-boot fail-safe request failed: %s",
                              TrybootRebootControlStatusString(
                                  reboot.last_status()));
#endif
    }
}

void RequestEarlyPreviousBootFailSafe() {
    if (g_early_previous_boot_failsafe_attempted) return;
    g_early_previous_boot_failsafe_attempted = true;
#if defined(RASPI_COMPILE)
    // This path runs before the update transaction is opened for writes (and
    // may run before FatFs is mounted), so application shutdown is neither
    // available nor required.  Clear/read back the one-shot selection first;
    // only then request a direct reboot into the known normal path.
    if (ClearOneShotTryboot() == TrybootStatus::Cleared) reboot();
#endif
}

class CandidateWatchdogRecoveryProgress : public UpdateRecoveryProgress {
public:
    CandidateWatchdogRecoveryProgress(CandidateUpdateWatchdog *watchdog,
                                      bool candidate_boot)
        : watchdog_(watchdog), candidate_boot_(candidate_boot),
          failed_(false) {}

    bool Report(const UpdateRecoveryProgressEvent &) {
        if (!candidate_boot_) return true;
        if (failed_) return false;
        failed_ = watchdog_ == 0 || !watchdog_->owned() ||
                  !watchdog_->IsRunning() ||
                  !watchdog_->RefreshForRecovery();
        return !failed_;
    }

private:
    CandidateUpdateWatchdog *watchdog_;
    bool candidate_boot_;
    bool failed_;
};

class BootRecoveryProgress : public UpdateRecoveryProgress {
public:
    explicit BootRecoveryProgress(UpdateRecoveryProgress *delegate)
        : delegate_(delegate), active_(false), phase_(0U), high_water_(0U),
          healthy_(false), rollback_(false), commit_base_(0U),
          commit_total_(0U), commit_counter_seen_(false) {}

    ~BootRecoveryProgress() {
        if (active_) ui_update_recovery_end();
    }

    void Begin() {
        active_ = ui_update_recovery_begin() != 0;
        if (active_) ui_update_recovery_present(0U, 0U);
    }

    void FinishCommitted() {
        healthy_ = true;
        Present(1U, 1000U);
    }

    void BeginMandatoryOperation() {
        if (delegate_ != 0) delegate_->BeginMandatoryOperation();
    }

    void EndMandatoryOperation() {
        if (delegate_ != 0) delegate_->EndMandatoryOperation();
    }

    bool Report(const UpdateRecoveryProgressEvent &event) {
        if (delegate_ != 0 && !delegate_->Report(event)) return false;

        switch (event.kind) {
        case UpdateRecoveryProgressKind::CandidateFileHashed:
            Present(0U, Scaled(event.completed_bytes, event.total_bytes,
                               0U, 950U));
            break;
        case UpdateRecoveryProgressKind::CandidateHealthEvaluated:
            healthy_ = event.completed_bytes ==
                static_cast<uint64_t>(CandidateHealthStatus::Healthy);
            Present(0U, 1000U);
#if defined(RASPI_COMPILE)
            CLogger::Get()->Write(
                kUpdateLogSource, healthy_ ? LogNotice : LogWarning,
                "candidate health: %s; probe=%s (%llu/%llu)",
                CandidateHealthStatusString(
                    static_cast<CandidateHealthStatus>(
                        event.completed_bytes)),
                CandidateHealthProbeStatusString(
                    static_cast<CandidateHealthProbeStatus>(
                        event.total_bytes)),
                static_cast<unsigned long long>(event.completed_bytes),
                static_cast<unsigned long long>(event.total_bytes));
#endif
            break;
        case UpdateRecoveryProgressKind::InstallerJournalPersisted:
            if (healthy_ && !rollback_) {
                if (!commit_counter_seen_) {
                    commit_counter_seen_ = true;
                    commit_base_ = event.completed_bytes;
                    commit_total_ = event.total_bytes;
                }
                const uint64_t completed =
                    event.completed_bytes > commit_base_
                        ? event.completed_bytes - commit_base_ : 0U;
                const uint64_t total = commit_total_ > commit_base_
                    ? commit_total_ - commit_base_ : 0U;
                Present(1U, Scaled(completed, total, 0U, 990U));
            }
            break;
        case UpdateRecoveryProgressKind::CandidateRollbackDecision:
            rollback_ = true;
            Present(2U, 0U);
#if defined(RASPI_COMPILE)
            CLogger::Get()->Write(
                kUpdateLogSource, LogWarning,
                "candidate rollback: trigger=%s; installer=%s (%llu/%llu)",
                UpdateOrchestratorStatusString(
                    static_cast<UpdateOrchestratorStatus>(
                        event.completed_bytes)),
                InstallerStatusString(static_cast<InstallerStatus>(
                    event.total_bytes)),
                static_cast<unsigned long long>(event.completed_bytes),
                static_cast<unsigned long long>(event.total_bytes));
#endif
            break;
        case UpdateRecoveryProgressKind::InstallerRollbackStep:
            if (rollback_ && event.total_bytes != 0U) {
                Present(2U, Scaled(event.completed_bytes,
                                   event.total_bytes, 0U, 990U));
            }
            break;
        case UpdateRecoveryProgressKind::CandidateRollbackComplete:
            Present(2U, 1000U);
            Present(3U, 1000U);
            break;
        default:
            break;
        }
        return true;
    }

private:
    static unsigned Scaled(uint64_t completed, uint64_t total,
                           unsigned begin, unsigned end) {
        if (total == 0U) return begin;
        if (completed >= total) return end;
        const uint64_t span = end - begin;
        const uint64_t quotient = completed / total;
        const uint64_t remainder = completed % total;
        uint64_t scaled = quotient * span;
        scaled += remainder <= UINT64_MAX / span
            ? (remainder * span) / total
            : remainder / (total / span + 1U);
        return static_cast<unsigned>(begin + scaled);
    }

    void Present(unsigned phase, unsigned progress) {
        if (!active_) return;
        if (phase != phase_) {
            phase_ = phase;
            high_water_ = 0U;
        }
        if (progress > high_water_) high_water_ = progress;
        ui_update_recovery_present(phase_, high_water_);
    }

    UpdateRecoveryProgress *delegate_;
    bool active_;
    unsigned phase_;
    unsigned high_water_;
    bool healthy_;
    bool rollback_;
    uint64_t commit_base_;
    uint64_t commit_total_;
    bool commit_counter_seen_;
};

bool AllocateState() {
    if (g_state.allocated) return true;
    g_state.installed_bytes = new uint8_t[kMaximumBuildInfoBytes];
    g_state.github_bytes = new uint8_t[kMaximumGitHubReleaseResponseBytes];
    g_state.manifest_bytes = new uint8_t[kMaximumReleaseManifestBytes];
    g_state.signature_bytes = new uint8_t[kMaximumSignatureEnvelopeBytes];
    g_state.installed_tokens = new JsonToken[2048U];
    g_state.github_tokens = new JsonToken[16384U];
    g_state.manifest_tokens = new JsonToken[kMaximumManifestTokens];
    g_state.github_assets =
        new GitHubReleaseAsset[kMaximumGitHubReleaseAssets];
    g_state.manifest_files = new ManifestFile[kMaximumManifestFiles];
    g_state.manifest_directories =
        new ManifestDirectory[kMaximumManifestDirectories];
    g_state.zip_entries = new ZipEntry[kZipMaximumEntries];
    g_state.expected_files = new ZipExpectedFile[kMaximumManifestFiles];
    g_state.expected_directories =
        new const char *[kMaximumManifestDirectories];
    g_state.zip_workspace = new ZipWorkspace;
    g_state.installer_io_buffer = new uint8_t[kZipInputBufferBytes];
    g_state.verification_buffer = new uint8_t[kZipInputBufferBytes];
    g_state.https_workspace = new HttpsGetWorkspace;
    g_state.allocated = g_state.installed_bytes != 0 &&
        g_state.github_bytes != 0 && g_state.manifest_bytes != 0 &&
        g_state.signature_bytes != 0 && g_state.installed_tokens != 0 &&
        g_state.github_tokens != 0 && g_state.manifest_tokens != 0 &&
        g_state.github_assets != 0 && g_state.manifest_files != 0 &&
        g_state.manifest_directories != 0 && g_state.zip_entries != 0 &&
        g_state.expected_files != 0 && g_state.expected_directories != 0 &&
        g_state.zip_workspace != 0 && g_state.installer_io_buffer != 0 &&
        g_state.verification_buffer != 0 && g_state.https_workspace != 0;
    if (!g_state.allocated) {
        delete[] g_state.installed_bytes;
        delete[] g_state.github_bytes;
        delete[] g_state.manifest_bytes;
        delete[] g_state.signature_bytes;
        delete[] g_state.installed_tokens;
        delete[] g_state.github_tokens;
        delete[] g_state.manifest_tokens;
        delete[] g_state.github_assets;
        delete[] g_state.manifest_files;
        delete[] g_state.manifest_directories;
        delete[] g_state.zip_entries;
        delete[] g_state.expected_files;
        delete[] g_state.expected_directories;
        delete g_state.zip_workspace;
        delete[] g_state.installer_io_buffer;
        delete[] g_state.verification_buffer;
        delete g_state.https_workspace;
        g_state.installed_bytes = 0;
        g_state.github_bytes = 0;
        g_state.manifest_bytes = 0;
        g_state.signature_bytes = 0;
        g_state.installed_tokens = 0;
        g_state.github_tokens = 0;
        g_state.manifest_tokens = 0;
        g_state.github_assets = 0;
        g_state.manifest_files = 0;
        g_state.manifest_directories = 0;
        g_state.zip_entries = 0;
        g_state.expected_files = 0;
        g_state.expected_directories = 0;
        g_state.zip_workspace = 0;
        g_state.installer_io_buffer = 0;
        g_state.verification_buffer = 0;
        g_state.https_workspace = 0;
    }
    return g_state.allocated;
}

enum class LocalReadStatus { Ok, Missing, InvalidSize, IoError };

LocalReadStatus ReadInstalledBuild() {
    FILINFO info;
    FRESULT status = f_stat(kInstalledBuildPath, &info);
    if (status == FR_NO_FILE || status == FR_NO_PATH) return LocalReadStatus::Missing;
    if (status != FR_OK) return LocalReadStatus::IoError;
    if (info.fsize == 0U || info.fsize > kMaximumBuildInfoBytes) {
        return LocalReadStatus::InvalidSize;
    }
    FIL file;
    status = f_open(&file, kInstalledBuildPath, FA_READ);
    if (status != FR_OK) return LocalReadStatus::IoError;
    size_t offset = 0U;
    while (offset < static_cast<size_t>(info.fsize)) {
        UINT amount = 0U;
        const size_t remaining = static_cast<size_t>(info.fsize) - offset;
        const UINT request = remaining > 16384U
                                 ? 16384U
                                 : static_cast<UINT>(remaining);
        status = f_read(&file, g_state.installed_bytes + offset, request, &amount);
        if (status != FR_OK || amount != request) {
            f_close(&file);
            return LocalReadStatus::IoError;
        }
        offset += amount;
    }
    if (f_close(&file) != FR_OK) return LocalReadStatus::IoError;
    g_state.installed_size = offset;
    return LocalReadStatus::Ok;
}

LocalReadStatus ReadBoundedLocalFile(const char *path, uint8_t *output,
                                     size_t capacity, size_t *size) {
    if (path == 0 || output == 0 || capacity == 0U || size == 0) {
        return LocalReadStatus::IoError;
    }
    *size = 0U;
    FILINFO info;
    FRESULT status = f_stat(path, &info);
    if (status == FR_NO_FILE || status == FR_NO_PATH) {
        return LocalReadStatus::Missing;
    }
    if (status != FR_OK) return LocalReadStatus::IoError;
    if (info.fsize == 0U || info.fsize > capacity) {
        return LocalReadStatus::InvalidSize;
    }
    FIL file;
    status = f_open(&file, path, FA_READ);
    if (status != FR_OK) return LocalReadStatus::IoError;
    size_t offset = 0U;
    while (offset < static_cast<size_t>(info.fsize)) {
        UINT amount = 0U;
        const size_t remaining = static_cast<size_t>(info.fsize) - offset;
        const UINT request = remaining > 4096U
                                 ? 4096U : static_cast<UINT>(remaining);
        status = f_read(&file, output + offset, request, &amount);
        if (status != FR_OK || amount != request) {
            f_close(&file);
            return LocalReadStatus::IoError;
        }
        offset += amount;
    }
    if (f_close(&file) != FR_OK) return LocalReadStatus::IoError;
    *size = offset;
    return LocalReadStatus::Ok;
}

struct DraftTicketWorkspace {
    uint8_t ticket[kMaximumDraftTestTicketBytes];
    uint8_t signature[kMaximumSignatureEnvelopeBytes];
    JsonToken tokens[256U];
};

DraftTestTicketStatus LoadDraftTestTicket(DraftTestTicket *ticket) {
    if (ticket == 0 || kGitHubReleaseChannelIsTest) {
        return DraftTestTicketStatus::InvalidArgument;
    }
    DraftTicketWorkspace *workspace = new DraftTicketWorkspace;
    if (workspace == 0) return DraftTestTicketStatus::StorageTooSmall;
    size_t ticket_size = 0U;
    size_t signature_size = 0U;
    const LocalReadStatus ticket_read = ReadBoundedLocalFile(
        kDraftTestTicketPath, workspace->ticket, sizeof(workspace->ticket),
        &ticket_size);
    const LocalReadStatus signature_read = ReadBoundedLocalFile(
        kDraftTestSignaturePath, workspace->signature,
        sizeof(workspace->signature), &signature_size);
    if (ticket_read != LocalReadStatus::Ok ||
        signature_read != LocalReadStatus::Ok) {
        SecureZero(workspace, sizeof(*workspace));
        delete workspace;
        return ticket_read == LocalReadStatus::InvalidSize ||
                       signature_read == LocalReadStatus::InvalidSize
                   ? DraftTestTicketStatus::InvalidSize
                   : DraftTestTicketStatus::InvalidArgument;
    }
    size_t key_count = 0U;
    const TrustedReleaseKey *keys = ReleaseTrustStore(&key_count);
    JsonParseResult json_result;
    const DraftTestTicketStatus result = VerifyDraftTestTicket(
        ByteView(workspace->ticket, ticket_size),
        ByteView(workspace->signature, signature_size), workspace->tokens,
        sizeof(workspace->tokens) / sizeof(workspace->tokens[0]), keys,
        key_count, VerifyP256SignatureMbedTls, 0, CurrentUniversalEpoch(),
        ticket, &json_result);
    SecureZero(workspace, sizeof(*workspace));
    delete workspace;
    return result;
}

bool RemoveDraftTestTicket() {
    const FRESULT ticket = f_unlink(kDraftTestTicketPath);
    const FRESULT signature = f_unlink(kDraftTestSignaturePath);
    const bool ticket_ok = ticket == FR_OK || ticket == FR_NO_FILE ||
                           ticket == FR_NO_PATH;
    const bool signature_ok = signature == FR_OK || signature == FR_NO_FILE ||
                              signature == FR_NO_PATH;
    return ticket_ok && signature_ok;
}

ReleaseOfferStorage OfferStorage() {
    const ReleaseOfferStorage storage = {
        g_state.installed_tokens, 2048U,
        g_state.github_tokens, 16384U,
        g_state.github_assets, kMaximumGitHubReleaseAssets,
        g_state.manifest_tokens, kMaximumManifestTokens,
        g_state.manifest_files, kMaximumManifestFiles,
        g_state.manifest_directories, kMaximumManifestDirectories};
    return storage;
}

// Start() never invokes candidate health, but its dependency must still be
// explicit.  The real, local-only production health stack is constructed by
// RecoveryComposition after a boot.  Keeping this adapter unavailable makes
// accidental foreground health collection fail closed.
class StartOnlyCandidateHealthProbe : public CandidateHealthProbe {
public:
    bool Collect(const AuthenticatedUpdateBinding &,
                 const ReleaseManifest &,
                 CandidateHealthEvidence *) {
        return false;
    }
};

// These compositions are intentionally heap-only.  Together the FatFs,
// prepared-config, authorization and archive adapters are too large for the
// target's 128 KiB kernel stack once parser/installer call frames are added.
class StartComposition {
public:
    StartComposition(CNetSubSystem *network, uint64_t minimum_epoch,
                     const TrustedReleaseKey *keys, size_t key_count,
                     const UpdateOrchestratorWorkspace &workspace,
                     const UpdateInstallPlatformReadiness &platform,
                     UpdateForegroundProgress *foreground_progress,
                     const char *bearer_token,
                     bool authenticated_api_asset)
        : file_system_("SYS:"),
          selector_backend_(&file_system_,
                            ProductionSelectorCandidatePlatformReadiness()),
          installer_(&file_system_, &selector_backend_),
          installer_operations_(&installer_),
          secure_factory_(network, minimum_epoch),
          transport_(&secure_factory_, g_state.https_workspace,
                     foreground_progress, bearer_token,
                     authenticated_api_asset),
          archive_storage_("SYS:"),
          request_store_(&file_system_),
          prepared_configs_(&file_system_, workspace.installer, "SYS:"),
          start_only_health_(),
          reboot_(ProductionTrybootRebootOperations()),
          validator_(keys, key_count, VerifyP256SignatureMbedTls, 0,
                     OfferStorage()),
          entropy_(), clock_(), network_state_(),
          foreground_source_(&entropy_, &clock_, &network_state_),
          authorization_controller_(&foreground_source_),
          current_config_("SYS:"),
          authorization_(&foreground_source_, &current_config_),
          readiness_(&file_system_, platform),
          orchestrator_(&validator_, &authorization_, &readiness_,
                        &transport_, &archive_storage_, &request_store_,
                        &prepared_configs_, &installer_operations_,
                        &start_only_health_, &reboot_) {
    }

    CircleHardwareAuthorizationTokenEntropySource *entropy() {
        return &entropy_;
    }
    ExplicitUpdateMenuAuthorizationController *authorization_controller() {
        return &authorization_controller_;
    }
    UpdateOrchestrator *orchestrator() { return &orchestrator_; }

private:
    StartComposition(const StartComposition &);
    StartComposition &operator=(const StartComposition &);

    FatFsUpdateFileSystem file_system_;
    SelectorCandidateBackend selector_backend_;
    UpdateInstaller installer_;
    DirectUpdateInstallOperations installer_operations_;
    CircleSecureStreamFactory secure_factory_;
    CircleHttpsUpdateArchiveTransport transport_;
    FatFsUpdateArchiveStorage archive_storage_;
    UpdateTransactionRequestStore request_store_;
    FatFsPreparedConfigProvider prepared_configs_;
    StartOnlyCandidateHealthProbe start_only_health_;
    TrybootUpdateRebootControl reboot_;
    RawAuthenticatedReleaseValidator validator_;
    CircleHardwareAuthorizationTokenEntropySource entropy_;
    CircleAuthorizationMonotonicClock clock_;
    ExistingNetworkStateSource network_state_;
    OneShotForegroundUpdateAuthorizationSource foreground_source_;
    ExplicitUpdateMenuAuthorizationController authorization_controller_;
    FatFsCurrentConfigConsentSource current_config_;
    ForegroundNetworkAuthorizationConsentGate authorization_;
    ProbeInstallReadinessGate readiness_;
    UpdateOrchestrator orchestrator_;
};

class RecoveryComposition {
public:
    RecoveryComposition(const TrustedReleaseKey *keys, size_t key_count,
                        const UpdateOrchestratorWorkspace &workspace,
                        CandidateUpdateWatchdog *watchdog,
                        UpdateRecoveryProgress *recovery_progress)
        : file_system_("SYS:"),
          selector_backend_(&file_system_,
                            ProductionSelectorCandidatePlatformReadiness()),
          installer_(&file_system_, &selector_backend_),
          installer_operations_(&installer_), archive_storage_("SYS:"),
          request_store_(&file_system_),
          prepared_configs_(&file_system_, workspace.installer, "SYS:"),
          configuration_health_("SYS:"),
          selector_observation_(&file_system_, RunningBoard()),
          menu_core_ready_(true), safe_reboot_ready_(true),
          runtime_operations_(BuildRuntimeOperations(
              &file_system_, &selector_observation_, watchdog,
              &menu_core_ready_, &safe_reboot_ready_)),
          runtime_health_(runtime_operations_),
          health_(&file_system_, &configuration_health_, &runtime_health_,
                  workspace.verification_buffer,
                  workspace.verification_buffer_size, recovery_progress),
          reboot_(ProductionTrybootRebootOperations()),
          validator_(keys, key_count, VerifyP256SignatureMbedTls, 0,
                     OfferStorage()),
          orchestrator_(&validator_, 0, 0, 0, &archive_storage_,
                        &request_store_, &prepared_configs_,
                        &installer_operations_, &health_, &reboot_) {
    }

    UpdateTransactionRequestStore *request_store() { return &request_store_; }
    UpdateOrchestrator *orchestrator() { return &orchestrator_; }
    UpdateRebootControl *reboot() { return &reboot_; }
    const ProductionCandidateConfigurationHealthSource *configuration_health()
        const { return &configuration_health_; }

private:
    RecoveryComposition(const RecoveryComposition &);
    RecoveryComposition &operator=(const RecoveryComposition &);

    FatFsUpdateFileSystem file_system_;
    SelectorCandidateBackend selector_backend_;
    UpdateInstaller installer_;
    DirectUpdateInstallOperations installer_operations_;
    FatFsUpdateArchiveStorage archive_storage_;
    UpdateTransactionRequestStore request_store_;
    FatFsPreparedConfigProvider prepared_configs_;
    ProductionCandidateConfigurationHealthSource configuration_health_;
    SelectorCandidateBootObservation selector_observation_;
    bool menu_core_ready_;
    bool safe_reboot_ready_;
    ProductionCandidateRuntimeOperations runtime_operations_;
    ProductionCandidateRuntimeHealthSource runtime_health_;
    LocalCandidateHealthProbe health_;
    TrybootUpdateRebootControl reboot_;
    RawAuthenticatedReleaseValidator validator_;
    UpdateOrchestrator orchestrator_;
};

// The pending offer in g_state must remain byte-for-byte intact until Start()
// revalidates it. A retained previous transaction therefore needs separate
// raw-input storage, but it may synchronously reuse the global parser arrays:
// Start() reparses the pending offer before consuming any manifest pointers.
class RetainedRequestScratch {
public:
    RetainedRequestScratch()
        : download(), request(), installed_(0), github_(0), manifest_(0),
          signature_(0) {
    }

    ~RetainedRequestScratch() {
        delete[] installed_;
        delete[] github_;
        delete[] manifest_;
        delete[] signature_;
    }

    bool Allocate() {
        installed_ = new uint8_t[kMaximumBuildInfoBytes];
        github_ = new uint8_t[kMaximumGitHubReleaseResponseBytes];
        manifest_ = new uint8_t[kMaximumReleaseManifestBytes];
        signature_ = new uint8_t[kMaximumSignatureEnvelopeBytes];
        return installed_ != 0 && github_ != 0 && manifest_ != 0 &&
               signature_ != 0;
    }

    PersistedUpdateRequestBuffers Buffers() {
        const PersistedUpdateRequestBuffers buffers = {
            installed_, kMaximumBuildInfoBytes,
            github_, kMaximumGitHubReleaseResponseBytes,
            manifest_, kMaximumReleaseManifestBytes,
            signature_, kMaximumSignatureEnvelopeBytes};
        return buffers;
    }

    ValidatedReleaseDownload download;
    AuthenticatedUpdateRequest request;

private:
    RetainedRequestScratch(const RetainedRequestScratch &);
    RetainedRequestScratch &operator=(const RetainedRequestScratch &);

    uint8_t *installed_;
    uint8_t *github_;
    uint8_t *manifest_;
    uint8_t *signature_;
};

class RetireComposition {
public:
    RetireComposition(const TrustedReleaseKey *keys, size_t key_count)
        : file_system_("SYS:"),
          selector_backend_(&file_system_,
                            ProductionSelectorCandidatePlatformReadiness()),
          installer_(&file_system_, &selector_backend_),
          installer_operations_(&installer_), request_store_(&file_system_),
          validator_(keys, key_count, VerifyP256SignatureMbedTls, 0,
                     OfferStorage()),
          orchestrator_(&validator_, 0, 0, 0, 0, &request_store_, 0,
                        &installer_operations_, 0, 0) {
    }

    UpdateTransactionRequestStore *request_store() { return &request_store_; }
    UpdateOrchestrator *orchestrator() { return &orchestrator_; }

private:
    RetireComposition(const RetireComposition &);
    RetireComposition &operator=(const RetireComposition &);

    FatFsUpdateFileSystem file_system_;
    SelectorCandidateBackend selector_backend_;
    UpdateInstaller installer_;
    DirectUpdateInstallOperations installer_operations_;
    UpdateTransactionRequestStore request_store_;
    RawAuthenticatedReleaseValidator validator_;
    UpdateOrchestrator orchestrator_;
};

enum class RetainedTransactionRetireStatus {
    None = 0,
    Retired,
    Failed
};

RetainedTransactionRetireStatus RetirePreviousTransaction(
    const TrustedReleaseKey *keys, size_t key_count,
    const UpdateOrchestratorWorkspace &base_workspace) {
    if (keys == 0 || key_count == 0U) {
        return RetainedTransactionRetireStatus::Failed;
    }
    FatFsUpdateFileSystem probe("SYS:");
    UpdateFileStat committed;
    UpdateFileStat retiring;
    if (!probe.Stat(kUpdateTransactionCommittedPath, &committed) ||
        !probe.Stat(kUpdateTransactionRetiringPath, &retiring)) {
        return RetainedTransactionRetireStatus::Failed;
    }
    const bool committed_present =
        committed.type == UpdateNodeType::RegularFile &&
        committed.size == kPersistedUpdateRequestStateBytes;
    const bool retiring_present =
        retiring.type == UpdateNodeType::RegularFile &&
        retiring.size == kPersistedUpdateRequestStateBytes;
    if ((committed.type != UpdateNodeType::Missing && !committed_present) ||
        (retiring.type != UpdateNodeType::Missing && !retiring_present) ||
        (committed_present && retiring_present)) {
        return RetainedTransactionRetireStatus::Failed;
    }
    if (!committed_present && !retiring_present) {
        return RetainedTransactionRetireStatus::None;
    }

    // A retiring marker is created only after the fully authenticated
    // installer cleanup removed its journal last. It contains no boot
    // activation and authorizes only idempotent deletion of fixed internal
    // raw-payload names.
    if (retiring_present) {
        UpdateTransactionRequestStore store(&probe);
        AuthenticatedUpdateBinding binding = AuthenticatedUpdateBinding();
        binding.transaction_root = kUpdateTransactionRoot;
        return store.DiscardRetainedCommitted(
                   binding, base_workspace.recovery_progress) ==
                       UpdateRequestPersistenceStatus::Ok
            ? RetainedTransactionRetireStatus::Retired
            : RetainedTransactionRetireStatus::Failed;
    }

    RetainedRequestScratch *scratch = new RetainedRequestScratch;
    if (scratch == 0 || !scratch->Allocate()) {
        delete scratch;
        return RetainedTransactionRetireStatus::Failed;
    }
    RetireComposition *composition = new RetireComposition(keys, key_count);
    if (composition == 0) {
        delete scratch;
        return RetainedTransactionRetireStatus::Failed;
    }
    const UpdateTransactionStoreStatus loaded =
        composition->request_store()->LoadCommitted(
            kUpdateTransactionRoot, RunningBoard(), scratch->Buffers(),
            &scratch->download, &scratch->request);
    if (loaded != UpdateTransactionStoreStatus::Ok) {
        delete composition;
        delete scratch;
        return RetainedTransactionRetireStatus::Failed;
    }
    UpdateOrchestratorWorkspace workspace = base_workspace;
    workspace.release_offer = &scratch->download.offer;
    const UpdateOrchestratorResult result =
        composition->orchestrator()->RetireCommitted(scratch->request,
                                                      workspace);
    delete composition;
    delete scratch;
    return result.status == UpdateOrchestratorStatus::PreviousRetired
        ? RetainedTransactionRetireStatus::Retired
        : RetainedTransactionRetireStatus::Failed;
}

int ReportClientFailure(const ReleaseClientResult &result, char *message,
                        unsigned message_size) {
    if (result.status == ReleaseClientStatus::OfferInvalid &&
        result.offer_result.status == ReleaseOfferStatus::ReleaseRejected) {
        if (result.offer_result.release_decision ==
            ReleaseDecision::AlreadyCurrent) {
            Message(message, message_size, "BMX is already up to date.");
            return 0;
        }
        if (result.offer_result.release_decision ==
            ReleaseDecision::DowngradeDenied) {
            Message(message, message_size,
                    "The authenticated release is older than this installation; no downgrade was performed.");
            return 0;
        }
    }
    const char *detail = ReleaseClientStatusString(result.status);
    if (result.status == ReleaseClientStatus::DiscoveryDownloadFailed ||
        result.status == ReleaseClientStatus::ManifestDownloadFailed ||
        result.status == ReleaseClientStatus::SignatureDownloadFailed) {
        detail = HttpsGetStatusString(result.https_result.status);
    } else if (result.status == ReleaseClientStatus::OfferInvalid) {
        detail = ReleaseOfferStatusString(result.offer_result.status);
    }
    Message(message, message_size, "Update check failed: %s", detail);
    return -1;
}

enum class CurrentConfigStatus {
    Ok = 0,
    ReadFailed,
    InvalidManifestPolicy,
    AssessmentFailed,
    Blocked,
    Unrepresentable,
    DigestFailed
};

CurrentConfigStatus AssessCurrentConfiguration(char *detail,
                                                size_t detail_size) {
    if (detail != 0 && detail_size != 0U) detail[0] = '\0';
    const FatFsConfigSnapshotStatus load = g_state.config_snapshot.Load("SYS:");
    if (load != FatFsConfigSnapshotStatus::Ok) {
        if (detail != 0 && detail_size != 0U) {
            snprintf(detail, detail_size, "%s",
                     FatFsConfigSnapshotStatusString(load));
            detail[detail_size - 1U] = '\0';
        }
        return CurrentConfigStatus::ReadFailed;
    }

    const ReleaseManifest &manifest = g_state.download.offer.manifest;
    if (manifest.schema_count != kConfigMigrationAreaCount ||
        manifest.migration_count > kMaximumDeclaredConfigMigrations) {
        return CurrentConfigStatus::InvalidManifestPolicy;
    }
    ConfigSchemaRequirement requirements[kConfigMigrationAreaCount];
    for (size_t i = 0U; i < manifest.schema_count; ++i) {
        requirements[i].area = manifest.schemas[i].area;
        requirements[i].target_version = manifest.schemas[i].target_version;
        requirements[i].accepted_versions =
            manifest.schemas[i].accepted_versions;
        requirements[i].accepted_version_count =
            manifest.schemas[i].accepted_version_count;
    }
    DeclaredConfigMigration migrations[kMaximumDeclaredConfigMigrations];
    for (size_t i = 0U; i < manifest.migration_count; ++i) {
        migrations[i].id = manifest.migrations[i].id;
        migrations[i].area = manifest.migrations[i].area;
        migrations[i].from_version = manifest.migrations[i].from_version;
        migrations[i].to_version = manifest.migrations[i].to_version;
        migrations[i].lossy = manifest.migrations[i].lossy;
    }
    ConfigMigrationPlan plan;
    const ConfigAssessmentStatus assessed = AssessConfigSnapshot(
        g_state.config_snapshot.snapshot(), requirements,
        manifest.schema_count, migrations, manifest.migration_count, &plan);
    if (assessed != ConfigAssessmentStatus::Ok) {
        if (detail != 0 && detail_size != 0U) {
            snprintf(detail, detail_size, "%s",
                     ConfigAssessmentStatusString(assessed));
            detail[detail_size - 1U] = '\0';
        }
        return CurrentConfigStatus::AssessmentFailed;
    }
    if (plan.decision == ConfigPlanDecision::BlockedUnknownOrCorrupt ||
        plan.decision == ConfigPlanDecision::BlockedNewerThanTarget ||
        plan.decision == ConfigPlanDecision::InvalidInput ||
        plan.blocked_count != 0U) {
        if (detail != 0 && detail_size != 0U) {
            snprintf(detail, detail_size,
                     "unknown, corrupt, or newer configuration in %u area(s)",
                     static_cast<unsigned>(plan.blocked_count));
            detail[detail_size - 1U] = '\0';
        }
        return CurrentConfigStatus::Blocked;
    }

    const PreparedConfigRepresentabilityResult representability =
        CheckPreparedConfigRepresentability(
            plan, g_state.config_snapshot.snapshot(), manifest);
    if (!representability.representable()) {
        if (detail != 0 && detail_size != 0U &&
            !FormatPreparedConfigRepresentabilityFailure(
                representability, detail, detail_size)) {
            snprintf(detail, detail_size, "%s",
                     PreparedConfigRepresentabilityStatusString(
                         representability.status));
            detail[detail_size - 1U] = '\0';
        }
        return CurrentConfigStatus::Unrepresentable;
    }

    uint8_t manifest_digest[kSha256DigestBytes];
    if (!Sha256Digest(g_state.download.manifest, manifest_digest)) {
        return CurrentConfigStatus::DigestFailed;
    }
    ConsentConfigItem items[kConfigMigrationAreaCount];
    for (size_t i = 0U; i < plan.area_count; ++i) {
        const ConfigAreaAssessment &area = plan.areas[i];
        if (area.classification != ConfigClassification::Compatible &&
            area.classification != ConfigClassification::LosslessMigration &&
            area.classification != ConfigClassification::ResetRequired) {
            return CurrentConfigStatus::Blocked;
        }
        items[i].area = area.area;
        items[i].classification = area.classification;
        items[i].source_schema_version = area.source_version;
        items[i].target_schema_version = area.target_version;
        memcpy(items[i].source_content_sha256, area.source_content_sha256,
               kSha256DigestBytes);
    }
    ConsentDigestInput input;
    input.board = RunningBoard();
    input.target_release_sequence = manifest.release_sequence;
    memcpy(input.manifest_sha256, manifest_digest, kSha256DigestBytes);
    input.items = items;
    input.item_count = plan.area_count;
    uint8_t encoded[kMaximumConsentEncodedBytes];
    size_t encoded_size = 0U;
    if (SerializeConsentDigestInput(
            input, MutableByteView(encoded, sizeof(encoded)), &encoded_size) !=
            ConsentInputStatus::Valid ||
        !Sha256Digest(ByteView(encoded, encoded_size),
                      g_state.config_consent_sha256)) {
        return CurrentConfigStatus::DigestFailed;
    }
    g_state.config_plan = plan;
    g_state.config_consent_valid = true;

    ReleaseOffer &offer = g_state.download.offer;
    offer.reset_area_count = 0U;
    for (size_t i = 0U; i < plan.area_count; ++i) {
        if (plan.areas[i].classification ==
            ConfigClassification::ResetRequired) {
            offer.reset_areas[offer.reset_area_count++] = plan.areas[i].area;
        }
    }
    offer.configuration_status = offer.reset_area_count == 0U
        ? OfferConfigurationStatus::Compatible
        : OfferConfigurationStatus::ResetConfirmationRequired;
    return CurrentConfigStatus::Ok;
}

const char *CurrentConfigStatusString(CurrentConfigStatus status) {
    switch (status) {
    case CurrentConfigStatus::Ok: return "ok";
    case CurrentConfigStatus::ReadFailed: return "configuration read failed";
    case CurrentConfigStatus::InvalidManifestPolicy:
        return "signed configuration policy invalid";
    case CurrentConfigStatus::AssessmentFailed:
        return "configuration assessment failed";
    case CurrentConfigStatus::Blocked:
        return "configuration is incompatible or ambiguous";
    case CurrentConfigStatus::Unrepresentable:
        return "configuration change cannot be represented safely";
    case CurrentConfigStatus::DigestFailed:
        return "configuration consent digest failed";
    }
    return "unknown configuration error";
}

UpdateInstallPlatformReadiness ProductionInstallPlatformReadiness(
    bool prepared_draft = false) {
    UpdateInstallPlatformReadiness readiness;
    memset(&readiness, 0, sizeof(readiness));
    const SelectorCandidatePlatformReadiness selector =
        ProductionSelectorCandidatePlatformReadiness();
    ProductionCandidateRuntimeOperations callbacks =
        EmptyProductionCandidateRuntimeOperations();
    callbacks.read_running_board = ReadRunningBoardObservation;
    callbacks.read_candidate_boot_expected =
        SelectorCandidateBootObservation::ReadCallback;
    callbacks.read_firmware_reports_tryboot =
        ReadFirmwareTrybootObservation;
    callbacks.read_filesystem_ready = ReadFileSystemReadyObservation;
    callbacks.read_menu_core_ready = ReadBooleanObservation;
    callbacks.read_safe_reboot_ready = ReadSafeRebootObservation;
    callbacks.read_hardware_watchdog_ready =
        ReadCandidateWatchdogObservation;
    const ProductionCandidateRuntimeReadiness runtime =
        ProductionCandidateRuntimeReadinessForCallbacks(callbacks);

    readiness.tryboot_one_shot_validated =
        selector.one_shot_boot_validated &&
        TrybootObservationHardwareGateEnabled();
    readiness.recovery_executor_available =
        ProductionCandidateRuntimeReady(runtime);
    readiness.candidate_selector_available =
        selector.fallback_kernel_validated &&
        selector.selector_replace_validated;
#if defined(RASPI_COMPILE)
    // These three flags describe concrete code which is linked into the
    // target.  They remain independently blocked by the selector, tryboot,
    // watchdog and FatFs durability evidence above.
    readiness.stable_kernel_layout = true;
    readiness.prepared_config_builder_available = true;
#if defined(BMX_UPDATE_ENABLE_TARGET_UI)
    // This gate may be opened only after the long-running target path has a
    // responsive progress/cancel UI and the complete foreground integration
    // has passed its hardware matrix.  The concrete synchronous composition
    // exists regardless, but that alone is not a release-readiness claim.
    readiness.target_orchestrator_available = true;
#elif defined(BMX_UPDATE_ENABLE_OWNER_DRAFT_UI)
    // A production release keeps the concrete path available only for a
    // locally ticketed owner draft.  Normal stable discovery/install remains
    // closed until BMX_UPDATE_TARGET_UI_VALIDATED is an established fact.
    readiness.target_orchestrator_available = prepared_draft;
#endif
#endif
    return readiness;
}

}  // namespace

void ArmCandidateUpdateWatchdogBeforeRuntime(
    CandidateUpdateWatchdog *watchdog) {
    if (g_candidate_boot_guard_attempted) return;
    // Latch before reading the DTB or touching the watchdog.  Re-entry must
    // never replace the boot-lifetime owner or retrigger a foreign timer.
    g_candidate_boot_guard_attempted = true;
    g_candidate_boot_watchdog = watchdog;
    g_candidate_boot_observed = RunningBootWasOneShotTryboot();
    if (!g_candidate_boot_observed) return;
    if (watchdog == 0) {
        RequestEarlyPreviousBootFailSafe();
        return;
    }
    g_candidate_boot_watchdog_start_result = watchdog->StartForRecovery();
    g_candidate_boot_watchdog_armed =
        g_candidate_boot_watchdog_start_result ==
        CandidateUpdateWatchdogStartResult::Owned;
    if (!g_candidate_boot_watchdog_armed) {
        // ForeignRunning is deliberately not adopted or fed.  A genuine
        // start failure and a foreign owner are both unsafe candidate guards,
        // so immediately request the already-cleared normal boot path.
        RequestEarlyPreviousBootFailSafe();
    }
}

bool ReadInstalledVersionForMenu(char *version, unsigned version_size) {
    if (version == 0 || version_size == 0U || !AllocateState() ||
        ReadInstalledBuild() != LocalReadStatus::Ok) return false;
    InstalledBuildInfo installed;
    JsonParseResult json;
    if (ParseBuildInfo(ByteView(g_state.installed_bytes, g_state.installed_size),
                       g_state.installed_tokens, 2048U, &installed, &json) !=
        BuildInfoStatus::Ok) return false;
    const size_t length = strlen(installed.version);
    if (length + 1U > version_size) return false;
    memcpy(version, installed.version, length + 1U);
    return true;
}

bool ReportCandidateUpdateBootProgress(
    CandidateUpdateBootMilestone milestone) {
    if (g_candidate_boot_observed &&
        milestone == CandidateUpdateBootMilestone::LoggerReady) {
        // The logger now owns its final serial/null sink, while filesystem
        // recovery has not started.  An instrumented candidate can therefore
        // arm a relay before its first persistent recovery transition.
        LogUpdateFaultInjectionBootConfiguration();
    }
    if (!g_candidate_boot_observed) return true;
    if (g_candidate_boot_progress_failed) return false;
    CandidateUpdateWatchdog *watchdog = g_candidate_boot_watchdog;
    if (!g_candidate_boot_guard_attempted ||
        !g_candidate_boot_watchdog_armed || watchdog == 0 ||
        !watchdog->owned() || !watchdog->IsRunning() ||
        !watchdog->RefreshForRecovery()) {
        g_candidate_boot_progress_failed = true;
        RequestEarlyPreviousBootFailSafe();
        return false;
    }
    return true;
}

int PreparedDraftTestAvailableForMenu() {
#if !defined(BMX_UPDATE_ENABLE_OWNER_DRAFT_UI)
    return 0;
#else
    DraftTestTicket ticket;
    return !kGitHubReleaseChannelIsTest &&
                   LoadDraftTestTicket(&ticket) == DraftTestTicketStatus::Ok
               ? 1 : 0;
#endif
}

int BeginPreparedDraftTestFromMenu(char *message, unsigned message_size) {
    if (message == 0 || message_size == 0U) return -1;
    message[0] = '\0';
    g_state.offer_valid = false;
    g_state.config_consent_valid = false;
    ClearDraftAuthorization();
#if !defined(BMX_UPDATE_ENABLE_OWNER_DRAFT_UI)
    Message(message, message_size,
            "Prepared-draft testing is not enabled for this build.");
    return -1;
#endif
    if (kGitHubReleaseChannelIsTest) {
        Message(message, message_size,
                "Prepared production drafts cannot be tested by a non-production update-channel build.");
        return -1;
    }
    bool network_feature_enabled = false;
    bool network_ready = false;
    if (!ReadNetworkFeatureState(&network_feature_enabled, &network_ready) ||
        !network_feature_enabled || !network_ready) {
        Message(message, message_size,
                "Network is disabled or not ready. No GitHub authorization was started.");
        return -1;
    }
    CNetSubSystem *network = GetActiveNetworkSubsystem();
    UpdateForegroundProgress *progress = ActiveMenuUpdateForegroundProgress();
    if (network == 0 || !network->IsRunning() || progress == 0 ||
        !AllocateState() || ReadInstalledBuild() != LocalReadStatus::Ok) {
        Message(message, message_size,
                "The prepared-draft test could not initialize its local update state.");
        return -1;
    }
    InstalledBuildInfo installed;
    JsonParseResult json;
    if (ParseBuildInfo(ByteView(g_state.installed_bytes, g_state.installed_size),
                       g_state.installed_tokens, 2048U, &installed, &json) !=
            BuildInfoStatus::Ok ||
        installed.board != RunningBoard() || CompiledUpdaterAbi() == 0U ||
        CompiledUpdaterAbi() != installed.updater_abi) {
        Message(message, message_size,
                "Installed BMX update metadata is invalid; draft testing is blocked.");
        return -1;
    }
    if (LoadDraftTestTicket(&g_state.draft_ticket) !=
        DraftTestTicketStatus::Ok) {
        Message(message, message_size,
                "The local prepared-draft ticket is missing, expired or invalid.");
        return -1;
    }
    const uint64_t minimum_epoch =
        installed.release_epoch > g_state.draft_ticket.issued_epoch
            ? installed.release_epoch : g_state.draft_ticket.issued_epoch;
    char clock_error[128U];
    if (!EnsureCertificateClockAtLeast(minimum_epoch, clock_error,
                                       sizeof(clock_error)) ||
        LoadDraftTestTicket(&g_state.draft_ticket) !=
            DraftTestTicketStatus::Ok) {
        Message(message, message_size,
                "Prepared-draft test blocked by its signed time limit.");
        return -1;
    }
    CircleSecureStreamFactory factory(network, minimum_epoch);
    const GitHubDeviceFlowResult device = RequestGitHubDeviceCode(
        g_state.draft_ticket.github_app_client_id, &factory,
        g_state.https_workspace, g_state.github_bytes,
        kMaximumGitHubReleaseResponseBytes, g_state.github_tokens, 16384U,
        &g_state.device_authorization, progress);
    SecureZero(g_state.github_bytes, kMaximumGitHubReleaseResponseBytes);
    if (device.status != GitHubDeviceFlowStatus::Ok) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "GitHub device authorization could not start: %s",
                GitHubDeviceFlowStatusString(device.status));
        return -1;
    }
    const uint64_t now = CurrentUniversalEpoch();
    g_state.device_authorization_deadline_epoch =
        now + g_state.device_authorization.expires_in_seconds;
    g_state.device_authorization_next_poll_epoch =
        now + g_state.device_authorization.polling_interval_seconds;
    g_state.device_authorization_pending = true;
    snprintf(message, message_size,
             "Open github.com/login/device and enter code %s. Authorize read-only access to kdre/bmx, then select Continue. Draft: %s. TLS chain and hostname are verified; certificate time uses BMX's signed time floor.",
             g_state.device_authorization.user_code,
             g_state.draft_ticket.tag);
    message[message_size - 1U] = '\0';
    return 1;
}

int FinishPreparedDraftOffer(const ReleaseClientResult &result,
                             char *message, unsigned message_size) {
    if (result.status != ReleaseClientStatus::Ok) {
        ClearDraftAuthorization();
        return ReportClientFailure(result, message, message_size);
    }
    char config_detail[160U];
    const CurrentConfigStatus config =
        AssessCurrentConfiguration(config_detail, sizeof(config_detail));
    if (config != CurrentConfigStatus::Ok) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "Draft update blocked by local configuration: %s",
                config_detail[0] != '\0' ? config_detail
                                         : CurrentConfigStatusString(config));
        return -1;
    }
    FatFsUpdateFileSystem *file_system = new FatFsUpdateFileSystem("SYS:");
    if (file_system == 0) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "Not enough memory for the draft installation check.");
        return -1;
    }
    const UpdateInstallReadinessResult readiness = ProbeUpdateInstallReadiness(
        file_system, &g_state.download.offer.manifest,
        ProductionInstallPlatformReadiness(true));
    delete file_system;
    if (!readiness.ready()) {
        ClearDraftAuthorization();
        if (!FormatUpdateInstallReadinessForRelease(
                readiness, g_state.download.offer.manifest.version,
                message, message_size)) {
            Message(message, message_size,
                    "Prepared draft is authentic but this installation is not ready for online update.");
        }
        return 0;
    }
    g_state.offer_valid = true;
    const ReleaseOffer &offer = g_state.download.offer;
    if (offer.configuration_status ==
        OfferConfigurationStatus::ResetConfirmationRequired) {
        if (!FormatConfigResetWarning(
                g_state.config_plan, offer.manifest.lossy_changes,
                offer.manifest.lossy_change_count, message, message_size)) {
            ClearDraftAuthorization();
            g_state.offer_valid = false;
            Message(message, message_size,
                    "Draft update requires a configuration reset, but its warning could not be displayed safely.");
            return -1;
        }
        return 2;
    }
    const unsigned download_mib = static_cast<unsigned>(
        (offer.manifest.asset.download_size + 1024U * 1024U - 1U) /
        (1024U * 1024U));
    snprintf(message, message_size,
             "Prepared draft BMX %s is available. Installed: %s. Download size: %u MiB.",
             offer.manifest.version, offer.installed.version, download_mib);
    message[message_size - 1U] = '\0';
    return 1;
}

int CompletePreparedDraftTestFromMenu(char *message,
                                      unsigned message_size) {
    if (message == 0 || message_size == 0U) return -1;
    message[0] = '\0';
    if (!g_state.device_authorization_pending) {
        Message(message, message_size,
                "No prepared-draft GitHub authorization is pending.");
        return -1;
    }
    bool network_feature_enabled = false;
    bool network_ready = false;
    CNetSubSystem *network = GetActiveNetworkSubsystem();
    UpdateForegroundProgress *progress = ActiveMenuUpdateForegroundProgress();
    if (!ReadNetworkFeatureState(&network_feature_enabled, &network_ready) ||
        !network_feature_enabled || !network_ready || network == 0 ||
        !network->IsRunning() || progress == 0) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "Network became unavailable; draft authorization was discarded.");
        return -1;
    }
    const uint64_t now = CurrentUniversalEpoch();
    if (now == 0U || now > g_state.device_authorization_deadline_epoch) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "The GitHub device code expired. Start the draft test again.");
        return -1;
    }
    if (now < g_state.device_authorization_next_poll_epoch) {
        snprintf(message, message_size,
                 "GitHub authorization is waiting for its polling interval. Complete authorization at github.com/login/device with code %s, wait a moment, then select Continue again.",
                 g_state.device_authorization.user_code);
        message[message_size - 1U] = '\0';
        return 3;
    }
    DraftTestTicket current_ticket;
    if (LoadDraftTestTicket(&current_ticket) != DraftTestTicketStatus::Ok ||
        memcmp(&current_ticket, &g_state.draft_ticket,
               sizeof(current_ticket)) != 0) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "The prepared-draft ticket changed during authorization.");
        return -1;
    }
    CircleSecureStreamFactory factory(network, current_ticket.issued_epoch);
    const GitHubDeviceFlowResult token = ExchangeGitHubDeviceCode(
        current_ticket.github_app_client_id,
        g_state.device_authorization.device_code, &factory,
        g_state.https_workspace, g_state.github_bytes,
        kMaximumGitHubReleaseResponseBytes, g_state.github_tokens, 16384U,
        g_state.access_token, sizeof(g_state.access_token), progress);
    SecureZero(g_state.github_bytes, kMaximumGitHubReleaseResponseBytes);
    if (token.status == GitHubDeviceFlowStatus::AuthorizationPending ||
        token.status == GitHubDeviceFlowStatus::SlowDown) {
        if (token.status == GitHubDeviceFlowStatus::SlowDown &&
            g_state.device_authorization.polling_interval_seconds <= 55U) {
            g_state.device_authorization.polling_interval_seconds += 5U;
        }
        g_state.device_authorization_next_poll_epoch =
            now + g_state.device_authorization.polling_interval_seconds;
        snprintf(message, message_size,
                 "GitHub authorization is not complete. Open github.com/login/device, enter %s, authorize, then select Continue again.",
                 g_state.device_authorization.user_code);
        message[message_size - 1U] = '\0';
        return 3;
    }
    if (token.status != GitHubDeviceFlowStatus::Ok) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "GitHub draft authorization failed: %s",
                GitHubDeviceFlowStatusString(token.status));
        return -1;
    }
    SecureZero(&g_state.device_authorization,
               sizeof(g_state.device_authorization));
    g_state.device_authorization_pending = false;
    g_state.device_authorization_deadline_epoch = 0U;
    g_state.device_authorization_next_poll_epoch = 0U;

    if (ReadInstalledBuild() != LocalReadStatus::Ok) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "Installed update metadata became unavailable.");
        return -1;
    }
    InstalledBuildInfo installed;
    JsonParseResult json;
    if (ParseBuildInfo(ByteView(g_state.installed_bytes, g_state.installed_size),
                       g_state.installed_tokens, 2048U, &installed, &json) !=
            BuildInfoStatus::Ok || installed.board != RunningBoard()) {
        ClearDraftAuthorization();
        Message(message, message_size,
                "Installed update metadata became invalid.");
        return -1;
    }
    size_t key_count = 0U;
    const TrustedReleaseKey *keys = ReleaseTrustStore(&key_count);
    const UpdateStartContext start = {
        UpdateInvocation::ConfirmedUpdateMenuAction,
        network_feature_enabled, network_ready};
    const ReleaseClientBuffers buffers = {
        g_state.github_bytes, kMaximumGitHubReleaseResponseBytes,
        g_state.manifest_bytes, kMaximumReleaseManifestBytes,
        g_state.signature_bytes, kMaximumSignatureEnvelopeBytes};
    const ReleaseClientResult result = CheckPreparedDraftRelease(
        start, current_ticket, g_state.access_token,
        ByteView(g_state.installed_bytes, g_state.installed_size),
        RunningBoard(), keys, key_count, VerifyP256SignatureMbedTls, 0,
        &factory, g_state.https_workspace, buffers, OfferStorage(),
        &g_state.download, progress);
    return FinishPreparedDraftOffer(result, message, message_size);
}

void CancelPendingUpdateFromMenu() {
    g_state.offer_valid = false;
    g_state.config_consent_valid = false;
    ClearDraftAuthorization();
}

int CheckForUpdateFromMenu(char *message, unsigned message_size) {
    if (message == 0 || message_size == 0U) return -1;
    message[0] = '\0';
    // This function is reachable only from the explicit System > Update...
    // action. The best-effort local record performs no network operation and
    // is never written merely by opening or navigating the menu.
    RecordLocal(UpdateLocalLogScope::Online,
                UpdateLocalLogCode::OnlineRequested);
    g_state.offer_valid = false;
    g_state.config_consent_valid = false;
    ClearDraftAuthorization();
#if !defined(BMX_UPDATE_ENABLE_TARGET_UI)
    // Discovery is synchronous on the current menu integration.  Keep even
    // its read-only HTTPS path closed until the target build explicitly
    // certifies a responsive progress/cancel UI; otherwise a single click
    // could block the menu for the transport deadline.  This check precedes
    // all network lookup and allocation.
    Message(message, message_size,
            "Online update is not enabled for this build because the target progress/cancel UI has not been validated. Use the normal GitHub release ZIP for a manual update.");
    return -1;
#endif
    bool network_feature_enabled = false;
    bool network_ready = false;
    if (!ReadNetworkFeatureState(&network_feature_enabled, &network_ready) ||
        !network_feature_enabled || !network_ready) {
        RecordLocal(UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ErrorNetwork);
        Message(message, message_size,
                "Network is disabled or not ready. No update check was made.");
        return -1;
    }
    CNetSubSystem *network = GetActiveNetworkSubsystem();
    if (network == 0 || !network->IsRunning()) {
        RecordLocal(UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ErrorNetwork);
        Message(message, message_size,
                "Network is disabled or not ready. No update check was made.");
        return -1;
    }
    UpdateForegroundProgress *foreground_progress =
        ActiveMenuUpdateForegroundProgress();
    if (foreground_progress == 0) {
        Message(message, message_size,
                "The explicit foreground update session is unavailable. No update check was made.");
        return -1;
    }
    if (!AllocateState()) {
        RecordLocal(UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ErrorInternal);
        Message(message, message_size,
                "Not enough memory to check for an update.");
        return -1;
    }
    const LocalReadStatus local = ReadInstalledBuild();
    if (local == LocalReadStatus::Missing) {
        Message(message, message_size,
                "This is a legacy BMX installation. Install the first updater-capable bootstrap ZIP manually from github.com/kdre/bmx/releases; no files were changed.");
        return 0;
    }
    if (local != LocalReadStatus::Ok) {
        Message(message, message_size,
                "BMX-BUILD.json is invalid or unreadable; online update is blocked.");
        return -1;
    }

    InstalledBuildInfo installed;
    JsonParseResult json;
    const BuildInfoStatus build_status = ParseBuildInfo(
        ByteView(g_state.installed_bytes, g_state.installed_size),
        g_state.installed_tokens, 2048U, &installed, &json);
    if (build_status != BuildInfoStatus::Ok ||
        installed.board != RunningBoard()) {
        Message(message, message_size,
                "Installed update metadata is invalid or belongs to another board.");
        return -1;
    }
    if (CompiledUpdaterAbi() == 0U ||
        CompiledUpdaterAbi() != installed.updater_abi) {
        Message(message, message_size,
                "The running updater ABI does not match BMX-BUILD.json; online update is blocked. Reinstall the normal GitHub release ZIP manually.");
        return -1;
    }
    char clock_error[128];
    clock_error[0] = '\0';
    if (!EnsureCertificateClockAtLeast(installed.release_epoch, clock_error,
                                       sizeof(clock_error))) {
        Message(message, message_size, "Update check blocked: %s", clock_error);
        return -1;
    }

    size_t key_count = 0U;
    const TrustedReleaseKey *keys = ReleaseTrustStore(&key_count);
    CircleSecureStreamFactory factory(network, installed.release_epoch);
    const UpdateStartContext start = {
        UpdateInvocation::ConfirmedUpdateMenuAction,
        network_feature_enabled, network_ready};
    const ReleaseClientBuffers buffers = {
        g_state.github_bytes, kMaximumGitHubReleaseResponseBytes,
        g_state.manifest_bytes, kMaximumReleaseManifestBytes,
        g_state.signature_bytes, kMaximumSignatureEnvelopeBytes};
    RecordLocal(UpdateLocalLogScope::Online,
                UpdateLocalLogCode::OnlineDiscoveryStarted);
    const ReleaseClientResult result = CheckLatestRelease(
        start, ByteView(g_state.installed_bytes, g_state.installed_size),
        RunningBoard(), keys, key_count, VerifyP256SignatureMbedTls, 0,
        &factory, g_state.https_workspace, buffers, OfferStorage(),
        &g_state.download, foreground_progress);
    if (result.status != ReleaseClientStatus::Ok) {
        if (result.status == ReleaseClientStatus::Canceled) {
            RecordLocal(UpdateLocalLogScope::Online,
                        UpdateLocalLogCode::ResultOnlineCanceled);
            Message(message, message_size,
                    "Update check canceled. No update files were downloaded or changed.");
            return 0;
        }
        UpdateLocalLogCode code = UpdateLocalLogCode::ErrorInternal;
        if (result.status == ReleaseClientStatus::DiscoveryDownloadFailed ||
            result.status == ReleaseClientStatus::ManifestDownloadFailed ||
            result.status == ReleaseClientStatus::SignatureDownloadFailed) {
            code = UpdateLocalLogCode::ErrorNetwork;
        } else if (result.status == ReleaseClientStatus::OfferInvalid &&
                   result.offer_result.status ==
                       ReleaseOfferStatus::ReleaseRejected) {
            code = UpdateLocalLogCode::ResultOnlineCompleted;
        } else if (result.status == ReleaseClientStatus::OfferInvalid &&
                   result.offer_result.status ==
                       ReleaseOfferStatus::OnlineSourceUnsupported) {
            code = UpdateLocalLogCode::ResultOnlineCompleted;
        } else if (result.status == ReleaseClientStatus::OfferInvalid) {
            code = UpdateLocalLogCode::ErrorAuthentication;
        }
        RecordLocal(UpdateLocalLogScope::Online, code);
        return ReportClientFailure(result, message, message_size);
    }
    RecordLocal(UpdateLocalLogScope::Online,
                UpdateLocalLogCode::OnlineDiscoveryAccepted);
    char config_detail[160];
    const CurrentConfigStatus config =
        AssessCurrentConfiguration(config_detail, sizeof(config_detail));
    if (config != CurrentConfigStatus::Ok) {
        RecordLocal(UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ErrorConfiguration);
        const char *reason = config_detail[0] != '\0'
                                 ? config_detail
                                 : CurrentConfigStatusString(config);
        Message(message, message_size,
                "Update blocked by local configuration: %s", reason);
        return -1;
    }

    // Do not offer an Install confirmation for a build that cannot safely
    // execute it.  This remains after authenticated discovery/config
    // assessment so the explicit menu action can still report which version
    // exists, but the probe itself is read-only and precedes any ZIP download.
    FatFsUpdateFileSystem *readiness_file_system =
        new FatFsUpdateFileSystem("SYS:");
    if (readiness_file_system == 0) {
        Message(message, message_size,
                "Not enough memory for the read-only installation check.");
        return -1;
    }
    const UpdateInstallReadinessResult readiness = ProbeUpdateInstallReadiness(
        readiness_file_system, &g_state.download.offer.manifest,
        ProductionInstallPlatformReadiness(false));
    delete readiness_file_system;
    if (!readiness.ready()) {
        RecordLocal(UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ErrorPrecondition);
        const char *version = g_state.download.offer.manifest.version;
        if (!FormatUpdateInstallReadinessForRelease(
                readiness, version, message, message_size)) {
            snprintf(message, message_size,
                     "BMX %s is available, but online install is blocked before ZIP download/write by the storage, durability, tryboot, recovery, selector and configuration safety gate. Use the normal GitHub release ZIP manually.",
                     version);
            message[message_size - 1U] = '\0';
        }
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return 0;
    }
    g_state.offer_valid = true;

    const ReleaseOffer &offer = g_state.download.offer;
    const unsigned download_mib = static_cast<unsigned>(
        (offer.manifest.asset.download_size + 1024U * 1024U - 1U) /
        (1024U * 1024U));
    if (offer.configuration_status ==
        OfferConfigurationStatus::ResetConfirmationRequired) {
        if (!FormatConfigResetWarning(
                g_state.config_plan, offer.manifest.lossy_changes,
                offer.manifest.lossy_change_count, message, message_size)) {
            Message(message, message_size,
                    "Update requires a configuration reset, but its warning could not be represented safely.");
            g_state.offer_valid = false;
            return -1;
        }
        return 2;
    }
    snprintf(message, message_size,
             "BMX %s is available. Installed: %s. Download size: %u MiB.",
             offer.manifest.version, offer.installed.version, download_mib);
    message[message_size - 1U] = '\0';
    return 1;
}

int InstallCheckedUpdateFromMenu(bool destructive_reset_consent,
                                 char *message, unsigned message_size) {
    if (message == 0 || message_size == 0U) return -1;
    DraftAuthorizationCleanup draft_authorization_cleanup;
    message[0] = '\0';
    if (!g_state.offer_valid) {
        Message(message, message_size,
                "No authenticated update offer is pending. Run Update again.");
        return -1;
    }
    bool network_feature_enabled = false;
    bool network_ready = false;
    if (!ReadNetworkFeatureState(&network_feature_enabled, &network_ready) ||
        !network_feature_enabled || !network_ready) {
        Message(message, message_size,
                "Network became disabled or unavailable; no installation was started.");
        return -1;
    }
    CNetSubSystem *network = GetActiveNetworkSubsystem();
    if (network == 0 || !network->IsRunning()) {
        Message(message, message_size,
                "Network became unavailable; no installation was started.");
        return -1;
    }
    UpdateForegroundProgress *foreground_progress =
        ActiveMenuUpdateForegroundProgress();
    if (foreground_progress == 0) {
        Message(message, message_size,
                "The explicit foreground update session is unavailable; no installation was started.");
        return -1;
    }
    if (!g_state.config_consent_valid) {
        Message(message, message_size,
                "Configuration consent state is missing. Run Update again.");
        g_state.offer_valid = false;
        return -1;
    }
    size_t key_count = 0U;
    const TrustedReleaseKey *keys = ReleaseTrustStore(&key_count);
    if (keys == 0 || key_count == 0U) {
        Message(message, message_size,
                "No trusted release key is available; no installation was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    // Authenticate the still-pending raw offer again before the confirmed
    // action is allowed to retire an older rollback snapshot. Start() repeats
    // this boundary once more immediately before download.
    RawAuthenticatedReleaseValidator pending_validator(
        keys, key_count, VerifyP256SignatureMbedTls, 0, OfferStorage());
    const AuthenticatedReleaseValidationResult pending_validation =
        pending_validator.Revalidate(g_state.download, RunningBoard(),
                                     &g_state.download.offer);
    if (pending_validation.status !=
        AuthenticatedReleaseValidationStatus::Ok) {
        Message(message, message_size,
                "The pending release could not be authenticated again; no files were changed.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    uint8_t consent_before[kSha256DigestBytes];
    memcpy(consent_before, g_state.config_consent_sha256,
           sizeof(consent_before));
    const size_t reset_count_before = g_state.config_plan.reset_count;
    char config_detail[160];
    const CurrentConfigStatus config =
        AssessCurrentConfiguration(config_detail, sizeof(config_detail));
    if (config != CurrentConfigStatus::Ok ||
        !ConstantTimeDigestEqual(consent_before,
                                 g_state.config_consent_sha256) ||
        reset_count_before != g_state.config_plan.reset_count) {
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        Message(message, message_size,
                "Configuration changed after the warning. No files were changed; run Update again to reclassify it.");
        return -1;
    }
    const bool reset_required = g_state.config_plan.reset_count != 0U;
    if (reset_required && !destructive_reset_consent) {
        Message(message, message_size,
                "Configuration reset consent was not supplied; no installation was started.");
        return -1;
    }

    if (CompiledUpdaterAbi() !=
            g_state.download.offer.installed.updater_abi) {
        Message(message, message_size,
                "The running updater ABI does not match the authenticated installed metadata; no installation was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }

    LocalLogOwner online_log;
    online_log.Start(UpdateLocalLogScope::Online, foreground_progress);
    if (online_log.log() != 0) {
        online_log.log()->Record(UpdateLocalLogScope::Online,
                                 UpdateLocalLogCode::OnlineInstallConfirmed);
    }
    UpdateOrchestratorWorkspace workspace = ServiceOrchestratorWorkspace();
    workspace.recovery_progress = online_log.progress(foreground_progress);
    // First inspect all fixed state names read-only. A retained COMMITTED
    // transaction is inert; a live activation still belongs to boot recovery
    // and must never be displaced by a foreground update.
    FatFsUpdateFileSystem *file_system = new FatFsUpdateFileSystem("SYS:");
    if (file_system == 0) {
        Message(message, message_size,
                "Not enough memory for the read-only installation check; no files were changed.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    UpdateFileStat pending = UpdateFileStat();
    UpdateFileStat committed = UpdateFileStat();
    UpdateFileStat retiring = UpdateFileStat();
    const bool pending_probe =
        file_system->Stat(kUpdateTransactionActivationPath, &pending) &&
        file_system->Stat(kUpdateTransactionCommittedPath, &committed) &&
        file_system->Stat(kUpdateTransactionRetiringPath, &retiring);
    const bool committed_valid =
        committed.type == UpdateNodeType::Missing ||
        (committed.type == UpdateNodeType::RegularFile &&
         committed.size == kPersistedUpdateRequestStateBytes);
    const bool retiring_valid =
        retiring.type == UpdateNodeType::Missing ||
        (retiring.type == UpdateNodeType::RegularFile &&
         retiring.size == kPersistedUpdateRequestStateBytes);
    if (!pending_probe || pending.type != UpdateNodeType::Missing ||
        !committed_valid || !retiring_valid ||
        (committed.type != UpdateNodeType::Missing &&
         retiring.type != UpdateNodeType::Missing)) {
        delete file_system;
        Message(message, message_size,
                pending_probe && pending.type != UpdateNodeType::Missing
                    ? "A previous update transaction is still active. Reboot once to run local recovery before starting another update."
                    : "The retained previous-update state is missing, malformed or ambiguous; no download or write was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    const bool retained_transaction_present =
        committed.type != UpdateNodeType::Missing ||
        retiring.type != UpdateNodeType::Missing;
    delete file_system;

    RetainedUpdateStateConsentEvidence retirement_evidence;
    if (retained_transaction_present) {
        const RetainedUpdateStateConsentStatus captured =
            CaptureRetainedUpdateStateConsentEvidence(
                g_state.config_snapshot.snapshot(), g_state.config_plan,
                &retirement_evidence);
        if (captured != RetainedUpdateStateConsentStatus::Ok) {
            if (online_log.log() != 0) {
                online_log.log()->Record(UpdateLocalLogScope::Online,
                                         UpdateLocalLogCode::ErrorConfiguration);
            }
            Message(message, message_size,
                    "The confirmed configuration could not be bound safely across previous-backup cleanup. No files were changed; run Update again.");
            g_state.offer_valid = false;
            g_state.config_consent_valid = false;
            return -1;
        }
    }

    const RetainedTransactionRetireStatus retired =
        RetirePreviousTransaction(keys, key_count, workspace);
    if (retired == RetainedTransactionRetireStatus::Failed) {
        if (foreground_progress->cancel_requested()) {
            if (online_log.log() != 0) {
                online_log.log()->Record(
                    UpdateLocalLogScope::Online,
                    UpdateLocalLogCode::ResultOnlineCanceled);
            }
            Message(message, message_size,
                    "Update canceled at a safe retention checkpoint. No new ZIP download was started; any partial inert cleanup remains locally retryable.");
            g_state.offer_valid = false;
            g_state.config_consent_valid = false;
            return 0;
        }
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ErrorStorage);
        }
        Message(message, message_size,
                "The retained previous rollback/configuration backup could not be retired safely. No new ZIP download was started; choose Update again to retry the inert local cleanup.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    if (retained_transaction_present &&
        retired != RetainedTransactionRetireStatus::Retired) {
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ErrorInternal);
        }
        Message(message, message_size,
                "The retained previous-update state changed unexpectedly. No new ZIP was downloaded; run Update again.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }

    // Retirement reuses the bounded parser arrays, so restore the pending
    // authenticated offer before any readiness or Start input consumes its
    // manifest inventory.
    const AuthenticatedReleaseValidationResult restored_validation =
        pending_validator.Revalidate(g_state.download, RunningBoard(),
                                     &g_state.download.offer);
    if (restored_validation.status !=
        AuthenticatedReleaseValidationStatus::Ok) {
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ErrorAuthentication);
        }
        Message(message, message_size,
                "The previous backup was retired as confirmed, but the pending release could not be authenticated again. No new ZIP was downloaded.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }

    // Retiring the inert previous transaction deliberately removes the two
    // internal journals covered by UpdateState's consent hash. Recompute and
    // rebind only after proving that BMX-BUILD.json and every user-owned
    // configuration assessment are unchanged and that no journal remains.
    if (retired == RetainedTransactionRetireStatus::Retired) {
        const CurrentConfigStatus reassessed =
            AssessCurrentConfiguration(config_detail, sizeof(config_detail));
        const RetainedUpdateStateConsentStatus transition =
            reassessed == CurrentConfigStatus::Ok
                ? ValidateRetainedUpdateStateConsentTransition(
                      retirement_evidence,
                      g_state.config_snapshot.snapshot(), g_state.config_plan)
                : RetainedUpdateStateConsentStatus::ConfigurationChanged;
        if (transition != RetainedUpdateStateConsentStatus::Ok) {
            if (online_log.log() != 0) {
                online_log.log()->Record(UpdateLocalLogScope::Online,
                                         UpdateLocalLogCode::ErrorConfiguration);
            }
            Message(message, message_size,
                    "Configuration changed unexpectedly while the previous backup was retired. No new ZIP was downloaded; run Update again to review it.");
            g_state.offer_valid = false;
            g_state.config_consent_valid = false;
            return -1;
        }
    }

    // Re-read actual free space and all platform gates after retirement and
    // before constructing a download sink. Stock FatFs still reports both
    // crash-safe rename guarantees false unless the platform validation gate
    // explicitly proves its lower layer.
    const bool prepared_draft = g_state.download.acquisition_mode ==
                                ReleaseAcquisitionMode::PreparedDraft;
    file_system = new FatFsUpdateFileSystem("SYS:");
    if (file_system == 0) {
        Message(message, message_size,
                "Not enough memory for the final read-only installation check; no new ZIP was downloaded.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    const UpdateInstallReadinessResult readiness = ProbeUpdateInstallReadiness(
        file_system, &g_state.download.offer.manifest,
        ProductionInstallPlatformReadiness(prepared_draft));
    delete file_system;
    if (!readiness.ready()) {
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ErrorStorage);
        }
        if (!FormatUpdateInstallReadiness(readiness, message, message_size)) {
            Message(message, message_size,
                    "Online install blocked before download/write by the storage, durability, tryboot, recovery, selector and configuration safety gate. Use the normal GitHub release ZIP for a manual update.");
        }
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    if (prepared_draft && g_state.access_token[0] == '\0') {
        Message(message, message_size,
                "The temporary GitHub draft authorization is unavailable; no installation was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }
    StartComposition *composition = new StartComposition(
        network, g_state.download.offer.installed.release_epoch,
        keys, key_count, workspace,
        ProductionInstallPlatformReadiness(prepared_draft),
        foreground_progress, prepared_draft ? g_state.access_token : 0,
        prepared_draft);
    if (composition == 0) {
        delete composition;
        Message(message, message_size,
                "Not enough memory or no trusted release key is available; no installation was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }

    AuthenticatedUpdateRequest request;
    memset(&request, 0, sizeof(request));
    request.release = &g_state.download;
    request.running_board = RunningBoard();
    request.transaction_root = kUpdateTransactionRoot;
    request.old_boot_generation =
        g_state.download.offer.installed.release_sequence;
    request.new_boot_generation =
        g_state.download.offer.manifest.release_sequence;
    memcpy(request.consent_sha256, g_state.config_consent_sha256,
           kSha256DigestBytes);
    request.reset_required = reset_required;
    request.reset_approved = reset_required;
    if (!GenerateTransactionId(composition->entropy(),
                               request.transaction_id)) {
        delete composition;
        Message(message, message_size,
                "A secure update transaction ID could not be generated; no installation was started.");
        g_state.offer_valid = false;
        g_state.config_consent_valid = false;
        return -1;
    }

    // Invalidate the menu offer before issuing the one-use foreground
    // capability.  Re-entry can therefore never replay the same confirmation.
    g_state.offer_valid = false;
    g_state.config_consent_valid = false;
    if (!composition->authorization_controller()->
            IssueForConfirmedMenuAction(
                &request.foreground_authorization_token)) {
        delete composition;
        Message(message, message_size,
                "The one-use update authorization could not be issued; no installation was started.");
        return -1;
    }

    const UpdateOrchestratorResult result =
        composition->orchestrator()->Start(request, workspace);
    composition->authorization_controller()->Revoke();
    delete composition;

    if (result.status ==
        UpdateOrchestratorStatus::CandidateRebootRequested) {
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ResultOnlineCompleted);
        }
        Message(message, message_size,
                "The authenticated update was staged and a one-shot candidate reboot was requested.");
        return 0;
    }
    if (result.status == UpdateOrchestratorStatus::ReadinessBlocked &&
        FormatUpdateInstallReadiness(result.readiness, message,
                                     message_size)) {
        if (online_log.log() != 0) {
            online_log.log()->Record(UpdateLocalLogScope::Online,
                                     UpdateLocalLogCode::ErrorStorage);
        }
        return -1;
    }
    if (online_log.log() != 0) {
        const UpdateLocalLogCode code =
            result.status == UpdateOrchestratorStatus::DownloadCanceled
                ? UpdateLocalLogCode::ResultOnlineCanceled
                : result.status ==
                          UpdateOrchestratorStatus::AuthenticatedOfferInvalid
                    ? UpdateLocalLogCode::ErrorAuthentication
                    : result.status == UpdateOrchestratorStatus::DownloadFailed
                        ? UpdateLocalLogCode::ErrorNetwork
                        : UpdateLocalLogCode::ErrorInternal;
        if (code == UpdateLocalLogCode::ErrorInternal &&
            result.status == UpdateOrchestratorStatus::AuthorizationDenied) {
            const uint64_t details =
                static_cast<uint64_t>(result.authorization.status) |
                (static_cast<uint64_t>(result.authorization.start_decision)
                 << 16U) |
                (static_cast<uint64_t>(result.authorization.config_status)
                 << 32U);
            online_log.log()->Record(
                UpdateLocalLogScope::Online,
                UpdateLocalLogCode::ErrorOnlineAuthorization,
                static_cast<uint64_t>(result.status), details);
        } else if (code == UpdateLocalLogCode::ErrorInternal) {
            const uint64_t details =
                static_cast<uint64_t>(result.installer_result.status) |
                (static_cast<uint64_t>(result.rollback_result.status) << 16U) |
                (static_cast<uint64_t>(
                     result.rollback_cleanup_result.status) << 32U);
            online_log.log()->Record(
                UpdateLocalLogScope::Online,
                UpdateLocalLogCode::ErrorOnlineInstallation,
                static_cast<uint64_t>(result.status), details);
        } else {
            online_log.log()->Record(UpdateLocalLogScope::Online, code);
        }
    }
    if (result.status == UpdateOrchestratorStatus::RecoveryProgressFailed &&
        foreground_progress->cancel_requested()) {
        Message(message, message_size,
                "Update canceled at a safe checkpoint. Mandatory local cleanup was completed or left retryable; no candidate boot was requested.");
        return 0;
    }
    if (result.status == UpdateOrchestratorStatus::DownloadCanceled) {
        Message(message, message_size,
                "Update download canceled. The partial archive was not activated and local cleanup was completed or left retryable.");
        return 0;
    }
    if (result.status == UpdateOrchestratorStatus::AuthorizationDenied) {
        snprintf(message, message_size,
                 "Online installation stopped safely in phase %s: %s (authorization=%s, action=%s, config=%s). No download or installer action was started.",
                 UpdateOrchestratorPhaseString(result.phase),
                 UpdateOrchestratorStatusString(result.status),
                 AuthorizationConsentStatusString(result.authorization.status),
                 UpdateStartDecisionString(
                     result.authorization.start_decision),
                 CurrentConfigConsentStatusString(
                     result.authorization.config_status));
        message[message_size - 1U] = '\0';
        return -1;
    }
    snprintf(message, message_size,
             "Online installation stopped safely in phase %s: %s (installer=%s, rollback=%s, cleanup=%s). A pending local transaction, if any, will be handled on the next boot without network access.",
             UpdateOrchestratorPhaseString(result.phase),
             UpdateOrchestratorStatusString(result.status),
             InstallerStatusString(result.installer_result.status),
             InstallerStatusString(result.rollback_result.status),
             InstallerStatusString(result.rollback_cleanup_result.status));
    message[message_size - 1U] = '\0';
    return -1;
}

void RecoverPendingUpdateAfterBoot() {
    if (g_recovery_attempted) return;
    // Latch before the first local read.  A re-entrant boot-complete callback
    // must never execute a second journal transition in the same boot.
    g_recovery_attempted = true;

    const bool firmware_tryboot = g_candidate_boot_guard_attempted
        ? g_candidate_boot_observed
        : RunningBootWasOneShotTryboot();
    CandidateUpdateWatchdog *watchdog = g_candidate_boot_watchdog;

    // A candidate watchdog is armed before any emulator/runtime construction.
    // At this late hook we only prove continued ownership. Refreshes are
    // emitted after successful synchronous progress below; an unconditional
    // entry feed would hide a stalled operation.
    if (firmware_tryboot &&
        (!g_candidate_boot_guard_attempted ||
         !g_candidate_boot_watchdog_armed || watchdog == 0 ||
         !watchdog->owned() || !watchdog->IsRunning())) {
        RequestMinimalPreviousBootFailSafe(
            "early candidate watchdog is unavailable");
        return;
    }

    // Cheap, network-free precheck.  Parser buffers and the full recovery
    // composition are allocated only when the fixed activation record exists.
    FatFsUpdateFileSystem *probe_file_system =
        new FatFsUpdateFileSystem("SYS:");
    if (probe_file_system == 0) {
        if (firmware_tryboot) {
            RequestMinimalPreviousBootFailSafe("precheck allocation failed");
        } else {
            LogRecoveryMessage("update recovery precheck skipped: out of memory");
        }
        return;
    }
    SelectorCandidateBootObservation selector_observation(
        probe_file_system, RunningBoard());
    bool selector_expected = false;
    const bool selector_available =
        selector_observation.ReadCandidateBootExpected(&selector_expected);
    const bool exact_candidate_boot =
        firmware_tryboot && selector_available && selector_expected;

    UpdateFileStat activation;
    const bool activation_probe = probe_file_system->Stat(
        kUpdateTransactionActivationPath, &activation);
    const bool activation_present =
        activation_probe && activation.type != UpdateNodeType::Missing;
    delete probe_file_system;

    CandidateWatchdogRecoveryProgress watchdog_progress(
        watchdog, firmware_tryboot);
    BootRecoveryProgress boot_progress(&watchdog_progress);
    LocalLogOwner recovery_log;
    if (activation_present) {
        // Force a real framebuffer presentation before candidate hashing.
        // circle_boot_complete() runs before the emulator's first normal
        // present, so relying on the main frame loop would leave HDMI black.
        boot_progress.Begin();
        recovery_log.Start(UpdateLocalLogScope::BootRecovery,
                           &boot_progress);
        if (recovery_log.log() != 0) {
            recovery_log.log()->Record(UpdateLocalLogScope::BootRecovery,
                                       UpdateLocalLogCode::RecoveryStarted);
        }
    }
    UpdateRecoveryProgress *recovery_progress =
        recovery_log.progress(&boot_progress);
    if (activation_probe && !ReportUpdateRecoveryProgress(
            recovery_progress,
            UpdateRecoveryProgressKind::RecoveryPrecheck)) {
        RequestEarlyPreviousBootFailSafe();
        return;
    }

    if (!activation_probe) {
        if (firmware_tryboot) {
            RequestMinimalPreviousBootFailSafe(
                "transaction activation record is unreadable");
        } else {
            LogRecoveryMessage(
                "update recovery precheck failed on normal boot");
        }
        return;
    }
    if (!activation_present) {
        if (firmware_tryboot) {
            // A tryboot without an authenticated transaction is never allowed
            // to become the active installation.  A malformed selector is an
            // additional reason to fail safe, not a reason to trust it.
            RequestMinimalPreviousBootFailSafe(
                exact_candidate_boot
                    ? "orphan candidate boot"
                    : "unbound or malformed tryboot candidate");
        }
        return;
    }

    if (!AllocateState()) {
        if (recovery_log.log() != 0) {
            recovery_log.log()->Record(UpdateLocalLogScope::BootRecovery,
                                       UpdateLocalLogCode::ErrorInternal);
        }
        if (firmware_tryboot) {
            RequestMinimalPreviousBootFailSafe(
                "recovery workspace allocation failed");
        } else {
            LogRecoveryMessage(
                "pending update recovery deferred: out of memory");
        }
        return;
    }

    size_t key_count = 0U;
    const TrustedReleaseKey *keys = ReleaseTrustStore(&key_count);
    UpdateOrchestratorWorkspace workspace = ServiceOrchestratorWorkspace();
    workspace.recovery_progress = recovery_progress;
    RecoveryComposition *composition = keys == 0 || key_count == 0U
        ? 0
        : new RecoveryComposition(keys, key_count, workspace, watchdog,
                                  recovery_progress);
    if (composition == 0) {
        if (recovery_log.log() != 0) {
            recovery_log.log()->Record(UpdateLocalLogScope::BootRecovery,
                                       UpdateLocalLogCode::ErrorInternal);
        }
        if (firmware_tryboot) {
            RequestMinimalPreviousBootFailSafe(
                "recovery composition is unavailable");
        } else {
            LogRecoveryMessage(
                "pending update recovery deferred: composition unavailable");
        }
        return;
    }

    const PersistedUpdateRequestBuffers buffers = {
        g_state.installed_bytes, kMaximumBuildInfoBytes,
        g_state.github_bytes, kMaximumGitHubReleaseResponseBytes,
        g_state.manifest_bytes, kMaximumReleaseManifestBytes,
        g_state.signature_bytes, kMaximumSignatureEnvelopeBytes};
    bool cached_candidate_boot = exact_candidate_boot;
    UpdateRecoveryExecutorScratch recovery_scratch;
    recovery_scratch.release_download = &g_state.download;
    UpdateRecoveryExecutor executor(
        composition->request_store(), composition->orchestrator(),
        composition->reboot(), RunningBoard(), buffers, workspace,
        recovery_scratch, ReadCachedCandidateBoot, &cached_candidate_boot);
    const UpdateRecoveryExecutorResult result = executor.Run();

    if (recovery_log.log() != 0) {
        UpdateLocalLogCode code = UpdateLocalLogCode::ErrorRecovery;
        if (result.status ==
            UpdateRecoveryExecutorStatus::NoPendingTransaction) {
            code = UpdateLocalLogCode::ResultRecoveryNoPending;
        } else if (result.status ==
                   UpdateRecoveryExecutorStatus::ResumeFinished) {
            code = UpdateLocalLogCode::ResultRecoveryCompleted;
        } else if (result.status ==
                   UpdateRecoveryExecutorStatus::RejectedStateDiscarded) {
            code = UpdateLocalLogCode::ResultRecoveryRejected;
        } else if (result.status ==
                   UpdateRecoveryExecutorStatus::
                       PreviousBootFailSafeRequested) {
            code = UpdateLocalLogCode::ResultPreviousBootFailSafeRequested;
        } else if (result.status ==
                   UpdateRecoveryExecutorStatus::RecoveryProgressFailed) {
            code = UpdateLocalLogCode::ErrorWatchdog;
        } else if (result.status == UpdateRecoveryExecutorStatus::LoadFailed ||
                   result.status ==
                       UpdateRecoveryExecutorStatus::LoadWorkspaceTooSmall) {
            code = UpdateLocalLogCode::ErrorIntegrity;
        } else if (result.status ==
                   UpdateRecoveryExecutorStatus::DiscardFailed) {
            code = UpdateLocalLogCode::ErrorStorage;
        }
        recovery_log.log()->Record(UpdateLocalLogScope::BootRecovery, code);
    }

#if defined(RASPI_COMPILE)
    CLogger::Get()->Write(
        kUpdateLogSource,
        result.status == UpdateRecoveryExecutorStatus::ResumeFinished
            ? LogNotice : LogWarning,
        "local recovery: %s; load=%s; resume=%s/%s",
        UpdateRecoveryExecutorStatusString(result.status),
        UpdateTransactionStoreStatusString(result.load_status),
        UpdateOrchestratorStatusString(result.resume_status),
        UpdateOrchestratorPhaseString(result.resume_phase));
#endif

    const bool committed =
        result.status == UpdateRecoveryExecutorStatus::ResumeFinished &&
        result.resume_status == UpdateOrchestratorStatus::UpdateCommitted;
#if defined(RASPI_COMPILE)
    const ProductionCandidateConfigurationHealthSource *configuration_health =
        composition->configuration_health();
    if (configuration_health->last_status() !=
            ProductionCandidateConfigurationStatus::InvalidArgument) {
        CLogger::Get()->Write(
            kUpdateLogSource,
            configuration_health->last_status() ==
                    ProductionCandidateConfigurationStatus::Ok
                ? LogNotice : LogWarning,
            "candidate configuration: %s; snapshot=%s; assessment=%s",
            ProductionCandidateConfigurationStatusString(
                configuration_health->last_status()),
            FatFsConfigSnapshotStatusString(
                configuration_health->last_snapshot_status()),
            ConfigAssessmentStatusString(
                configuration_health->last_assessment_status()));
    }
#endif
    if (committed) {
        boot_progress.FinishCommitted();
        if (g_state.download.acquisition_mode ==
                ReleaseAcquisitionMode::PreparedDraft &&
            !RemoveDraftTestTicket()) {
#if defined(RASPI_COMPILE)
            CLogger::Get()->Write(
                kUpdateLogSource, LogWarning,
                "prepared-draft update committed but local ticket cleanup failed");
#endif
        }
    }
    delete composition;
    if (committed &&
        (watchdog == 0 || !watchdog->StopAfterCommit())) {
        if (recovery_log.log() != 0) {
            recovery_log.log()->Record(UpdateLocalLogScope::BootRecovery,
                                       UpdateLocalLogCode::ErrorWatchdog);
        }
#if defined(RASPI_COMPILE)
        CLogger::Get()->Write(
            kUpdateLogSource, LogError,
            "candidate committed but update watchdog did not stop");
#endif
    }
    // On every non-committed candidate result the owned watchdog remains
    // armed.  Its reset follows the firmware-cleared, normal boot path even
    // if an unexpected failure returned without requesting a reboot.
}

}  // namespace update
}  // namespace bmx

extern "C" int emux_update_check_explicit(char *message,
                                            unsigned message_size) {
    return bmx::update::CheckForUpdateFromMenu(message, message_size);
}

extern "C" int emux_update_draft_test_available(void) {
    return bmx::update::PreparedDraftTestAvailableForMenu();
}

extern "C" int emux_update_draft_begin_explicit(char *message,
                                                   unsigned message_size) {
    return bmx::update::BeginPreparedDraftTestFromMenu(message, message_size);
}

extern "C" int emux_update_draft_complete_explicit(
    char *message, unsigned message_size) {
    return bmx::update::CompletePreparedDraftTestFromMenu(message,
                                                           message_size);
}

extern "C" void emux_update_cancel_explicit(void) {
    bmx::update::CancelPendingUpdateFromMenu();
}

extern "C" int emux_update_channel_info(char *label,
                                           unsigned label_size) {
    if (label == 0 || label_size == 0U) return -1;
    const bmx::update::GitHubReleaseChannelInfo channel =
        bmx::update::ConfiguredGitHubReleaseChannel();
    const size_t size = strlen(channel.display_label);
    if (size >= label_size) {
        label[0] = '\0';
        return -1;
    }
    memcpy(label, channel.display_label, size + 1U);
    bmx::update::LogUpdateFaultInjectionConfiguration();
    return channel.is_test ? 1 : 0;
}

extern "C" int emux_update_install_explicit(int destructive_reset_consent,
                                              char *message,
                                              unsigned message_size) {
    return bmx::update::InstallCheckedUpdateFromMenu(
        destructive_reset_consent != 0, message, message_size);
}
