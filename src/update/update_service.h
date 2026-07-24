#ifndef BMX_UPDATE_UPDATE_SERVICE_H
#define BMX_UPDATE_UPDATE_SERVICE_H

namespace bmx {
namespace update {

class CandidateUpdateWatchdog;

enum class CandidateUpdateBootMilestone : unsigned char {
    RuntimeObjectsAllocated = 0,
    BaseRuntimeReady,
    LoggerReady,
    EmulatorCoreReady,
    TimerReady,
    GpioReady,
    VideoReady,
    NetworkReady,
    StorageReady,
    FileSystemReady,
    BootStatReady,
    EmulatorLaunched,
    UsbReady
};

// Called as the first statement after Circle's MachineInfo/DTB and the
// boot-lifetime watchdog owner have been constructed, before emulator/runtime
// objects are created or initialized.  It performs no filesystem, network or
// UI work.  On a validated firmware tryboot it arms the supplied single owner
// so hangs before circle_boot_complete() still reset into the normal path.
void ArmCandidateUpdateWatchdogBeforeRuntime(
    CandidateUpdateWatchdog *watchdog);

// Called synchronously immediately after a successful initialization
// milestone.  Normal boots are a no-op.  A candidate refreshes only the
// watchdog owned by ArmCandidateUpdateWatchdogBeforeRuntime(); failure
// requests the earliest safe previous-boot reboot and returns false.
bool ReportCandidateUpdateBootProgress(
    CandidateUpdateBootMilestone milestone);

// C++ implementation behind the narrow menu ABI. No constructor, boot hook,
// timer or network callback invokes online discovery.
int CheckForUpdateFromMenu(char *message, unsigned message_size);
int PreparedDraftTestAvailableForMenu();
int BeginPreparedDraftTestFromMenu(char *message, unsigned message_size);
int CompletePreparedDraftTestFromMenu(char *message, unsigned message_size);
void CancelPendingUpdateFromMenu();
int InstallCheckedUpdateFromMenu(bool destructive_reset_consent,
                                 char *message, unsigned message_size);
bool ReadInstalledVersionForMenu(char *version, unsigned version_size);

// Called once after the emulator/menu core has reached its local boot-complete
// point.  It performs only fixed-path, network-free transaction recovery and
// never discovers or downloads releases.
void RecoverPendingUpdateAfterBoot();

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_SERVICE_H
