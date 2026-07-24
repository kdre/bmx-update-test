#include "update/update_watchdog.h"

#include "update/update_hardware_test_mode.h"

namespace bmx {
namespace update {

bool UpdateWatchdogHardwareGateEnabled()
{
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_WATCHDOG)
    return true;
#else
    return false;
#endif
}

CandidateUpdateWatchdog::CandidateUpdateWatchdog(
    CandidateUpdateWatchdogDriver *test_driver)
    : test_driver_(test_driver), owned_(false)
{
}

CandidateUpdateWatchdog::~CandidateUpdateWatchdog()
{
    // Never stop here.  See the class contract in the header.
}

CandidateUpdateWatchdogStartResult
CandidateUpdateWatchdog::StartForRecovery()
{
    if (test_driver_ != 0) {
        if (owned_) {
            return test_driver_->IsRunning()
                ? CandidateUpdateWatchdogStartResult::Owned
                : CandidateUpdateWatchdogStartResult::Failed;
        }
        if (test_driver_->IsRunning()) {
            return CandidateUpdateWatchdogStartResult::ForeignRunning;
        }
        test_driver_->StartMaximumTimeout();
        owned_ = test_driver_->IsRunning();
        return owned_ ? CandidateUpdateWatchdogStartResult::Owned
                      : CandidateUpdateWatchdogStartResult::Failed;
    }
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_WATCHDOG)
    if (owned_) {
        return implementation_.IsRunning()
            ? CandidateUpdateWatchdogStartResult::Owned
            : CandidateUpdateWatchdogStartResult::Failed;
    }
    if (implementation_.IsRunning()) {
        return CandidateUpdateWatchdogStartResult::ForeignRunning;
    }
    implementation_.Start(CBcmWatchdog::MaxTimeoutSeconds);
    owned_ = implementation_.IsRunning();
    return owned_ ? CandidateUpdateWatchdogStartResult::Owned
                  : CandidateUpdateWatchdogStartResult::Failed;
#else
    return CandidateUpdateWatchdogStartResult::Failed;
#endif
}

bool CandidateUpdateWatchdog::RefreshForRecovery()
{
    if (test_driver_ != 0) {
        if (!owned_ || !test_driver_->IsRunning()) return false;
        test_driver_->StartMaximumTimeout();
        return test_driver_->IsRunning();
    }
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_WATCHDOG)
    if (!owned_ || !implementation_.IsRunning()) return false;
    implementation_.Start(CBcmWatchdog::MaxTimeoutSeconds);
    return implementation_.IsRunning();
#else
    return false;
#endif
}

bool CandidateUpdateWatchdog::IsRunning() const
{
    if (test_driver_ != 0) {
        return owned_ && test_driver_->IsRunning();
    }
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_WATCHDOG)
    return owned_ && implementation_.IsRunning();
#else
    return false;
#endif
}

bool CandidateUpdateWatchdog::StopAfterCommit()
{
    if (test_driver_ != 0) {
        if (!owned_) return false;
        test_driver_->Stop();
        if (test_driver_->IsRunning()) return false;
        owned_ = false;
        return true;
    }
#if defined(RASPI_COMPILE) && defined(BMX_UPDATE_ENABLE_WATCHDOG)
    if (!owned_) return false;
    implementation_.Stop();
    if (implementation_.IsRunning()) return false;
    owned_ = false;
    return true;
#else
    return false;
#endif
}

const char *CandidateUpdateWatchdogStartResultString(
    CandidateUpdateWatchdogStartResult result)
{
    switch (result) {
    case CandidateUpdateWatchdogStartResult::Owned: return "owned";
    case CandidateUpdateWatchdogStartResult::ForeignRunning:
        return "foreign-running";
    case CandidateUpdateWatchdogStartResult::Failed: return "failed";
    }
    return "unknown";
}

}  // namespace update
}  // namespace bmx
