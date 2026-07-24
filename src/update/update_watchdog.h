#ifndef BMX_UPDATE_UPDATE_WATCHDOG_H
#define BMX_UPDATE_UPDATE_WATCHDOG_H

#include <stdint.h>

#if defined(RASPI_COMPILE)
#include <circle/bcmwatchdog.h>
#endif

namespace bmx {
namespace update {

// Separate evidence gate for the runtime watchdog used while a tryboot
// candidate is validated and committed.  It is intentionally independent of
// the firmware's one-shot tryboot gate.
bool UpdateWatchdogHardwareGateEnabled();

enum class CandidateUpdateWatchdogStartResult : uint8_t {
    Owned = 0,
    ForeignRunning,
    Failed
};

// Narrow injectable boundary used by host tests.  Production leaves this
// null and uses the inline Circle driver below; injection never changes the
// target hardware gate.
class CandidateUpdateWatchdogDriver {
public:
    virtual ~CandidateUpdateWatchdogDriver() {}
    virtual bool IsRunning() const = 0;
    virtual void StartMaximumTimeout() = 0;
    virtual void Stop() = 0;
};

// Single-owner wrapper around Circle's BCM watchdog.  The target driver is an
// inline member so the pre-runtime candidate guard cannot fail because of an
// early heap allocation.  StartForRecovery()
// refuses to take over an already-running watchdog.  Destruction deliberately
// does not stop an owned watchdog: on an unhandled recovery failure it must
// still reset into the already-cleared normal boot path.  Only a completed,
// healthy commit calls StopAfterCommit().
class CandidateUpdateWatchdog {
public:
    explicit CandidateUpdateWatchdog(
        CandidateUpdateWatchdogDriver *test_driver = 0);
    ~CandidateUpdateWatchdog();

    CandidateUpdateWatchdogStartResult StartForRecovery();
    // Re-arms the full fixed timeout only when this object already owns the
    // still-running watchdog.  It never adopts or feeds another owner's timer.
    bool RefreshForRecovery();
    bool IsRunning() const;
    bool StopAfterCommit();
    bool owned() const { return owned_; }

private:
    CandidateUpdateWatchdog(const CandidateUpdateWatchdog &);
    CandidateUpdateWatchdog &operator=(const CandidateUpdateWatchdog &);

#if defined(RASPI_COMPILE)
    CBcmWatchdog implementation_;
#endif
    CandidateUpdateWatchdogDriver *test_driver_;
    bool owned_;
};

const char *CandidateUpdateWatchdogStartResultString(
    CandidateUpdateWatchdogStartResult result);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_UPDATE_WATCHDOG_H
