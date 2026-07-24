#include "update/update_fault_injection.h"

#if defined(BMX_UPDATE_FAULT_INJECTION)
#include <circle/logger.h>
#include <circle/timer.h>
#include <stdio.h>
#endif

#include <limits.h>
#include <string.h>

namespace bmx {
namespace update {

#if defined(BMX_UPDATE_FAULT_INJECTION_TESTING)

namespace {

static const size_t kFaultPointCounterCount = 706U;

struct TestState {
    UpdateFaultPoint selected_point;
    uint32_t selected_occurrence;
    UpdateFaultInjectionTestObserver observer;
    void *context;
    uint32_t occurrences[kFaultPointCounterCount];
    bool configured;
    bool triggered;
};

TestState g_test_state;

size_t PointIndex(UpdateFaultPoint point)
{
    return static_cast<size_t>(static_cast<uint16_t>(point));
}

}  // namespace

bool ConfigureUpdateFaultInjectionForTest(
    UpdateFaultPoint selected_point, uint32_t selected_occurrence,
    UpdateFaultInjectionTestObserver observer, void *context)
{
    ResetUpdateFaultInjectionForTest();
    if (!IsKnownUpdateFaultPoint(selected_point) ||
        selected_occurrence == 0U) {
        return false;
    }
    g_test_state.selected_point = selected_point;
    g_test_state.selected_occurrence = selected_occurrence;
    g_test_state.observer = observer;
    g_test_state.context = context;
    g_test_state.configured = true;
    return true;
}

void ResetUpdateFaultInjectionForTest()
{
    memset(&g_test_state, 0, sizeof(g_test_state));
}

bool UpdateFaultInjectionTriggeredForTest()
{
    return g_test_state.triggered;
}

uint32_t UpdateFaultPointOccurrenceForTest(UpdateFaultPoint point)
{
    if (!IsKnownUpdateFaultPoint(point)) return 0U;
    const size_t index = PointIndex(point);
    return index < kFaultPointCounterCount
        ? g_test_state.occurrences[index] : 0U;
}

void UpdateFaultCheckpoint(UpdateFaultPoint point)
{
    if (!g_test_state.configured || !IsKnownUpdateFaultPoint(point)) return;
    const size_t index = PointIndex(point);
    if (index >= kFaultPointCounterCount) return;
    uint32_t &occurrence = g_test_state.occurrences[index];
    if (occurrence != UINT32_MAX) ++occurrence;
    const bool selected = !g_test_state.triggered &&
        point == g_test_state.selected_point &&
        occurrence == g_test_state.selected_occurrence;
    if (selected) g_test_state.triggered = true;
    if (g_test_state.observer != 0) {
        const UpdateFaultInjectionTestEvent event = {
            point, occurrence, selected
        };
        g_test_state.observer(g_test_state.context, event);
    }
}

#elif defined(BMX_UPDATE_FAULT_INJECTION)

namespace {

uint32_t g_selected_point_occurrences;
bool g_fault_injection_armed;
static const uint64_t kPowerCutOfferMicroseconds = 3000000ULL;

void WriteFaultMessageNoAlloc(const char *message)
{
    CLogger::Get()->WriteNoAlloc("bmx-update-fi", LogError, message);
}

bool FormatFaultSelection(char *buffer, size_t capacity, const char *prefix,
                          UpdateFaultPoint point, uint32_t occurrence,
                          const char *suffix)
{
    if (buffer == 0 || capacity == 0U || prefix == 0 || suffix == 0) {
        return false;
    }
    const char *const name = UpdateFaultPointName(point);
    const int written = snprintf(
        buffer, capacity, "%s|id=%u|name=%s|occurrence=%u|%s", prefix,
        static_cast<unsigned>(static_cast<uint16_t>(point)),
        name == 0 ? "invalid" : name, static_cast<unsigned>(occurrence),
        suffix);
    return written > 0 && static_cast<size_t>(written) < capacity;
}

void OfferExternalPowerCut(UpdateFaultPoint point, uint32_t occurrence)
{
    char detail[176];

    // The short token minimizes UART serialization delay. The relay accepts
    // it only after the exact source CONFIG or current-boot BOOT-CONFIG
    // record; the detailed line that follows is diagnostic and may be
    // truncated by the intended cut.
    WriteFaultMessageNoAlloc("BMX-UPDATE-CUT");
    if (FormatFaultSelection(
            detail, sizeof(detail), "BMX-UPDATE-FAULT", point, occurrence,
            "CUT-POWER-NOW")) {
        WriteFaultMessageNoAlloc(detail);
    }

    // Intentionally do not pump events, yield, or feed update/watchdog
    // progress. Interrupts remain enabled. A bounded offer window lets an
    // unarmed recovery boot continue instead of hanging at the same RAM-only
    // occurrence forever after power is restored.
    const uint64_t deadline =
        CTimer::GetClockTicks64() + kPowerCutOfferMicroseconds;
    while (CTimer::GetClockTicks64() < deadline) {
        __asm__ volatile ("nop" ::: "memory");
    }
    if (FormatFaultSelection(
            detail, sizeof(detail), "BMX-UPDATE-FAULT-TIMEOUT", point,
            occurrence, "CONTINUING")) {
        WriteFaultMessageNoAlloc(detail);
    }
}

}  // namespace

void UpdateFaultCheckpoint(UpdateFaultPoint point)
{
    // Boot and unrelated local update plumbing must not consume the selected
    // occurrence.  An explicit source action or an observed candidate boot
    // arms this instrumented kernel first.
    if (!g_fault_injection_armed) return;
    if (static_cast<unsigned>(static_cast<uint16_t>(point)) !=
        static_cast<unsigned>(BMX_UPDATE_FAULT_POINT_ID)) {
        return;
    }
    if (g_selected_point_occurrences != UINT32_MAX) {
        ++g_selected_point_occurrences;
    }
    if (g_selected_point_occurrences ==
        static_cast<uint32_t>(BMX_UPDATE_FAULT_OCCURRENCE)) {
        OfferExternalPowerCut(point, g_selected_point_occurrences);
    }
}

#endif

void LogUpdateFaultInjectionConfiguration()
{
#if defined(BMX_UPDATE_FAULT_INJECTION)
    char message[176];
    const UpdateFaultPoint selected =
        static_cast<UpdateFaultPoint>(BMX_UPDATE_FAULT_POINT_ID);
    if (FormatFaultSelection(
            message, sizeof(message), "BMX-UPDATE-FAULT-CONFIG", selected,
            static_cast<uint32_t>(BMX_UPDATE_FAULT_OCCURRENCE),
            "dwell-ms=3000")) {
        WriteFaultMessageNoAlloc(message);
        g_fault_injection_armed = true;
    }
#endif
}

void LogUpdateFaultInjectionBootConfiguration()
{
#if defined(BMX_UPDATE_FAULT_INJECTION)
    static bool emitted;
    if (emitted) return;

    char message[176];
    const UpdateFaultPoint selected =
        static_cast<UpdateFaultPoint>(BMX_UPDATE_FAULT_POINT_ID);
    if (FormatFaultSelection(
            message, sizeof(message), "BMX-UPDATE-FAULT-BOOT-CONFIG",
            selected, static_cast<uint32_t>(BMX_UPDATE_FAULT_OCCURRENCE),
            "dwell-ms=3000")) {
        WriteFaultMessageNoAlloc(message);
        // Latch only after the complete record was formatted and handed to
        // the no-allocation logger.  A formatting failure stays disarmed and
        // may be retried by an unexpected duplicate milestone callback.
        emitted = true;
        g_fault_injection_armed = true;
    }
#endif
}

}  // namespace update
}  // namespace bmx
