#include "update/circle_update_authorization_adapters.h"

#if defined(RASPI_COMPILE)

#include "network/network_manager.h"

#include <circle/bcmrandom.h>
#include <circle/timer.h>

#include <string.h>

namespace bmx {
namespace update {

CircleHardwareAuthorizationTokenEntropySource::
CircleHardwareAuthorizationTokenEntropySource()
    : generator_(new CBcmRandomNumberGenerator())
{
}

CircleHardwareAuthorizationTokenEntropySource::
~CircleHardwareAuthorizationTokenEntropySource()
{
    delete static_cast<CBcmRandomNumberGenerator *>(generator_);
    generator_ = 0;
}

bool CircleHardwareAuthorizationTokenEntropySource::Fill(uint8_t *output,
                                                          size_t size)
{
    if (output == 0 || size == 0U || generator_ == 0) return false;
    CBcmRandomNumberGenerator *generator =
        static_cast<CBcmRandomNumberGenerator *>(generator_);
    size_t offset = 0U;
    while (offset < size) {
        const uint32_t value = generator->GetNumber();
        const size_t remaining = size - offset;
        const size_t amount = remaining < sizeof(value) ? remaining
                                                        : sizeof(value);
        memcpy(output + offset, &value, amount);
        offset += amount;
    }
    return true;
}

bool CircleAuthorizationMonotonicClock::NowMilliseconds(
    uint64_t *milliseconds)
{
    if (milliseconds == 0) return false;
    *milliseconds = CTimer::GetClockTicks64() / 1000U;
    return true;
}

bool ExistingNetworkStateSource::Read(bool *feature_enabled, bool *ready)
{
    return bmx::ReadNetworkFeatureState(feature_enabled, ready);
}

}  // namespace update
}  // namespace bmx

#endif  // RASPI_COMPILE
