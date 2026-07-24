#ifndef BMX_UPDATE_CIRCLE_UPDATE_AUTHORIZATION_ADAPTERS_H
#define BMX_UPDATE_CIRCLE_UPDATE_AUTHORIZATION_ADAPTERS_H

#include "update/update_authorization_adapters.h"

#if defined(RASPI_COMPILE)

namespace bmx {
namespace update {

class CircleHardwareAuthorizationTokenEntropySource
    : public AuthorizationTokenEntropySource {
public:
    CircleHardwareAuthorizationTokenEntropySource();
    ~CircleHardwareAuthorizationTokenEntropySource();
    bool Fill(uint8_t *output, size_t size);

private:
    CircleHardwareAuthorizationTokenEntropySource(
        const CircleHardwareAuthorizationTokenEntropySource &);
    CircleHardwareAuthorizationTokenEntropySource &operator=(
        const CircleHardwareAuthorizationTokenEntropySource &);
    void *generator_;
};

class CircleAuthorizationMonotonicClock : public AuthorizationMonotonicClock {
public:
    bool NowMilliseconds(uint64_t *milliseconds);
};

class ExistingNetworkStateSource : public UpdateNetworkStateSource {
public:
    bool Read(bool *feature_enabled, bool *ready);
};

}  // namespace update
}  // namespace bmx

#endif  // RASPI_COMPILE

#endif  // BMX_UPDATE_CIRCLE_UPDATE_AUTHORIZATION_ADAPTERS_H
