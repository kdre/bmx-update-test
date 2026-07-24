#include "crc32.h"

namespace bmx {
namespace update {

uint32_t CalculateCrc32(ByteView bytes)
{
    if (bytes.data == 0 && bytes.size != 0U) {
        return 0U;
    }
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0U; i < bytes.size; ++i) {
        crc ^= bytes.data[i];
        for (unsigned bit = 0U; bit < 8U; ++bit) {
            const uint32_t mask = static_cast<uint32_t>(
                -static_cast<int32_t>(crc & UINT32_C(1)));
            crc = (crc >> 1U) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

}  // namespace update
}  // namespace bmx
