#ifndef BMX_UPDATE_CRC32_H
#define BMX_UPDATE_CRC32_H

#include "update_types.h"

namespace bmx {
namespace update {

// IEEE CRC-32 (polynomial 0xEDB88320), used only for torn-write and corruption
// detection. It is not an authenticity primitive.
uint32_t CalculateCrc32(ByteView bytes);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CRC32_H
