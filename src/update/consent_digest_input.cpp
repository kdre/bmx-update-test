#include "consent_digest_input.h"

#include <string.h>

namespace bmx {
namespace update {

namespace {

static const uint8_t kConsentMagic[8] = {'B', 'M', 'X', 'C', 'N', 'S', '1', 0};

bool BytesAreNonZero(const uint8_t *bytes, size_t size)
{
    if (bytes == 0) {
        return false;
    }
    uint8_t combined = 0U;
    for (size_t i = 0U; i < size; ++i) {
        combined = static_cast<uint8_t>(combined | bytes[i]);
    }
    return combined != 0U;
}

bool IsConsentClassification(ConfigClassification classification)
{
    return classification == ConfigClassification::Compatible ||
           classification == ConfigClassification::LosslessMigration ||
           classification == ConfigClassification::ResetRequired;
}

ConsentInputStatus ValidateAndSort(const ConsentDigestInput &input,
                                   size_t sorted_indices[kMaximumConfigAreas])
{
    if (!IsKnownBoardFamily(input.board) || input.target_release_sequence == 0U ||
        !BytesAreNonZero(input.manifest_sha256, kSha256DigestBytes) ||
        input.items == 0 || input.item_count == 0U ||
        input.item_count > kMaximumConfigAreas) {
        return ConsentInputStatus::InvalidInput;
    }
    for (size_t i = 0U; i < input.item_count; ++i) {
        const ConsentConfigItem &item = input.items[i];
        if (!IsKnownConfigArea(item.area) || !IsConsentClassification(item.classification) ||
            item.target_schema_version == 0U ||
            (item.source_schema_version == 0U &&
             item.classification != ConfigClassification::Compatible) ||
            !BytesAreNonZero(item.source_content_sha256, kSha256DigestBytes)) {
            return ConsentInputStatus::InvalidInput;
        }
        sorted_indices[i] = i;
        for (size_t j = 0U; j < i; ++j) {
            if (input.items[j].area == item.area) {
                return ConsentInputStatus::DuplicateConfigArea;
            }
        }
    }

    for (size_t i = 1U; i < input.item_count; ++i) {
        const size_t value = sorted_indices[i];
        size_t position = i;
        while (position > 0U &&
               static_cast<uint8_t>(input.items[sorted_indices[position - 1U]].area) >
                   static_cast<uint8_t>(input.items[value].area)) {
            sorted_indices[position] = sorted_indices[position - 1U];
            --position;
        }
        sorted_indices[position] = value;
    }
    return ConsentInputStatus::Valid;
}

void WriteU16(uint8_t *destination, uint16_t value)
{
    destination[0] = static_cast<uint8_t>(value & 0xffU);
    destination[1] = static_cast<uint8_t>((value >> 8U) & 0xffU);
}

void WriteU32(uint8_t *destination, uint32_t value)
{
    for (unsigned i = 0U; i < 4U; ++i) {
        destination[i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

void WriteU64(uint8_t *destination, uint64_t value)
{
    for (unsigned i = 0U; i < 8U; ++i) {
        destination[i] = static_cast<uint8_t>((value >> (8U * i)) & 0xffU);
    }
}

}  // namespace

ConsentInputStatus SerializeConsentDigestInput(const ConsentDigestInput &input,
                                               MutableByteView output,
                                               size_t *encoded_size)
{
    if (encoded_size == 0) {
        return ConsentInputStatus::InvalidInput;
    }
    *encoded_size = 0U;
    size_t indices[kMaximumConfigAreas];
    const ConsentInputStatus status = ValidateAndSort(input, indices);
    if (status != ConsentInputStatus::Valid) {
        return status;
    }

    const size_t required = kConsentHeaderEncodedBytes +
                            input.item_count * kConsentItemEncodedBytes;
    if (output.data == 0 || output.size < required || required > UINT16_MAX) {
        return ConsentInputStatus::OutputTooSmall;
    }

    memset(output.data, 0, required);
    memcpy(output.data, kConsentMagic, sizeof(kConsentMagic));
    WriteU16(output.data + 8U, 1U);
    WriteU16(output.data + 10U, static_cast<uint16_t>(required));
    output.data[12U] = static_cast<uint8_t>(input.board);
    output.data[13U] = static_cast<uint8_t>(input.item_count);
    WriteU64(output.data + 16U, input.target_release_sequence);
    memcpy(output.data + 24U, input.manifest_sha256, kSha256DigestBytes);

    size_t offset = kConsentHeaderEncodedBytes;
    for (size_t i = 0U; i < input.item_count; ++i) {
        const ConsentConfigItem &item = input.items[indices[i]];
        output.data[offset] = static_cast<uint8_t>(item.area);
        output.data[offset + 1U] = static_cast<uint8_t>(item.classification);
        WriteU32(output.data + offset + 4U, item.source_schema_version);
        WriteU32(output.data + offset + 8U, item.target_schema_version);
        memcpy(output.data + offset + 12U, item.source_content_sha256,
               kSha256DigestBytes);
        offset += kConsentItemEncodedBytes;
    }
    *encoded_size = required;
    return ConsentInputStatus::Valid;
}

bool ConsentDigestInputsEqual(const ConsentDigestInput &left,
                              const ConsentDigestInput &right)
{
    uint8_t left_bytes[kMaximumConsentEncodedBytes];
    uint8_t right_bytes[kMaximumConsentEncodedBytes];
    size_t left_size = 0U;
    size_t right_size = 0U;
    if (SerializeConsentDigestInput(left, MutableByteView(left_bytes, sizeof(left_bytes)),
                                    &left_size) != ConsentInputStatus::Valid ||
        SerializeConsentDigestInput(right, MutableByteView(right_bytes, sizeof(right_bytes)),
                                    &right_size) != ConsentInputStatus::Valid ||
        left_size != right_size) {
        return false;
    }
    return memcmp(left_bytes, right_bytes, left_size) == 0;
}

}  // namespace update
}  // namespace bmx
