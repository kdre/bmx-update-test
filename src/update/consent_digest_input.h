#ifndef BMX_UPDATE_CONSENT_DIGEST_INPUT_H
#define BMX_UPDATE_CONSENT_DIGEST_INPUT_H

#include "config_schema.h"
#include "update_types.h"

namespace bmx {
namespace update {

static const size_t kConsentHeaderEncodedBytes = 56U;
static const size_t kConsentItemEncodedBytes = 44U;
static const size_t kMaximumConsentEncodedBytes =
    kConsentHeaderEncodedBytes + kMaximumConfigAreas * kConsentItemEncodedBytes;

struct ConsentConfigItem {
    ConfigArea area;
    ConfigClassification classification;
    uint32_t source_schema_version;
    uint32_t target_schema_version;
    uint8_t source_content_sha256[kSha256DigestBytes];
};

struct ConsentDigestInput {
    BoardFamily board;
    uint64_t target_release_sequence;
    uint8_t manifest_sha256[kSha256DigestBytes];
    const ConsentConfigItem *items;
    size_t item_count;
};

enum class ConsentInputStatus : uint8_t {
    Valid = 0,
    InvalidInput,
    DuplicateConfigArea,
    OutputTooSmall
};

// Produces canonical binary input for a cryptographic SHA-256 implementation.
// It does not calculate the digest and does not grant consent by itself.
ConsentInputStatus SerializeConsentDigestInput(const ConsentDigestInput &input,
                                               MutableByteView output,
                                               size_t *encoded_size);

// Compares the security-relevant snapshot logically, independent of item order.
// Use immediately before installation to invalidate stale UI consent.
bool ConsentDigestInputsEqual(const ConsentDigestInput &left,
                              const ConsentDigestInput &right);

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CONSENT_DIGEST_INPUT_H
