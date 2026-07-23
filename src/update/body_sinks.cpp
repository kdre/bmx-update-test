#include "update/body_sinks.h"

#include <string.h>

namespace bmx {
namespace update {

BoundedMemoryBodySink::BoundedMemoryBodySink(uint8_t *buffer, size_t capacity)
    : buffer_(buffer), capacity_(capacity), size_(0U), overflowed_(false) {}

bool BoundedMemoryBodySink::Write(const uint8_t *data, size_t size) {
    if ((data == 0 && size != 0U) || buffer_ == 0 || size > capacity_ - size_) {
        overflowed_ = true;
        return false;
    }
    if (size != 0U) memcpy(buffer_ + size_, data, size);
    size_ += size;
    return true;
}

void BoundedMemoryBodySink::Reset() {
    size_ = 0U;
    overflowed_ = false;
}

HashingBodySink::HashingBodySink(HttpBodySink *destination, uint64_t exact_size)
    : destination_(destination), exact_size_(exact_size), bytes_written_(0U),
      failed_(destination == 0 || exact_size == 0U), finished_(false) {}

bool HashingBodySink::Write(const uint8_t *data, size_t size) {
    if (failed_ || finished_ || (data == 0 && size != 0U) ||
        bytes_written_ > exact_size_ ||
        static_cast<uint64_t>(size) > exact_size_ - bytes_written_) {
        failed_ = true;
        return false;
    }
    if (!sha256_.Update(data, size) || !destination_->Write(data, size)) {
        failed_ = true;
        return false;
    }
    bytes_written_ += static_cast<uint64_t>(size);
    return true;
}

bool HashingBodySink::Finish(uint8_t digest[kSha256DigestBytes]) {
    if (digest == 0 || failed_ || finished_ || bytes_written_ != exact_size_) {
        failed_ = true;
        return false;
    }
    finished_ = true;
    return sha256_.Final(digest);
}

}  // namespace update
}  // namespace bmx
