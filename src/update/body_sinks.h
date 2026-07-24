#ifndef BMX_UPDATE_BODY_SINKS_H
#define BMX_UPDATE_BODY_SINKS_H

#include "update/http_response_parser.h"
#include "update/sha256.h"

namespace bmx {
namespace update {

class BoundedMemoryBodySink : public HttpBodySink {
 public:
    BoundedMemoryBodySink(uint8_t *buffer, size_t capacity);
    bool Write(const uint8_t *data, size_t size) override;
    void Reset();
    ByteView bytes() const { return ByteView(buffer_, size_); }
    bool overflowed() const { return overflowed_; }

 private:
    uint8_t *buffer_;
    size_t capacity_;
    size_t size_;
    bool overflowed_;
};

class HashingBodySink : public HttpBodySink {
 public:
    HashingBodySink(HttpBodySink *destination, uint64_t exact_size);
    bool Write(const uint8_t *data, size_t size) override;
    bool Finish(uint8_t digest[kSha256DigestBytes]);
    uint64_t bytes_written() const { return bytes_written_; }

 private:
    HttpBodySink *destination_;
    uint64_t exact_size_;
    uint64_t bytes_written_;
    Sha256 sha256_;
    bool failed_;
    bool finished_;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_BODY_SINKS_H
