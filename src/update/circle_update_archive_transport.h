#ifndef BMX_UPDATE_CIRCLE_UPDATE_ARCHIVE_TRANSPORT_H
#define BMX_UPDATE_CIRCLE_UPDATE_ARCHIVE_TRANSPORT_H

#include "update/https_stream.h"
#include "update/update_orchestrator.h"

namespace bmx {
namespace update {

// Production supplies its already-initialized CircleSecureStreamFactory.
// Keeping the dependency at the SecureStreamFactory boundary makes the exact
// URL, redirect policy and byte ceiling host-testable without target network
// hardware.  This adapter never derives, rewrites or substitutes a source.
class CircleHttpsUpdateArchiveTransport : public UpdateArchiveTransport {
public:
    CircleHttpsUpdateArchiveTransport(SecureStreamFactory *factory,
                                      HttpsGetWorkspace *workspace,
                                      UpdateForegroundProgress *
                                          foreground_progress = 0,
                                      const char *bearer_token = 0,
                                      bool authenticated_api_asset = false);

    ArchiveFetchStatus Fetch(const char *authenticated_url,
                             uint64_t maximum_body_bytes,
                             HttpBodySink *sink) override;

    const HttpsGetResult &last_result() const { return last_result_; }

private:
    CircleHttpsUpdateArchiveTransport(
        const CircleHttpsUpdateArchiveTransport &);
    CircleHttpsUpdateArchiveTransport &operator=(
        const CircleHttpsUpdateArchiveTransport &);

    SecureStreamFactory *factory_;
    HttpsGetWorkspace *workspace_;
    UpdateForegroundProgress *foreground_progress_;
    const char *bearer_token_;
    bool authenticated_api_asset_;
    HttpsGetResult last_result_;
};

}  // namespace update
}  // namespace bmx

#endif  // BMX_UPDATE_CIRCLE_UPDATE_ARCHIVE_TRANSPORT_H
