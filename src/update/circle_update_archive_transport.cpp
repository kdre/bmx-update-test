#include "update/circle_update_archive_transport.h"

#include <string.h>

namespace bmx {
namespace update {

CircleHttpsUpdateArchiveTransport::CircleHttpsUpdateArchiveTransport(
    SecureStreamFactory *factory, HttpsGetWorkspace *workspace,
    UpdateForegroundProgress *foreground_progress, const char *bearer_token,
    bool authenticated_api_asset)
    : factory_(factory), workspace_(workspace),
      foreground_progress_(foreground_progress), bearer_token_(bearer_token),
      authenticated_api_asset_(authenticated_api_asset), last_result_()
{
    memset(&last_result_, 0, sizeof(last_result_));
    last_result_.status = HttpsGetStatus::InvalidArgument;
}

ArchiveFetchStatus CircleHttpsUpdateArchiveTransport::Fetch(
    const char *authenticated_url, uint64_t maximum_body_bytes,
    HttpBodySink *sink)
{
    bool terminated = false;
    if (authenticated_url != 0) {
        for (size_t index = 0U; index < kMaximumUpdateUrlBytes; ++index) {
            if (authenticated_url[index] == '\0') {
                terminated = index != 0U;
                break;
            }
        }
    }
    if (authenticated_url == 0 || maximum_body_bytes == 0U || sink == 0 ||
        factory_ == 0 || workspace_ == 0 || !terminated) {
        memset(&last_result_, 0, sizeof(last_result_));
        last_result_.status = HttpsGetStatus::InvalidArgument;
        return ArchiveFetchStatus::Failed;
    }
    if (authenticated_api_asset_) {
        HttpsRequestOptions options;
        options.bearer_token = bearer_token_;
        options.accept = "application/octet-stream";
        last_result_ = HttpsRequest(
            authenticated_url, UpdateUrlPurpose::AuthenticatedReleaseAsset,
            HttpsRequestKind::ReleaseZip, options, maximum_body_bytes, sink,
            factory_, workspace_, foreground_progress_);
    } else {
        last_result_ = HttpsGet(
            authenticated_url, UpdateUrlPurpose::ReleaseAsset,
            HttpsRequestKind::ReleaseZip, maximum_body_bytes, sink, factory_,
            workspace_, foreground_progress_);
    }
    if (last_result_.status == HttpsGetStatus::Ok) {
        return ArchiveFetchStatus::Ok;
    }
    return last_result_.status == HttpsGetStatus::Canceled
        ? ArchiveFetchStatus::Canceled : ArchiveFetchStatus::Failed;
}

}  // namespace update
}  // namespace bmx
