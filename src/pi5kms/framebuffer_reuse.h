#ifndef BMX_PI5KMS_FRAMEBUFFER_REUSE_H
#define BMX_PI5KMS_FRAMEBUFFER_REUSE_H

namespace pi5kms {

inline bool CanReuseFramebuffer(unsigned current_width,
                                unsigned current_height,
                                unsigned current_depth,
                                unsigned requested_width,
                                unsigned requested_height,
                                unsigned requested_depth) {
  return current_depth == requested_depth &&
         current_width >= requested_width &&
         current_height >= requested_height;
}

inline unsigned ExpandedFramebufferDimension(unsigned current,
                                              unsigned requested) {
  return current > requested ? current : requested;
}

}  // namespace pi5kms

#endif
