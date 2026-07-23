#ifndef _pi5_kms_h
#define _pi5_kms_h

#include <circle/types.h>
#include <stdint.h>

namespace pi5kms {

struct Mode {
  u32 width;
  u32 height;
  u32 pixel_clock;
  u16 h_front_porch;
  u16 h_sync;
  u16 h_back_porch;
  u16 v_front_porch;
  u16 v_sync;
  u16 v_back_porch;
  bool h_sync_positive;
  bool v_sync_positive;
};

struct Framebuffer {
  uint8_t *pixels;
  u32 width;
  u32 height;
  u32 pitch;
  u32 depth;
  u32 size;
};

struct Rect {
  s32 x;
  s32 y;
  u32 width;
  u32 height;
};

enum PixelFormat {
  kPixelFormatRgb565 = 0,
  kPixelFormatArgb8888 = 1,
};

enum ScaleFilter {
  kScaleFilterNearest = 0,
  kScaleFilterMitchell = 1,
};

struct Plane {
  u32 framebuffer_bus_address;
  u32 pitch;
  u32 width;
  u32 height;
  u32 depth;
  PixelFormat format;
  ScaleFilter filter;
  Rect source;
  Rect destination;
};

bool ResolveBmcMode(unsigned hdmi_group, unsigned hdmi_mode,
                    const char *hdmi_timings, const char *named_mode,
                    Mode *mode);
bool SetMode(const Mode &mode);
bool CreateFramebuffer(u32 width, u32 height, u32 depth, Framebuffer *fb);
void DestroyFramebuffer(Framebuffer *fb);
void ClearFramebuffer(const Framebuffer &fb);
void FlushFramebuffer(const Framebuffer &fb);
bool WaitForVBlank(unsigned timeout_us = 50000);
bool ConfigureScanout(const Framebuffer &fb);
bool ConfigureScanout(u32 framebuffer_bus_address, u32 pitch, u32 width,
                      u32 height, u32 depth);
bool ConfigureScanout(const Plane &plane, u32 display_width,
                      u32 display_height);
bool ConfigureScanout(const Plane *planes, unsigned plane_count,
                      u32 display_width, u32 display_height);
bool PresentScanout(const Plane *planes, unsigned plane_count,
                    u32 display_width, u32 display_height,
                    bool wait_for_vblank);

}  // namespace pi5kms

#endif
