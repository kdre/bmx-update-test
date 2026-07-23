//
// vicesound.cpp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vicesound.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <strings.h>
}

#include <circle/sched/scheduler.h>

#include <circle/koptions.h>
#include <circle/sound/hdmisoundbasedevice.h>
#include <circle/sound/usbsoundbasedevice.h>

namespace {

const unsigned HDMI_CHUNK_WORDS = 384 * 4;

int clamp_percent(int value) {
  if (value < 0) {
    return 0;
  }
  if (value > 100) {
    return 100;
  }
  return value;
}

bool sound_device_matches(const char *configured, const char *name) {
  return configured && strcasecmp(configured, name) == 0;
}

bool sound_device_is_usb(const char *configured) {
  return sound_device_matches(configured, "usb") ||
         sound_device_matches(configured, "sndusb");
}

bool start_sound_device(CSoundBaseDevice *device, const char *name,
                        unsigned queue_size_frames, unsigned channels) {
  if (!device->AllocateQueueFrames(queue_size_frames)) {
    printf("boot: sound %s queue allocation failed\r\n", name);
    return false;
  }

  device->SetWriteFormat(SoundFormatSigned16, channels);
  if (!device->Start()) {
    printf("boot: sound %s start failed\r\n", name);
    return false;
  }

  printf("boot: sound %s ready channels %u\r\n", name, channels);
  return true;
}

} // namespace

SoundOutputPriority ViceSound::DefaultOutputPriority(void) {
  const char *sounddev = CKernelOptions::Get()->GetSoundDevice();
  if (sound_device_is_usb(sounddev)) {
    return SOUND_OUTPUT_PRIORITY_USB_HDMI;
  }
  return SOUND_OUTPUT_PRIORITY_HDMI_USB;
}

ViceSound::ViceSound(CInterruptSystem *pInterrupt,
                     TVCHIQSoundDestination Destination)
    : mSoundDevice(nullptr),
      mInterrupt(pInterrupt),
      mDestination(Destination),
      mQueueSizeFrames(FRAG_SIZE * NUM_FRAGS),
      mNumChannels(2),
      mVolumePercent(100) {}

ViceSound::~ViceSound(void) {
  CancelPlayback();
}

boolean ViceSound::StartHDMI(void) {
  mSoundDevice = new CHDMISoundBaseDevice(mInterrupt, SAMPLE_RATE,
                                          HDMI_CHUNK_WORDS);
  if (start_sound_device(mSoundDevice, "hdmi",
                         mQueueSizeFrames, mNumChannels)) {
    return TRUE;
  }

  delete mSoundDevice;
  mSoundDevice = nullptr;
  return FALSE;
}

boolean ViceSound::StartUSB(void) {
  mSoundDevice = new CUSBSoundBaseDevice(SAMPLE_RATE,
                                         CUSBSoundBaseDevice::DeviceModeTXOnly,
                                         0);
  if (start_sound_device(mSoundDevice, "usb",
                         mQueueSizeFrames, mNumChannels)) {
    return TRUE;
  }

  delete mSoundDevice;
  mSoundDevice = nullptr;
  return FALSE;
}

boolean ViceSound::Playback(int volume, int channels,
                            SoundOutputPriority priority) {
  CancelPlayback();

  mNumChannels = channels >= 1 ? (unsigned) channels : 1;
  mControlLock.Acquire();
  mVolumePercent = clamp_percent(volume);
  mControlLock.Release();

  if (priority == SOUND_OUTPUT_PRIORITY_USB_HDMI) {
    return StartUSB() || StartHDMI();
  }
  return StartHDMI() || StartUSB();
}

boolean ViceSound::PlaybackActive(void) const {
  return mSoundDevice != nullptr && mSoundDevice->IsActive();
}

void ViceSound::CancelPlayback(void) {
  if (!mSoundDevice) {
    return;
  }

  mSoundDevice->Cancel();
  delete mSoundDevice;
  mSoundDevice = nullptr;
}

void ViceSound::SetControl(int nVolume, TVCHIQSoundDestination Destination) {
  mControlLock.Acquire();
  mVolumePercent = clamp_percent(nVolume);
  if (Destination < VCHIQSoundDestinationUnknown) {
    mDestination = Destination;
  }
  mControlLock.Release();
}

unsigned ViceSound::AddChunk(s16 *pBuffer, unsigned nChunkSize) {
  if (!mSoundDevice) {
    return 0;
  }

  size_t total_bytes = (size_t) nChunkSize * BYTES_PER_SAMPLE;
  const s16 *write_buffer = pBuffer;
  s16 *scaled_buffer = nullptr;
  mControlLock.Acquire();
  int volume_percent = mVolumePercent;
  mControlLock.Release();

  if (volume_percent != 100) {
    scaled_buffer = (s16 *) malloc(total_bytes);
    if (!scaled_buffer) {
      return 0;
    }

    for (unsigned i = 0; i < nChunkSize; i++) {
      scaled_buffer[i] = (s16) ((int) pBuffer[i] * volume_percent / 100);
    }
    write_buffer = scaled_buffer;
  }

  size_t written = 0;
  while (written < total_bytes) {
    int consumed = mSoundDevice->Write(((const char *) write_buffer) + written,
                                       total_bytes - written);
    if (consumed > 0) {
      written += (size_t) consumed;
      continue;
    }
    CScheduler::Get()->Yield();
  }

  if (scaled_buffer) {
    free(scaled_buffer);
  }

  return 0;
}

unsigned ViceSound::BufferSpaceSamples() {
  if (!mSoundDevice) {
    return mQueueSizeFrames;
  }

  unsigned used_frames = mSoundDevice->GetQueueFramesAvail();
  if (used_frames >= mQueueSizeFrames) {
    return 0;
  }

  return mQueueSizeFrames - used_frames;
}
