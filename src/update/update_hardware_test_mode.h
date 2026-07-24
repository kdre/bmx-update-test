#ifndef BMX_UPDATE_UPDATE_HARDWARE_TEST_MODE_H
#define BMX_UPDATE_UPDATE_HARDWARE_TEST_MODE_H

// Hardware validation needs to execute the real target adapters before their
// production evidence flags can honestly be set.  This separate gate-under-
// test mode never defines a *_VALIDATED fact and is deliberately restricted
// to a debug binary pinned to a non-production GitHub test repository.
#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) && \
    BMX_UPDATE_HARDWARE_TEST_MODE != 1
#error "BMX_UPDATE_HARDWARE_TEST_MODE must be exactly 1 when defined"
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) && \
    (!defined(RASPI_COMPILE) || !defined(BMC64_DEBUG_PROFILE) || \
     !defined(BMX_UPDATE_TEST_CHANNEL))
#error "BMX update hardware-test mode requires a Raspberry Pi debug test-channel build"
#endif

// Release artifacts retain one owner-only route for testing the exact bytes
// of a production GitHub draft before publication.  The route is invisible
// without a locally installed production-key-signed ticket and still uses
// verified TLS plus the independently signed release manifest.  It compiles
// the real target adapters without asserting that their hardware-validation
// facts have already been established.
#if defined(BMX_UPDATE_OWNER_DRAFT_TEST) && \
    BMX_UPDATE_OWNER_DRAFT_TEST != 1
#error "BMX_UPDATE_OWNER_DRAFT_TEST must be exactly 1 when defined"
#endif

#if defined(BMX_UPDATE_OWNER_DRAFT_TEST) && \
    (!defined(RASPI_COMPILE) || defined(BMC64_DEBUG_PROFILE) || \
     defined(BMX_UPDATE_TEST_CHANNEL))
#error "BMX owner draft testing requires a Raspberry Pi production release build"
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_TARGET_UI_VALIDATED)
#define BMX_UPDATE_ENABLE_TARGET_UI 1
#endif

#if defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_ENABLE_TARGET_UI)
#define BMX_UPDATE_ENABLE_OWNER_DRAFT_UI 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_TRYBOOT_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_TRYBOOT 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_TRYBOOT_OBSERVATION_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_TRYBOOT_OBSERVATION 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_FATFS_FLUSH_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_FATFS_FLUSH 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_FATFS_RECOVERY_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_FATFS_RECOVERY 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_SELECTOR_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_SELECTOR 1
#endif

#if defined(BMX_UPDATE_HARDWARE_TEST_MODE) || \
    defined(BMX_UPDATE_OWNER_DRAFT_TEST) || \
    defined(BMX_UPDATE_WATCHDOG_HARDWARE_VALIDATED)
#define BMX_UPDATE_ENABLE_WATCHDOG 1
#endif

#endif  // BMX_UPDATE_UPDATE_HARDWARE_TEST_MODE_H
