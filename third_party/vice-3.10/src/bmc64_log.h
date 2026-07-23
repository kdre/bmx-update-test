/*
 * BMC64 UART diagnostics.
 *
 * Release builds compile these paths out. Debug builds keep compact events
 * enabled by default; noisy byte/register traces require explicit per-domain
 * log level defines.
 */

#ifndef BMC64_LOG_H
#define BMC64_LOG_H

#include <stdio.h>

#define BMC64_LOG_OFF   0
#define BMC64_LOG_EVENT 1
#define BMC64_LOG_DEBUG 2
#define BMC64_LOG_TRACE 3

#ifdef BMC64_DEBUG_PROFILE
#ifndef BMC64_RS232_LOG_LEVEL
#define BMC64_RS232_LOG_LEVEL BMC64_LOG_EVENT
#endif
#ifndef BMC64_ACIA_LOG_LEVEL
#define BMC64_ACIA_LOG_LEVEL BMC64_LOG_EVENT
#endif
#ifndef BMC64_NET_LOG_LEVEL
#define BMC64_NET_LOG_LEVEL BMC64_LOG_EVENT
#endif
#else
#undef BMC64_RS232_LOG_LEVEL
#undef BMC64_ACIA_LOG_LEVEL
#undef BMC64_NET_LOG_LEVEL
#define BMC64_RS232_LOG_LEVEL BMC64_LOG_OFF
#define BMC64_ACIA_LOG_LEVEL BMC64_LOG_OFF
#define BMC64_NET_LOG_LEVEL BMC64_LOG_OFF
#endif

#if BMC64_RS232_LOG_LEVEL >= BMC64_LOG_EVENT
#define BMC64_RS232_EVENT(_fmt, ...) \
    printf("rs232: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_RS232_EVENT(_fmt, ...)
#endif

#if BMC64_RS232_LOG_LEVEL >= BMC64_LOG_DEBUG
#define BMC64_RS232_DEBUG(_fmt, ...) \
    printf("rs232dbg: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_RS232_DEBUG(_fmt, ...)
#endif

#if BMC64_RS232_LOG_LEVEL >= BMC64_LOG_TRACE
#define BMC64_RS232_TRACE(_fmt, ...) \
    printf("rs232trace: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_RS232_TRACE(_fmt, ...)
#endif

#if BMC64_ACIA_LOG_LEVEL >= BMC64_LOG_EVENT
#define BMC64_ACIA_EVENT(_fmt, ...) \
    printf("acia: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_ACIA_EVENT(_fmt, ...)
#endif

#if BMC64_ACIA_LOG_LEVEL >= BMC64_LOG_DEBUG
#define BMC64_ACIA_DEBUG(_fmt, ...) \
    printf("aciadbg: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_ACIA_DEBUG(_fmt, ...)
#endif

#if BMC64_ACIA_LOG_LEVEL >= BMC64_LOG_TRACE
#define BMC64_ACIA_TRACE(_fmt, ...) \
    printf("aciatrace: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_ACIA_TRACE(_fmt, ...)
#endif

#if BMC64_NET_LOG_LEVEL >= BMC64_LOG_EVENT
#define BMC64_NET_EVENT(_fmt, ...) \
    printf("net: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_NET_EVENT(_fmt, ...)
#endif

#if BMC64_NET_LOG_LEVEL >= BMC64_LOG_DEBUG
#define BMC64_NET_DEBUG(_fmt, ...) \
    printf("netdbg: " _fmt "\r\n", ##__VA_ARGS__)
#else
#define BMC64_NET_DEBUG(_fmt, ...)
#endif

#endif
