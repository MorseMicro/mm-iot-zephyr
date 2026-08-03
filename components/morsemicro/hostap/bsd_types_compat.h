/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <sys/types.h>

/* Required non default definitions, implemented as a shim for lib & compiler compatability */

#ifndef __u_char_defined
typedef unsigned char u_char;
#define __u_char_defined
#endif
#ifndef __u_short_defined
typedef unsigned short u_short;
#define __u_short_defined
#endif
#ifndef __u_int_defined
typedef unsigned int u_int;
#define __u_int_defined
#endif
#ifndef __u_long_defined
typedef unsigned long u_long;
#define __u_long_defined
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER__
#endif

#ifndef typeof
#define typeof(x) __typeof__(x)
#endif
