
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng/nng.h"
#include "nng_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef NNG_PLATFORM_WINDOWS
#include <io.h>
#endif
#ifdef NNG_PLATFORM_POSIX
#include <syslog.h>
#include <unistd.h>
#endif
#include <time.h>

static nng_log_level    log_level    = NNG_LOG_NOTICE;
static nng_log_facility log_facility = NNG_LOG_USER;
static nng_logger       log_logger   = nng_null_logger;

void
nng_log_set_facility(nng_log_facility facility)
{
	log_facility = facility;
}

void
nng_log_set_level(nng_log_level level)
{
	log_level = level;
}

nng_log_level
nng_log_get_level(void)
{
	return (log_level);
}

void
nng_log_set_logger(nng_logger logger)
{
	if (logger == NULL) {
		logger = nng_null_logger;
	}
	log_logger = logger;
}

void
nng_null_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	NNI_ARG_UNUSED(level);
	NNI_ARG_UNUSED(facility);
	NNI_ARG_UNUSED(msgid);
	NNI_ARG_UNUSED(msg);
}

void
stderr_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg, bool timechk)
{
	(void) level;
	(void) facility;
	(void) msgid;
	(void) msg;
	(void) timechk;
}

void
nng_stderr_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
	stderr_logger(level, facility, msgid, msg, true);
}

void
nng_system_logger(nng_log_level level, nng_log_facility facility,
    const char *msgid, const char *msg)
{
#ifdef NNG_PLATFORM_POSIX
	int pri;
	switch (level) {
	case NNG_LOG_ERR:
		pri = LOG_ERR;
		break;
	case NNG_LOG_WARN:
		pri = LOG_WARNING;
		break;
	case NNG_LOG_NOTICE:
		pri = LOG_NOTICE;
		break;
	case NNG_LOG_INFO:
		pri = LOG_INFO;
		break;
	case NNG_LOG_DEBUG:
		pri = LOG_DEBUG;
		break;
	default:
		pri = LOG_INFO;
		break;
	}
	switch (facility) {
	case NNG_LOG_DAEMON:
		pri |= LOG_DAEMON;
		break;
	case NNG_LOG_USER:
		pri |= LOG_USER;
		break;
	case NNG_LOG_AUTH:
		pri |= LOG_AUTHPRIV;
		break;
	case NNG_LOG_LOCAL0:
		pri |= LOG_LOCAL0;
		break;
	case NNG_LOG_LOCAL1:
		pri |= LOG_LOCAL1;
		break;
	case NNG_LOG_LOCAL2:
		pri |= LOG_LOCAL2;
		break;
	case NNG_LOG_LOCAL3:
		pri |= LOG_LOCAL3;
		break;
	case NNG_LOG_LOCAL4:
		pri |= LOG_LOCAL4;
		break;
	case NNG_LOG_LOCAL5:
		pri |= LOG_LOCAL5;
		break;
	case NNG_LOG_LOCAL6:
		pri |= LOG_LOCAL6;
		break;
	case NNG_LOG_LOCAL7:
		pri |= LOG_LOCAL7;
		break;
	}

	if (msgid) {
		syslog(pri, "%s: %s", msgid, msg);
	} else {
		syslog(pri, "%s", msg);
	}
#else
	nng_stderr_logger(level, facility, msgid, msg);
#endif
}

static void
nni_vlog(nng_log_level level, nng_log_facility facility, const char *msgid,
    const char *msg, va_list ap)
{
	if (level > log_level || log_level == 0 || facility == 0) {
		return;
	}
	char formatted[512];
	vsnprintf(formatted, sizeof(formatted), msg, ap);
	log_logger(level, facility, msgid, formatted);
}

void
nng_log_debug(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_DEBUG, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_info(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_INFO, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_notice(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_NOTICE, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_warn(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_WARN, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_err(const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(NNG_LOG_ERR, log_facility, msgid, msg, ap);
	va_end(ap);
}

void
nng_log_auth(nng_log_level level, const char *msgid, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	nni_vlog(level, NNG_LOG_AUTH, msgid, msg, ap);
	va_end(ap);
}
