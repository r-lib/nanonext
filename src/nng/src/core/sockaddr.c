//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "nng/nng.h"

#include <stdio.h>
#include <string.h>

static const char *
str_sa_inproc(const nng_sockaddr_inproc *sa, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "inproc[%s]", sa->sa_name);
	return buf;
}

static const char *
str_sa_inet(const nng_sockaddr_in *sa, char *buf, size_t bufsz)
{
	uint8_t *a_bytes = (uint8_t *) &sa->sa_addr;
	uint8_t *p_bytes = (uint8_t *) &sa->sa_port;

	snprintf(buf, bufsz, "%u.%u.%u.%u:%u", a_bytes[0], a_bytes[1],
	    a_bytes[2], a_bytes[3],
	    (((uint16_t) p_bytes[0]) << 8) + p_bytes[1]);
	return (buf);
}

static char *
nni_inet_ntop(const uint8_t addr[16], char buf[46])
{

	const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (memcmp(addr, v4map, 12) == 0) {
		snprintf(buf, 46, "::ffff:%u.%u.%u.%u", addr[12], addr[13],
		    addr[14], addr[15]);
		return (buf);
	}

	uint8_t off    = 0;
	uint8_t cnt    = 0;
	uint8_t maxoff = 0;
	uint8_t maxcnt = 0;

	for (uint8_t i = 0; i < 16; i += 2) {
		if ((addr[i] == 0) && (addr[i + 1] == 0)) {
			cnt += 2;
			if (cnt == 2) {
				off = i;
			}
			if (cnt > maxcnt) {
				maxcnt = cnt;
				maxoff = off;
			}
		} else {
			cnt = 0;
		}
	}
	if (maxcnt < 2) {
		maxoff = 0xff;
	}

	int  idx = 0;
	bool sep = false;
	buf[0]   = 0;
	for (uint8_t i = 0; i < 16; i += 2) {
		if (i == maxoff) {
			NNI_ASSERT(idx <= 43);
			strcat(buf + idx, "::");
			idx += 2;
			sep = false;
		} else if (i < maxoff || i >= maxoff + maxcnt) {
			NNI_ASSERT(idx <= 40);
			snprintf(buf + idx, 6, sep ? ":%x" : "%x",
			    (((uint16_t) addr[i]) << 8) + addr[i + 1]);
			idx += strlen(buf + idx);
			sep = true;
		}
	}
	return (buf);
}

static const char *
str_sa_inet6(const nng_sockaddr_in6 *sa, char *buf, size_t bufsz)
{
	const uint8_t *p_bytes = (uint8_t *) &sa->sa_port;
	char           istr[46];

	if (sa->sa_scope) {
		snprintf(buf, bufsz, "[%s%%%u]:%u",
		    nni_inet_ntop(sa->sa_addr, istr), sa->sa_scope,
		    (((uint16_t) (p_bytes[0])) << 8) + p_bytes[1]);
	} else {
		snprintf(buf, bufsz, "[%s]:%u",
		    nni_inet_ntop(sa->sa_addr, istr),
		    (((uint16_t) (p_bytes[0])) << 8) + p_bytes[1]);
	}
	return (buf);
}

static const char *
str_sa_ipc(const nng_sockaddr_ipc *sa, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s", sa->sa_path);
	return (buf);
}

static const char *
str_sa_abstract(const nng_sockaddr_abstract *sa, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "abstract[%s]", sa->sa_name);
	return (buf);
}

static const char *
str_sa_zt(const nng_sockaddr_zt *sa, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "ZT[%llx:%llx:%u]",
	    (unsigned long long) sa->sa_nodeid,
	    (unsigned long long) sa->sa_nwid, sa->sa_port);
	return (buf);
}

const char *
nng_str_sockaddr(const nng_sockaddr *sa, char *buf, size_t bufsz)
{
	switch (sa->s_family) {
	case NNG_AF_INPROC:
		return (str_sa_inproc(&sa->s_inproc, buf, bufsz));
	case NNG_AF_INET:
		return (str_sa_inet(&sa->s_in, buf, bufsz));
	case NNG_AF_INET6:
		return (str_sa_inet6(&sa->s_in6, buf, bufsz));
	case NNG_AF_IPC:
		return (str_sa_ipc(&sa->s_ipc, buf, bufsz));
	case NNG_AF_ABSTRACT:
		return (str_sa_abstract(&sa->s_abstract, buf, bufsz));
	case NNG_AF_ZT:
		return (str_sa_zt(&sa->s_zt, buf, bufsz));
	case NNG_AF_UNSPEC:
	default:
		return ("unknown");
	}
}
