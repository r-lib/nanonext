// nanonext - NNG internal structure mirrors ------------------------------------

// Mirror structures for NNG HTTP header iteration (matches NNG v1.6+ internals)
// Layout must match: src/nng/src/core/list.h and src/nng/src/supplemental/http/http_msg.c

// Copyright 2017 Garrett D'Amore <garrett@damore.org>
// Copyright 2019 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.

#ifndef NANONEXT_NNG_STRUCTS_H
#define NANONEXT_NNG_STRUCTS_H

#include <stddef.h>
#include <stdint.h>

typedef struct nano_list_node_s {
  struct nano_list_node_s *next;
  struct nano_list_node_s *prev;
} nano_list_node_s;

typedef struct nano_list_s {
  nano_list_node_s head;
  size_t           offset;
} nano_list_s;

typedef struct nano_http_header_s {
  char             *name;
  char             *value;
  nano_list_node_s  node;
} nano_http_header_s;

// Mirror of nng_http_req/nng_http_res - only hdrs field needed (first field in both)
typedef struct nano_http_msg_s {
  nano_list_s hdrs;
} nano_http_msg_s;

// Generic header iteration - works for both nng_http_req and nng_http_res
// since both have hdrs as their first field with identical structure

static inline nano_http_header_s *nano_http_header_first(void *msg) {
  nano_http_msg_s *m = (nano_http_msg_s *) msg;
  nano_list_node_s *node = m->hdrs.head.next;
  if (node == &m->hdrs.head)
    return NULL;
  return (nano_http_header_s *) ((char *) node - m->hdrs.offset);
}

static inline nano_http_header_s *nano_http_header_next(void *msg,
                                                         nano_http_header_s *h) {
  nano_http_msg_s *m = (nano_http_msg_s *) msg;
  nano_list_node_s *node = h->node.next;
  if (node == &m->hdrs.head)
    return NULL;
  return (nano_http_header_s *) ((char *) node - m->hdrs.offset);
}

// Mirror of NNG nng_msg body layout for zero-copy buffer transfer.
// Used by nano_serialize_msg() to install a realloc'd serialization buffer
// directly as the message body, avoiding a redundant allocation + memcpy.
//
// Assumed NNG internal layout (stable since NNG 1.6, required >= 1.11.0):
//
//   struct nng_msg {                          // src/nng/src/core/message.c
//     uint32_t       m_header_buf[16];        // NNI_MAX_MAX_TTL (15) + 1
//     size_t         m_header_len;
//     nni_chunk      m_body;                  // <-- we access this
//     uint32_t       m_pipe;
//     nni_atomic_int m_refcnt;
//   };
//
//   typedef struct {                          // nni_chunk
//     size_t   ch_cap;
//     size_t   ch_len;
//     uint8_t *ch_buf;
//     uint8_t *ch_ptr;
//   } nni_chunk;
//
// nni_free() is free() on all platforms, so body.buf may be a malloc'd buffer.

typedef struct nano_nng_chunk_s {
  size_t   cap;
  size_t   len;
  uint8_t *buf;
  uint8_t *ptr;
} nano_nng_chunk;

typedef struct nano_nng_msg_s {
  uint32_t       header_buf[16];
  size_t         header_len;
  nano_nng_chunk body;
} nano_nng_msg;

#endif // NANONEXT_NNG_STRUCTS_H
