//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
#define NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H

#include <stdbool.h>

typedef struct nni_ws          nni_ws;
typedef struct nni_ws_listener nni_ws_listener;
typedef struct nni_ws_dialer   nni_ws_dialer;

#define NNI_OPT_WS_MSGMODE "ws:msgmode"

extern int nni_ws_listener_alloc(nng_stream_listener **, const nni_url *);
extern int nni_ws_dialer_alloc(nng_stream_dialer **, const nni_url *);

#endif // NNG_SUPPLEMENTAL_WEBSOCKET_WEBSOCKET_H
