//
// Copyright (c) 2014 Wirebird Labs LLC.  All rights reserved.
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//

#ifndef NNI_BASE64_INCLUDED
#define NNI_BASE64_INCLUDED

#include <stddef.h>
#include <stdint.h>

size_t nni_base64_encode(const uint8_t *, size_t, char *, size_t);

size_t nni_base64_decode(const char *, size_t, uint8_t *, size_t);

#endif
