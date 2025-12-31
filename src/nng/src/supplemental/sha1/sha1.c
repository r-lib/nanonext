//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdint.h>
#include <string.h>

#include "sha1.h"

#define nni_sha1_circular_shift(bits, word) \
	((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32 - (bits))))

static void nni_sha1_process(nni_sha1_ctx *);
static void nni_sha1_pad(nni_sha1_ctx *);

void
nni_sha1_init(nni_sha1_ctx *ctx)
{
	ctx->len = 0;
	ctx->idx = 0;

	ctx->digest[0] = 0x67452301;
	ctx->digest[1] = 0xEFCDAB89;
	ctx->digest[2] = 0x98BADCFE;
	ctx->digest[3] = 0x10325476;
	ctx->digest[4] = 0xC3D2E1F0;
}

void
nni_sha1_final(nni_sha1_ctx *ctx, uint8_t digest[20])
{
	nni_sha1_pad(ctx);
	for (int i = 0; i < 5; i++) {
		digest[i * 4]     = (ctx->digest[i] >> 24) & 0xff;
		digest[i * 4 + 1] = (ctx->digest[i] >> 16) & 0xff;
		digest[i * 4 + 2] = (ctx->digest[i] >> 8) & 0xff;
		digest[i * 4 + 3] = (ctx->digest[i] >> 0) & 0xff;
	}
}

void
nni_sha1(const void *msg, size_t length, uint8_t digest[20])
{
	nni_sha1_ctx ctx;

	nni_sha1_init(&ctx);
	nni_sha1_update(&ctx, msg, length);
	nni_sha1_final(&ctx, digest);
}

void
nni_sha1_update(nni_sha1_ctx *ctx, const void *data, size_t length)
{
	const uint8_t *msg = data;

	if (!length) {
		return;
	}

	while (length--) {
		ctx->blk[ctx->idx++] = (*msg & 0xFF);
		ctx->len += 8;

		if (ctx->idx == 64) {
			nni_sha1_process(ctx);
		}

		msg++;
	}
}

void
nni_sha1_process(nni_sha1_ctx *ctx)
{
	const unsigned K[] =
	    { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
	unsigned temp;
	unsigned W[80];
	unsigned A, B, C, D, E;

	for (int t = 0; t < 16; t++) {
		W[t] = ((unsigned) ctx->blk[t * 4]) << 24;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 1]) << 16;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 2]) << 8;
		W[t] |= ((unsigned) ctx->blk[t * 4 + 3]);
	}

	for (int t = 16; t < 80; t++) {
		W[t] = nni_sha1_circular_shift(
		    1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = ctx->digest[0];
	B = ctx->digest[1];
	C = ctx->digest[2];
	D = ctx->digest[3];
	E = ctx->digest[4];

	for (int t = 0; t < 20; t++) {
		temp = nni_sha1_circular_shift(5, A) + ((B & C) | ((~B) & D)) +
		    E + W[t] + K[0];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 20; t < 40; t++) {
		temp = nni_sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] +
		    K[1];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 40; t < 60; t++) {
		temp = nni_sha1_circular_shift(5, A) +
		    ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 60; t < 80; t++) {
		temp = nni_sha1_circular_shift(5, A) + (B ^ C ^ D) + E + W[t] +
		    K[3];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = nni_sha1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	ctx->digest[0] = (ctx->digest[0] + A) & 0xFFFFFFFF;
	ctx->digest[1] = (ctx->digest[1] + B) & 0xFFFFFFFF;
	ctx->digest[2] = (ctx->digest[2] + C) & 0xFFFFFFFF;
	ctx->digest[3] = (ctx->digest[3] + D) & 0xFFFFFFFF;
	ctx->digest[4] = (ctx->digest[4] + E) & 0xFFFFFFFF;

	ctx->idx = 0;
}

void
nni_sha1_pad(nni_sha1_ctx *ctx)
{
	if (ctx->idx > 55) {
		ctx->blk[ctx->idx++] = 0x80;
		while (ctx->idx < 64) {
			ctx->blk[ctx->idx++] = 0;
		}

		nni_sha1_process(ctx);

		while (ctx->idx < 56) {
			ctx->blk[ctx->idx++] = 0;
		}
	} else {
		ctx->blk[ctx->idx++] = 0x80;
		while (ctx->idx < 56) {
			ctx->blk[ctx->idx++] = 0;
		}
	}

	ctx->blk[56] = (ctx->len >> 56) & 0xff;
	ctx->blk[57] = (ctx->len >> 48) & 0xff;
	ctx->blk[58] = (ctx->len >> 40) & 0xff;
	ctx->blk[59] = (ctx->len >> 32) & 0xff;
	ctx->blk[60] = (ctx->len >> 24) & 0xff;
	ctx->blk[61] = (ctx->len >> 16) & 0xff;
	ctx->blk[62] = (ctx->len >> 8) & 0xff;
	ctx->blk[63] = (ctx->len) & 0xff;

	nni_sha1_process(ctx);
}
