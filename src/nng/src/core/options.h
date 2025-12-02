//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_OPTIONS_H
#define CORE_OPTIONS_H

#define NNI_MAXINT (2147483647)

#define NNI_MININT (-2147483647 - 1)

#define NNI_MINSZ (0)
#define NNI_MAXSZ ((size_t) 0xffffffff)

extern int nni_copyin_ms(nni_duration *, const void *, size_t, nni_type);
extern int nni_copyin_bool(bool *, const void *, size_t, nni_type);
extern int nni_copyin_int(int *, const void *, size_t, int, int, nni_type);
extern int nni_copyin_size(
    size_t *, const void *, size_t, size_t, size_t, nni_type);
extern int nni_copyin_str(char *, const void *, size_t, size_t, nni_type);
extern int nni_copyin_ptr(void **, const void *, size_t, nni_type);
extern int nni_copyin_u64(uint64_t *, const void *, size_t, nni_type);
extern int nni_copyin_sockaddr(nng_sockaddr *, const void *, size_t, nni_type);

extern int nni_copyout(const void *, size_t, void *, size_t *);
extern int nni_copyout_bool(bool, void *, size_t *, nni_type);
extern int nni_copyout_int(int, void *, size_t *, nni_type);
extern int nni_copyout_ms(nng_duration, void *, size_t *, nni_type);
extern int nni_copyout_ptr(void *, void *, size_t *, nni_type);
extern int nni_copyout_size(size_t, void *, size_t *, nni_type);
extern int nni_copyout_sockaddr(
    const nng_sockaddr *, void *, size_t *, nni_type);
extern int nni_copyout_u64(uint64_t, void *, size_t *, nni_type);

extern int nni_copyout_str(const char *, void *, size_t *, nni_type);

typedef struct nni_option_s nni_option;
struct nni_option_s {

	const char *o_name;

	int (*o_get)(void *, void *, size_t *, nni_type);

	int (*o_set)(void *, const void *, size_t, nni_type);
};

extern int nni_getopt(
    const nni_option *, const char *, void *, void *, size_t *, nni_type);
extern int nni_setopt(
    const nni_option *, const char *, void *, const void *, size_t, nni_type);

#endif // CORE_OPTIONS_H
