//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PLATFORM_H
#define CORE_PLATFORM_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

extern void nni_plat_abort(void);

extern void nni_plat_println(const char *);

extern void nni_plat_printf(const char *, ...);

extern const char *nni_plat_strerror(int);

extern void *nni_alloc(size_t);

extern void *nni_zalloc(size_t);

extern void nni_free(void *, size_t);

typedef struct nni_plat_mtx    nni_plat_mtx;
typedef struct nni_plat_rwlock nni_plat_rwlock;
typedef struct nni_plat_cv     nni_plat_cv;
typedef struct nni_plat_thr    nni_plat_thr;
typedef struct nni_rwlock      nni_rwlock;

extern void nni_plat_mtx_init(nni_plat_mtx *);

extern void nni_plat_mtx_fini(nni_plat_mtx *);

extern void nni_plat_mtx_lock(nni_plat_mtx *);

extern void nni_plat_mtx_unlock(nni_plat_mtx *);

extern void nni_rwlock_init(nni_rwlock *);
extern void nni_rwlock_fini(nni_rwlock *);
extern void nni_rwlock_rdlock(nni_rwlock *);
extern void nni_rwlock_wrlock(nni_rwlock *);
extern void nni_rwlock_unlock(nni_rwlock *);

extern void nni_plat_cv_init(nni_plat_cv *, nni_plat_mtx *);

extern void nni_plat_cv_fini(nni_plat_cv *);

extern void nni_plat_cv_wake(nni_plat_cv *);

extern void nni_plat_cv_wake1(nni_plat_cv *);

extern void nni_plat_cv_wait(nni_plat_cv *);

extern int nni_plat_cv_until(nni_plat_cv *, nni_time);

extern int nni_plat_thr_init(nni_plat_thr *, void (*)(void *), void *);

extern void nni_plat_thr_fini(nni_plat_thr *);

extern bool nni_plat_thr_is_self(nni_plat_thr *);

extern void nni_plat_thr_set_name(nni_plat_thr *, const char *);

typedef struct nni_atomic_flag nni_atomic_flag;

extern bool nni_atomic_flag_test_and_set(nni_atomic_flag *);
extern void nni_atomic_flag_reset(nni_atomic_flag *);

typedef struct nni_atomic_bool nni_atomic_bool;

extern void nni_atomic_init_bool(nni_atomic_bool *);
extern void nni_atomic_set_bool(nni_atomic_bool *, bool);
extern bool nni_atomic_get_bool(nni_atomic_bool *);
extern bool nni_atomic_swap_bool(nni_atomic_bool *, bool);

typedef struct nni_atomic_u64 nni_atomic_u64;

extern void     nni_atomic_init64(nni_atomic_u64 *);
extern void     nni_atomic_add64(nni_atomic_u64 *, uint64_t);
extern void     nni_atomic_sub64(nni_atomic_u64 *, uint64_t);
extern uint64_t nni_atomic_get64(nni_atomic_u64 *);
extern void     nni_atomic_set64(nni_atomic_u64 *, uint64_t);
extern uint64_t nni_atomic_swap64(nni_atomic_u64 *, uint64_t);
extern uint64_t nni_atomic_dec64_nv(nni_atomic_u64 *);
extern void     nni_atomic_inc64(nni_atomic_u64 *);

extern bool nni_atomic_cas64(nni_atomic_u64 *, uint64_t, uint64_t);

typedef struct nni_atomic_int nni_atomic_int;

extern void nni_atomic_init(nni_atomic_int *);
extern void nni_atomic_add(nni_atomic_int *, int);
extern void nni_atomic_sub(nni_atomic_int *, int);
extern int  nni_atomic_get(nni_atomic_int *);
extern void nni_atomic_set(nni_atomic_int *, int);
extern int  nni_atomic_swap(nni_atomic_int *, int);
extern int  nni_atomic_dec_nv(nni_atomic_int *);
extern void nni_atomic_dec(nni_atomic_int *);
extern void nni_atomic_inc(nni_atomic_int *);

extern bool nni_atomic_cas(nni_atomic_int *, int, int);

typedef struct nni_atomic_ptr nni_atomic_ptr;
extern void nni_atomic_set_ptr(nni_atomic_ptr *, void *);
extern void *nni_atomic_get_ptr(nni_atomic_ptr *);

extern nni_time nni_clock(void);

extern void nni_msleep(nni_duration);

uint32_t nni_random(void);

extern int nni_plat_init(int (*)(void));

extern void nni_plat_fini(void);

extern int nni_plat_ncpu(void);

typedef struct nni_tcp_conn     nni_tcp_conn;
typedef struct nni_tcp_dialer   nni_tcp_dialer;
typedef struct nni_tcp_listener nni_tcp_listener;

extern int nni_tcp_dialer_init(nni_tcp_dialer **);

extern void nni_tcp_dialer_fini(nni_tcp_dialer *);

extern void nni_tcp_dialer_close(nni_tcp_dialer *);

extern void nni_tcp_dial(nni_tcp_dialer *, const nng_sockaddr *, nni_aio *);

extern int nni_tcp_dialer_set(
    nni_tcp_dialer *, const char *, const void *, size_t, nni_type);

extern int nni_tcp_dialer_get(
    nni_tcp_dialer *, const char *, void *, size_t *, nni_type);

extern int nni_tcp_listener_init(nni_tcp_listener **);

extern void nni_tcp_listener_fini(nni_tcp_listener *);

extern void nni_tcp_listener_close(nni_tcp_listener *);

extern int nni_tcp_listener_listen(nni_tcp_listener *, const nni_sockaddr *);

extern void nni_tcp_listener_accept(nni_tcp_listener *, nni_aio *);

extern int nni_tcp_listener_set(
    nni_tcp_listener *, const char *, const void *, size_t, nni_type);

extern int nni_tcp_listener_get(
    nni_tcp_listener *, const char *, void *, size_t *, nni_type);

extern void nni_resolv_ip(
    const char *, const char *, int, bool, nng_sockaddr *sa, nni_aio *);

extern int nni_parse_ip(const char *, nng_sockaddr *);

extern int nni_parse_ip_port(const char *, nng_sockaddr *);

typedef struct nni_ipc_conn     nni_ipc_conn;
typedef struct nni_ipc_dialer   nni_ipc_dialer;
typedef struct nni_ipc_listener nni_ipc_listener;

extern int nni_ipc_dialer_alloc(nng_stream_dialer **, const nng_url *);
extern int nni_ipc_listener_alloc(nng_stream_listener **, const nng_url *);

typedef struct nni_plat_udp nni_plat_udp;

extern int nni_plat_udp_open(nni_plat_udp **, nni_sockaddr *);

extern void nni_plat_udp_close(nni_plat_udp *);

extern void nni_plat_udp_send(nni_plat_udp *, nni_aio *);

extern void nni_plat_udp_recv(nni_plat_udp *, nni_aio *);

extern int nni_plat_pipe_open(int *, int *);

extern void nni_plat_pipe_raise(int);

extern void nni_plat_pipe_clear(int);

extern void nni_plat_pipe_close(int, int);

extern int nni_plat_udp_sockname(nni_plat_udp *, nni_sockaddr *);

extern int nni_socket_pair(int [2]);

extern int nni_plat_file_put(const char *, const void *, size_t);

extern int nni_plat_file_get(const char *, void **, size_t *);

extern int nni_plat_file_delete(const char *);

enum nni_plat_file_type_val {
	NNI_PLAT_FILE_TYPE_FILE,  // normal file
	NNI_PLAT_FILE_TYPE_DIR,   // normal directory
	NNI_PLAT_FILE_TYPE_OTHER, // something else (pipe, device node, etc.)
};
extern int nni_plat_file_type(const char *, int *);

enum nni_plat_file_walk_result {
	NNI_PLAT_FILE_WALK_CONTINUE,
	NNI_PLAT_FILE_WALK_STOP,        // stop walking (all done)
	NNI_PLAT_FILE_WALK_PRUNE_SIB,   // skip siblings and their children
	NNI_PLAT_FILE_WALK_PRUNE_CHILD, // skip children
};

enum nni_plat_file_walk_flags {
	NNI_PLAT_FILE_WALK_DEPTH_FIRST   = 0, // get children first
	NNI_PLAT_FILE_WALK_BREADTH_FIRST = 1, // get siblings first (later)
	NNI_PLAT_FILE_WALK_SHALLOW = 2, // do not descend into subdirectories
	NNI_PLAT_FILE_WALK_FILES_ONLY = 4, // directory names are not reported
};

typedef int (*nni_plat_file_walker)(const char *, void *);

extern int nni_plat_file_walk(const char *, nni_plat_file_walker, void *, int);

typedef struct nni_plat_flock nni_plat_flock;

extern int nni_plat_file_lock(const char *path, nni_plat_flock *);

extern void nni_plat_file_unlock(nni_plat_flock *);

extern int nni_plat_dir_open(void **, const char *);

extern int nni_plat_dir_next(void *, const char **);

extern void nni_plat_dir_close(void *);

extern int nni_plat_dir_create(const char *);

extern int nni_plat_dir_remove(const char *);

extern char *nni_plat_temp_dir(void);

extern char *nni_plat_join_dir(const char *, const char *);

extern const char *nni_plat_file_basename(const char *);

#if defined(NNG_PLATFORM_POSIX)
#include "platform/posix/posix_impl.h"
#elif defined(NNG_PLATFORM_WINDOWS)
#include "platform/windows/win_impl.h"
#else
#error "unknown platform"
#endif

#endif // CORE_PLATFORM_H
