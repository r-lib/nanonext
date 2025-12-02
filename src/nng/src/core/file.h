//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_FILE_H
#define CORE_FILE_H

extern int nni_file_put(const char *, const void *, size_t);

extern int nni_file_get(const char *, void **, size_t *);

extern int nni_file_delete(const char *);

enum nni_file_type_val {
	NNI_FILE_TYPE_FILE,
	NNI_FILE_TYPE_DIR,
	NNI_FILE_TYPE_OTHER,
};

extern int nni_file_type(const char *, int *);

enum nni_file_walk_result {
	NNI_FILE_WALK_CONTINUE,
	NNI_FILE_WALK_STOP,
	NNI_FILE_WALK_PRUNE_SIB,
	NNI_FILE_WALK_PRUNE_CHILD,
};

enum nni_file_walk_flags {
	NNI_FILE_WALK_DEPTH_FIRST   = 0, // get children first
	NNI_FILE_WALK_BREADTH_FIRST = 1, // get siblings first (later)
	NNI_FILE_WALK_SHALLOW       = 2, // do not descend into subdirectories
	NNI_FILE_WALK_FILES_ONLY    = 4, // directory names are not reported
};

typedef int (*nni_file_walker)(const char *, void *);
extern int nni_file_walk(const char *, nni_file_walker, void *, int);

extern char *nni_file_join(const char *, const char *);

extern const char *nni_file_basename(const char *);

extern bool nni_file_is_file(const char *);

extern bool nni_file_is_dir(const char *);

typedef struct nni_file_lockh nni_file_lockh;

extern int nni_file_lock(const char *, nni_file_lockh **);

extern void nni_file_unlock(nni_file_lockh *);

#endif // CORE_FILE_H
