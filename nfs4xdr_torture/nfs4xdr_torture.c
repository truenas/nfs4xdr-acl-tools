/*-
 * Copyright 2021 iXsystems, Inc.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <getopt.h>
#include <sysexits.h>
#include <err.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/xattr.h>
#include <time.h>
#include "torture.h"

static void usage(int);
static char *execname = NULL;

static struct option long_options[] = {
        { "test",		1, 0, 't' },
        { NULL,			0, 0, 0,  },
};

static char *to_run = NULL;
bool run_all = false;

static struct timespec ts_current(void)
{
	struct timespec ts;
	int error;
	error = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (error) {
		errx(EX_OSERR, "clock_gettime() failed: %s\n", strerror(errno));
	}
	return ts;
}

static double elapsed(const struct timespec *ts1)
{
	struct timespec ts2;
	ts2 = ts_current();
	return (ts2.tv_sec - ts1->tv_sec) +
		(ts2.tv_nsec - ts1->tv_nsec)*1.0e-9;
}

static struct nfs4_acl *generate_acl_with_entries(uint entries)
{
	struct nfs4_acl *out = NULL;
	int error, i;
	out = nfs4_new_acl(true);
	if (out == NULL) {
		errx(EX_OSERR, "nfs4_new_acl() failed: %s", strerror(errno));
	}
	for (i = 0; i < entries; i++) {
		struct nfs4_ace *ace = NULL;
		int idx = 0;
		idx = i % ARRAY_SIZE(acetemplates);
		ace = nfs4_new_ace(
		    true,
		    acetemplates[idx].ace.type,
		    acetemplates[idx].ace.flag,
		    acetemplates[idx].ace.access_mask,
		    acetemplates[idx].ace.whotype,
		    acetemplates[idx].ace.who_id);
		if (ace == NULL) {
			errx(EX_OSERR, "nfs4_new_ace() failed.");
		}
		error = nfs4_append_ace(out, ace);
		if (error) {
			errx(EX_OSERR, "nfs4_append_ace() failed");
		}
	}
	if (out->naces != entries) {
		errx(EX_OSERR, "failed to generate ACL with %d entries", entries);
	}
	return out;
}

/*
 * Push upper limit of number of ACEs allowed in ACL.
 */
static int acl_set_max_cnt(const char *path)
{
	printf("Testing setting maximum number of ACLs\n");
	int error = 0, i;
	struct nfs4_acl *original = NULL;
	original = nfs4_acl_get_file(path);
	if (original == NULL) {
		errx(EX_OSERR, "%s: nfs4_acl_get_file() failed: %s\n",
		    path, strerror(errno));
	}

	for (i = 0; i <= NFS41ACLMAXACES; i ++) {
		struct nfs4_acl *to_set = NULL;
		int acl_size = i + 1;
		to_set = generate_acl_with_entries(acl_size);
		if (to_set == NULL) {
			nfs4_free_acl(original);
			errx(EX_OSERR, "%s: failed to generate ACL entry", path);
		}
		error = nfs4_acl_set_file(to_set, path);
		if (error) {
			if (errno == E2BIG) {
				printf("Stopped at %d aces in ACL\n", i);
				nfs4_free_acl(to_set);
				error = nfs4_acl_set_file(original, path);
				if (error) {
					errx(EX_OSERR, "failed to reset original ACL: %s",
					    strerror(errno));
				}
				nfs4_free_acl(original);
				return 0;
			}
			nfs4_free_acl(original);
			nfs4_free_acl(to_set);
			errx(EX_OSERR, "%s: nfs4_acl_set_file() failed on ace %d: %s",
			    path, acl_size, strerror(errno));
		}
		nfs4_free_acl(to_set);
	}
	nfs4_free_acl(original);
	errx(EX_OSERR, "Exceeded MAX permitted ACEs on ACL: %d", (i + 1));
}

/*
 * Check rates at which we can set ACLs of varying sizes
 */
static int acl_set_bench(const char *path)
{
	int error = 0;
	int aclsize[10] = { 1, 4, 8, 12, 16, 20, 24, 28, 32, 36 };
	int i;

	for (i = 0; i < ARRAY_SIZE(aclsize); i++) {
		printf("Bench ACL [%d] entries\n", aclsize[i]);
		struct nfs4_acl *to_set = NULL;
		struct timespec start;
		size_t cnt = 0;
		to_set = generate_acl_with_entries(aclsize[i]);
		if (to_set == NULL) {
			errx(EX_OSERR, "%s: failed to generate ACL entry", path);
		}
		start = ts_current();
		do {
			error = nfs4_acl_set_file(to_set, path);
			if (error) {
				errx(EX_OSERR, "%s: nfs4_acl_set_file() failed: %s\n",
				    path, strerror(errno));
			}
			cnt++;
		} while (elapsed(&start) < 10.0);

		printf("set ACL with %d entries, %zu times in 10 seconds\n", aclsize[i], cnt);
		nfs4_free_acl(to_set);
	}
	return error;
}

/*
 * Check rates at which we can get ACLs of varying sizes
 */
static int acl_get_bench(const char *path)
{
	int error = 0;
	int aclsize[10] = { 1, 4, 8, 12, 16, 20, 24, 28, 32, 36 };
	int i;

	for (i = 0; i < ARRAY_SIZE(aclsize); i++) {
		printf("Bench ACL [%d] entries\n", aclsize[i]);
		struct nfs4_acl *to_set = NULL, *retrieved = NULL;
		struct timespec start;
		size_t cnt = 0;
		to_set = generate_acl_with_entries(aclsize[i]);
		if (to_set == NULL) {
			errx(EX_OSERR, "%s: failed to generate ACL entry", path);
		}
		error = nfs4_acl_set_file(to_set, path);
		if (error) {
			errx(EX_OSERR, "%s: nfs4_acl_set_file() failed: %s\n",
			    path, strerror(errno));
		}
		nfs4_free_acl(to_set);
		start = ts_current();
		do {
			retrieved = nfs4_acl_get_file(path);
			if (retrieved == NULL) {
				errx(EX_OSERR, "%s: nfs4_acl_get_file() failed: %s\n",
				    path, strerror(errno));
			}
			nfs4_free_acl(retrieved);
			cnt++;
		} while (elapsed(&start) < 10.0);

		printf("Retrieved ACL with %d entries, %zu times in 10 seconds\n", aclsize[i], cnt);
	}
	return error;
}

/*
 * Basic test that sets an ACL with single ACE on
 * the give path. Iterates through all ACE whotypes.
 * Resets ACL on path after each iteration.
 */
static int set_and_verify_aces(const char *path)
{
	int error, i;
	int carried_error = 0;
	struct nfs4_acl *old_acl = NULL;

	/*
	 * Test sets directory-specific flags
	 */
	old_acl = nfs4_acl_get_file(path);
	if (old_acl == NULL) {
		errx(EX_OSERR, "%s: nfs4_acl_get_file() failed.", path);
	}
	for (i = 0; i < ARRAY_SIZE(acetemplates); i++) {
		printf("Testing [%s]\n", acetemplates[i].name);
		struct nfs4_acl *new_acl = NULL, *ret_acl = NULL;
		struct nfs4_ace *new_ace = NULL, *ret_ace = NULL;
		bool is_equal = false;

		new_ace = nfs4_new_ace(
		    true,
		    acetemplates[i].ace.type,
		    acetemplates[i].ace.flag,
		    acetemplates[i].ace.access_mask,
		    acetemplates[i].ace.whotype,
		    acetemplates[i].ace.who_id);
		if (new_ace == NULL) {
			errx(EX_OSERR, "%s: nfs4_new_ace() failed.", path);
		};

		new_acl = nfs4_new_acl(old_acl->is_directory);
		if (new_acl == NULL) {
			errx(EX_OSERR, "%s: nfs4_new_acl() failed.", path);
		}

		error = nfs4_append_ace(new_acl, new_ace);
		if (error) {
			errx(EX_OSERR, "%s: nfs4_append_ace() failed", path);
		}

		error = nfs4_acl_set_file(new_acl, path);
		if (error) {
			errx(EX_OSERR, "%s: nfs4_acl_set_file() failed: %s", path, strerror(errno));
		}

		ret_acl = nfs4_acl_get_file(path);
		if (ret_acl == NULL) {
			errx(EX_OSERR, "%s: nfs4_acl_get_file() failed for new ACL.", path);
		}

		ret_ace = nfs4_get_first_ace(ret_acl);
		if (ret_ace == NULL) {
			errx(EX_OSERR, "%s: nfs4_acl_get_first_ace() failed for new ACL.", path);
		}

		is_equal = ace_is_equal(new_ace, ret_ace);
		if (!is_equal) {
			fprintf(stderr, "%s: resulting ACEs differ\n", path);
			carried_error = -1;
		}
		nfs4_free_acl(new_acl);
		nfs4_free_acl(ret_acl);
	}

	error = nfs4_acl_set_file(old_acl, path);
	if (error) {
		errx(EX_OSERR, "%s: nfs4_acl_set_file() failed to restore original ACL: %s", path, strerror(errno));
	}
	nfs4_free_acl(old_acl);
	return carried_error;
}
/*
 * This test verifies that JSON input correctly
 * sets an ACL entry.
 */
static int json_set_and_verify(const char *path)
{
	int error, i;
	int carried_error = 0;
	struct nfs4_acl *old_acl = NULL;
	bool verbose = true;

	/*
	 * Test sets directory-specific flags
	 */
	old_acl = nfs4_acl_get_file(path);
	if (old_acl == NULL) {
		errx(EX_OSERR, "%s: nfs4_acl_get_file() failed.", path);
	}
	if (!old_acl->is_directory) {
		errno = ENOTDIR;
		warnx("%s: path must be directory.", path);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(acetemplates); i++) {
		printf("Testing [%s]\n", acetemplates[i].name);
		char *acltxt1 = NULL;
		char *acltxt2 = NULL;
		char *acetxt = NULL;
		struct nfs4_acl *new_acl = NULL;
		struct nfs4_ace *new_ace = NULL;
		json_t *jsacl = NULL, *jsace = NULL;
		int json_flags = ACL_TEXT_NUMERIC_IDS;

		if (verbose) {
			json_flags |= ACL_TEXT_VERBOSE;
		}

		new_ace = nfs4_new_ace(
		    true,
		    acetemplates[i].ace.type,
		    acetemplates[i].ace.flag,
		    acetemplates[i].ace.access_mask,
		    acetemplates[i].ace.whotype,
		    acetemplates[i].ace.who_id);
		if (new_ace == NULL) {
			errx(EX_OSERR, "%s: nfs4_new_ace() failed.", path);
		};

		jsace = _nfs4_ace_to_json(new_ace, json_flags);
		if (jsace == NULL) {
			errx(EX_OSERR, "%s: _nfs4_ace_to_json() failed.", path);
		}

		acetxt = json_dumps(jsace, 0);
		if (acetxt == NULL) {
			errx(EX_OSERR, "%s: json_dumps() failed.", path);
		}
		json_decref(jsace);

		error = asprintf(&acltxt1, "[ %s ]", acetxt);
		if (error == -1) {
			errx(EX_OSERR, "%s: asprintf() failed for [%s].", path, acetxt);
		}
		free(acetxt);

		error = set_acl_path_json(path, acltxt1);
		if (error) {
			errx(EX_OSERR, "%s: set_acl_path_json() failed.", path);
		}

		new_acl = nfs4_acl_get_file(path);
		if (new_acl == NULL) {
			errx(EX_OSERR, "%s: nfs4_acl_get_file() failed.", path);
		}

		jsacl = _nfs4_acl_to_json(new_acl, json_flags);
		if (jsacl == NULL) {
			errx(EX_OSERR, "%s: nfs_acl_to_json() failed.", path);
		}

		acltxt2 = json_dumps(jsacl, 0);
		if (acltxt2 == NULL) {
			errx(EX_OSERR, "%s: json_dumps() failed.", path);
		}

		error = strcmp(acltxt1, acltxt2);
		if (error) {
			fprintf(stderr, "initial and final ACLs differ");
			carried_error = -1;
		}

		json_decref(jsacl);
		free(new_acl);
		error = nfs4_acl_set_file(old_acl, path);
		if (error) {
			errx(EX_OSERR, "%s: failed to restore original acl.", path);
		}
	}
	free(old_acl);
	return carried_error;
}
/*
 * This test generates a random buffer of pre-determined size and
 * writes payload to the NFSv4 ACL xattr and validates errno.
 */
static int random_test_1(const char *path)
{
	char *rndbuf = NULL;
	size_t bufsz;
	int error, i;
	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		printf("testing [%s] size random buffer for ACL\n",
			attrs[i].name);

		rndbuf = malloc(attrs[i].size);
		if (rndbuf == NULL) {
			errx(EX_OSERR, "%s: malloc() failed", path);
		}

		bufsz = getrandom(rndbuf, attrs[i].size, 0);
		if (bufsz == -1) {
			errx(EX_OSERR, "%s: getrandom() failed for %ld bytes",
			     path, attrs[i].size);
		}

		error = setxattr(path, ACL_NFS4_XATTR, rndbuf, bufsz, 0);
		if (error != -1) {
			errx(EX_OSERR, "%s: setxattr() succeeded unexpectedly on "
			     "test [%s]", path, attrs[i].name);
		}

		if (attrs[i].err && (attrs[i].err != errno)) {
			errx(EX_OSERR, "%s: test %s, errno %d != %d",
			     path, attrs[i].name, errno, attrs[i].err);
		}

		printf("%s: test [%s] succeeded\n", path, attrs[i].name);
		free(rndbuf);
		sleep(1);
	}
	return 0;
}


/*
 * This test generates a random buffer of random size and
 * writes payload to the NFSv4 ACL xattr. This is a stress
 * test.
 */
static int random_test_2(const char *path)
{
	char *rndbuf = NULL;
	char sz[2];
	size_t bufsz;
	int error, i;

	printf("testing random data and size writes to ACL xattr\n");
	for (i = 0; i < 100000; i++) {
		int s;
		bufsz = getrandom(&sz, 2, 0);
		if (bufsz == -1) {
			errx(EX_OSERR, "%s: getrandom() failed", path);
		}

		s = (int)sz[0] + ((int)sz[1] << 8);

		if (i <= 5) {
			printf("preparing to set %d byte data\n", s);
			sleep(1);
		}
		else if (i == 6) {
			printf("starting unbounded setxattr tests\n");
		}

		rndbuf = malloc(s);
		if (rndbuf == NULL) {
			errx(EX_OSERR, "%s: malloc() failed", path);
		}

		bufsz = getrandom(rndbuf, s, 0);
		if (bufsz == -1) {
			errx(EX_OSERR, "%s: getrandom() failed for %d bytes",
			     path, s);
		}

		error = setxattr(path, ACL_NFS4_XATTR, rndbuf, bufsz, 0);
		if (error != -1) {
			errx(EX_OSERR, "%s: setxattr() succeeded unexpectedly on "
			     "test [%s]", path, attrs[i].name);
		}
		free(rndbuf);
	}
	return (0);
}

const struct {
	const char *name;
	int (*test_acl_fn)(const char *path);
} tests[] = {
	{ "set_max_aces", acl_set_max_cnt },
	{ "bench_acl_get", acl_get_bench },
	{ "bench_acl_set", acl_set_bench },
	{ "basic_read_and_write", set_and_verify_aces },	/* basic validation of reading and writing of ACLs */
#if 0 	/* disabled until development complete */
	{ "json_basic", json_set_and_verify },			/* basic validation of reading and writing via JSON */
#endif
	{ "random1", random_test_1 },				/* set an array of different xattr size. check errno */
	{ "random2", random_test_2 },				/* stress test with randomized xattr buffers */
};

int run_tests(const char *path)
{
	int error, carried_error = 0, i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (run_all || (strcmp(to_run, tests[i].name) == 0)) {
			printf("test: [%s]\n",tests[i].name);
			error = tests[i].test_acl_fn(path);
			if (error) {
				carried_error = error;
			}
			printf("result: %s\n\n", error ? "FAIL" : "PASS");
		}
	}
	return carried_error;
}

int main(int argc, char **argv)
{
	int i, error, opt;
	int carried_error = 0;
	execname = basename(argv[0]);

        while ((opt = getopt_long(argc, argv, "t:h?", long_options, NULL)) != -1) {
                switch (opt) {
		case 't':
			to_run = optarg;
			if (strcmp(to_run, "all") == 0) {
				run_all = true;
			}
			break;
		case 'h':
		case '?':
		default:
			usage(1);
			return 0;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fprintf(stderr, "%s: path not specified.\n", execname);
		usage(0);
		return (1);
	}

	for (i = 0; i < argc; i++) {
		printf("Torture testing NFSv4 ACL on path: %s\n", argv[i]);
		error = run_tests(argv[i]);
		if (error) {
			carried_error = error;
		}
	}
	return carried_error;
}

static void usage(int label)
{
	int i;
	if (label)
		fprintf(stderr, "%s %s -- test NFSv4 file or directory access control lists.\n", execname, VERSION);

	static const char *_usage = \
	"Usage: %s [OPTIONS] [file ...]\n\n"
	"    -t, --test          name of test to run\n\n";

	fprintf(stderr, _usage, execname);
	fprintf(stderr, "Available tests:\n");
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		fprintf(stderr, "\t%s\n", tests[i].name);
	}
	fprintf(stderr, "\n\n\"all\" may be used to run all of the aforementioned tests.\n");
}
