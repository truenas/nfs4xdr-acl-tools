/*
 *  * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 iXsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <err.h>
#include <jansson.h>
#include "libacl_nfs4.h"

int
nfs4_print_acl_json(char *path, int flags)
{
	struct nfs4_acl *acl = NULL;
	char *acl_text = NULL;
	struct stat st;
	json_t *json_acl = NULL;
	int error, is_trivial;

	acl = nfs4_acl_get_file(path);
	if (acl == NULL) {
		return (-1);
	}
	error = nfs4_acl_is_trivial_np(acl, &is_trivial);
	if (error) {
		nfs4_free_acl(acl);
		warnx("acl_is_trivial() failed\n");
		return (-1);
	}

	error = stat(path, &st);
	if (error) {
		nfs4_free_acl(acl);
		return (-1);
	}

	json_acl = _nfs4_acl_to_json(acl, flags);
	if (json_acl == NULL) {
		warnx("Failed to convert NFSv4 ACL to JSON: %s",
		      strerror(errno));
		nfs4_free_acl(acl);
		return (-1);
	}
	nfs4_free_acl(acl);

	error = json_object_set_new(json_acl,
	    "trivial",
	    json_boolean(is_trivial ? true : false));
	if (error) {
		json_decref(json_acl);
		warnx("acl_is_trivial() failed");
		return (error);
	}

	error = json_object_set_new(json_acl,
	    "uid",
	    json_integer(st.st_uid));
	if (error) {
		json_decref(json_acl);
		warnx("failed to add uid to JSON output");
		return (error);
	}

	error = json_object_set_new(json_acl,
	    "gid",
	    json_integer(st.st_uid));
	if (error) {
		json_decref(json_acl);
		warnx("failed to add gid to JSON output");
		return (error);
	}

	error = json_object_set_new(json_acl,
	    "path",
	    json_string(path));
	if (error) {
		json_decref(json_acl);
		warnx("failed to add path to JSON output");
		return (error);
	}

	acl_text = json_dumps(json_acl, 0);
	if (acl_text == NULL) {
		json_decref(json_acl);
		warnx("Failed to convert ACL to JSON text");
		return (error);
	}

	printf("%s\n", acl_text);
	json_decref(json_acl);
	free(acl_text);
	return (0);
}
