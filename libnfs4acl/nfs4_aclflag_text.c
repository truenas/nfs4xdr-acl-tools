/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
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
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <sys/types.h>

#include "libacl_nfs4.h"

#define ACLFLAG_STR_MAX 34

static const struct {
	nfs4_acl_aclflags_t flag;
	const char *flagstr;
} acl_flag_str[] = {
	{ ACL_AUTO_INHERIT, "auto-inherit" },
	{ ACL_PROTECTED, "protected" },
	{ ACL_DEFAULTED, "defaulted" },
	{ 0, "none" },
	{ 0, NULL },
};

bool
nfs4_aclflag_from_text(char *flags, nfs4_acl_aclflags_t *_flags4p)
{
	int flags4p = 0, i, mapped;
	char *field = NULL;
	bool found;

	while ((field = strsep(&flags, ",")) != NULL) {
		found = false;
		mapped = 0;
		for (i = 0; acl_flag_str[i].flagstr != NULL; i++) {
			if (strcmp(field, acl_flag_str[i].flagstr) == 0) {
				mapped = acl_flag_str[i].flag;
				flags4p |= acl_flag_str[i].flag;
				found = true;
			}
		}
		if (!found) {
			warnx("%s: invalid aclflag", field);
			errno = EINVAL;
			return (false);
		}
	}

	*_flags4p = flags4p;
	return (true);
}


bool
nfs4_aclflag_to_text(nfs4_acl_aclflags_t flags4, char **out)
{
	int i, off = 0;
	size_t size = ACLFLAG_STR_MAX;
	char *flags = NULL;

	flags = calloc(1, size);
	if (flags == NULL) {
		errno = ENOMEM;
		return false;
	}
	for (i = 0; acl_flag_str[i].flag != 0; i++) {
		if (acl_flag_str[i].flag & flags4) {
			if (off) {
				off += snprintf(flags + off, size - off, ",");
			}
			off += snprintf(flags + off, size - off, "%s:",
					acl_flag_str[i].flagstr);
		}
	}
	if (*flags == '\0') {
		snprintf(flags, size, "none");
	}
	*out = flags;
	return true;
}
