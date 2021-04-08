/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008, 2009 Edward Tomasz Napierała <trasz@FreeBSD.org>
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
#include <ctype.h>
#include <assert.h>
#include <stdint.h>
#include <err.h>
#include "libacl_nfs4.h"

struct flagnames_struct {
	uint32_t	flag;
	const char	*name;
	char		letter;
};

struct flagnames_struct a_flags[] =
    {{ NFS4_ACE_FILE_INHERIT_ACE, "file_inherit", 'f'},
     { NFS4_ACE_DIRECTORY_INHERIT_ACE, "dir_inherit", 'd'},
     { NFS4_ACE_INHERIT_ONLY_ACE, "inherit_only", 'i'},
     { NFS4_ACE_NO_PROPAGATE_INHERIT_ACE, "no_propagate", 'n'},
     { NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG, "successfull_access", 'S'},
     { NFS4_ACE_FAILED_ACCESS_ACE_FLAG, "failed_access", 'F'},
     { NFS4_ACE_INHERITED_ACE, "inherited", 'I' },
     /*
      * There is no ACE_IDENTIFIER_GROUP here - SunOS does not show it
      * in the "flags" field.  There is no ACE_OWNER, ACE_GROUP or
      * ACE_EVERYONE either, for obvious reasons.
      */
     { 0, 0, 0}};

struct flagnames_struct a_access_masks[] =
    {{ NFS4_ACE_READ_DATA, "read_data", 'r'},
     { NFS4_ACE_WRITE_DATA, "write_data", 'w'},
     { NFS4_ACE_EXECUTE, "execute", 'x'},
     { NFS4_ACE_APPEND_DATA, "append_data", 'p'},
     { NFS4_ACE_DELETE_CHILD, "delete_child", 'D'},
     { NFS4_ACE_DELETE, "delete", 'd'},
     { NFS4_ACE_READ_ATTRIBUTES, "read_attributes", 'a'},
     { NFS4_ACE_WRITE_ATTRIBUTES, "write_attributes", 'A'},
     { NFS4_ACE_READ_NAMED_ATTRS, "read_xattr", 'R'},
     { NFS4_ACE_WRITE_NAMED_ATTRS, "write_xattr", 'W'},
     { NFS4_ACE_READ_ACL, "read_acl", 'c'},
     { NFS4_ACE_WRITE_ACL, "write_acl", 'C'},
     { NFS4_ACE_WRITE_OWNER, "write_owner", 'o'},
     { NFS4_ACE_SYNCHRONIZE, "synchronize", 's'},
     { NFS4_ACE_FULL_SET, "full_set", '\0'},
     { NFS4_ACE_MODIFY_SET, "modify_set", '\0'},
     { NFS4_ACE_READ_SET, "read_set", '\0'},
     { NFS4_ACE_WRITE_SET, "write_set", '\0'},
     { 0, 0, 0}};

static const char *
format_flag(uint32_t *var, const struct flagnames_struct *flags)
{

	for (; flags->name != NULL; flags++) {
		if ((flags->flag & *var) == 0)
			continue;

		*var &= ~flags->flag;
		return (flags->name);
	}

	return (NULL);
}

static int
format_flags_verbose(char *str, size_t size, uint32_t var,
    const struct flagnames_struct *flags)
{
	size_t off = 0;
	const char *tmp;

	while ((tmp = format_flag(&var, flags)) != NULL) {
		off += snprintf(str + off, size - off, "%s/", tmp);
		assert (off < size);
	}

	/* If there were any flags added... */
	if (off > 0) {
		off--;
		/* ... then remove the last slash. */
		assert(str[off] == '/');
	}

	str[off] = '\0';

	return (0);
}

static int
format_flags_compact(char *str, size_t size, uint32_t var,
    const struct flagnames_struct *flags)
{
	size_t i;

	for (i = 0; flags[i].letter != '\0'; i++) {
		assert(i < size);
		if ((flags[i].flag & var) == 0)
			str[i] = '-';
		else
			str[i] = flags[i].letter;
	}

	str[i] = '\0';

	return (0);
}

static int
parse_flags_verbose(const char *strp, uint32_t *var,
    const struct flagnames_struct *flags, const char *flags_name,
    int *try_compact)
{
	int i, found, ever_found = 0;
	char *str, *flag;

	str = strdup(strp);
	*try_compact = 0;
	*var = 0;

	while (str != NULL) {
		flag = strsep(&str, "/:");

		found = 0;
		for (i = 0; flags[i].name != NULL; i++) {
			if (strcmp(flags[i].name, flag) == 0) {
				*var |= flags[i].flag;
				found = 1;
				ever_found = 1;
			}
		}

		if (!found) {
			if (ever_found)
				warnx("malformed ACL: \"%s\" field contains "
				    "invalid flag \"%s\"", flags_name, flag);
			else
				*try_compact = 1;
			free(str);
			return (-1);
		}
	}

	free(str);
	return (0);
}

static int
parse_flags_compact(const char *str, uint32_t *var,
    const struct flagnames_struct *flags, const char *flags_name)
{
	int i, j, found;

	*var = 0;

	for (i = 0;; i++) {
		if (str[i] == '\0')
			return (0);

		/* Ignore minus signs. */
		if (str[i] == '-')
			continue;

		found = 0;

		for (j = 0; flags[j].name != NULL; j++) {
			if (flags[j].letter == str[i]) {
				*var |= flags[j].flag;
				found = 1;
				break;
			}
		}

		if (!found) {
			warnx("malformed ACL: \"%s\" field contains "
			    "invalid flag \"%c\"", flags_name, str[i]);
			return (-1);
		}
	}
}

int
_nfs4_format_flags(char *str, size_t size, uint var, int verbose)
{

	if (verbose)
		return (format_flags_verbose(str, size, var, a_flags));

	return (format_flags_compact(str, size, var, a_flags));
}

int
_nfs4_format_access_mask(char *str, size_t size, uint var, int verbose)
{

	if (verbose)
		return (format_flags_verbose(str, size, var, a_access_masks));

	return (format_flags_compact(str, size, var, a_access_masks));
}

int
_nfs4_parse_flags(const char *str, nfs4_acl_flag_t *flags)
{
	int error, try_compact;
	uint32_t tmpflags;

	error = parse_flags_verbose(str, &tmpflags, a_flags, "flags", &try_compact);
	if (error && try_compact)
		error = parse_flags_compact(str, &tmpflags, a_flags, "flags");

	*flags = (nfs4_acl_flag_t)tmpflags;

	return (error);
}

int
_nfs4_parse_access_mask(const char *str, nfs4_acl_perm_t *perms)
{
	int error, try_compact;
	uint32_t tmpperms;

	error = parse_flags_verbose(str, &tmpperms, a_access_masks,
	    "access permissions", &try_compact);
	if (error && try_compact)
		error = parse_flags_compact(str, &tmpperms,
		    a_access_masks, "access permissions");

	*perms = (nfs4_acl_perm_t)tmpperms;

	return (error);
}
