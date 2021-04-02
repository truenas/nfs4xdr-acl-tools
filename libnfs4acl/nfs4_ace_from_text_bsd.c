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
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <sys/types.h>

#include "libacl_nfs4.h"

#define MAX_ENTRY_LENGTH 512

/*
 * Parse the tag field of ACL entry passed as "str".  If qualifier
 * needs to follow, then the variable referenced by "need_qualifier"
 * is set to 1, otherwise it's set to 0.
 */

static char *
string_skip_whitespace(char *string)
{

	while (*string && ((*string == ' ') || (*string == '\t')))
		string++;

	return (string);
}

static int
parse_tag(const char *str, struct nfs4_ace *entry, int *need_qualifier)
{

	assert(need_qualifier != NULL);
	char who_str[NFS4_MAX_PRINCIPALSIZE] = {0};
	int whotype;

	*need_qualifier = 0;

	if (strcmp(str, "owner@") == 0) {
		snprintf(who_str, NFS4_MAX_PRINCIPALSIZE,
			 NFS4_ACL_WHO_OWNER_STRING);
		whotype = NFS4_ACL_WHO_OWNER;
		entry->flag |= NFS4_ACE_OWNER;
		return acl_nfs4_set_who(entry, whotype, who_str);
	}

	if (strcmp(str, "group@") == 0) {
		snprintf(who_str, NFS4_MAX_PRINCIPALSIZE,
			 NFS4_ACL_WHO_GROUP_STRING);
		whotype = NFS4_ACL_WHO_GROUP;
		entry->flag |= (NFS4_ACE_GROUP | NFS4_ACE_IDENTIFIER_GROUP);
		return acl_nfs4_set_who(entry, whotype, who_str);
	}

	if (strcmp(str, "everyone@") == 0) {
		snprintf(who_str, NFS4_MAX_PRINCIPALSIZE,
			 NFS4_ACL_WHO_EVERYONE_STRING);
		whotype = NFS4_ACL_WHO_EVERYONE;
		entry->flag |= NFS4_ACE_EVERYONE;
		return acl_nfs4_set_who(entry, whotype, who_str);
	}

	/*
	 * Whotype in this case will be NFS4_ACL_WHO_NAMED,
	 * which means that acl_nfs4_set_who can be called
	 * based on information in the ace qualifier section.
	 */
	if (strcmp(str, "user") == 0 || strcmp(str, "u") == 0) {
		*need_qualifier = 1;
		return 0;
	}
	if (strcmp(str, "group") == 0 || strcmp(str, "g") == 0) {
		*need_qualifier = 1;
		entry->flag |= NFS4_ACE_IDENTIFIER_GROUP;
		return 0;
	}

	warnx("malformed ACL: invalid \"tag\" field");
	return (-1);
}

/*
 * Parse the qualifier field of ACL entry passed as "str".
 * If user or group name cannot be resolved, then the variable
 * referenced by "need_qualifier" is set to 1; it will be checked
 * later to figure out whether the appended_id is required.
 */
static int
parse_qualifier(char *str, struct nfs4_ace *entry, int *need_qualifier)
{
	int qualifier_length;

	assert(need_qualifier != NULL);
	*need_qualifier = 0;

	qualifier_length = strlen(str);

	if (qualifier_length == 0) {
		warnx("malformed ACL: empty \"qualifier\" field");
		return (-1);
	}

	return acl_nfs4_set_who(entry, NFS4_ACL_WHO_NAMED, str);
}

static int
parse_access_mask(char *str, struct nfs4_ace *entry)
{
	int error;
	uint perm;

	error = _nfs4_parse_access_mask(str, &perm);
	if (error)
		return (error);

	entry->access_mask = perm;
	return (0);
}

static int
parse_flags(char *str, struct nfs4_ace *entry)
{
	int error;
	uint flags;

	error = _nfs4_parse_flags(str, &flags);
	if (error)
		return (error);

	entry->flag |= flags;
	return (0);
}

static int
parse_entry_type(const char *str, struct nfs4_ace *entry)
{

	if (strcmp(str, "allow") == 0)
		entry->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
	else if (strcmp(str, "deny") == 0)
		entry->type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
	else if (strcmp(str, "audit") == 0)
		entry->type = NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE;
	else if (strcmp(str, "alarm") == 0)
		entry->type = NFS4_ACE_SYSTEM_ALARM_ACE_TYPE;
	else {
		warnx("malformed ACL: invalid \"type\" field");
		return (-1);
	}
	return (0);
}

static int
parse_appended_id(char *str, struct nfs4_ace *entry)
{
	int qualifier_length;

	qualifier_length = strlen(str);
	if (qualifier_length == 0) {
		warnx("malformed ACL: \"appended id\" field present, "
	           "but empty");
		return (-1);
	}

	return acl_nfs4_set_who(entry, NFS4_ACL_WHO_NAMED, str);
}

static int
number_of_colons(const char *str)
{
	int count = 0;

	while (*str != '\0') {
		if (*str == ':')
			count++;

		str++;
	}

	return (count);
}

struct nfs4_ace
*nfs4_ace_from_text(u_int32_t is_dir, char *str) {
	int error, need_qualifier;
	struct nfs4_ace *entry = NULL;
	char *field = NULL, *qualifier_field = NULL;

	entry = nfs4_new_ace(is_dir,
			     NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
			     0, /* flag */
			     0, /* access_mask */
			     NFS4_ACL_WHO_OWNER,
			     NFS4_ACL_WHO_OWNER_STRING);

	if (entry == NULL) {
		fprintf(stderr, "Failed to create new entry\n");
		return (NULL);
	}

	if (str == NULL)
		goto truncated_entry;
	field = strsep(&str, ":");

	field = string_skip_whitespace(field);
	if ((*field == '\0') && (!str)) {
		/*
		 * Is an entirely comment line, skip to next
		 * comma.
		 */
		free(entry);
		errno = ENODATA;
		return (NULL);
	}

	error = parse_tag(field, entry, &need_qualifier);
	if (error)
		goto malformed_field;

	if (need_qualifier) {
		if (str == NULL)
			goto truncated_entry;
		qualifier_field = field = strsep(&str, ":");
		error = parse_qualifier(field, entry, &need_qualifier);
		if (error)
			goto malformed_field;
	}

	if (str == NULL)
		goto truncated_entry;
	field = strsep(&str, ":");
	error = parse_access_mask(field, entry);
	if (error)
		goto malformed_field;

	if (str == NULL)
		goto truncated_entry;
	/* Do we have "flags" field? */
	if (number_of_colons(str) > 0) {
		field = strsep(&str, ":");
		error = parse_flags(field, entry);
		if (error)
			goto malformed_field;
	}

	if (str == NULL)
		goto truncated_entry;
	field = strsep(&str, ":");
	error = parse_entry_type(field, entry);
	if (error)
		goto malformed_field;

	if (need_qualifier) {
		if (str == NULL) {
			warnx("malformed ACL: unknown user or group name "
			    "\"%s\"", qualifier_field);
			goto truncated_entry;
		}

		error = parse_appended_id(str, entry);
		if (error)
			goto malformed_field;
	}
	fprintf(stderr, "ACL string: [%s] -> whotype: [%d], who: [%s], "
			"access_mask: [0x%08x], flag: [0x%08x], type: [%d]\n",
			str, entry->whotype, entry->who, entry->access_mask,
			entry->flag, entry->type);
	return (entry);

truncated_entry:
malformed_field:
	free(entry);
	errno = EINVAL;
	return (NULL);
}

int
_nfs4_acl_entry_from_text(struct nfs4_acl *aclp, char *str, uint *index)
{
	struct nfs4_ace *entry = NULL;
	int error;
	entry = nfs4_ace_from_text(aclp->is_directory, str);
	if (entry == NULL) {
		fprintf(stderr, "failed to generate ACL entry\n");
		return (-1);
	}

	if (index == NULL) {
		error = nfs4_append_ace(aclp, entry);
	}
	else {
		error = nfs4_insert_ace_at(aclp, entry, *index);
	}
	if (error) {
		fprintf(stderr, "ACL action failed\n");
		free(entry);
		return (error);
	}
	return (0);
}
