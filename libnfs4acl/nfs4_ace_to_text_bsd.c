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
#include "libacl_nfs4.h"


#define MAX_ENTRY_LENGTH 512

static int
format_who(char *str, size_t size, struct nfs4_ace *entry, bool numeric)
{
	int error;
	char who_str[NFS4_MAX_PRINCIPALSIZE + 1] = {0};
	char *tag = NULL;
	uid_t who_id;

	switch(entry->whotype) {
	case NFS4_ACL_WHO_NAMED:
		tag = NFS4_IS_GROUP(entry->flag) ? "group" : "user";
		if (numeric) {
			error = acl_nfs4_get_who(entry, &who_id, NULL, 0);
			if (error) {
				return error;
			}
			snprintf(str, size, "%s:%d", tag, who_id);
		}
		else {
			error = acl_nfs4_get_who(entry, NULL, who_str,
						 sizeof(who_str));
			if (error) {
				return error;
			}
			snprintf(str, size, "%s:%s", tag, who_str);
		}
		break;
	case NFS4_ACL_WHO_OWNER:
		snprintf(str, size, "owner@");
		break;
	case NFS4_ACL_WHO_GROUP:
		snprintf(str, size, "group@");
		break;
	case NFS4_ACL_WHO_EVERYONE:
		snprintf(str, size, "everyone@");
		break;
	default:
		return (-1);
	}

	return 0;
}


static int
format_entry_type(char *str, size_t size, struct nfs4_ace *entry)
{
	switch (entry->type) {
	case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
		snprintf(str, size, "allow");
		break;
	case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
		snprintf(str, size, "deny");
		break;
	case NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE:
		snprintf(str, size, "audit");
		break;
	case NFS4_ACE_SYSTEM_ALARM_ACE_TYPE:
		snprintf(str, size, "alarm");
		break;
	default:
		return (-1);
	}
	return (0);
}

static int
format_additional_id(char *str, size_t size, struct nfs4_ace *entry)
{
	uid_t id;
	int error;

	if (entry->whotype == NFS4_ACL_WHO_NAMED) {
		error = acl_nfs4_get_who(entry, &id, NULL, 0);
		if (error) {
			return (error);
		}
		snprintf(str, size, ":%d", (unsigned int)id);
	}
	else {
		str[0] = '\0';
	}
	return (0);
}

static int
format_entry(char *str, size_t size, struct nfs4_ace *entry, int flags)
{
	size_t off = 0, min_who_field_length = 18;
	int error, len, flagset;
	char buf[MAX_ENTRY_LENGTH + 1];
	error = format_who(buf, sizeof(buf), entry,
			   flags & ACL_TEXT_NUMERIC_IDS);
	if (error) {
		return error;
	}
	len = strlen(buf);
	if (len < min_who_field_length) {
		len = min_who_field_length;
	}
	off += snprintf(str + off, size - off, "%*s:", len, buf);

	error = _nfs4_format_access_mask(buf, sizeof(buf),
					 entry->access_mask,
					 flags & ACL_TEXT_VERBOSE);
	if (error) {
		return error;
	}

	off += snprintf(str + off, size - off, "%s:", buf);

	flagset = entry->flag & (NFS4_ACE_DIRECTORY_INHERIT_ACE |
				  NFS4_ACE_FILE_INHERIT_ACE |
				  NFS4_ACE_INHERIT_ONLY_ACE |
				  NFS4_ACE_NO_PROPAGATE_INHERIT_ACE |
				  NFS4_ACE_INHERITED_ACE);

	error = _nfs4_format_flags(buf, sizeof(buf),
				   flagset,
				   flags & ACL_TEXT_VERBOSE);
	if (error) {
		return error;
	}

	off += snprintf(str + off, size - off, "%s:", buf);

	error = format_entry_type(buf, sizeof(buf), entry);
	if (error) {
		return error;
	}

	off += snprintf(str + off, size - off, "%s", buf);

	if (flags & ACL_TEXT_APPEND_ID) {
		error = format_additional_id(buf, sizeof(buf), entry);
		if (error) {
			return error;
		}
		off += snprintf(str + off, size - off, "%s", buf);
	}
	off += snprintf(str + off, size - off, "\n");

	assert (off < size);

	return(0);
}

char *
_nfs4_acl_to_text_np(struct nfs4_acl *aclp, ssize_t *len_p, int flags)
{
	int error, off = 0, size;
	char *str = NULL;
	struct nfs4_ace *ace = NULL;

	if (aclp->naces == 0) {
		return strdup("");
	}

	size = aclp->naces * MAX_ENTRY_LENGTH;
	str = calloc(1, size);
	if (str == NULL) {
		return (NULL);
	}

	for (ace = nfs4_get_first_ace(aclp); ace != NULL;
	     ace = nfs4_get_next_ace(&ace)) {
		assert(off < size);

		error = format_entry(str + off, size - off, ace, flags);
		if (error) {
			free(str);
			errno = EINVAL;
			return (NULL);
		}

		off = strlen(str);
	}

	assert(off < size);
	str[off] = '\0';

	if (len_p != NULL) {
		*len_p = off;
	}
	return str;
}
