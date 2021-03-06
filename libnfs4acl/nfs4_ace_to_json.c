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
#include <ctype.h>
#include <assert.h>
#include <jansson.h>
#include <sysexits.h>
#include <err.h>
#include "nfs4_json.h"
#include "libacl_nfs4.h"

static int
who_to_json(json_t *_parent, struct nfs4_ace *entry, bool numeric)
{
	int error;
	char *tag = NULL;
	char who_str[NFS4_MAX_PRINCIPALSIZE + 1] = {0};
	nfs4_acl_id_t who_id = -1;

	switch (entry->whotype) {
	case NFS4_ACL_WHO_NAMED:
		tag = NFS4_IS_GROUP(entry->flag) ? "GROUP" : "USER";
		if (numeric) {
			error = acl_nfs4_get_who(entry, &who_id, NULL, 0);
			if (error) {
				return (error);
			}
		}
		else {
			error = acl_nfs4_get_who(entry, &who_id, who_str,
						 sizeof(who_str));
			if (error) {
				return (error);
			}
		}
		break;
	case NFS4_ACL_WHO_OWNER:
		tag = "owner@";
		break;
	case NFS4_ACL_WHO_GROUP:
		tag = "group@";
		break;
	case NFS4_ACL_WHO_EVERYONE:
		tag = "everyone@";
		break;
	default:
		return (-1);

	}
	error = json_object_set_new(_parent, "tag", json_string(tag));
	if (error) {
		return (error);
	}
	if (!numeric && entry->whotype == NFS4_ACL_WHO_NAMED) {
		error = json_object_set_new(_parent, "who", json_string(who_str));
		if (error) {
			return (error);
		}
	}
	error = json_object_set_new(_parent, "id", json_integer((int)who_id));
	if (error) {
		return (error);
	}

	return (0);
}

static int
perms_to_json(json_t *_parent, nfs4_acl_perm_t access_mask, bool verbose)
{
	int error, i;
	json_t *basic = NULL, *perms = NULL;
	perms = json_object();
	if (perms == NULL) {
		return (-1);
	}
	if (!verbose) {
		for (i = 0; i < ARRAY_SIZE(basicperms2txt); i++) {
			if (basicperms2txt[i].perm == access_mask) {
				basic = json_string(basicperms2txt[i].name);
				if (basic == NULL) {
					errx(EX_OSERR, "json_string() failed for %s",
					    basicperms2txt[i].name);
				}
				break;
			}
		}
		if (basic) {
			error = json_object_set_new(perms, "BASIC", basic);
			if (error) {
				return (error);
			}
			goto done;
		}

	}
	for (i = 0; i < ARRAY_SIZE(perms2txt); i++) {
		error = json_object_set_new(
		    perms,
		    perms2txt[i].name,
		    json_boolean(access_mask & perms2txt[i].perm ? true : false));

		if (error) {
			return (error);
		}
	}

done:
	error = json_object_set_new(_parent, "perms", perms);
	return (error);
}

static int
flags_to_json(json_t *_parent, nfs4_acl_flag_t flagset, bool verbose)
{
	int error, i;
	json_t *basic = NULL, *flags = NULL;
	flags = json_object();
	if (flags == NULL) {
		return (-1);
	}
	if (!verbose) {
		for (i = 0; i < ARRAY_SIZE(basicflags2txt); i++) {
			if (basicflags2txt[i].flag == flagset) {
				basic = json_string(basicflags2txt[i].name);
				if (basic == NULL) {
					errx(EX_OSERR, "json_string() failed for %s",
					    basicflags2txt[i].name);
				}
				break;
			}
		}
		if (basic) {
			error = json_object_set_new(flags, "BASIC", basic);
			if (error) {
				return (error);
			}
			goto done;
		}

	}

	for (i = 0; i < ARRAY_SIZE(flags2txt); i++) {
		error = json_object_set_new(
		    flags,
		    flags2txt[i].name,
		    json_boolean(flagset & flags2txt[i].flag ? true : false));

		if (error) {
			return (error);
		}
	}

done:
	error = json_object_set_new(_parent, "flags", flags);
	return (error);
}

static int
type_to_json(json_t *_parent, nfs4_acl_type_t _type)
{
	int error;
	json_t *acl_type = NULL;
	acl_type = json_object();
	if (acl_type == NULL) {
		return (-1);
	}

	switch (_type) {
	case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
		acl_type = json_string("ALLOW");
		break;
	case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
		acl_type = json_string("DENY");
		break;
	case NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE:
		acl_type = json_string("AUDIT");
		break;
	case NFS4_ACE_SYSTEM_ALARM_ACE_TYPE:
		acl_type = json_string("ALARM");
		break;
	default:
		return (-1);
	}

	if (acl_type == NULL) {
		return (-1);
	}

	error = json_object_set_new(_parent, "type", acl_type);

	return (error);
}

static int
aclflags_to_json(json_t *_parent, nfs4_acl_aclflags_t _flags)
{
	int i, error;
	json_t *nfs41_flags = NULL;

	nfs41_flags = json_object();
	if (nfs41_flags == NULL) {
		return (-1);
	}

	for (i = 0; i < ARRAY_SIZE(aclflags2txt); i++) {
		error = json_object_set_new(
		    nfs41_flags,
		    aclflags2txt[i].name,
		    json_boolean(_flags & aclflags2txt[i].flag ? true : false));

		if (error) {
			return (error);
		}
	}
	error = json_object_set_new(_parent, "nfs41_flags", nfs41_flags);
	return (error);
}

json_t
*_nfs4_ace_to_json(struct nfs4_ace *entry, int flags)
{
	int error;
	json_t *jsout = NULL;
	nfs4_acl_flag_t flagset = 0;

	flagset = entry->flag & (NFS4_ACE_DIRECTORY_INHERIT_ACE |
				 NFS4_ACE_FILE_INHERIT_ACE |
				 NFS4_ACE_INHERIT_ONLY_ACE |
				 NFS4_ACE_NO_PROPAGATE_INHERIT_ACE |
				 NFS4_ACE_INHERITED_ACE);
	jsout = json_object();
	if (jsout == NULL) {
		return (NULL);
	}

	error = who_to_json(jsout, entry, flags & ACL_TEXT_NUMERIC_IDS);
	if (error) {
		json_decref(jsout);
		return (NULL);
	}

	error = perms_to_json(jsout, entry->access_mask, flags & ACL_TEXT_VERBOSE);
	if (error) {
		json_decref(jsout);
		return (NULL);
	}

	error = flags_to_json(jsout, flagset, flags & ACL_TEXT_VERBOSE);
	if (error) {
		json_decref(jsout);
		return (NULL);
	}

	error = type_to_json(jsout, entry->type);
	if (error) {
		json_decref(jsout);
		return (NULL);
	}

	return (jsout);
}


json_t
*_nfs4_acl_to_json(struct nfs4_acl *aclp, int flags)
{
	int error;
	struct nfs4_ace *ace = NULL;
	json_t *jsout = NULL, *dacl = NULL;

	if (aclp->naces == 0) {
		errno = ENODATA;
		return (NULL);
	}

	jsout = json_object();
	if (jsout == NULL) {
		return (NULL);
	}

	dacl = json_array();
	if (dacl == NULL) {
		json_decref(jsout);
		return (NULL);
	}

	for (ace = nfs4_get_first_ace(aclp); ace != NULL;
	     ace = nfs4_get_next_ace(&ace)) {
		json_t *js_ace = NULL;
		js_ace = _nfs4_ace_to_json(ace, flags);
		if (js_ace == NULL) {
			json_decref(jsout);
			return (NULL);
		}
		error = json_array_append_new(dacl, js_ace);
		if (error) {
			json_decref(jsout);
			return (NULL);
		}
	}

	error = json_object_set_new(jsout, "acl", dacl);

	error  = aclflags_to_json(jsout, aclp->aclflags4);
	if (error) {
		json_decref(jsout);
		return (NULL);
	}

	return jsout;
}
