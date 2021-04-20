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
#include <sysexits.h>
#include <err.h>
#include <sys/stat.h>
#include <jansson.h>
#include "nfs4_json.h"
#include "libacl_nfs4.h"


/*
 * Load user-provided text. Allocates memory.
 */
static json_t
*load_json(const char *text) {
	json_t *root = NULL;
	json_error_t error;

	root = json_loads(text, 0, &error);
	if (root == NULL) {
		errx(EX_DATAERR, "JSON error on line %d: %s",
		     error.line, error.text);
	}
	return root;
}

static int
json_verrors_append(json_t *verrors, char *err_field, char *err_txt)
{
	int error;
	json_t *verr = NULL;

	if (!json_is_array(verrors)) {
		warnx("verrors is not an array. Cannot append "
		      "error: %s for field: %s", err_txt, err_field);
		return (-1);
	}

	verr = json_object();
	if (verr == NULL) {
		warnx("json_verrors_append(): "
		      "Failed to generate JSON object.");
		return (-1);
	}

	error = json_object_set_new(verr, err_field, json_string(err_txt));
	if (error) {
		warnx("json_verrors_append(): "
		      "Failed to generate JSON error message for [%s]",
		      err_txt);
		json_decref(verr);
		return (-1);
	}

	error = json_array_append_new(verrors, verr);
	if (error) {
		warnx("json_verrors_append(): "
		      "Failed to append error message [%s] "
		      "to JSON error array.",
		      err_txt);
		json_decref(verr);
		return (-1);
	}

	free(err_field);
	free(err_txt);
	err_field = NULL;
	err_txt = NULL;

	return (0);

}

static int
json_ace_get_type(json_t *_jsace, int idx, nfs4_acl_type_t *_typep, json_t *_verrors)
{
	nfs4_acl_type_t acltype = 0;
	json_t *jsacltype = NULL;
	const char *type_str = NULL;
	char *err_str = NULL;
	char *err_field = NULL;
	int i, error;
	bool found_type = false;

	jsacltype = json_object_get(_jsace, "type");
	if (!json_is_string(jsacltype)) {
		if (jsacltype == NULL) {
			error = asprintf(&err_str, "ACE 'type' field is required.");
		}
		else {
			error = asprintf(&err_str, "ACE type must be a string.");
		}
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.type", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error == -1) {
			return (error);
		}
		return (-EINVAL);
	}

	type_str = json_string_value(jsacltype);
	for (i = 0; i < ARRAY_SIZE(type2txt); i++) {
		if (strcmp(type2txt[i].name, type_str) == 0) {
			acltype = type2txt[i].type;
			found_type = true;
			break;
		}
	}

	if (!found_type) {
		error = asprintf(&err_str, "Invalid ACE type: %s", type_str);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.type", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}
	*_typep = acltype;
	return (0);
}

static int
json_ace_get_perm(json_t *_jsace, int idx, nfs4_acl_perm_t *_perms, json_t *_verrors)
{
	nfs4_acl_perm_t permset = 0;
	json_t *jspermset = NULL;
	json_t *basic = NULL;
	char *err_str = NULL;
	char *err_field = NULL;
	void *iter;
	int i, error;

	jspermset = json_object_get(_jsace, "perms");
	if (!json_is_object(jspermset)) {
		if (jspermset == NULL) {
			error = asprintf(&err_str, "ACE 'perms' field is required.");
		}
		else {
			error = asprintf(&err_str, "ACE perms is not a JSON object.");
		}
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.perms", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		return (-EINVAL);
	}

	/*
	 * First check if the perms contain a BASIC permission type.
	 * If it does, we can avoid iterating keys / values in the JSON
	 * object.
	 */
	basic = json_object_get(jspermset, "BASIC");
	if (basic != NULL) {
		bool found_basic = false;
		const char *basic_str = NULL;
		if (!json_is_string(basic)) {
			error = asprintf(&err_str, "BASIC ACE permset is not a string.");
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.perms", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			return (-EINVAL);
		}
		basic_str = json_string_value(basic);
		for (i = 0; i < ARRAY_SIZE(basicperms2txt); i++) {
			if (strcmp(basic_str, basicperms2txt[i].name) == 0) {
				found_basic = true;
				permset = basicperms2txt[i].perm;
				break;
			}
		}
		if (!found_basic) {
			error = asprintf(&err_str, "Invalid BASIC ACE type: %s", basic_str);
			if (error == -1) {
				return (error);
			}

			error = asprintf(&err_field, "acl.%d.perms", idx);
			if (error == -1) {
				return (error);
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		*_perms = permset;
		return (0);
	}

	/*
	 * Iterate through key-value pairs in JSON perms object.
	 * Generate error messages for unexpected keys and values
	 * that are not boolean.
	 */
	iter = json_object_iter(jspermset);
	while (iter) {
		const char *key;
		json_t *value = NULL;
		bool found_key = false;
		bool is_set;

		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (!json_is_boolean(value)) {
			error = asprintf(&err_str, "ACE perm [%s] is not boolean.", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.perms", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}

			return (-EINVAL);
		}
		is_set = json_boolean_value(value);
		for (i = 0; i < ARRAY_SIZE(perms2txt); i++) {
			if (strcmp(perms2txt[i].name, key) == 0) {
				permset |= is_set ? perms2txt[i].perm : 0;
				found_key = true;
				break;
			}
		}
		if (!found_key) {
			error = asprintf(&err_str, "Invalid ACE perm: %s", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.perms", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		iter = json_object_iter_next(jspermset, iter);
	}
	*_perms = permset;
	return (0);
}

static int
json_ace_get_flag(json_t *_jsace, int idx, nfs4_acl_flag_t *_flags, json_t *_verrors)
{
	nfs4_acl_flag_t flagset = 0;
	json_t *jsflagset = NULL;
	json_t *basic = NULL;
	char *err_str = NULL;
	char *err_field = NULL;
	void *iter;
	int i, error;

	jsflagset = json_object_get(_jsace, "flags");
	if (!json_is_object(jsflagset)) {
		if (jsflagset == NULL) {
			error = asprintf(&err_str, "ACE 'flags' field is required.");
		}
		else {
			/* Seriously malformed JSON */
			error = asprintf(&err_str, "ACE flags is not a JSON object.");
		}
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.flags", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}

	/*
	 * First check if the perms contain a BASIC flag type.
	 * If it does, we can avoid iterating keys / values in the JSON
	 * object.
	 */
	basic = json_object_get(jsflagset, "BASIC");
	if (basic != NULL) {
		bool found_basic = false;
		const char *basic_str = NULL;
		if (!json_is_string(basic)) {
			error = asprintf(&err_str, "BASIC ACE flagset is not a string.");
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.flags", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		basic_str = json_string_value(basic);
		for (i = 0; i < ARRAY_SIZE(basicflags2txt); i++) {
			if (strcmp(basic_str, basicflags2txt[i].name) == 0) {
				found_basic = true;
				flagset = basicflags2txt[i].flag;
				break;
			}
		}
		if (!found_basic) {
			error = asprintf(&err_str, "Invalid BASIC ACE flag type: %s",
					 basic_str);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}
			error = asprintf(&err_field, "acl.%d.flags", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		*_flags = flagset;
		return (0);
	}

	/*
	 * Iterate through key-value pairs in JSON perms object.
	 * Generate error messages for unexpected keys and values
	 * that are not boolean.
	 */
	iter = json_object_iter(jsflagset);
	while (iter) {
		const char *key;
		json_t *value = NULL;
		bool found_key = false;
		bool is_set;

		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (!json_is_boolean(value)) {
			error = asprintf(&err_str, "ACE flag [%s] is not boolean.", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.flags", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		is_set = json_boolean_value(value);
		for (i = 0; i < ARRAY_SIZE(flags2txt); i++) {
			if (strcmp(flags2txt[i].name, key) == 0) {
				flagset |= is_set ? flags2txt[i].flag : 0;
				found_key = true;
				break;
			}
		}
		if (!found_key) {
			error = asprintf(&err_str, "Invalid ACE flag: %s", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.%d.flags", idx);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		iter = json_object_iter_next(jsflagset, iter);
	}
	*_flags = flagset;
	return (0);
}

static int
json_ace_get_who(json_t *_jsace, int idx, struct nfs4_ace *entry, json_t *_verrors)
{
	nfs4_acl_who_t whotype = 0;
	nfs4_acl_id_t id = -1;
	json_t *jstag = NULL;
	json_t *jsid = NULL;
	json_t *jswho = NULL;
	char *err_str = NULL;
	char *err_field = NULL;
	const char *tag = NULL, *who = NULL;
	int error;


	jstag = json_object_get(_jsace, "tag");
	if (!json_is_string(jstag)) {
		if (jstag == NULL) {
			error = asprintf(&err_str, "ACE 'tag' field is required.");
		}
		else {
			error = asprintf(&err_str, "ACE tag is not a string.");
		}
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.tag", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}
	tag = json_string_value(jstag);
	if (strcmp(tag, "owner@") == 0) {
		whotype = NFS4_ACL_WHO_OWNER;
		entry->flag |= NFS4_ACE_OWNER;
		return acl_nfs4_set_who(entry, whotype, NULL, &id);
	}

	if (strcmp(tag, "group@") == 0) {
		whotype = NFS4_ACL_WHO_GROUP;
		entry->flag |= (NFS4_ACE_GROUP | NFS4_ACE_IDENTIFIER_GROUP);
		return acl_nfs4_set_who(entry, whotype, NULL, &id);
	}

	if (strcmp(tag, "everyone@") == 0) {
		whotype = NFS4_ACL_WHO_EVERYONE;
		entry->flag |= NFS4_ACE_EVERYONE;
		return acl_nfs4_set_who(entry, whotype, NULL, &id);
	}

	/*
	 * Whotype in this case will be NFS4_ACL_WHO_NAMED,
	 * which means that acl_nfs4_set_who can be called
	 * based on information in the ace qualifier section.
	 */
	if (strcmp(tag, "USER") == 0) {
		whotype = NFS4_ACL_WHO_NAMED;
	}
	else if (strcmp(tag, "GROUP") == 0) {
		whotype = NFS4_ACL_WHO_NAMED;
		entry->flag |= NFS4_ACE_IDENTIFIER_GROUP;
	}
	else {
		error = asprintf(&err_str, "ACE tag [%s] is invalid.", tag);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.tag", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}

	/*
	 * Principal can be specified through either numeric ID
	 * or name.
	 */

	/* First check for Numeric ID */
	jsid = json_object_get(_jsace, "id");
	if (jsid && (!json_is_integer(jsid))) {
		error = asprintf(&err_str, "ACE id is not an integer.");
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.id", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}
	else if (jsid) {
		id = (nfs4_acl_id_t)json_integer_value(jsid);
		return acl_nfs4_set_who(entry, whotype, NULL, &id);
	}

	/* We did not have a numeric ID, now check for name */
	jswho = json_object_get(_jsace, "who");
	if (jswho && (!json_is_string(jswho))) {
		error = asprintf(&err_str, "ACE who is not a string.");
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.%d.who", idx);
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error) {
			return (error);
		}
		return (-EINVAL);
	}
	else if (jswho) {
		who = json_string_value(jswho);
		return acl_nfs4_set_who(entry, whotype, who, NULL);
	}

	/* Neither a numerical ID nor name was specified. Return failure. */
	error = asprintf(&err_str, "ACE principal for [%s] is unspecified.", tag);
	if (error == -1) {
		err(EX_OSERR, "asprintf() failed");
	}

	error = asprintf(&err_field, "acl.%d.id", idx);
	if (error == -1) {
		err(EX_OSERR, "asprintf() failed");
	}

	error = json_verrors_append(_verrors, err_field, err_str);
	if (error) {
		return (error);
	}

	return (-EINVAL);
}

static int
get_aclflags_from_json(json_t *_jsacl, nfs4_acl_aclflags_t *_aclflags, json_t *_verrors)
{
	nfs4_acl_aclflags_t flags4 = 0;
	json_t *js_aclflags = NULL;
	char *err_str = NULL;
	char *err_field = NULL;
	void *iter;
	int i, error;

	js_aclflags = json_object_get(_jsacl, "nfs41_flags");
	if (!json_is_object(js_aclflags)) {
		/*
		 * These flags aren't required to be passed to us,
		 * But due to API / xattr limitations, we have to set
		 * them to something. In this case, 0 and return;
		 */
		if (js_aclflags == NULL) {
			*_aclflags = flags4;
			return (0);
		}
		error = asprintf(&err_str, "'nfs41_flags' field must be JSON object.");
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = asprintf(&err_field, "acl.nfs41_flags");
		if (error == -1) {
			err(EX_OSERR, "asprintf() failed");
		}

		error = json_verrors_append(_verrors, err_field, err_str);
		if (error == -1) {
			return (error);
		}

		return (-EINVAL);
	}

	iter = json_object_iter(js_aclflags);
	while (iter) {
		const char *key;
		json_t *value = NULL;
		bool found_key = false;
		bool is_set;

		key = json_object_iter_key(iter);
		value = json_object_iter_value(iter);
		if (!json_is_boolean(value)) {
			error = asprintf(&err_str, "ACL flag [%s] is not boolean.", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.nfs41_flags");
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}

			return (-EINVAL);
		}
		is_set = json_boolean_value(value);
		for (i = 0; i < ARRAY_SIZE(aclflags2txt); i++) {
			if (strcmp(aclflags2txt[i].name, key) == 0) {
				flags4 |= is_set ? aclflags2txt[i].flag : 0;
				found_key = true;
				break;
			}
		}
		if (!found_key) {
			error = asprintf(&err_str, "Invalid ACL flag: %s", key);
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = asprintf(&err_field, "acl.nfs41_flags");
			if (error == -1) {
				err(EX_OSERR, "asprintf() failed");
			}

			error = json_verrors_append(_verrors, err_field, err_str);
			if (error) {
				return (error);
			}
			return (-EINVAL);
		}
		iter = json_object_iter_next(js_aclflags, iter);
	}
	*_aclflags = flags4;
	return (0);
}

struct nfs4_ace
*convert_json_to_ace(json_t *_jsace, bool is_dir, int idx, json_t *_verrors)
{
	struct nfs4_ace *out = NULL;
	int error;

	/* Initialize an empty ACE */
	out = nfs4_new_ace(is_dir,
	    NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
	    0, /* flag */
	    0, /* access_mask */
	    NFS4_ACL_WHO_OWNER,
	    -1);

	assert(out != NULL);

	error = json_ace_get_type(_jsace, idx, &out->type, _verrors);
	if (error && (error != -EINVAL)) {
		goto error;
	}

	error = json_ace_get_perm(_jsace, idx, &out->access_mask, _verrors);
	if (error && (error != -EINVAL)) {
		goto error;
	}

	error = json_ace_get_flag(_jsace, idx, &out->flag, _verrors);
	if (error && (error != -EINVAL)) {
		goto error;
	}

	error = json_ace_get_who(_jsace, idx, out, _verrors);
	if (error && (error != -EINVAL)) {
		goto error;
	}

	if (json_array_size(_verrors) != 0) {
		/*
		 * There have been validation errors in generating this ACL
		 * avoid adding any ACEs to the internal nfs4_acl struct at
		 * this point.
		 */
		free(out);
		return NULL;
	}

	return out;
error:
	free(out);
	return (NULL);
}

struct nfs4_acl
*convert_json_to_acl(json_t *json_acl, bool is_dir)
{
	struct nfs4_acl *out = NULL;
	struct nfs4_ace *ace = NULL;
	json_t *js_aces = NULL, *verrors = NULL;
	size_t nsaces;
	int i, error;

	out = nfs4_new_acl(is_dir);
	if (out == NULL) {
		errx(EX_OSERR, "nfs4_new_acl() failed");
	}

	verrors = json_array();
	if (!json_is_array(verrors)) {
		err(EX_OSERR, "Failed to generate JSON array for verrors");
	}

	js_aces = json_object_get(json_acl, "acl");
	if (!json_is_array(js_aces)) {
		warnx("{\"acl\": \"ACES array not found\"}");
		return (NULL);
	}

	nsaces = json_array_size(js_aces);
	for (i = 0; i < nsaces; i++) {
		json_t *jsace = json_array_get(js_aces, i);
		if (!json_is_object(jsace)) {
			errx(EX_OSERR, "json_array_get() failed for idx %d", i);
		}
		ace = convert_json_to_ace(jsace, is_dir, i, verrors);
		if (ace == NULL) {
			if (json_array_size(verrors) != 0) {
				continue;
			}
			return (NULL);
		}
		error = nfs4_append_ace(out, ace);
		if (error) {
			errx(EX_OSERR, "Failed to add entry %d to ACL", i);
		}
	}

	error = get_aclflags_from_json(json_acl, &out->aclflags4, verrors);
	if (error && (error != -EINVAL)) {
		errx(EX_OSERR, "(get_aclflags_from_json() failed.");
	}

	if (json_array_size(verrors) > 0) {
		/*
		 * We have some validation errors.
		 * Print them to stderr as JSON and exit.
		 * Invalid ACL will not be applied.
		 */
		char *err_txt = NULL;
		err_txt = json_dumps(verrors, 0);
		if (err_txt == NULL) {
			json_decref(json_acl);
			warnx("Failed to convert verrors to JSON text");
			return (NULL);
		}
		errx(EX_DATAERR, "%s", err_txt);
	}

	return out;
}

struct nfs4_acl
*get_acl_json(const char *json_text, bool is_dir)
{
	struct nfs4_acl *newacl = NULL;
	json_t *json_acl = NULL;

	json_acl = load_json(json_text);
	newacl = convert_json_to_acl(json_acl, is_dir);
	json_decref(json_acl);

	return (newacl);
}

int
set_acl_path_json(const char *path, const char *json_text)
{
	int error;
	struct stat st;
	struct nfs4_acl *newacl = NULL;

	error = stat(path, &st);
	if (error) {
		errx(EX_OSERR, "%s: stat() failed: %s", path, strerror(errno));
	}

	newacl = get_acl_json(json_text, S_ISDIR(st.st_mode));
	if (newacl == NULL) {
		return (-1);
	}

	error = nfs4_acl_set_file(newacl, path);
	return (error);
}
