/*
 *  NFSv4 ACL Code
 *  Read the who value from the ace and return its type and optionally
 *  its value.
 *
 *  Ace is a reference to the ace to extract the who value from.
 *  Type is a reference where the value of the whotype will be stored.
 *  Who is a double reference that should either be passed as NULL
 *  (and thus no who string will be returned) or as a pointer to a
 *  char* where the who string will be allocated. This string must be
 *  freed by the caller.
 *
 *  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Nathaniel Gallaher <ngallahe@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "libacl_nfs4.h"
#include <pwd.h>
#include <grp.h>

#define	NAMRBUF	65536

static char *_get_name(uid_t id, bool is_group) {
	char *out = NULL;
	char *buf = NULL;
	struct passwd *pwd = NULL, pw;
	struct group *grp = NULL, gr;
	int error;
	buf = calloc(1, NAMRBUF);
	if (is_group) {
		error = getgrgid_r(id, &gr, buf, NAMRBUF, &grp);
		if (error || (grp == NULL)) {
			free(buf);
			return NULL;
		}
		out = strdup(grp->gr_name);
	}
	else {
		error = getpwuid_r(id, &pw, buf, NAMRBUF, &pwd);
		if (error || pwd == NULL) {
			free(buf);
			return NULL;
		}
		out = strdup(pwd->pw_name);

	}
	free(buf);
	return out;
}

int acl_nfs4_get_who(struct nfs4_ace *ace, nfs4_acl_id_t *_who_id, char *_who_str, size_t buf_size)
{
	int rv = 0;
	char *who_str = NULL;
	nfs4_acl_id_t who_id = -1;
	size_t wholen, ncopied;

	if (ace == NULL) {
		errno = EINVAL;
		return -1;
	}

	switch(ace->whotype) {
	case NFS4_ACL_WHO_NAMED:
		who_id = ace->who_id;
		/*
		 * If who string is requested, then
		 * try conversion of id to name. If this fails
		 * return numeric id as a string.
		 */
		if (_who_str != NULL) {
			who_str = _get_name(who_id, NFS4_IS_GROUP(ace->flag));
			if (who_str == NULL) {
				snprintf(_who_str, buf_size, "%d", who_id);
				if (_who_id != NULL) {
					*_who_id = who_id;
				}
				return 0;
			}
		}
		break;
	case NFS4_ACL_WHO_OWNER:
		who_str = NFS4_ACL_WHO_OWNER_STRING;
		who_id = -1;
		break;
	case NFS4_ACL_WHO_GROUP:
		who_str = NFS4_ACL_WHO_GROUP_STRING;
		who_id = -1;
		break;
	case NFS4_ACL_WHO_EVERYONE:
		who_str = NFS4_ACL_WHO_EVERYONE_STRING;
		who_id = -1;
		break;
	default:
		errno = EINVAL;
		return -1;
	}
	if (_who_id != NULL) {
		*_who_id = who_id;
	}

	if (_who_str == NULL) {
		return 0;
	}

	wholen = strlen(who_str);
	if (wholen > buf_size) {
		errno = ERANGE;
		return -1;
	}
	ncopied = strlcpy(_who_str, who_str, buf_size);
	if (ncopied != wholen) {
		fprintf(stderr, "acl_nfs4_get_who(): truncated who_str\n");
		errno = EINVAL;
		rv = -1;
	}
	if (ace->whotype == NFS4_ACL_WHO_NAMED) {
		free(who_str);
	}
	return rv;
}
