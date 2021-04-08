/*
 *  NFSv4 ACL Code
 *  Write the who entry in the nfs4 ace. Who is a user supplied buffer
 *  containing a named who entry (null terminated string) if type is
 *  set to NFS4_ACL_WHO_NAMED. Otherwise, the who buffer is not used.
 *  The user supplied who buffer must be freed by the caller.
 *
 *  This code allocates the who buffer used in the ace. This must be freed
 *  upon ace removal by the ace_remove or acl_free.
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

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include "libacl_nfs4.h"

/*
 * `who` may be a uid/gid string or it may
 * be an actual user or group name. First see if
 * entire `who` string is numeric. If it's not,
 * then proceed with converting using normal
 * passwd / group methods. Returns (uid_t -1) on
 * error. This should never be set on-disk for a
 * regular username / group so it's an acceptable
 * error return here.
 */
static uid_t _get_id(char *who, bool is_group) {
	uid_t out;
	unsigned long id;
	char *remainder = NULL;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;

	id = strtoul(who, &remainder, 10);
	if (*remainder == '\0') {
		return (uid_t)id;
	}
	if (is_group) {
		grp = getgrnam(who);
		if (grp == NULL) {
			return (uid_t)-1;
		}
		out = grp->gr_gid;
	}
	else {
		pwd = getpwnam(who);
		if (pwd == NULL) {
			return (uid_t)-1;
		}
		out = pwd->pw_uid;

	}
	return out;
}

int acl_nfs4_set_who(struct nfs4_ace* ace, int type, char *who)
{
	uid_t id;

	if (ace == NULL) {
		goto inval_failed;
	}

	switch (type) {
		case NFS4_ACL_WHO_NAMED:
			if (who == NULL) {
				fprintf(stderr, "ERROR: named user seems to have no name.\n");
				goto inval_failed;
			}
			id = _get_id(who, NFS4_IS_GROUP(ace->flag));
			if (id == -1) {
				fprintf(stderr, "acl_nfs4_set_who(): name [%s] "
					"is invalid\n", who);
				goto inval_failed;
			}
			snprintf(ace->who, NFS4_MAX_PRINCIPALSIZE, "%d", id);
			break;
		case NFS4_ACL_WHO_OWNER:
			snprintf(ace->who, NFS4_MAX_PRINCIPALSIZE,
				 NFS4_ACL_WHO_OWNER_STRING);
			break;
		case NFS4_ACL_WHO_GROUP:
			snprintf(ace->who, NFS4_MAX_PRINCIPALSIZE,
				 NFS4_ACL_WHO_GROUP_STRING);
			break;
		case NFS4_ACL_WHO_EVERYONE:
			snprintf(ace->who, NFS4_MAX_PRINCIPALSIZE,
				 NFS4_ACL_WHO_EVERYONE_STRING);
			break;
		default:
			goto inval_failed;
	}
	ace->whotype = type;

	return 0;

inval_failed:
	errno = EINVAL;
	return -1;
}
