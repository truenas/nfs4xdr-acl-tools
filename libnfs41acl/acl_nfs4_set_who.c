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
#include "libacl_nfs4.h"

int acl_nfs4_set_who(struct nfs4_ace* ace, int type, char* who)
{
	char *iwho = NULL;
	int wholen;

	if (ace == NULL)
		goto inval_failed;

	switch (type) {
		case NFS4_ACL_WHO_NAMED:
			if (who == NULL) {
				fprintf(stderr, "ERROR: named user seems to have no name.\n");
				goto inval_failed;
			}
			iwho = who;
			break;
		case NFS4_ACL_WHO_OWNER:
			iwho = NFS4_ACL_WHO_OWNER_STRING;
			break;
		case NFS4_ACL_WHO_GROUP:
			iwho = NFS4_ACL_WHO_GROUP_STRING;
			break;
		case NFS4_ACL_WHO_EVERYONE:
			iwho = NFS4_ACL_WHO_EVERYONE_STRING;
			break;
		default:
			goto inval_failed;
	}

	wholen = strlen(iwho);
	if (wholen < 1)
		goto inval_failed;

	memset(ace->who, '\0', NFS4_MAX_PRINCIPALSIZE);
	strcpy(ace->who, iwho);
	ace->whotype = type;

	return 0;

inval_failed:
	errno = EINVAL;
	return -1;
}

