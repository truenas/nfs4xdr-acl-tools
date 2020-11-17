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

int acl_nfs4_get_who(struct nfs4_ace* ace, int* type, char** who)
{
	int itype;
	char* iwho = NULL;
	int wholen;

	if (ace == NULL || ace->who == NULL)
		goto inval_failed;

	itype = acl_nfs4_get_whotype(ace->who);
	if (type != NULL) {
		*type = itype;
	}

	if(who == NULL)
		return 0;

	switch(itype) {
		case NFS4_ACL_WHO_NAMED:
			iwho = ace->who;
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
	if (wholen < 0)
		goto inval_failed;

	(*who) = (char *)malloc(sizeof(char) * (wholen + 1));
	if ((*who) == NULL) {
		errno = ENOMEM;
		goto failed;
	}
	strcpy((*who), iwho);

	return 0;

inval_failed:
	errno = EINVAL;
failed:
	return -1;
}

