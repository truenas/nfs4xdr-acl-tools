/*
 *  NFSv4 ACL Code
 *  Pack an NFS4 ACL into an XDR encoded buffer.
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

#include <netinet/in.h>
#include <rpc/xdr.h>
#include "libacl_nfs4.h"
#include "nfs41acl.h"
#include <stdio.h>
#include <stdbool.h>

int acl_nfs4_xattr_pack(struct nfs4_acl * acl, char** bufp)
{
	struct nfs4_ace *ace = NULL;
	nfsacl41i *nacl = NULL;
	int buflen;
	int ace_num;
	int result;
	int i = 0;
	XDR xdr = {0};
	bool ok;
	size_t acl_size = sizeof(nfsacl41i) + (acl->naces * sizeof(struct nfsace4i));
	
	char* p;
	char* who;

	if (acl == NULL || bufp == NULL) {
		errno = EINVAL;
		goto failed;
	}

	buflen = acl_nfs4_xattr_size(acl);
	if (buflen < 0) {
		goto failed;
	}

	nacl = calloc(1, acl_size);
	*bufp = (char*) calloc(1, acl_size);
	if (*bufp == NULL) {
		errno = ENOMEM;
		goto failed;
	}
	nacl->na41_aces.na41_aces_len = acl->naces;
	nacl->na41_flag = acl->aclflags4;
	nacl->na41_aces.na41_aces_val = (nfsace4i *)((char *)nacl + sizeof(nfsacl41i));	
	ace = nfs4_get_first_ace(acl);
	ace_num = 1;
	while (1) {
		int whotype = 0;
		if (ace == NULL) {
			if (ace_num > acl->naces) {
				break;
			} else {
				errno = ENODATA;
				goto failed;
			}
		}
		if (ace->whotype != 0) {
			whotype = ace->whotype;
		}
		else {
			result = acl_nfs4_get_who(ace, &whotype, &who);
			if (result < 0) {
				goto free_failed;
			}
		}
		nfsace4i *nacep = &nacl->na41_aces.na41_aces_val[ace_num -1];
		nacep->type = ace->type;
		nacep->flag = ace->flag;
		nacep->access_mask = ace->access_mask;

		switch(whotype) {
		case NFS4_ACL_WHO_OWNER:
			nacep->iflag |= ACEI4_SPECIAL_WHO;
			nacep->who = ACE4_SPECIAL_OWNER;
			break;
		case NFS4_ACL_WHO_GROUP:
			nacep->iflag |= ACEI4_SPECIAL_WHO;
			nacep->who = ACE4_SPECIAL_GROUP;
			break;
		case NFS4_ACL_WHO_EVERYONE:
			nacep->iflag |= ACEI4_SPECIAL_WHO;
			nacep->who = ACE4_SPECIAL_EVERYONE;
			break;
		case NFS4_ACL_WHO_NAMED:
			nacep->iflag = 0;
			nacep->who = atoi(who);

		}
#ifdef NFS4_DEBUG
		fprintf(stderr, "who: 0x%08x, iflag: 0x%08x, type: 0x%08x "
			"access_mask: 0x%08x, flags: 0x%08x\n",
			nacep->who, nacep->iflag, nacep->type,
			nacep->access_mask, nacep->flag);
#endif
		nfs4_get_next_ace(&ace);
		ace_num++;
	}
        xdrmem_create(&xdr, *bufp, acl_size, XDR_ENCODE);
	ok = xdr_nfsacl41i(&xdr, nacl);
	if (!ok) {
		free(nacl);
		goto free_failed;
	}
	free(nacl);
	return buflen;

free_failed:
	free(*bufp);
	*bufp = NULL;

failed:
	return -1;
}



