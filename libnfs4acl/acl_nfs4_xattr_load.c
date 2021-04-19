/*
 *  NFSv4 ACL Code
 *  Convert NFSv4 xattr values to a posix ACL
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
#include <stdbool.h>
#include "libacl_nfs4.h"
#include "rpc/xdr.h"
#include "nfs41acl.h"


struct nfs4_acl * acl_nfs4_xattr_load(char *xattr_v, int xattr_size, u32 is_dir)
{
	struct nfs4_acl *acl = NULL;
	struct nfs4_ace *ace = NULL;
	struct nfsacl41i *nacl = NULL;
	char *bufp = xattr_v;
	u32 ace_n;
	u32 num_aces;
	nfs4_acl_type_t type;
	nfs4_acl_flag_t flag;
	nfs4_acl_perm_t access_mask;
	XDR xdr = {0};
	size_t acl_size = 0, xdr_size = 0;
	bool ok;


	if (xattr_size > ACES_2_XDRSIZE(NFS41ACLMAXACES)) {
		errno = E2BIG;
		return NULL;
	}

	if (!XDRSIZE_IS_VALID(xattr_size)) {
		fprintf(stderr, "xattr size: %d is invalid\n", xattr_size);
		errno = EINVAL;
		return NULL;
	}

	if ((acl = nfs4_new_acl(is_dir)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	num_aces = XDRSIZE_2_ACES(xattr_size);
	acl_size = ACES_2_ACLSIZE(num_aces);

	nacl = (nfsacl41i *)calloc(1, acl_size);
	if (nacl == NULL) {
		errno = ENOMEM;
		goto err1;
	}

	xdrmem_create(&xdr, bufp, xattr_size, XDR_DECODE);
	ok = xdr_nfsacl41i(&xdr, nacl);
	if (!ok) {
		errno = ENOMEM;
		free(nacl);
		goto err1;
	}
	for(ace_n = 0; num_aces > ace_n ; ace_n++) {
		nfsace4i *nacep = &nacl->na41_aces.na41_aces_val[ace_n]; 
		char who[20] = {0};
		/* Get the acl type */
		type = (nfs4_acl_type_t)nacep->type;
		flag = (nfs4_acl_flag_t)nacep->flag;
		access_mask = (nfs4_acl_perm_t)nacep->access_mask;
		nfs4_acl_who_t whotype;

		if (nacep->iflag & ACEI4_SPECIAL_WHO) {
			switch(nacep->who) {
			case ACE4_SPECIAL_OWNER:
				whotype = NFS4_ACL_WHO_OWNER;
				snprintf(who, sizeof(who), "%s", NFS4_ACL_WHO_OWNER_STRING);
				break;
			case ACE4_SPECIAL_GROUP:
				whotype = NFS4_ACL_WHO_GROUP;
				snprintf(who, sizeof(who), "%s", NFS4_ACL_WHO_GROUP_STRING);
				break;
			case ACE4_SPECIAL_EVERYONE:
				whotype = NFS4_ACL_WHO_EVERYONE;
				snprintf(who, sizeof(who), "%s", NFS4_ACL_WHO_EVERYONE_STRING);
				break;
			default:
				fprintf(stderr, "Unknown id: 0x%08x\n", nacep->who);
				errno = EINVAL;
				free(nacl);
				goto err1;
			}

		}
		else {
			whotype = NFS4_ACL_WHO_NAMED;
			snprintf(who, sizeof(who), "%d", nacep->who);
		}
		ace = nfs4_new_ace(is_dir, type, flag, access_mask, whotype, who);
		if (ace == NULL) {
			free(nacl);
			goto err1;
		}

		if (nfs4_append_ace(acl, ace)){
			free(nacl);
			goto err1;
		}

	}

	free(nacl);
	return acl;

err1:
	nfs4_free_acl(acl);
	return NULL;
}
