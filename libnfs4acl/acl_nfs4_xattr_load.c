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


#include <stdbool.h>
#include <arpa/inet.h>
#include "libacl_nfs4.h"

static struct nfs4_ace
*native_to_nfs4ace(u32 *xattrbuf, bool is_dir)
{
	u32 ae_type, ae_flags, ae_iflag, ae_perms, ae_id;
	nfs4_acl_who_t whotype = NFS4_ACL_WHO_NAMED;
	nfs4_acl_id_t id;

	ae_type = ntohl(*(xattrbuf++));
	ae_flags = ntohl(*(xattrbuf++));
	ae_iflag = ntohl(*(xattrbuf++));
	ae_perms = ntohl(*(xattrbuf++));
	ae_id = ntohl(*(xattrbuf++));

	if (ae_iflag & ACEI4_SPECIAL_WHO) {
                switch (ae_id) {
		case ACE4_SPECIAL_OWNER:
			whotype = NFS4_ACL_WHO_OWNER;
			id = -1;
			break;
		case ACE4_SPECIAL_GROUP:
			whotype = NFS4_ACL_WHO_GROUP;
			id = -1;
			break;
		case ACE4_SPECIAL_EVERYONE:
			whotype = NFS4_ACL_WHO_EVERYONE;
			id = -1;
			break;
		default:
			fprintf(stderr, "Unknown id: 0x%08x\n", ae_id);
			errno = EINVAL;
			return NULL;
		}
	} else {
		id = ae_id;
	}

	return nfs4_new_ace(is_dir, ae_type, ae_flags, ae_perms, whotype, id);
}

static bool
native_to_nfs4acl(u32 *xattrbuf, size_t bufsz, struct nfs4_acl *acl)
{
	int i, num_aces;

	acl->aclflags4 = ntohl(*(xattrbuf++));
	num_aces = ntohl(*(xattrbuf++));
	bufsz -= (2 * sizeof (u32));

	for (i= 0; i < num_aces; i++, xattrbuf += ACE4ELEM) {
		struct nfs4_ace *ace = NULL;
		ace = native_to_nfs4ace(xattrbuf, acl->is_directory);
		if (ace == NULL) {
			return false;
		}
		if (nfs4_append_ace(acl, ace)) {
			return false;
		}
	}

	return true;
}


struct nfs4_acl * acl_nfs4_xattr_load(char *xattr_v, int xattr_size, u32 is_dir)
{
	struct nfs4_acl *acl = NULL;

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

	if (!native_to_nfs4acl((u32 *)xattr_v, xattr_size, acl)) {
		free(acl);
		return NULL;
	}

	return acl;
}
