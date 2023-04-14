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

#include "libacl_nfs4.h"
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

static bool
nfs4ace_to_buf(u32 *xattrbuf, struct nfs4_ace *ace)
{
	u32 who = 0, iflag = 0;

	switch(ace->whotype) {
	case NFS4_ACL_WHO_OWNER:
		iflag = ACEI4_SPECIAL_WHO;
		who = ACE4_SPECIAL_OWNER;
		break;
	case NFS4_ACL_WHO_GROUP:
		iflag = ACEI4_SPECIAL_WHO;
		who = ACE4_SPECIAL_GROUP;
		break;
	case NFS4_ACL_WHO_EVERYONE:
		iflag = ACEI4_SPECIAL_WHO;
		who = ACE4_SPECIAL_EVERYONE;
		break;
	case NFS4_ACL_WHO_NAMED:
		iflag = 0;
		who = ace->who_id;
	}

	*xattrbuf++ = htonl(ace->type);
	*xattrbuf++ = htonl(ace->flag);
	*xattrbuf++ = htonl(iflag);
	*xattrbuf++ = htonl(ace->access_mask);
	*xattrbuf++ = htonl(who);

	return true;
}

static bool
nfs4acl_to_buf(u32 *xattrbuf, struct nfs4_acl *acl)
{
	struct nfs4_ace *ace = NULL;

	*xattrbuf++ = htonl(acl->aclflags4);
	*xattrbuf++ = htonl(acl->naces);

	for (ace = nfs4_get_first_ace(acl); ace != NULL;
	     ace = nfs4_get_next_ace(&ace), xattrbuf += ACE4ELEM) {
		if (!nfs4ace_to_buf(xattrbuf, ace)) {
			return false;
		}
        }

	return true;
}

size_t acl_nfs4_xattr_pack(struct nfs4_acl * acl, char** bufp)
{
	char *buf = NULL;
	size_t acl_size = 0;
	
	if (acl == NULL || bufp == NULL) {
		errno = EINVAL;
		return -1;
	}

	acl_size = ACES_2_ACLSIZE(acl->naces);
	buf = calloc(1, acl_size);
	if (buf == NULL) {
		return -1;
	}

	if (!nfs4acl_to_buf((u32 *)buf, acl)) {
		free(buf);
		return -1;
	}

	*bufp = buf;
	return acl_size;
}
