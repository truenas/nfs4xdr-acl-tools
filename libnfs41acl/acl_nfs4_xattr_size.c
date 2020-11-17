/*
 *  NFSv4 ACL Code
 *  Return the expected xattr XDR encoded size of the nfs acl. Used for
 *  figuring the size of the xattr buffer.
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

int acl_nfs4_xattr_size(struct nfs4_acl * acl)
{
	int size = 0;
	struct nfs4_ace * ace;
	int ace_num;

	if (acl == NULL) {
		errno = EINVAL;
		goto failed;
	}

	/* Space for number of aces */
	size += sizeof(u32);

	/* size of aclflag */
	size += sizeof(u32);

	ace = nfs4_get_first_ace(acl);
	ace_num = 1;

	while (1) {
		if (ace == NULL) {
			if (ace_num > acl->naces) {
				break;
			} else {
				errno = ENODATA;
				goto failed;
			}
		}

		/* space for type, flag, and mask */
		size += (3 * sizeof(u32));

		/* space for strlen */
		size += sizeof(u32);

		/* space for the who string... xdr encoded */
		size += (strlen(ace->who) / NFS4_XDR_MOD) * NFS4_XDR_MOD * sizeof(char);
		if (strlen(ace->who) % NFS4_XDR_MOD) {
			size += NFS4_XDR_MOD;
		}
		nfs4_get_next_ace(&ace);
		ace_num++;
	}

	return size;

failed:
	return -1;
}

