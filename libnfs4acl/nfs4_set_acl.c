/*  Copyright (c) 2002, 2003, 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@citi.umich.edu>
 *  David M. Richter <richterd@citi.umich.edu>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <attr/xattr.h>
#include <unistd.h>
#include <stdio.h>
#include "libacl_nfs4.h"

int nfs4_set_acl(struct nfs4_acl *acl, const char *path)
{
	int res = 0;
	char *xdrbuf = NULL;

	res = acl_nfs4_xattr_pack(acl, &xdrbuf);
	if (res <= 0) {
		fprintf(stderr, "Failed to populate xattr from nfs4acl\n");
		goto out_free;
	}

	res = setxattr(path, ACL_NFS4_XATTR, (char *)xdrbuf, res, XATTR_REPLACE);
	if (res < -10000) {
		fprintf(stderr,"An internal NFS server error code (%d) was returned; this should never happen.\n",res);
		goto out_free;
	} else if (res < 0) {
		if (errno == EOPNOTSUPP)
			fprintf(stderr,"Operation to set ACL not supported.\n");
		else if (errno == ENOATTR)
			fprintf(stderr,"ACL Attribute not found on file.\n");
		else if (errno == EREMOTEIO)
			fprintf(stderr,"An NFS server error occurred.\n");
		else
			perror("Failed setxattr operation");
	}

out_free:
	free(xdrbuf);
	return res;
}
