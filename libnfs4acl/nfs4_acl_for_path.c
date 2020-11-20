
/*  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  David M. Richter <richterd@citi.umich.edu>
 *  Alexis Mackenzie <allamack@umich.edu>
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


#include <sys/types.h>
#include <attr/xattr.h>
#include <sys/stat.h>
#include <stdio.h>
#include "libacl_nfs4.h"

static int nfs4_getxattr(const char *, void *, size_t);

/* returns a newly-allocated struct nfs4_acl for `path', or NULL on error. */
struct nfs4_acl* nfs4_acl_for_path(const char *path)
{
	int result;
	struct nfs4_acl *acl = NULL;
	struct stat st;
	char *xattr;
	u32 iflags;

	if (path == NULL)
		goto out;

	result = stat(path, &st);
	if (result < 0) {
		printf("Invalid filename: %s\n", path);
		goto out;
	}
	if (st.st_mode & S_IFDIR)
		iflags = NFS4_ACL_ISDIR;
	else
		iflags = NFS4_ACL_ISFILE;

	/* find necessary buffer size */
	result = nfs4_getxattr(path, NULL, 0);
	if (result < 0)
		goto out;
	xattr = malloc(result);
	if (!xattr) {
		printf("Failed to allocate memory\n");
		goto out;
	}

	/* reconstruct the ACL */
	result = nfs4_getxattr(path, xattr, result);
	if (result < 0)
		goto out_free;
	acl = acl_nfs4_xattr_load(xattr, result, iflags);
	if (acl == NULL)
		perror("Failed to extract nfs4acl from xattr");
out_free:
	free(xattr);
out:
	return acl;
}

static int nfs4_getxattr(const char *path, void *value, size_t size)
{
	int res;

	res = getxattr(path, ACL_NFS4_XATTR, value, size);
	if (res < -10000) {
		fprintf(stderr,"An internal NFS server error code (%d) was returned; this should never happen.\n",res);
	} else if (res < 0) {
		if (errno == ENOATTR)
			fprintf(stderr,"Attribute not found on file.\n");
		else if (errno == EREMOTEIO)
		    fprintf(stderr,"An NFS server error occurred.\n");
		else if (errno == EOPNOTSUPP)
			fprintf(stderr,"Operation to request attribute not supported.\n");
		else
			perror("Failed getxattr operation");
	}
	return res;
}
