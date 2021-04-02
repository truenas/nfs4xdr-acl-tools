
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
#include <err.h>
#include "libacl_nfs4.h"

static int nfs4_getxattr(const char *, const int, void *, size_t);

/* returns a newly-allocated struct nfs4_acl for `path', or NULL on error. */

struct nfs4_acl *do_xattr_load(const char *path, int fd,
			       char *xattr, int size)
{
	struct stat st;
	int error;
	u32 iflags;
	struct nfs4_acl *acl = NULL;

	if (path != NULL) {
		error = stat(path, &st);
		if (error) {
			warnx("%s: stat() failed", path);
			free(xattr);
			return NULL;
		}
	}
	else {
		error = fstat(fd, &st);
		if (error) {
			warnx("fstat() failed");
			free(xattr);
			return NULL;
		}
	}
	if (st.st_mode & S_IFDIR)
		iflags = NFS4_ACL_ISDIR;
	else
		iflags = NFS4_ACL_ISFILE;

	acl = acl_nfs4_xattr_load(xattr, size, iflags);
	if (acl == NULL)
		warnx("acl_nfs4_xattr_load() failed");
	return acl;
}

struct nfs4_acl* nfs4_acl_get_file(const char *path)
{
	int result;
	struct nfs4_acl *acl = NULL;
	char *xattr = NULL;

	if (path == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* find necessary buffer size */
	result = nfs4_getxattr(path, -1, NULL, 0);
	if (result < 0)
		return NULL;

	xattr = malloc(result);
	if (xattr == NULL) {
		warnx("Failed to allocate memory");
		return NULL;
	}

	/* reconstruct the ACL */
	result = nfs4_getxattr(path, -1, xattr, result);
	if (result < 0) {
		free(xattr);
		return NULL;
	}

	acl = do_xattr_load(path, -1, xattr, result);

	free(xattr);
	return acl;
}


struct nfs4_acl* nfs4_acl_get_fd(int fd)
{
	int result;
	struct nfs4_acl *acl = NULL;
	char *xattr = NULL;

	/* find necessary buffer size */
	result = nfs4_getxattr(NULL, fd, NULL, 0);
	if (result < 0)
		return NULL;

	xattr = malloc(result);
	if (xattr == NULL) {
		warnx("Failed to allocate memory");
		return NULL;
	}

	/* reconstruct the ACL */
	result = nfs4_getxattr(NULL, fd, xattr, result);
	if (result < 0) {
		free(xattr);
		return NULL;
	}
	acl = do_xattr_load(NULL, fd, xattr, result);

	free(xattr);
	return acl;
}

static int nfs4_getxattr(const char *path, int fd, void *value, size_t size)
{
	int res;

	if (path != NULL) {
		res = getxattr(path, ACL_NFS4_XATTR, value, size);
	}
	else if (fd) {
		res = fgetxattr(fd, ACL_NFS4_XATTR, value, size);
	}
	else {
		errno = EINVAL;
		return (-1);
	}
	if (res < 0) {
		warnx("Failed to get NFSv4 ACL");
	}
	return res;
}
