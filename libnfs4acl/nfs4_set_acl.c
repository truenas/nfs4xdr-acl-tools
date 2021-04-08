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
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include "nfs41acl.h"
#include "libacl_nfs4.h"

#define NFS4_MIN_ACLSIZE	(sizeof(nfsacl41i) + sizeof(nfsace4i))

int nfs4_acl_set_file(struct nfs4_acl *acl, const char *path)
{
	size_t acl_size = 0;
	char *xdrbuf = NULL;
	int res;

	acl_size = acl_nfs4_xattr_pack(acl, &xdrbuf);
	if (acl_size < NFS4_MIN_ACLSIZE) {
		warnx("nfs4_acl_set_file() failed");
		free(xdrbuf);
		return (-1);
	}

#ifdef USE_SECURITY_NAMESPACE
	/*
	 * Check for system ACL and fail hard if
	 * it exists.
	 */
	res = getxattr(path, SYSTEM_XATTR, NULL, 0);
	if (res != -1) {
		warnx("nfs4xdr-acl-tools is built with option "
		      "to write to the 'security' xattr namespace, "
		      "but filesystem uses native NFSv4 ACLs.");
		free(xdrbuf);
		errno = ENOSYS;
		return (-1);
	}

	res = setxattr(path, ACL_NFS4_XATTR, xdrbuf, acl_size, 0);
#else
	res = setxattr(path, ACL_NFS4_XATTR, xdrbuf, res, XATTR_REPLACE);
#endif
	if (res < 0) {
		warnx("nfs4_acl_set_file() failed");
	}

	free(xdrbuf);
	return (res);
}


int nfs4_acl_set_fd(struct nfs4_acl *acl, int fd)
{
	size_t acl_size = 0;
	char *xdrbuf = NULL;
	int res;

	acl_size = acl_nfs4_xattr_pack(acl, &xdrbuf);
	if (acl_size < NFS4_MIN_ACLSIZE) {
		warnx("nfs4_acl_set_file() failed");
		free(xdrbuf);
		return (-1);
	}

#ifdef USE_SECURITY_NAMESPACE
	/*
	 * Check for system ACL and fail hard if
	 * it exists.
	 */
	res = fgetxattr(fd, SYSTEM_XATTR, NULL, 0);
	if (res != -1) {
		warnx("nfs4xdr-acl-tools is built with option "
		      "to write to the 'security' xattr namespace, "
		      "but filesystem uses native NFSv4 ACLs.");
		free(xdrbuf);
		errno = ENOSYS;
		return (-1);
	}
	res = fsetxattr(fd, ACL_NFS4_XATTR, xdrbuf, acl_size, 0);
#else
	/*
	 * If system namespace is used and filesystem supports native
	 * NFSv4 ACLs, then absence of xattr is significant error
	 * condition and we should fail with ENODATA.
	 */
	res = fsetxattr(fd, ACL_NFS4_XATTR, xdrbuf, res, XATTR_REPLACE);
#endif
	if (res < 0) {
		warnx("nfs4_acl_set_fd() failed");
	}

	free(xdrbuf);
	return res;
}
