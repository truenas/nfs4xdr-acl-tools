
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


#ifdef USE_SECURITY_NAMESPACE
/*
 * Non-native NFSv4 ACLs may not exist on file when we try to read
 * them. In this case, synthesize a new NFSv4 ACL from the POSIX
 * mode of the file.
 */
static struct nfs4_acl *synthesize_acl_from_mode(const char *path, int fd)
{
	struct stat st;
	struct nfs4_acl *acl = NULL;
	int error;
	bool ok;

	if (path != NULL) {
		error = stat(path, &st);
		if (error) {
			warnx("%s: stat() failed", path);
			return NULL;
		}
	}
	else {
		error = fstat(fd, &st);
		if (error) {
			warnx("fstat() failed");
			return NULL;
		}
	}

	acl = nfs4_new_acl(S_ISDIR(st.st_mode));
	if (acl == NULL) {
		return NULL;
	}
	ok = acl_nfs4_calculate_inherited_acl(NULL, acl,
					      st.st_mode,
					      false,
					      S_ISDIR(st.st_mode));
	if (!ok) {
		nfs4_free_acl(acl);
		return NULL;
	}

	return acl;
}
#endif

struct nfs4_acl *do_xattr_load(const char *path, int fd,
			       char *xattr, int size)
{
	struct stat st;
	int error;
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

	acl = acl_nfs4_xattr_load(xattr, size, S_ISDIR(st.st_mode));
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

#ifdef USE_SECURITY_NAMESPACE
	if ((result < 0) && (errno == ENODATA)) {
		return synthesize_acl_from_mode(path, -1);
	}
#else
	if (result < 0)
		return NULL;
#endif


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
	fprintf(stderr, "namespace: %s\n", ACL_NFS4_XATTR);
	result = nfs4_getxattr(NULL, fd, NULL, 0);

#ifdef USE_SECURITY_NAMESPACE
	if ((result < 0) && (errno == ENODATA)) {
		return synthesize_acl_from_mode(NULL, fd);
	}
	else if (result < 0) {
		return NULL;
	}
#else
	if (result < 0)
		return NULL;
#endif

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
	if ((path == NULL) && (fd == -1)) {
		errno = EINVAL;
		return (-1);
	}

#ifdef USE_SECURITY_NAMESPACE
	/*
	 * Security namespace xattr must not be used on paths with
	 * native NFSv4 ACLs that are exposed by system namespace.
	 */
	if (path != NULL) {
		res = getxattr(path, SYSTEM_XATTR, value, size);
	}
	if (fd) {
		res = fgetxattr(fd, SYSTEM_XATTR, value, size);
	}
	if (res != -1) {
		/*
		 * Convert errno to ENOSYS so that we avoid
		 * synthesizing a fake ACL from mode and simply
		 * fail the nfs4_acl_get_*() call.
		 */
		warnx("nfs4xdr-acl-tools is built with option "
		      "to write to the 'security' xattr namespace, "
		      "but filesystem uses native NFSv4 ACLs.");
		errno = ENOSYS;
		return (-1);
	}
#endif

	if (path != NULL) {
		res = getxattr(path, ACL_NFS4_XATTR, value, size);
	}
	else {
		res = fgetxattr(fd, ACL_NFS4_XATTR, value, size);
	}
	if ((res < 0) && (errno != ENODATA)) {
		warnx("Failed to get NFSv4 ACL");
	}
	return res;
}
