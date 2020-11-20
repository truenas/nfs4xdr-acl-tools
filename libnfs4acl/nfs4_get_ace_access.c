/*
 *  NFSv4 ACL Code
 *  Copyright (c) 2006 The Regents of the University of Michigan.
 *  All rights reserved.
 *
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

#include "libacl_nfs4.h"

/* "buf" must be at least 16 bytes */
char* nfs4_get_ace_access(struct nfs4_ace *ace, char *buf, int isdir)
{
	int mask = ace->access_mask;
	char *bp = buf;

	if (isdir) {
		if (mask & NFS4_ACE_LIST_DIRECTORY)
			*buf++ = PERM_LIST_DIR;
		if (mask & NFS4_ACE_ADD_FILE)
			*buf++ = PERM_CREATE_FILE;
		if (mask & NFS4_ACE_ADD_SUBDIRECTORY)
			*buf++ = PERM_CREATE_SUBDIR;
		if (mask & NFS4_ACE_DELETE_CHILD)
			*buf++ = PERM_DELETE_CHILD;
	} else {
		if (mask & NFS4_ACE_READ_DATA)
			*buf++ = PERM_READ_DATA;
		if (mask & NFS4_ACE_WRITE_DATA)
			*buf++ = PERM_WRITE_DATA;
		if (mask & NFS4_ACE_APPEND_DATA)
			*buf++ = PERM_APPEND_DATA;
	}

	if (mask & NFS4_ACE_DELETE)
		*buf++ = PERM_DELETE;
	if (mask & NFS4_ACE_EXECUTE)
		*buf++ = PERM_EXECUTE;
	if (mask & NFS4_ACE_READ_ATTRIBUTES)
		*buf++ = PERM_READ_ATTR;
	if (mask & NFS4_ACE_WRITE_ATTRIBUTES)
		*buf++ = PERM_WRITE_ATTR;
	if (mask & NFS4_ACE_READ_NAMED_ATTRS)
		*buf++ = PERM_READ_NAMED_ATTR;
	if (mask & NFS4_ACE_WRITE_NAMED_ATTRS)
		*buf++ = PERM_WRITE_NAMED_ATTR;
	if (mask & NFS4_ACE_READ_ACL)
		*buf++ = PERM_READ_ACL;
	if (mask & NFS4_ACE_WRITE_ACL)
		*buf++ = PERM_WRITE_ACL;
	if (mask & NFS4_ACE_WRITE_OWNER)
		*buf++ = PERM_WRITE_OWNER;
	if (mask & NFS4_ACE_SYNCHRONIZE)
		*buf++ = PERM_SYNCHRONIZE;
	*buf = '\0';

	return bp;
}
