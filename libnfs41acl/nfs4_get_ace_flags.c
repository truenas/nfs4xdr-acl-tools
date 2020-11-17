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
char* nfs4_get_ace_flags(struct nfs4_ace *ace, char *buf)
{
	int flags = ace->flag;
	char *bp = buf;

	if (flags & NFS4_ACE_FILE_INHERIT_ACE)
		*buf++ = FLAG_FILE_INHERIT;
	if (flags & NFS4_ACE_DIRECTORY_INHERIT_ACE)
		*buf++ = FLAG_DIR_INHERIT;
	if (flags & NFS4_ACE_NO_PROPAGATE_INHERIT_ACE)
		*buf++ = FLAG_NO_PROPAGATE_INHERIT;
	if (flags & NFS4_ACE_INHERIT_ONLY_ACE)
		*buf++ = FLAG_INHERIT_ONLY;
	if (flags & NFS4_ACE_INHERITED_ACE)
		*buf++ = FLAG_INHERITED;
	if (flags & NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG)
		*buf++ = FLAG_SUCCESSFUL_ACCESS;
	if (flags & NFS4_ACE_FAILED_ACCESS_ACE_FLAG)
		*buf++ = FLAG_FAILED_ACCESS;;
	if (flags & NFS4_ACE_IDENTIFIER_GROUP)
		*buf++ = FLAG_GROUP;
	if (flags & NFS4_ACE_OWNER)
		*buf++ = FLAG_OWNER_AT;
	if (flags & NFS4_ACE_GROUP)
		*buf++ = FLAG_GROUP_AT;
	if (flags & NFS4_ACE_EVERYONE)
		*buf++ = FLAG_EVERYONE_AT;
	*buf = '\0';

	return bp;
}
